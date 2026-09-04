<?php

declare(strict_types=1);

namespace VPNDetection;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;
use VPNDetection\Internal\Api\DatabaseApi as WireDatabaseApi;
use VPNDetection\Internal\Model\DatasetChecksumsResponse;
use VPNDetection\Internal\Model\DatasetList;
use VPNDetection\Internal\Model\DatasetMetadata as WireDatasetMetadata;
use VPNDetection\Internal\Model\DownloadList;

/**
 * The licensed dataset downloads. Access is granted by contract, not self-serve.
 *
 * Reached as `$client->database`.
 */
final class DatabaseApi
{
    // One chunk of a transfer, and therefore the ceiling on what a download of
    // any size costs in memory.
    private const CHUNK_BYTES = 1024 * 1024;

    public function __construct(
        private readonly WireDatabaseApi $api,
        private readonly Transport $transport,
    ) {
    }

    /**
     * @return list<LicensedDataset>
     * @throws VPNDetectionException
     */
    public function list(): array
    {
        $wire = $this->model($this->transport->send($this->api->listDatabasesRequest()), DatasetList::class);
        return array_map(LicensedDataset::fromWire(...), $wire->getDatasets());
    }

    /** @throws VPNDetectionException */
    public function metadata(string $id): DatasetMetadata
    {
        $response = $this->transport->send($this->api->databaseMetadataRequest($id));
        return DatasetMetadata::fromWire($this->model($response, WireDatasetMetadata::class));
    }

    /**
     * The digests for one dataset file.
     *
     * @param string $format `csvgz` or `mmdb`.
     * @throws VPNDetectionException
     */
    public function checksums(string $id, string $format): DatasetChecksums
    {
        $response = $this->transport->send($this->api->databaseChecksumRequest($id, $format));
        // The digests are nested one level down, under `checksums`. Unwrapping a
        // generated response type rather than a hand-written shape is what keeps
        // the depth honest; reading a top-level `sha256` returns nothing against
        // a perfectly healthy API.
        $wire = $this->model($response, DatasetChecksumsResponse::class);
        return DatasetChecksums::fromWire($wire->getChecksums());
    }

    /**
     * Your organization's recent download attempts, newest first.
     *
     * @return list<Download>
     * @throws VPNDetectionException
     */
    public function downloads(int $limit = 50): array
    {
        $response = $this->transport->send($this->api->listDownloadsRequest($limit));
        $wire = $this->model($response, DownloadList::class);
        return array_map(Download::fromWire(...), $wire->getDownloads());
    }

    /**
     * The time-limited URL for one dataset file.
     *
     * The API answers `302` to object storage. The URL is returned rather than
     * the bytes so the caller decides how to transfer a file that routinely runs
     * to gigabytes; the link authorizes the START of a transfer, so one already
     * running is not interrupted when it lapses.
     *
     * @param string $format `csvgz` or `mmdb`.
     * @throws VPNDetectionException
     */
    public function downloadUrl(string $id, string $format): string
    {
        $response = $this->transport->send($this->api->downloadDatabaseRequest($id, $format));
        $location = $response->getHeaderLine('Location');
        if ($response->getStatusCode() === 302 && $location !== '') {
            return $location;
        }
        throw new VPNDetectionException(
            ErrorKind::ServerError,
            'expected a redirect to object storage',
            $response->getStatusCode(),
        );
    }

    /**
     * Download one dataset file, streaming it to `$destination`.
     *
     * `$destination` is either a path to write or a stream resource you opened
     * yourself. A path is written through a neighboring `.part` file and renamed
     * on completion, so a transfer that dies half way leaves no truncated file
     * that reads as a whole dataset; a stream you pass is written as-is and stays
     * yours to close. Nothing larger than one chunk is ever held in memory,
     * whatever the dataset weighs.
     *
     * Returns the number of bytes written.
     *
     * @param string $format `csvgz` or `mmdb`.
     * @param string|resource $destination
     * @throws VPNDetectionException
     */
    public function download(string $id, string $format, mixed $destination): int
    {
        // Checked before the request, so a bad destination costs no quota.
        if (!is_string($destination) && !is_resource($destination)) {
            throw new InvalidArgumentException('destination must be a path or a stream resource');
        }
        $response = $this->fetchDatasetFile($id, $format);
        if (!is_string($destination)) {
            return self::drain($response, $destination);
        }

        $partial = $destination . '.part';
        $handle = Utils::tryFopen($partial, 'wb');
        try {
            $written = self::drain($response, $handle);
        } catch (Throwable $e) {
            fclose($handle);
            unlink($partial);
            throw $e;
        }
        fclose($handle);
        if (!rename($partial, $destination)) {
            unlink($partial);
            throw new RuntimeException(sprintf('could not move the dataset into place at %s', $destination));
        }
        return $written;
    }

    /**
     * Download one dataset file and hand back its bytes.
     *
     * **This holds the entire file in memory**, and the catalog spans five orders
     * of magnitude: `cdn_ip_v1` is 10 KB while `resproxy_ip_90d_v1` is 1.79 GB,
     * which PHP's `memory_limit` turns into a fatal error rather than mere
     * pressure. Reach for this at the small end, where the bytes go straight into
     * a parser; use `download` for anything you have not measured.
     *
     * @param string $format `csvgz` or `mmdb`.
     * @throws VPNDetectionException
     */
    public function downloadBytes(string $id, string $format): string
    {
        $response = $this->fetchDatasetFile($id, $format);
        $bytes = (string) $response->getBody();
        self::assertWholeTransfer($response, strlen($bytes));
        return $bytes;
    }

    // Follows the 302 as a SECOND, unauthenticated request: the presigned URL
    // carries its own authorization, so forwarding the API key would hand a
    // credential to a host that has no business holding it.
    private function fetchDatasetFile(string $id, string $format): ResponseInterface
    {
        return $this->transport->sendStreaming(
            new Request('GET', $this->downloadUrl($id, $format)),
            'object storage refused the download link',
        );
    }

    /** @param resource $handle */
    private static function drain(ResponseInterface $response, $handle): int
    {
        $body = $response->getBody();
        $written = 0;
        while (true) {
            $chunk = $body->read(self::CHUNK_BYTES);
            if ($chunk === '') {
                break;
            }
            while ($chunk !== '') {
                // A failure writing is the caller's to read: a full disk and a
                // reset socket are different problems, and only one is ours.
                $n = fwrite($handle, $chunk);
                if ($n === false || $n === 0) {
                    throw new RuntimeException('could not write the dataset to the destination');
                }
                $written += $n;
                $chunk = substr($chunk, $n);
            }
        }
        self::assertWholeTransfer($response, $written);
        return $written;
    }

    // A transfer that dies mid-body reaches PHP as a plain EOF, so a short read
    // is silent unless what arrived is checked against what was promised. Node's
    // fetch raises this for itself; here it has to be asserted.
    private static function assertWholeTransfer(ResponseInterface $response, int $written): void
    {
        $declared = $response->getHeaderLine('Content-Length');
        if ($declared !== '' && (int) $declared !== $written) {
            throw new VPNDetectionException(
                ErrorKind::Network,
                sprintf('the transfer ended after %d of %s bytes', $written, $declared),
                $response->getStatusCode(),
            );
        }
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    private function model(ResponseInterface $response, string $class): object
    {
        return Transport::toModel(
            (string) $response->getBody(),
            $class,
            $response->getStatusCode(),
        );
    }
}
