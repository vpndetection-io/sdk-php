<?php

declare(strict_types=1);

namespace VPNDetection;

use Psr\Http\Message\ResponseInterface;
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
