<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options;
use VPNDetection\VPNDetectionException;

/**
 * The dataset download path, against a real HTTP origin rather than a stub: what
 * these methods are for is the 302 and a body too large to hold, and neither
 * question survives a canned response.
 */
final class DownloadTest extends TestCase
{
    private const SMALL = 3;
    private const MIB = 1024 * 1024;

    private ?Origin $origin = null;
    private string $tmp = '';

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/vpndetection-dl-' . bin2hex(random_bytes(6));
        mkdir($this->tmp);
    }

    protected function tearDown(): void
    {
        $this->origin?->stop();
        foreach ((array) glob($this->tmp . '/*') as $file) {
            unlink((string) $file);
        }
        rmdir($this->tmp);
    }

    public function testDownloadFollowsTheRedirectAndWritesTheFile(): void
    {
        $client = $this->client(['blobBytes' => self::SMALL]);
        $path = $this->tmp . '/cdn_ip_v1.csv.gz';

        $written = $client->database->download('cdn_ip_v1', 'csvgz', $path);

        self::assertSame(self::SMALL, $written);
        self::assertSame('aaa', (string) file_get_contents($path));
        self::assertSame(
            ['/api/v1/database/download', '/blob'],
            array_column($this->origin->requests(), 'path'),
        );
        self::assertFileDoesNotExist($path . '.part', 'the .part file outlived a successful transfer');
    }

    public function testDownloadWritesIntoAStreamTheCallerOpened(): void
    {
        $client = $this->client(['blobBytes' => self::SMALL]);
        $handle = fopen('php://temp', 'w+b');

        $written = $client->database->download('cdn_ip_v1', 'csvgz', $handle);

        self::assertSame(self::SMALL, $written);
        rewind($handle);
        self::assertSame('aaa', (string) stream_get_contents($handle));
        // A stream the caller opened stays theirs: still open, still theirs to close.
        self::assertIsResource($handle);
        fclose($handle);
    }

    public function testDownloadBytesReturnsTheBytes(): void
    {
        $client = $this->client(['blobBytes' => self::SMALL]);

        self::assertSame('aaa', $client->database->downloadBytes('cdn_ip_v1', 'csvgz'));
    }

    public function testADestinationThatIsNeitherAPathNorAStreamIsRefusedBeforeAnyRequest(): void
    {
        $client = $this->client(['blobBytes' => self::SMALL]);

        try {
            $client->database->download('cdn_ip_v1', 'csvgz', ['not', 'a', 'destination']);
            self::fail('an unusable destination was accepted');
        } catch (InvalidArgumentException) {
            self::assertSame([], $this->origin->requests(), 'a bad destination must cost no quota');
        }
    }

    // The key authorizes minting the link. The link is presigned and authorizes
    // itself, so forwarding the key would hand a credential to a host that has no
    // business seeing it.
    public function testTheKeyReachesTheApiAndNeverObjectStorage(): void
    {
        $client = $this->client(['blobBytes' => self::SMALL]);

        $client->database->download('cdn_ip_v1', 'csvgz', $this->tmp . '/keys.csv.gz');

        $api = $this->origin->requestsTo('/api/v1/database/download')[0];
        $storage = $this->origin->requestsTo('/blob')[0];
        self::assertStringContainsString('secret-key', $api['headers']['authorization']);
        self::assertSame([], $storage['query'], 'the key must not ride in the storage query string');
        self::assertStringNotContainsString(
            'secret-key',
            json_encode($storage['headers'], JSON_THROW_ON_ERROR),
            'the API key was sent to object storage',
        );
    }

    /**
     * The assertion that matters most, and the one a vacuous measurement would
     * pass: `downloadBytes` moving the same body through the same origin has to
     * show the growth `download` does not, or the threshold proves nothing.
     */
    public function testALargeBodyIsStreamedRatherThanHeld(): void
    {
        $size = 32 * self::MIB;
        $client = $this->client(['blobBytes' => $size]);

        $before = memory_get_peak_usage(true);
        $written = $client->database->download('vpn_ip_extended_v1', 'mmdb', $this->tmp . '/big.mmdb');
        $streamed = memory_get_peak_usage(true) - $before;

        $before = memory_get_peak_usage(true);
        $bytes = $client->database->downloadBytes('vpn_ip_extended_v1', 'mmdb');
        $held = memory_get_peak_usage(true) - $before;

        self::assertSame($size, $written, 'the whole body must have been transferred');
        self::assertSame($size, strlen($bytes));
        self::assertLessThan(8 * self::MIB, $streamed, 'download held ' . $streamed . ' bytes of a 32 MiB body');
        self::assertGreaterThanOrEqual($size, $held, 'the measurement cannot see a buffered body at all');
    }

    public function testObjectStorageRefusingTheLinkIsATypedError(): void
    {
        $client = $this->client(['storageStatus' => 403], retries: 0);

        try {
            $client->database->downloadBytes('cdn_ip_v1', 'csvgz');
            self::fail('a refused link was not reported');
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::Forbidden, $e->kind);
            self::assertFalse($e->isRetryable());
            self::assertStringContainsString('object storage', $e->getMessage());
            // Reading it would mean holding an error page of no bounded size.
            self::assertStringNotContainsString('AccessDenied', $e->getMessage());
        }
    }

    // A truncated file that looks complete is worse than no file: the next run
    // reads it as a whole dataset. PHP sees a dropped transfer as a plain EOF, so
    // this only fails if the declared length is checked against what arrived.
    public function testATransferThatDiesPartWayLeavesNothingAtTheDestination(): void
    {
        $client = $this->client(['blobBytes' => 4 * self::MIB, 'dieAfterBytes' => self::MIB], retries: 0);
        $path = $this->tmp . '/half-a-dataset.csv.gz';

        try {
            $client->database->download('cdn_ip_v1', 'csvgz', $path);
            self::fail('a truncated transfer was reported as a whole one');
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::Network, $e->kind);
        }

        self::assertFileDoesNotExist($path);
        self::assertFileDoesNotExist($path . '.part');
    }

    /** @param array{blobBytes?: int, storageStatus?: int, dieAfterBytes?: int} $options */
    private function client(array $options, int $retries = 2): Client
    {
        $this->origin = new Origin($options);
        return new Client(new Options(
            apiKey: 'secret-key',
            baseUrl: $this->origin->baseUrl,
            retries: $retries,
        ));
    }
}
