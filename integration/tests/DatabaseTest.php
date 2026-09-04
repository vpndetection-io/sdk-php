<?php

declare(strict_types=1);

namespace VPNDetection\Integration\Tests;

use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\DatasetChecksums;
use VPNDetection\ErrorKind;
use VPNDetection\Integration\Staging;
use VPNDetection\Integration\Tiers;
use VPNDetection\VPNDetectionException;

/**
 * The licensed-download half, which only the max key can reach: it is the tier
 * holding dataset licenses, and `db.download` is a scope the other three keys do
 * not carry.
 *
 * The transfer is budgeted before it starts. `metadata` publishes a size per
 * format, and that size is checked against the ceiling below FIRST, so a mistaken
 * dataset id can never quietly pull one of the gigabyte datasets through CI.
 */
final class DatabaseTest extends TestCase
{
    // The max organization licenses `cdn_ip` for redistribution, and at ~10 KB it
    // is the only dataset small enough to move in CI.
    private const DATASET_ID = 'cdn_ip_v1';
    private const FORMAT = 'csvgz';
    // 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
    // tripping it means the suite is pointed somewhere unintended, which is
    // exactly when a transfer must not go ahead.
    private const CEILING = 8 * 1024 * 1024;
    // A real catalog id the max organization holds no license for.
    private const UNLICENSED_ID = 'hosting_ip_v1';

    /** @var list<array{host: string, path: string, carriedKey: bool}> */
    private static array $facts = [];

    private static ?Client $client = null;
    /** @var array{bytes: int, path: string, checksums: DatasetChecksums}|null */
    private static ?array $transfer = null;
    private static string $tmp = '';

    public static function setUpBeforeClass(): void
    {
        self::$tmp = sys_get_temp_dir() . '/vpndetection-integration-' . bin2hex(random_bytes(6));
        mkdir(self::$tmp);
    }

    public static function tearDownAfterClass(): void
    {
        foreach ((array) glob(self::$tmp . '/*') as $file) {
            unlink((string) $file);
        }
        rmdir(self::$tmp);
    }

    protected function setUp(): void
    {
        $reason = Tiers::skipFor(Tiers::max());
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
    }

    /**
     * A license covers a dataset FAMILY, and the ids a download takes hang off
     * `versions`. This is the endpoint that did not match its own schema until
     * 2026-09-04. PHP is loud about that where the other bindings are quiet: the
     * generated getters are typed, so a required field the payload does not
     * carry is a TypeError out of `getBase()` rather than a null field nothing
     * notices.
     */
    public function testTheLicensedCatalogAnswersTheFamilyShape(): void
    {
        $datasets = self::client()->database->list();

        self::assertNotEmpty($datasets, 'the max organization licenses nothing');
        foreach ($datasets as $dataset) {
            self::assertNotSame('', $dataset->base);
            self::assertNotSame('', $dataset->name);
            self::assertContains($dataset->standing, ['expired', 'licensed', 'unlicensed'],
                "{$dataset->base} carries an undocumented standing");
            self::assertContains($dataset->redistribution, ['evaluation', 'internal', 'redistribute'],
                "{$dataset->base} carries an undocumented right");
            self::assertNotEmpty($dataset->versions, "{$dataset->base} carries no versions");
            foreach ($dataset->versions as $version) {
                self::assertNotSame('', $version->id, "{$dataset->base} has a version with no id");
                self::assertGreaterThan(0, $version->version);
                self::assertNotEmpty($version->formats, "{$version->id} carries no formats");
            }
        }
        $ids = [];
        foreach ($datasets as $dataset) {
            foreach ($dataset->versions as $version) {
                $ids[] = $version->id;
            }
        }
        print 'licensed: ' . implode(', ', $ids) . "\n";
    }

    public function testADatasetTheOrganizationDoesNotLicenseIsRefusedCleanly(): void
    {
        $before = count(self::$facts);

        try {
            self::client()->database->downloadUrl(self::UNLICENSED_ID, self::FORMAT);
            self::fail(self::UNLICENSED_ID . ' is now licensed here, so point this at one that is not');
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::Forbidden, $e->kind);
            self::assertSame(403, $e->status);
            self::assertFalse($e->isRetryable(), 'a license refusal is not worth retrying');
            // The API says which refusal this is (`{"rc":"NOT_LICENSED"}`).
            // Falling back to the status means the envelope went unread.
            self::assertStringStartsNotWith(
                'request failed with status',
                $e->getMessage(),
                'the message is the client fallback, so the response body went unread',
            );
        }

        self::assertCount($before + 1, self::$facts, 'a 4xx must not be retried');
    }

    public function testDownloadStreamsARealDatasetToDiskIntact(): void
    {
        $dl = self::downloaded();

        self::assertGreaterThan(0, $dl['bytes'], 'nothing was transferred');
        self::assertSame(filesize($dl['path']), $dl['bytes'], 'the file is not the length the method reported');
        self::assertFileDoesNotExist($dl['path'] . '.part', 'the .part file outlived a successful transfer');
        $head = substr((string) file_get_contents($dl['path']), 0, 2);
        self::assertSame("\x1f\x8b", $head, 'the payload is not gzip');

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', (string) $dl['checksums']->sha256);
        self::assertSame(
            hash_file('sha256', $dl['path']),
            $dl['checksums']->sha256,
            'the bytes are not the published file',
        );

        // The presigned URL authorizes itself, so the second request must carry
        // no credential.
        $storage = array_filter(self::$facts, static fn (array $f): bool => $f['host'] !== Staging::STAGING_HOST);
        self::assertNotEmpty($storage, 'nothing was fetched from object storage, so no 302 was followed');
        foreach ($storage as $fact) {
            self::assertFalse($fact['carriedKey'], 'the API key was sent to object storage');
        }
    }

    public function testDownloadBytesAgreesWithTheStreamedCopy(): void
    {
        $dl = self::downloaded();

        $bytes = self::client()->database->downloadBytes(self::DATASET_ID, self::FORMAT);

        self::assertSame($dl['bytes'], strlen($bytes), 'the in-memory copy is a different length');
        self::assertSame($dl['checksums']->sha256, hash('sha256', $bytes), 'the in-memory copy is not the file');
    }

    private static function client(): Client
    {
        return self::$client ??= Staging::clientFor(Tiers::max(), static function (array $fact): void {
            self::$facts[] = $fact;
        });
    }

    /**
     * Memoized, so the two transfer tests share one download rather than pulling
     * the dataset twice each.
     *
     * @return array{bytes: int, path: string, checksums: DatasetChecksums}
     */
    private static function downloaded(): array
    {
        if (self::$transfer !== null) {
            return self::$transfer;
        }

        $meta = self::client()->database->metadata(self::DATASET_ID);
        self::assertSame(self::DATASET_ID, $meta->id);
        $size = $meta->size[self::FORMAT] ?? null;
        self::assertIsInt($size, self::DATASET_ID . ' publishes no size to check a transfer against');
        self::assertGreaterThan(0, $size);
        self::assertLessThanOrEqual(self::CEILING, $size, self::DATASET_ID . " is {$size} bytes, past the ceiling");

        $path = self::$tmp . '/' . self::DATASET_ID . '.csv.gz';
        $bytes = self::client()->database->download(self::DATASET_ID, self::FORMAT, $path);
        // Read after the transfer, so a rebuild between the two calls shows up as
        // a digest mismatch rather than passing against a digest of nothing.
        $checksums = self::client()->database->checksums(self::DATASET_ID, self::FORMAT);
        print self::DATASET_ID . '.' . self::FORMAT . ": {$bytes} bytes, metadata says {$size}\n";

        return self::$transfer = ['bytes' => $bytes, 'path' => $path, 'checksums' => $checksums];
    }
}
