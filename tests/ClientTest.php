<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use GuzzleHttp\RequestOptions;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use VPNDetection\Bogon;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options;
use VPNDetection\VPNDetectionException;

/**
 * The PHP-specific API surface, as distinct from the shared conformance corpus
 * in ConformanceTest.
 */
final class ClientTest extends TestCase
{
    /** @var list<string> */
    private const ADDRS = [
        '9.9.9.1', '9.9.9.2', '9.9.9.3', '9.9.9.4', '9.9.9.5', '9.9.9.6',
        '9.9.9.7', '9.9.9.8', '9.9.9.9', '9.9.9.10', '9.9.9.11', '9.9.9.12',
    ];

    public function testIsBogonIsOnTheClientAndAgreesWithTheStandaloneStatic(): void
    {
        $data = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
        $client = new Client();
        foreach ($data['isBogon'] as $case) {
            self::assertSame($case['expect'], $client->isBogon($case['ip']), $case['ip']);
            self::assertSame(
                Bogon::isBogon($case['ip']),
                $client->isBogon($case['ip']),
                "{$case['ip']}: client and static disagree",
            );
        }
    }

    // The shared corpus pins present-versus-absent for SOME of the tier-gated
    // members, but not for every one of them, so a per-field slip in the mapper
    // can survive it. Mutating `is_hosting` to copy on truthiness rather than on
    // presence passed the whole corpus; this is what fails instead.
    public function testEveryTierGatedMemberKeepsFalseApartFromAbsent(): void
    {
        $flags = [
            'is_hosting' => 'isHosting', 'is_relay' => 'isRelay', 'is_tor' => 'isTor',
            'is_cdn' => 'isCdn', 'is_resproxy' => 'isResproxy', 'is_dcproxy' => 'isDcproxy',
            'is_mobproxy' => 'isMobproxy',
        ];
        $details = ['vpn', 'hosting', 'relay', 'tor', 'cdn', 'resproxy', 'dcproxy', 'mobproxy'];

        $body = ['ip' => '9.9.9.1', 'is_vpn' => false];
        foreach (array_keys($flags) as $wire) {
            $body[$wire] = false;
        }
        foreach ($details as $wire) {
            $body[$wire] = [];
        }
        $present = self::lookupOnce($body);
        foreach ($flags as $wire => $property) {
            self::assertFalse($present->{$property}, "{$wire} answered false must stay false");
        }
        foreach ($details as $wire) {
            self::assertNotNull($present->{$wire}, "{$wire} answered {} must stay present");
            self::assertTrue($present->{$wire}->isEmpty(), "{$wire} answered {} must be empty");
        }

        $absent = self::lookupOnce(['ip' => '9.9.9.1', 'is_vpn' => false]);
        foreach ($flags as $wire => $property) {
            self::assertNull($absent->{$property}, "{$wire} left out must stay null, not false");
        }
        foreach ($details as $wire) {
            self::assertNull($absent->{$wire}, "{$wire} left out must stay null, not empty");
        }
    }

    public function testBatchConcurrencyIsConfigurablePerCall(): void
    {
        $stub = self::addressStub();
        $client = new Client(new Options(cache: false, httpClient: $stub->client));

        $client->lookupBatch(self::ADDRS, ['concurrency' => 3]);

        self::assertCount(count(self::ADDRS), $stub->calls);
        self::assertLessThanOrEqual(3, $stub->peak, "peak in flight was {$stub->peak}");
        self::assertGreaterThan(1, $stub->peak, 'requests should still overlap');
    }

    public function testAPerCallConcurrencyOverridesTheClientDefault(): void
    {
        $stub = self::addressStub();
        // Instance default of 2, raised to 6 for this one batch.
        $client = new Client(new Options(cache: false, concurrency: 2, httpClient: $stub->client));

        $client->lookupBatch(self::ADDRS, ['concurrency' => 6]);

        self::assertGreaterThan(2, $stub->peak, "override ignored: peak was {$stub->peak}");
        self::assertLessThanOrEqual(6, $stub->peak, "peak in flight was {$stub->peak}");
    }

    public function testWithoutAnOverrideTheClientConcurrencyStillApplies(): void
    {
        $stub = self::addressStub();
        $client = new Client(new Options(cache: false, concurrency: 2, httpClient: $stub->client));

        $client->lookupBatch(self::ADDRS);

        self::assertLessThanOrEqual(2, $stub->peak, "peak in flight was {$stub->peak}");
    }

    public function testRetriesAreConfigurablePerCall(): void
    {
        $stub = new Stub(Stub::lookups([
            '9.9.9.9' => ['status' => 500, 'body' => ['error' => 'lookup failed']],
        ]));
        $client = new Client(new Options(cache: false, retries: 0, httpClient: $stub->client));

        $this->expectException(VPNDetectionException::class);
        try {
            $client->lookup('9.9.9.9', ['retries' => 2]);
        } finally {
            // 1 initial attempt plus 2 retries, rather than the instance's 0.
            self::assertCount(3, $stub->calls);
        }
    }

    public function testARateLimitIsRetriedAfterTheDelayTheServerAskedFor(): void
    {
        $stub = new Stub(Stub::lookups([
            '9.9.9.9' => [
                [
                    'status' => 429,
                    'headers' => ['Retry-After' => '2'],
                    'body' => ['error' => 'rate limit exceeded'],
                ],
                Stub::ok(['ip' => '9.9.9.9', 'is_vpn' => true]),
            ],
        ]));
        $client = new Client(new Options(cache: false, retries: 1, httpClient: $stub->client));

        $result = $client->lookup('9.9.9.9');

        self::assertTrue($result->isVpn);
        // Scheduled rather than slept: a batch keeps moving while one address waits.
        self::assertSame([0, 2000], $stub->delays);
    }

    public function testA429WithoutRetryAfterIsASpentAllowanceAndIsNotRetried(): void
    {
        $stub = new Stub(Stub::lookups([
            '9.9.9.9' => ['status' => 429, 'body' => ['error' => 'request allowance exceeded']],
        ]));
        $client = new Client(new Options(cache: false, retries: 3, httpClient: $stub->client));

        try {
            $client->lookup('9.9.9.9');
            self::fail('expected a failure');
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::QuotaExceeded, $e->kind);
        }
        self::assertCount(1, $stub->calls, 'a spent allowance must not be hammered');
    }

    public function testAnyOther4xxIsAClientErrorAndIsNotRetried(): void
    {
        foreach ([404, 409, 418, 451] as $status) {
            $stub = new Stub(Stub::lookups([
                '9.9.9.9' => ['status' => $status, 'body' => ['rc' => 'NOT_FOUND']],
            ]));
            $client = new Client(new Options(cache: false, retries: 3, httpClient: $stub->client));

            try {
                $client->lookup('9.9.9.9');
                self::fail("expected a failure for {$status}");
            } catch (VPNDetectionException $e) {
                self::assertSame(ErrorKind::BadRequest, $e->kind, (string) $status);
                self::assertFalse($e->isRetryable(), (string) $status);
            }
            self::assertCount(1, $stub->calls, "{$status} must not be retried");
        }
    }

    public function testATransportFailureIsRetriedAndReportedAsNetwork(): void
    {
        $stub = new Stub(Stub::lookups(['9.9.9.9' => Stub::transportFailure()]));
        $client = new Client(new Options(cache: false, retries: 2, httpClient: $stub->client));

        try {
            $client->lookup('9.9.9.9');
            self::fail('expected a failure');
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::Network, $e->kind);
            self::assertStringContainsString('connection refused', $e->getMessage());
        }
        self::assertCount(3, $stub->calls);
    }

    public function testAnUnknownPerCallOptionIsRejectedRatherThanIgnored(): void
    {
        $client = new Client();

        $this->expectException(InvalidArgumentException::class);
        $client->lookupBatch(['1.1.1.1'], ['concurency' => 4]);
    }

    public function testConcurrencyIsNotAcceptedOnASingleLookup(): void
    {
        $client = new Client();

        $this->expectException(InvalidArgumentException::class);
        $client->lookup('1.1.1.1', ['concurrency' => 4]);
    }

    public function testTheCacheEvictsTheLeastRecentlyUsedAddress(): void
    {
        $stub = self::addressStub();
        $client = new Client(new Options(cacheMaxSize: 2, httpClient: $stub->client));

        $client->lookup('9.9.9.1');
        $client->lookup('9.9.9.2');
        $client->lookup('9.9.9.1');
        $client->lookup('9.9.9.3');
        self::assertCount(3, $stub->calls);

        // 9.9.9.1 was used again so 9.9.9.2 is the one that went.
        $client->lookup('9.9.9.1');
        self::assertCount(3, $stub->calls);
        $client->lookup('9.9.9.2');
        self::assertCount(4, $stub->calls);
    }

    public function testACachedAnswerExpires(): void
    {
        $stub = self::addressStub();
        $client = new Client(new Options(cacheTtlSeconds: 0.05, httpClient: $stub->client));

        $client->lookup('9.9.9.1');
        $client->lookup('9.9.9.1');
        self::assertCount(1, $stub->calls);

        usleep(60_000);
        $client->lookup('9.9.9.1');
        self::assertCount(2, $stub->calls);
    }

    // The database responses nest their payload, and a hand-written unwrap shape
    // is a claim nothing can check. `checksums` shipped broken in another SDK for
    // exactly that reason: it read a top-level `sha256` that is not there, and
    // returned nothing against a perfectly healthy API.
    public function testDatabaseResponsesAreUnwrappedAtTheRightDepth(): void
    {
        $stub = new Stub([
            '/api/v1/database/checksum' => Stub::ok([
                'id' => 'vpn_ip_extended_v1',
                'format' => 'mmdb',
                'checksums' => ['md5' => 'm', 'sha1' => 's1', 'sha256' => 's256', 'sha512' => 's512'],
            ]),
            // A license is held against the FAMILY, and the ids a download takes
            // hang off `versions`. Reading an id from the top level is how this
            // endpoint came to answer objects whose every typed field was null.
            '/api/v1/database/list' => Stub::ok([
                'databases' => [[
                    'base' => 'vpn_ip',
                    'name' => 'VPN IP',
                    'summary' => 'IP ranges observed as VPN infrastructure.',
                    'license_type' => 'standard',
                    'in_term' => true,
                    'standing' => 'licensed',
                    'versions' => [[
                        'id' => 'vpn_ip_extended_v1',
                        'version' => 1,
                        'formats' => [['format' => 'mmdb', 'bytes' => 1234]],
                    ]],
                ]],
            ]),
            '/api/v1/database/downloads' => Stub::ok([
                'downloads' => [[
                    'dataset_id' => 'vpn_ip_extended_v1',
                    'format' => 'mmdb',
                    'outcome' => 'ok',
                    'bytes' => 1234,
                    'created' => '2026-09-02T10:11:12Z',
                ]],
            ]),
            '/api/v1/database/metadata' => Stub::ok([
                'id' => 'vpn_ip_extended_v1',
                'updated' => '2026-09-02',
                'entries' => 42,
                'schema' => ['mmdb' => [['name' => 'ip', 'type' => 'string']]],
                'sample' => ['mmdb' => [['ip' => '1.1.1.1', 'is_vpn' => false]]],
            ]),
        ]);
        $client = new Client(new Options(apiKey: 'k', httpClient: $stub->client));

        $sums = $client->database->checksums('vpn_ip_extended_v1', 'mmdb');
        self::assertSame('s256', $sums->sha256, 'the digest a caller wants must not be null');
        self::assertSame(['m', 's1', 's256', 's512'], [$sums->md5, $sums->sha1, $sums->sha256, $sums->sha512]);

        $databases = $client->database->list();
        self::assertCount(1, $databases);
        self::assertSame('vpn_ip', $databases[0]->base);
        self::assertSame('licensed', $databases[0]->standing);
        // An unlicensed family carries no license_type at all. The wrapper used to
        // declare this non-null, so any catalog containing one threw on decode.
        self::assertSame('standard', $databases[0]->licenseType);
        self::assertSame('vpn_ip_extended_v1', $databases[0]->versions[0]->id);
        self::assertSame(1234, $databases[0]->versions[0]->formats[0]->bytes);

        $downloads = $client->database->downloads();
        self::assertSame('ok', $downloads[0]->outcome);
        self::assertSame('2026-09-02', $downloads[0]->created->format('Y-m-d'));

        $metadata = $client->database->metadata('vpn_ip_extended_v1');
        self::assertSame(42, $metadata->entries);
        self::assertSame('ip', $metadata->schema['mmdb'][0]->name);
        // A sample row has no schema to generate against, so it arrives as
        // stdClass while this property documents arrays. A caller following the
        // docblock wrote $row['ip'] and got a fatal.
        self::assertSame([['ip' => '1.1.1.1', 'is_vpn' => false]], $metadata->sample['mmdb']);
    }

    public function testDownloadUrlReturnsTheLinkWithoutFollowingIt(): void
    {
        $stub = new Stub([
            '/api/v1/database/download' => [
                'status' => 302,
                'headers' => ['Location' => 'https://example.invalid/vpn.mmdb?sig=x'],
            ],
        ]);
        $client = new Client(new Options(apiKey: 'k', httpClient: $stub->client));

        $url = $client->database->downloadUrl('vpn_ip_extended_v1', 'mmdb');

        self::assertSame('https://example.invalid/vpn.mmdb?sig=x', $url);
        // Following it would pull a multi-gigabyte dataset into memory.
        self::assertSame(['/api/v1/database/download'], $stub->calls);
    }

    public function testAKeyIsSentAsABearerTokenAndOmittedEntirelyWithoutOne(): void
    {
        $stub = new Stub(Stub::lookups(['9.9.9.1' => Stub::ok(['ip' => '9.9.9.1', 'is_vpn' => false])]));

        (new Client(new Options(apiKey: 'secret', httpClient: $stub->client)))->lookup('9.9.9.1');
        (new Client(new Options(httpClient: $stub->client)))->lookup('9.9.9.1');

        self::assertSame('Bearer secret', $stub->requests[0]->getHeaderLine('Authorization'));
        // A key must be absent rather than empty: `Authorization: Bearer ` is a 401.
        self::assertFalse($stub->requests[1]->hasHeader('Authorization'));
        self::assertStringStartsWith('vpndetection-php/', $stub->requests[0]->getHeaderLine('User-Agent'));
        self::assertSame('', $stub->requests[0]->getUri()->getQuery(), 'the key never rides in the query');
    }

    /** @param array<string, mixed> $body */
    private static function lookupOnce(array $body): \VPNDetection\Result
    {
        $stub = new Stub(Stub::lookups([$body['ip'] => Stub::ok($body)]));
        return (new Client(new Options(httpClient: $stub->client)))->lookup($body['ip']);
    }

    public function testApiCallsCarryATimeout(): void
    {
        $stub = new Stub(Stub::lookups(['1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false])]));

        (new Client(new Options(timeout: 7.5, httpClient: $stub->client)))->lookup('1.1.1.1');

        // Guzzle defaults both to 0, meaning unlimited, so an unset option here
        // is a caller held until the process is killed.
        self::assertSame(7.5, $stub->options[0][RequestOptions::TIMEOUT]);
        self::assertSame(7.5, $stub->options[0][RequestOptions::CONNECT_TIMEOUT]);
    }

    public function testATransferIsExemptFromTheWholeRequestTimeout(): void
    {
        $stub = new Stub([
            '/api/v1/database/download' => [
                'status' => 302,
                'headers' => ['Location' => 'https://storage.invalid/cdn_ip_v1.csv.gz'],
            ],
            '/cdn_ip_v1.csv.gz' => ['status' => 200, 'body' => 'payload'],
        ]);

        (new Client(new Options(apiKey: 'k', timeout: 7.5, httpClient: $stub->client)))
            ->database->downloadBytes('cdn_ip_v1', 'csvgz');

        $transfer = $stub->options[1];
        self::assertSame(0, $transfer[RequestOptions::TIMEOUT]);
        self::assertSame(7.5, $transfer[RequestOptions::CONNECT_TIMEOUT]);
    }

    public function testANegativeTimeoutIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Options(timeout: -1);
    }

    private static function addressStub(): Stub
    {
        $routes = [];
        foreach (self::ADDRS as $ip) {
            $routes[$ip] = Stub::ok(['ip' => $ip, 'is_vpn' => false]);
        }
        return new Stub(Stub::lookups($routes));
    }
    private const ACCOUNT_BODY = [
        'org_id' => '85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61',
        'apikey' => [
            'id' => '0ab424cc-7619-4dad-b027-afacdc2cedb0',
            'expires' => null,
            'allowed_cidrs' => [],
        ],
        'plan' => ['key' => 'max', 'tier' => 'max'],
        'usage' => [
            'requests' => 580,
            'quota' => 5000000,
            'hard_limit' => null,
            'window_start' => '2026-09-04T07:00:00Z',
            'window_end' => '2026-10-04T07:00:00Z',
        ],
    ];

    public function testMyIpClassifiesTheCallingAddress(): void
    {
        $stub = new Stub(['/myip' => Stub::ok(['ip' => '45.83.91.1', 'is_vpn' => true])]);
        $client = new Client(new Options(httpClient: $stub->client));

        $result = $client->myIp();

        self::assertSame('45.83.91.1', $result->ip);
        self::assertTrue($result->isVpn);
    }

    public function testMyIpIsNotCached(): void
    {
        // The cache is keyed by address, and which address this is IS the question.
        $stub = new Stub(['/myip' => Stub::ok(['ip' => '45.83.91.1', 'is_vpn' => true])]);
        $client = new Client(new Options(httpClient: $stub->client));

        $client->myIp();
        $client->myIp();

        self::assertCount(2, $stub->calls);
    }

    public function testMyAccountReportsThePlanAndTheUsage(): void
    {
        $stub = new Stub(['/api/v1/account/me' => Stub::ok(self::ACCOUNT_BODY)]);
        $client = new Client(new Options(httpClient: $stub->client));

        $account = $client->myAccount();

        self::assertSame('max', $account->plan->key);
        self::assertSame('max', $account->plan->tier);
        self::assertSame(580, $account->usage->requests);
        self::assertSame(5000000, $account->usage->quota);
        // Null means NEVER stop, which is not the same as a limit of zero.
        self::assertNull($account->usage->hardLimit);
        self::assertSame([], $account->apikey->allowedCidrs);
    }

    public function testMyAccountIsNotCached(): void
    {
        // The whole point is what has been spent.
        $stub = new Stub(['/api/v1/account/me' => Stub::ok(self::ACCOUNT_BODY)]);
        $client = new Client(new Options(httpClient: $stub->client));

        $client->myAccount();
        $client->myAccount();

        self::assertCount(2, $stub->calls);
    }

    public function testMyAccountSurfacesAnUnauthorizedKey(): void
    {
        $stub = new Stub([
            '/api/v1/account/me' => ['status' => 401, 'body' => ['error' => 'invalid API key']],
        ]);
        $client = new Client(new Options(retries: 0, httpClient: $stub->client));

        $this->expectException(VPNDetectionException::class);
        $client->myAccount();
    }

}
