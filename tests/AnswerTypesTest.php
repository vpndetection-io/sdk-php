<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * An answer must be of the types the spec gives it, at every depth, before
 * anything reads it. Through 4.10.0 the generated deserializer cast each scalar
 * with settype() and parsed each date with `new DateTime()`, so a wrong one came
 * back as a made-up value, sent once.
 */
final class AnswerTypesTest extends TestCase
{
    private const ENTITLEMENT = [
        'org_id' => '85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61',
        'apikey' => ['id' => '0ab424cc-7619-4dad-b027-afacdc2cedb0', 'expires' => null, 'allowed_cidrs' => []],
        'plan' => ['key' => 'max', 'tier' => 'max'],
        'usage' => [
            'requests' => 580,
            'quota' => 5000000,
            'hard_limit' => null,
            'window_start' => '2026-09-04T07:00:00Z',
            'window_end' => '2026-10-04T07:00:00Z',
        ],
    ];

    private const DATABASE = [
        'base' => 'vpn_ip',
        'name' => 'VPN IP',
        'summary' => 'IP ranges observed as VPN infrastructure.',
        'license_type' => 'standard',
        'starts' => null,
        'expires' => null,
        'renews_at' => null,
        'notice_due_at' => null,
        'in_term' => true,
        'standing' => 'licensed',
        'open' => false,
        'versions' => [['id' => 'vpn_ip_extended_v1', 'version' => 1, 'formats' => [['format' => 'mmdb', 'bytes' => 1234]]]],
    ];

    private const METADATA = [
        'id' => 'vpn_ip_extended_v1',
        'updated' => '2026-09-02',
        'entries' => 42,
        'schema' => ['mmdb' => [['name' => 'ip', 'type' => 'string']]],
        'sample' => ['mmdb' => [['ip' => '1.1.1.1']]],
    ];

    private const CHECKSUMS = [
        'id' => 'vpn_ip_extended_v1',
        'format' => 'mmdb',
        'checksums' => ['md5' => 'm', 'sha1' => 's1', 'sha256' => 's256', 'sha512' => 's512'],
    ];

    private const DOWNLOAD = [
        'dataset_id' => 'tor_ip_v1',
        'format' => 'mmdb',
        'outcome' => 'ok',
        'sample' => false,
        'open' => true,
        'bytes' => 1234,
        'http_status' => 200,
        'apikey_id' => null,
        'client_ip' => null,
        'user_agent' => null,
        'created' => '2026-09-02T10:11:12Z',
    ];

    /** @return array<string, array{array<string, mixed>}> */
    public static function lookupBodies(): array
    {
        $lookup = static fn (array $patch): array => [array_merge(['ip' => '9.9.9.9', 'is_vpn' => false], $patch)];
        return [
            'is_vpn "false"' => $lookup(['is_vpn' => 'false']),
            'is_vpn "yes"' => $lookup(['is_vpn' => 'yes']),
            'is_vpn 0' => $lookup(['is_vpn' => 0]),
            'is_vpn null' => $lookup(['is_vpn' => null]),
            'ip 1' => $lookup(['ip' => 1]),
            'a detail as a string' => $lookup(['vpn' => 'x']),
            'a detail as a list' => $lookup(['vpn' => ['x']]),
            'vpn.provider 1' => $lookup(['vpn' => ['provider' => 1]]),
            'dcproxy.hits "3"' => $lookup(['dcproxy' => ['hits' => '3']]),
            'pubproxy.protocols "http"' => $lookup(['pubproxy' => ['protocols' => 'http']]),
            'pubproxy.protocols [null]' => $lookup(['pubproxy' => ['protocols' => [null]]]),
            'asn.asn "13335"' => $lookup(['asn' => ['asn' => '13335']]),
            'vpn.last_seen "x"' => $lookup(['vpn' => ['last_seen' => 'x']]),
            'vpn.last_seen "tomorrow"' => $lookup(['vpn' => ['last_seen' => 'tomorrow']]),
            'vpn.last_seen 30 February' => $lookup(['vpn' => ['last_seen' => '2026-02-30']]),
            'vpn.last_seen with a time' => $lookup(['vpn' => ['last_seen' => '2026-10-20T10:00:00Z']]),
        ];
    }

    /** @param array<string, mixed> $body */
    #[DataProvider('lookupBodies')]
    public function testALookupOfTheWrongTypeIsARetriedServerError(array $body): void
    {
        $this->assertUnreadable('/9.9.9.9', $body, static fn (Client $c) => $c->lookup('9.9.9.9'));
        $this->assertUnreadable('/myip', $body, static fn (Client $c) => $c->myIp());
    }

    /** @return array<string, array{string, mixed, \Closure(Client): mixed}> */
    public static function databaseBodies(): array
    {
        $list = static fn (Client $c) => $c->database->list();
        $metadata = static fn (Client $c) => $c->database->metadata('vpn_ip_extended_v1');
        $checksums = static fn (Client $c) => $c->database->checksums('vpn_ip_extended_v1', 'mmdb');
        $downloads = static fn (Client $c) => $c->database->downloads();
        $entitlement = static fn (Client $c) => $c->myEntitlement();
        $version = static fn (mixed $v): array => array_replace(self::DATABASE, ['versions' => [
            ['id' => 'vpn_ip_extended_v1', 'version' => $v, 'formats' => []],
        ]]);
        $usage = static fn (array $patch): array => array_replace_recursive(self::ENTITLEMENT, ['usage' => $patch]);
        $databases = static fn (array $db): array => ['databases' => [$db]];
        return [
            'list: version "3"' => ['/api/v1/database/list', $databases($version('3')), $list],
            'list: version "x"' => ['/api/v1/database/list', $databases($version('x')), $list],
            'list: bytes "1234"' => ['/api/v1/database/list', $databases(array_replace(self::DATABASE, ['versions' => [
                ['id' => 'v', 'version' => 1, 'formats' => [['format' => 'mmdb', 'bytes' => '1234']]],
            ]])), $list],
            'list: open "yes"' => ['/api/v1/database/list', $databases(array_replace(self::DATABASE, ['open' => 'yes'])), $list],
            'list: starts "x"' => ['/api/v1/database/list', $databases(array_replace(self::DATABASE, ['starts' => 'x'])), $list],
            'list: expires 31 November' => [
                '/api/v1/database/list', $databases(array_replace(self::DATABASE, ['expires' => '2026-11-31T10:00:00Z'])), $list,
            ],
            'list: base absent' => ['/api/v1/database/list', $databases(array_diff_key(self::DATABASE, ['base' => 1])), $list],
            'list: a null entry' => ['/api/v1/database/list', ['databases' => [null]], $list],
            'metadata: entries "42"' => ['/api/v1/database/metadata', array_replace(self::METADATA, ['entries' => '42']), $metadata],
            'metadata: a size of "760"' => [
                '/api/v1/database/metadata', array_replace(self::METADATA, ['size' => ['mmdb' => '760']]), $metadata,
            ],
            'metadata: a size of null' => [
                '/api/v1/database/metadata', array_replace(self::METADATA, ['size' => ['mmdb' => null]]), $metadata,
            ],
            'metadata: updated "x"' => ['/api/v1/database/metadata', array_replace(self::METADATA, ['updated' => 'x']), $metadata],
            'metadata: updated 30 February' => [
                '/api/v1/database/metadata', array_replace(self::METADATA, ['updated' => '2026-02-30']), $metadata,
            ],
            'metadata: updated with a time' => [
                '/api/v1/database/metadata', array_replace(self::METADATA, ['updated' => '2026-09-02T10:00:00Z']), $metadata,
            ],
            'checksums: id absent' => ['/api/v1/database/checksum', array_diff_key(self::CHECKSUMS, ['id' => 1]), $checksums],
            'checksums: format null' => ['/api/v1/database/checksum', array_replace(self::CHECKSUMS, ['format' => null]), $checksums],
            'checksums: a digest of 1' => ['/api/v1/database/checksum', array_replace(self::CHECKSUMS, ['checksums' => [
                'md5' => 'm', 'sha1' => 's1', 'sha256' => 1, 'sha512' => 's512',
            ]]), $checksums],
            'downloads: bytes "1234"' => [
                '/api/v1/database/downloads', ['downloads' => [array_replace(self::DOWNLOAD, ['bytes' => '1234'])]], $downloads,
            ],
            'downloads: created with no zone' => ['/api/v1/database/downloads', ['downloads' => [
                array_replace(self::DOWNLOAD, ['created' => '2026-09-02T10:11:12']),
            ]], $downloads],
            'entitlement: requests "5"' => ['/api/v1/entitlement', $usage(['requests' => '5']), $entitlement],
            'entitlement: window_start "x"' => ['/api/v1/entitlement', $usage(['window_start' => 'x']), $entitlement],
            'entitlement: window_start at 24:00' => [
                '/api/v1/entitlement', $usage(['window_start' => '2026-09-04T24:00:00Z']), $entitlement,
            ],
            'entitlement: window_start 30 February' => [
                '/api/v1/entitlement', $usage(['window_start' => '2026-02-30T07:00:00Z']), $entitlement,
            ],
            'entitlement: org_id absent' => ['/api/v1/entitlement', array_diff_key(self::ENTITLEMENT, ['org_id' => 1]), $entitlement],
        ];
    }

    /** @param \Closure(Client): mixed $call */
    #[DataProvider('databaseBodies')]
    public function testAnAnswerOfTheWrongTypeIsARetriedServerError(string $path, mixed $body, \Closure $call): void
    {
        $this->assertUnreadable($path, $body, $call);
    }

    public function testAnswersOfTheRightTypesStillRead(): void
    {
        $stub = new Stub([
            '/9.9.9.9' => Stub::ok([
                'ip' => '9.9.9.9', 'is_vpn' => true,
                'vpn' => ['provider' => 'Example VPN', 'last_seen' => '2026-10-19'],
                'pubproxy' => ['protocols' => ['http'], 'num_ports' => 3],
                'hosting' => new \stdClass(),
            ]),
            '/api/v1/entitlement' => Stub::ok(self::ENTITLEMENT),
            '/api/v1/database/list' => Stub::ok(['databases' => [array_replace(self::DATABASE, [
                'starts' => '2026-09-04T10:00:00.123Z', 'expires' => '2027-09-04T10:00:00+02:00',
            ])]]),
            '/api/v1/database/metadata' => Stub::ok(self::METADATA),
            '/api/v1/database/checksum' => Stub::ok(self::CHECKSUMS),
            '/api/v1/database/downloads' => Stub::ok(['downloads' => [self::DOWNLOAD]]),
        ]);
        $client = new Client(new Options(apiKey: 'k', httpClient: $stub->client));

        $result = $client->lookup('9.9.9.9');
        self::assertSame('2026-10-19', $result->vpn?->lastSeen?->format('Y-m-d'));
        self::assertNotNull($result->hosting, 'a detail served as {} stays present');
        self::assertSame(580, $client->myEntitlement()->usage->requests);
        self::assertSame('2026-09-04 10:00:00', $client->database->list()[0]->starts?->format('Y-m-d H:i:s'));
        self::assertSame(42, $client->database->metadata('vpn_ip_extended_v1')->entries);
        self::assertSame('s256', $client->database->checksums('vpn_ip_extended_v1', 'mmdb')->sha256);
        self::assertSame(1234, $client->database->downloads()[0]->bytes);
        self::assertCount(6, $stub->calls, 'each sent once');
    }

    public function testABatchEntryOfTheWrongTypeFailsThatAddressAlone(): void
    {
        $stub = new Stub(['/batch' => Stub::ok([
            'results' => [
                '9.9.9.1' => ['ip' => '9.9.9.1', 'is_vpn' => true, 'vpn' => new \stdClass()],
                '9.9.9.2' => ['ip' => '9.9.9.2', 'is_vpn' => 'false'],
                '9.9.9.3' => ['ip' => '9.9.9.3', 'is_vpn' => false, 'vpn' => ['last_seen' => 'x']],
            ],
            'errors' => new \stdClass(),
        ])]);
        $client = new Client(new Options(cache: false, httpClient: $stub->client));

        $answers = $client->lookupBatch(['9.9.9.1', '9.9.9.2', '9.9.9.3']);

        self::assertInstanceOf(Result::class, $answers['9.9.9.1']);
        self::assertNotNull($answers['9.9.9.1']->vpn, 'a detail served as {} stays present in a batch');
        foreach (['9.9.9.2', '9.9.9.3'] as $ip) {
            self::assertInstanceOf(VPNDetectionException::class, $answers[$ip], $ip);
            self::assertSame(ErrorKind::ServerError, $answers[$ip]->kind, $ip);
            self::assertSame(200, $answers[$ip]->status, $ip);
        }
        self::assertCount(1, $stub->calls, 'an entry is never retried on its own');
    }

    /**
     * A PSR-16 store keeps the answer as PHP arrays, which write `{}` as `[]`,
     * so the reader must not take a stored empty detail for a list.
     */
    public function testAStoredAnswerWithAnEmptyDetailIsStillAHit(): void
    {
        $store = new ArrayStore();
        $first = new Stub(['/9.9.9.9' => Stub::ok(['ip' => '9.9.9.9', 'is_vpn' => false, 'vpn' => new \stdClass()])]);
        (new Client(new Options(cacheStore: $store, httpClient: $first->client)))->lookup('9.9.9.9');

        $second = new Stub();
        $result = (new Client(new Options(cacheStore: $store, httpClient: $second->client)))->lookup('9.9.9.9');

        self::assertSame([], $second->calls, 'the stored answer must be read, not fetched again');
        self::assertNotNull($result->vpn);
    }

    /** @param \Closure(Client): mixed $call */
    private function assertUnreadable(string $path, mixed $body, \Closure $call): void
    {
        $stub = new Stub([$path => Stub::ok($body)]);
        $client = new Client(new Options(apiKey: 'k', cache: false, retries: 2, httpClient: $stub->client));
        try {
            $answer = $call($client);
            self::fail("{$path}: answered " . json_encode($answer));
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::ServerError, $e->kind, $path);
            self::assertSame(200, $e->status, "{$path}: the status");
        }
        self::assertCount(3, $stub->calls, "{$path}: retried like an outage");
    }
}
