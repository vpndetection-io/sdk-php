<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use VPNDetection\Bogon;
use VPNDetection\Client;
use VPNDetection\Options;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * Asserts the shared conformance corpus that every VPNDetection SDK asserts.
 *
 * The corpus is generated into testdata/ and is identical across languages, so a
 * behavior that drifts here fails here rather than surfacing as two client
 * libraries quietly disagreeing about the same address.
 */
final class ConformanceTest extends TestCase
{
    /** The keys of a lookup case's `expect` that say how to read the rest. */
    private const EXPECT_KEYS = ['ip', 'isBogon', 'present', 'absent', 'emptyPresent'];

    /** The keys of a lookup case's `expect` that each give one member's whole value. */
    private const EXPECT_VALUES = [
        'vpn', 'hosting', 'dcproxy', 'pubproxy', 'location', 'asn', 'carrier', 'satellite', 'ssh',
        'smtp', 'web', 'dns_resolver', 'bittorrent', 'company', 'abuse', 'hostname', 'bot',
    ];

    /** The members `bogonResponse` gives a whole value for. */
    private const BOGON_VALUES = ['location', 'asn', 'web', 'hostname', 'company', 'abuse'];

    /** @var array<string, mixed> */
    private static array $data;

    public static function setUpBeforeClass(): void
    {
        self::$data = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    public function testIsBogonMatchesTheCanonicalRanges(): void
    {
        foreach (self::$data['isBogon'] as $case) {
            self::assertSame(
                $case['expect'],
                Bogon::isBogon($case['ip']),
                sprintf('%s (%s)', $case['ip'], $case['why']),
            );
        }
    }

    /**
     * A server listening on :: sees an IPv4 visitor as ::ffff:a.b.c.d, which read
     * whole is inside ::ffff:0:0/96: through 4.4.0 each was answered as a bogon
     * with no request made.
     */
    public function testAnIpv4MappedAddressIsTheIpv4AddressItCarries(): void
    {
        foreach (self::$data['ipv4Mapped'] as $case) {
            ['ip' => $ip, 'carries' => $carries, 'expect' => $bogon] = $case;
            self::assertSame($bogon, Bogon::isBogon($ip), sprintf('%s (%s)', $ip, $case['why']));
            $routes = Stub::lookups([$carries => Stub::ok(['ip' => $carries, 'is_vpn' => true])]);
            $wantSent = $bogon ? [] : [$carries];

            $stub = new Stub($routes);
            $client = new Client(new Options(httpClient: $stub->client));
            $result = $client->lookup($ip);
            self::assertSame($bogon, $result->isBogon, $ip);
            self::assertSame($carries, $result->ip, $ip);
            $client->lookup($carries);
            self::assertSame(array_map(fn (string $a): string => '/' . $a, $wantSent), $stub->calls, $ip);

            $batchStub = new Stub($routes);
            $uncached = new Client(new Options(httpClient: $batchStub->client, cache: false));
            $asked = array_values(array_unique([$ip, $carries]));
            $got = $uncached->lookupBatch($asked);
            self::assertSame($asked, array_map(strval(...), array_keys($got)), $ip);
            self::assertInstanceOf(Result::class, $got[$ip], $ip);
            self::assertSame($carries, $got[$ip]->ip, $ip);
            $sent = [];
            foreach ($batchStub->requests as $request) {
                $sent = [...$sent, ...json_decode((string) $request->getBody(), true)['ips']];
            }
            self::assertSame($wantSent, $sent, $ip);
        }
    }

    public function testABogonIsAnsweredLocallyInTheWidestShape(): void
    {
        $stub = new Stub();
        $client = new Client(new Options(httpClient: $stub->client));
        $result = $client->lookup('10.0.0.1');

        self::assertTrue($result->isBogon);
        self::assertSame('10.0.0.1', $result->ip);
        foreach (self::$data['bogonResponse']['flagsFalse'] as $flag) {
            self::assertFalse($result->{self::camel($flag)}, "{$flag} must be present and false");
        }
        foreach (self::$data['bogonResponse']['emptyObjects'] as $object) {
            $detail = $result->{self::camel($object)};
            self::assertNotNull($detail, "{$object} must be present");
            self::assertTrue($detail->isEmpty(), "{$object} must be empty");
        }
        foreach (self::BOGON_VALUES as $key) {
            self::assertArrayHasKey($key, self::$data['bogonResponse'], "the corpus's bogon gives {$key}");
            self::assertNotNull($result->{self::camel($key)}, "{$key} must be present");
            self::assertSame(
                self::canonical(self::$data['bogonResponse'][$key]),
                self::canonical(self::asWire($result->{self::camel($key)})),
                $key,
            );
        }
        self::assertSame([], $stub->calls, 'a bogon must not reach the network');
    }

    public function testLookupPreservesAbsentVersusFalseAcrossEveryPlanShape(): void
    {
        foreach (self::$data['lookup'] as $i => $case) {
            $ip = $case['body']['ip'];
            $stub = new Stub(Stub::lookups([
                $ip => ['status' => $case['status'], 'body' => self::wire('lookup', $i)],
            ]));
            $client = new Client(new Options(httpClient: $stub->client));
            $result = $client->lookup($ip);
            $name = $case['name'];

            self::assertSame($case['expect']['ip'], $result->ip, $name);
            self::assertSame($case['expect']['isBogon'], $result->isBogon, $name);

            foreach ($case['expect']['present'] ?? [] as $key => $value) {
                self::assertSame($value, $result->{self::camel($key)}, "{$name}: {$key}");
            }
            foreach ($case['expect']['absent'] ?? [] as $key) {
                self::assertNull(
                    $result->{self::camel($key)},
                    "{$name}: {$key} must be ABSENT, not false",
                );
            }
            foreach ($case['expect']['emptyPresent'] ?? [] as $key) {
                $detail = $result->{self::camel($key)};
                self::assertNotNull($detail, "{$name}: {$key} must be present");
                self::assertTrue($detail->isEmpty(), "{$name}: {$key} must be empty");
            }
            // A key this runner does not know would otherwise pass without being read.
            foreach (array_keys($case['expect']) as $key) {
                self::assertContains($key, [...self::EXPECT_KEYS, ...self::EXPECT_VALUES], "{$name}: {$key} is not asserted");
            }
            foreach (self::EXPECT_VALUES as $key) {
                if (array_key_exists($key, $case['expect'])) {
                    self::assertNotNull($result->{self::camel($key)}, "{$name}: {$key} must be present");
                    $wire = self::asWire($result->{self::camel($key)});
                    // The AS's `type` is held at a plain string, so an answer that leaves it out
                    // reads '' and the answer's own `asn` shows it absent: leave it out of the view.
                    if ($key === 'asn' && !array_key_exists('type', $result->raw['asn'])) {
                        self::assertSame('', $wire['type'], "{$name}: an absent asn.type reads ''");
                        unset($wire['type']);
                    }
                    self::assertSame(
                        self::canonical($case['expect'][$key]),
                        self::canonical($wire),
                        "{$name}: {$key}",
                    );
                }
            }
            self::assertSame($case['body'], $result->raw, "{$name}: raw is the untouched wire object");
        }
    }

    public function testA429IsClassifiedByRetryAfterNotByItsStatus(): void
    {
        foreach (self::$data['errors'] as $case) {
            $stub = new Stub(Stub::lookups([
                '1.1.1.1' => [
                    'status' => $case['status'],
                    'headers' => $case['headers'],
                    'body' => $case['body'],
                ],
            ]));
            // No retries, so a retryable error still surfaces rather than looping.
            $client = new Client(new Options(httpClient: $stub->client, retries: 0));
            $name = $case['name'];

            try {
                $client->lookup('1.1.1.1');
                self::fail("{$name}: expected a failure");
            } catch (VPNDetectionException $e) {
                self::assertSame($case['expect']['kind'], $e->kind->value, $name);
                self::assertSame($case['expect']['retryable'], $e->isRetryable(), "{$name}: retryable");
                self::assertSame($case['status'], $e->status, "{$name}: status");
                if (isset($case['expect']['message'])) {
                    self::assertSame($case['expect']['message'], $e->getMessage(), "{$name}: message");
                }
                if (isset($case['expect']['retryAfterSeconds'])) {
                    self::assertSame($case['expect']['retryAfterSeconds'], $e->retryAfterSeconds, $name);
                }
            }
        }
    }

    public function testBatchDedupesShortCircuitsBogonsAndKeysByAddress(): void
    {
        $case = self::batchCase('dedup-bogon-and-order-free-keying');
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
            '8.8.8.8' => Stub::ok(['ip' => '8.8.8.8', 'is_vpn' => false]),
        ]));
        $client = new Client(new Options(httpClient: $stub->client));

        $got = $client->lookupBatch($case['input']);

        self::assertSame($case['expect']['keys'], array_keys($got));
        self::assertCount($case['expect']['httpRequests'], $stub->calls);
        foreach ($case['expect']['bogonKeys'] as $key) {
            self::assertTrue($got[$key]->isBogon, "{$key} should be a local answer");
        }
    }

    public function testOneBadAddressDoesNotLoseTheRestOfTheBatch(): void
    {
        $case = self::batchCase('partial-failure-does-not-fail-the-batch');
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
        ]));
        $client = new Client(new Options(httpClient: $stub->client, retries: 0));

        $got = $client->lookupBatch($case['input']);

        self::assertSame($case['expect']['keys'], array_keys($got));
        foreach ($case['expect']['errorKeys'] as $key) {
            self::assertInstanceOf(VPNDetectionException::class, $got[$key], "{$key} should carry its error");
            self::assertSame($case['expect']['errorKinds'][$key], $got[$key]->kind->value, $key);
        }
        self::assertInstanceOf(Result::class, $got['1.1.1.1']);
        self::assertFalse($got['1.1.1.1']->isVpn, 'the good address still answered');
    }

    public function testAServedIsBogonReachesTheResult(): void
    {
        $stub = new Stub(Stub::lookups([
            '8.8.8.8' => Stub::ok(['ip' => '8.8.8.8', 'is_bogon' => true, 'is_vpn' => false]),
            '8.8.4.4' => Stub::ok(['ip' => '8.8.4.4', 'is_bogon' => false, 'is_vpn' => false]),
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
        ]));
        $client = new Client(new Options(httpClient: $stub->client, cache: false));

        self::assertTrue($client->lookup('8.8.8.8')->isBogon, 'lookup: the served true');
        self::assertFalse($client->lookup('1.1.1.1')->isBogon, 'lookup: an absent is_bogon is false');
        $got = $client->lookupBatch(['8.8.8.8', '8.8.4.4']);
        self::assertTrue($got['8.8.8.8']->isBogon, 'batch: the served true');
        self::assertFalse($got['8.8.4.4']->isBogon, 'batch: the served false');
    }

    public function testACacheHitIssuesNoSecondRequest(): void
    {
        $case = self::batchCase('cache-hit-issues-no-second-request');
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
        ]));
        $client = new Client(new Options(httpClient: $stub->client));

        for ($i = 0; $i < $case['repeat']; $i++) {
            $client->lookupBatch($case['input']);
        }
        self::assertCount($case['expect']['httpRequests'], $stub->calls);
    }

    public function testALargeBatchIsSentInChunksOfAThousand(): void
    {
        $case = self::batchCase('chunks-of-one-thousand');
        $routes = [];
        foreach ($case['input'] as $ip) {
            $routes[$ip] = Stub::ok(['ip' => $ip, 'is_vpn' => false]);
        }
        $stub = new Stub(Stub::lookups($routes));
        $client = new Client(new Options(cache: false, httpClient: $stub->client));

        $got = $client->lookupBatch($case['input']);

        self::assertCount($case['expect']['keyCount'], $got);
        self::assertCount($case['expect']['httpRequests'], $stub->calls);
        foreach ($case['input'] as $ip) {
            self::assertInstanceOf(Result::class, $got[$ip], $ip);
            self::assertSame($ip, $got[$ip]->ip, "{$ip} should be answered for itself");
        }
    }

    public function testAnUncappedBatchIsChunkedAndAnswersEveryAddressOnce(): void
    {
        $case = self::batchCase('uncapped-input-is-chunked');
        $routes = [];
        foreach ($case['input'] as $ip) {
            $routes[$ip] = Stub::ok(['ip' => $ip, 'is_vpn' => false]);
        }
        $stub = new Stub(Stub::lookups($routes));
        $client = new Client(new Options(cache: false, httpClient: $stub->client));

        $got = $client->lookupBatch($case['input']);

        // Chunking to the endpoint's 1000 is the library's job, so a batch has no
        // cap of its own: never a refusal, and one POST per chunk.
        self::assertSame(array_fill(0, $case['expect']['httpRequests'], '/batch'), $stub->calls);
        $sizes = array_map(
            static fn ($request): int => count(json_decode((string) $request->getBody(), true)['ips']),
            $stub->requests,
        );
        self::assertSame([1000, 1000, 500], $sizes);
        self::assertSame($case['input'], array_keys($got));
        self::assertCount($case['expect']['keyCount'], $got);
        foreach ($case['input'] as $ip) {
            self::assertInstanceOf(Result::class, $got[$ip], $ip);
            self::assertSame($ip, $got[$ip]->ip, "{$ip} should be answered for itself");
        }
    }

    // A per-entry failure carries no headers, so its 429 can only be a spent
    // allowance, and a 500 is the server's; neither is retried per entry, because
    // retries belong to the call and the call succeeded.
    public function testAnEntryErrorIsClassifiedByItsStatus(): void
    {
        $case = self::batchCase('an-entry-error-is-classified-by-its-status');
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
            '8.8.8.8' => [
                'status' => 429,
                'body' => ['error' => 'overage cap reached; raise or remove it in Billing'],
            ],
            '9.9.9.9' => ['status' => 500, 'body' => ['error' => 'lookup failed']],
        ]));
        $client = new Client(new Options(httpClient: $stub->client, retries: 3));

        $got = $client->lookupBatch($case['input']);

        self::assertSame($case['expect']['keys'], array_keys($got));
        foreach ($case['expect']['errorKinds'] as $ip => $kind) {
            self::assertInstanceOf(VPNDetectionException::class, $got[$ip], "{$ip} should carry its error");
            self::assertSame($kind, $got[$ip]->kind->value, $ip);
        }
        self::assertCount($case['expect']['httpRequests'], $stub->calls);
    }

    public function testTwoClientsNeverShareACachedAnswer(): void
    {
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
        ]));
        $a = new Client(new Options(apiKey: 'key-a', httpClient: $stub->client));
        $b = new Client(new Options(apiKey: 'key-b', httpClient: $stub->client));

        $a->lookup('1.1.1.1');
        $b->lookup('1.1.1.1');

        // Two keys can be on different plans and so entitled to different fields;
        // a shared cache would serve one of them the other's shape.
        self::assertCount(2, $stub->calls);
    }

    public function testCachingCanBeTurnedOff(): void
    {
        $stub = new Stub(Stub::lookups([
            '1.1.1.1' => Stub::ok(['ip' => '1.1.1.1', 'is_vpn' => false]),
        ]));
        $client = new Client(new Options(cache: false, httpClient: $stub->client));

        $client->lookup('1.1.1.1');
        $client->lookup('1.1.1.1');

        self::assertCount(2, $stub->calls);
    }

    /** @return array<string, mixed> */
    /**
     * A value the API adds to a closed vocabulary in an answer (a tier, a standing,
     * a license type, a format, an outcome) comes back as served, and the plan's
     * name is read. Each `expect` key is a wire path through the answer.
     */
    public function testAVocabularyValueTheApiAddsComesBackAsServed(): void
    {
        $calls = [
            'myEntitlement' => ['/api/v1/entitlement', static fn (Client $c) => $c->myEntitlement()],
            'listDatabases' => ['/api/v1/database/list', static fn (Client $c) => $c->database->list()],
            'listDownloads' => ['/api/v1/database/downloads', static fn (Client $c) => $c->database->downloads()],
        ];
        $raw = json_decode((string) file_get_contents(__DIR__ . '/../testdata/testdata.json'), false, 512, JSON_THROW_ON_ERROR);
        self::assertNotEmpty(self::$data['vocabulary']['cases']);
        foreach (self::$data['vocabulary']['cases'] as $i => $case) {
            [$path, $call] = $calls[$case['call']];
            $stub = new Stub([$path => Stub::ok($raw->vocabulary->cases[$i]->answer)]);
            $value = $call(new Client(new Options(apiKey: 'test-key', httpClient: $stub->client)));
            foreach ($case['expect'] as $wirePath => $want) {
                $got = $value;
                foreach (explode('.', $wirePath) as $step) {
                    if (is_array($got) && !ctype_digit($step)) {
                        // A list call answers the list itself, not the object around it.
                        continue;
                    }
                    $got = is_array($got) ? $got[(int) $step] : $got->{self::camel($step)};
                }
                self::assertSame($want, $got, "{$case['name']}: {$wirePath}");
            }
        }
    }

    private static function batchCase(string $name): array
    {
        foreach (self::$data['batch'] as $case) {
            if ($case['name'] === $name) {
                return $case;
            }
        }
        self::fail("no batch fixture named {$name}");
    }

    /**
     * A case's body decoded with objects, as it goes on the wire: decoded into
     * arrays, a detail served as `{}` would be sent as the list `[]`.
     */
    private static function wire(string $section, int $i): object
    {
        $raw = json_decode((string) file_get_contents(__DIR__ . '/../testdata/testdata.json'), false, 512, JSON_THROW_ON_ERROR);
        return $raw->{$section}[$i]->body;
    }

    private static function camel(string $wire): string
    {
        return lcfirst(str_replace('_', '', ucwords($wire, '_')));
    }

    /**
     * Renders a value object back to its wire form, leaving out what it does not
     * hold. The corpus is language-neutral JSON, so its expectations are
     * snake_case with dates as strings.
     */
    private static function asWire(mixed $value): mixed
    {
        if (is_array($value)) {
            return array_map(self::asWire(...), $value);
        }
        if ($value instanceof DateTimeImmutable) {
            return $value->format('Y-m-d');
        }
        if (!is_object($value)) {
            return $value;
        }
        $out = [];
        foreach (get_object_vars($value) as $name => $member) {
            if ($member === null) {
                continue;
            }
            $out[strtolower((string) preg_replace('/(?<!^)[A-Z]/', '_$0', $name))] = self::asWire($member);
        }
        return $out;
    }

    /**
     * JSON with every object's keys sorted, so two values compare by content
     * alone: a float that holds a whole number encodes as the integer the corpus
     * writes, and nothing else is loosened.
     */
    private static function canonical(mixed $value): string
    {
        $sort = static function (mixed $v) use (&$sort): mixed {
            if (!is_array($v)) {
                return $v;
            }
            if (!array_is_list($v)) {
                ksort($v);
            }
            return array_map($sort, $v);
        };
        return json_encode($sort($value), JSON_THROW_ON_ERROR);
    }
}
