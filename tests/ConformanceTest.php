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

    public function testABogonIsAnsweredLocallyInTheFullMaxShape(): void
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
            $detail = $result->{$object};
            self::assertNotNull($detail, "{$object} must be present");
            self::assertTrue($detail->isEmpty(), "{$object} must be empty");
        }
        self::assertSame([], $stub->calls, 'a bogon must not reach the network');
    }

    public function testLookupPreservesAbsentVersusFalseAcrossEveryPlanShape(): void
    {
        foreach (self::$data['lookup'] as $case) {
            $ip = $case['body']['ip'];
            $stub = new Stub(Stub::lookups([
                $ip => ['status' => $case['status'], 'body' => $case['body']],
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
                $detail = $result->{$key};
                self::assertNotNull($detail, "{$name}: {$key} must be present");
                self::assertTrue($detail->isEmpty(), "{$name}: {$key} must be empty");
            }
            foreach (['vpn', 'hosting', 'dcproxy'] as $key) {
                if (isset($case['expect'][$key])) {
                    self::assertSame(
                        self::sorted($case['expect'][$key]),
                        self::sorted(self::asWire($result->{$key})),
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
        }
        self::assertInstanceOf(Result::class, $got['1.1.1.1']);
        self::assertFalse($got['1.1.1.1']->isVpn, 'the good address still answered');
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
    private static function batchCase(string $name): array
    {
        foreach (self::$data['batch'] as $case) {
            if ($case['name'] === $name) {
                return $case;
            }
        }
        self::fail("no batch fixture named {$name}");
    }

    private static function camel(string $wire): string
    {
        return lcfirst(str_replace('_', '', ucwords($wire, '_')));
    }

    /**
     * Renders a detail value object back to its wire form. The corpus is
     * language-neutral JSON, so its expectations are snake_case with dates as
     * strings.
     *
     * @return array<string, mixed>
     */
    private static function asWire(object $detail): array
    {
        $out = [];
        foreach (get_object_vars($detail) as $name => $value) {
            if ($value === null) {
                continue;
            }
            $key = strtolower((string) preg_replace('/(?<!^)[A-Z]/', '_$0', $name));
            $out[$key] = $value instanceof DateTimeImmutable ? $value->format('Y-m-d') : $value;
        }
        return $out;
    }

    /**
     * @param array<string, mixed> $values
     * @return array<string, mixed>
     */
    private static function sorted(array $values): array
    {
        ksort($values);
        return $values;
    }
}
