<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use VPNDetection\Cache;
use VPNDetection\Client;
use VPNDetection\Options;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * A spent trial's or a reached cap's answer can change as soon as the
 * organization's trial, plan or cap does, so it is cached for a minute at most,
 * in memory and in a store, rather than for the client's TTL.
 */
final class CacheLifeTest extends TestCase
{
    private const FLAGS = [
        '45.83.91.1' => [],
        '45.83.91.2' => ['trial_expired' => false, 'cap_reached' => false],
        '45.83.91.3' => ['trial_expired' => true],
        '45.83.91.4' => ['cap_reached' => true],
    ];

    private static function stub(): Stub
    {
        $routes = [];
        foreach (self::FLAGS as $ip => $flags) {
            $routes[$ip] = Stub::ok(['ip' => $ip, 'is_vpn' => false, ...$flags]);
        }
        return new Stub(Stub::lookups($routes));
    }

    /** @return list<array{string, string, int, int}> */
    public static function cases(): array
    {
        $cases = [];
        foreach (['lookup', 'lookupBatch'] as $how) {
            foreach ([
                ['45.83.91.1', 3600, 3600],
                ['45.83.91.2', 3600, 3600],
                ['45.83.91.3', 3600, 60],
                ['45.83.91.4', 3600, 60],
                ['45.83.91.3', 5, 5],
                ['45.83.91.4', 5, 5],
                ['45.83.91.1', 5, 5],
            ] as [$ip, $ttl, $want]) {
                $cases["$how $ip under $ttl s"] = [$how, $ip, $ttl, $want];
            }
        }
        return $cases;
    }

    #[DataProvider('cases')]
    public function testEachAnswerIsCachedAsLongAsItsFlagsAllow(string $how, string $ip, int $ttl, int $want): void
    {
        $client = new Client(new Options(cacheTtlSeconds: $ttl, httpClient: self::stub()->client));

        $before = microtime(true);
        $how === 'lookup' ? $client->lookup($ip) : $client->lookupBatch([$ip, '45.83.91.1']);
        $after = microtime(true);

        $cache = (new ReflectionProperty(Client::class, 'cache'))->getValue($client);
        self::assertInstanceOf(Cache::class, $cache);
        $expires = $cache->expiry($ip);
        self::assertNotNull($expires);
        self::assertGreaterThanOrEqual($before + $want, $expires);
        self::assertLessThanOrEqual($after + $want, $expires);
    }

    #[DataProvider('cases')]
    public function testEachAnswerIsStoredAsLongAsItsFlagsAllow(string $how, string $ip, int $ttl, int $want): void
    {
        $store = new ArrayStore();
        $client = new Client(new Options(cacheTtlSeconds: $ttl, cacheStore: $store, httpClient: self::stub()->client));

        $how === 'lookup' ? $client->lookup($ip) : $client->lookupBatch([$ip, '45.83.91.1']);

        $ttls = $store->ttls;
        sort($ttls);
        $expected = $how === 'lookup' ? [$want] : array_values(array_unique([$want, $ttl]));
        sort($expected);
        self::assertSame($expected, $ttls);
    }

    public function testAReducedAnswerIsStillCachedSoARepeatSendsNothing(): void
    {
        $stub = self::stub();
        $client = new Client(new Options(httpClient: $stub->client));

        $client->lookup('45.83.91.3');
        $again = $client->lookup('45.83.91.3');

        self::assertTrue($again->trialExpired);
        self::assertCount(1, $stub->calls);
    }
}
