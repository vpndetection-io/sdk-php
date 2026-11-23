<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use VPNDetection\Client;
use VPNDetection\Options;
use VPNDetection\Result;

/**
 * The user agent a lookup sends: on the wire, in the cache, and in the answer.
 */
final class UserAgentTest extends TestCase
{
    /** A real crawler's agent: its `+` must not reach the API as a space. */
    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) a&b=%41';

    private const VERDICT = ['agent' => 'Googlebot', 'kind' => 'bot', 'verdict' => 'verified'];

    private static function stub(int $n = 3): Stub
    {
        $routes = ['/myip' => Stub::ok(['ip' => '45.83.91.1', 'is_vpn' => false])];
        for ($i = 1; $i <= $n; $i++) {
            $routes['/9.9.9.' . $i] = Stub::ok(['ip' => '9.9.9.' . $i, 'is_vpn' => false]);
        }
        return new Stub($routes);
    }

    private static function client(Stub $stub, mixed ...$options): Client
    {
        return new Client(new Options(...$options, httpClient: $stub->client));
    }

    /** @return array<string, mixed> The query as a server decodes it. */
    private static function query(RequestInterface $request): array
    {
        parse_str($request->getUri()->getQuery(), $query);
        return $query;
    }

    /** @return array<string, mixed> */
    private static function body(RequestInterface $request): array
    {
        return json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR);
    }

    public function testALookupSendsItsUserAgentAsTheQueryParameter(): void
    {
        $stub = self::stub();
        self::client($stub)->lookup('9.9.9.1', ['userAgent' => self::GOOGLEBOT]);

        self::assertSame(['/9.9.9.1'], $stub->calls);
        self::assertSame(['user_agent' => self::GOOGLEBOT], self::query($stub->requests[0]));
    }

    public function testMyIpSendsItsUserAgentAndStaysUncached(): void
    {
        $stub = self::stub();
        $client = self::client($stub);
        $client->myIp(['userAgent' => self::GOOGLEBOT]);
        $client->myIp(['userAgent' => self::GOOGLEBOT]);

        self::assertSame(['/myip', '/myip'], $stub->calls);
        self::assertSame(['user_agent' => self::GOOGLEBOT], self::query($stub->requests[1]));
    }

    public function testAnEmptyUserAgentIsNone(): void
    {
        $stub = self::stub();
        $client = self::client($stub);
        $client->lookup('9.9.9.1', ['userAgent' => '']);
        $client->lookup('9.9.9.1');
        $client->lookup('9.9.9.1', ['userAgent' => null]);
        $client->myIp(['userAgent' => '']);

        self::assertSame(['/9.9.9.1', '/myip'], $stub->calls, 'an empty agent is the plain lookup, cached as one');
        self::assertSame('', $stub->requests[0]->getUri()->getQuery());
        self::assertSame('', $stub->requests[1]->getUri()->getQuery());
    }

    public function testAUserAgentPastTheSpecsLengthIsSentNotRefused(): void
    {
        $stub = self::stub();
        $long = str_repeat('Googlebot ', 200);
        self::client($stub)->lookup('9.9.9.1', ['userAgent' => $long]);
        self::client($stub)->myIp(['userAgent' => $long]);

        self::assertSame($long, self::query($stub->requests[0])['user_agent']);
        self::assertSame($long, self::query($stub->requests[1])['user_agent']);
    }

    public function testTheCacheHitsOnlyOnTheSameAddressAndUserAgent(): void
    {
        $stub = self::stub();
        $client = self::client($stub);
        $client->lookup('9.9.9.1');
        $client->lookup('9.9.9.1', ['userAgent' => 'A']);
        $client->lookup('9.9.9.1', ['userAgent' => 'A']);
        $client->lookup('9.9.9.1', ['userAgent' => 'B']);
        $client->lookup('9.9.9.1');
        $client->lookup('::ffff:9.9.9.1', ['userAgent' => 'B']);

        self::assertCount(3, $stub->calls, 'plain, A and B once each');
        self::assertSame([[], ['user_agent' => 'A'], ['user_agent' => 'B']], array_map(self::query(...), $stub->requests));
    }

    // Under PHP-FPM every request builds its own client, so a shared store stands
    // in for the cache a later request reads: a plain answer never answers an
    // agent's lookup, nor one agent's another's.
    public function testAStoreSharedByClientsKeysOnTheUserAgent(): void
    {
        $stub = self::stub();
        $store = new ArrayStore();
        self::client($stub, apiKey: 'k', cacheStore: $store)->lookup('9.9.9.1', ['userAgent' => 'A']);
        self::client($stub, apiKey: 'k', cacheStore: $store)->lookup('9.9.9.1');
        self::client($stub, apiKey: 'k', cacheStore: $store)->lookup('9.9.9.1', ['userAgent' => 'A']);
        self::client($stub, apiKey: 'k', cacheStore: $store)->lookup('9.9.9.1', ['userAgent' => 'B']);
        self::client($stub, apiKey: 'k', cacheStore: $store)->lookupBatch(['9.9.9.1', '9.9.9.2'], [
            'userAgents' => ['9.9.9.1' => 'B', '9.9.9.2' => 'A'],
        ]);

        self::assertSame(['/9.9.9.1', '/9.9.9.1', '/9.9.9.1', '/batch'], $stub->calls);
        self::assertSame(['ips' => ['9.9.9.2'], 'user_agents' => ['9.9.9.2' => 'A']], self::body($stub->requests[3]));
        self::assertCount(4, $store->values);
        foreach (array_keys($store->values) as $key) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_.]{1,64}$/', (string) $key);
        }
    }

    public function testABogonCarriesNoVerdictAndMakesNoRequest(): void
    {
        $stub = self::stub();
        $client = self::client($stub);
        $one = $client->lookup('10.0.0.1', ['userAgent' => 'Googlebot']);
        $many = $client->lookupBatch(['10.0.0.2', '::ffff:127.0.0.1'], [
            'userAgents' => ['10.0.0.2' => 'Googlebot', '::ffff:127.0.0.1' => 'Googlebot'],
        ]);

        self::assertSame([], $stub->calls);
        self::assertTrue($one->isBogon);
        self::assertNotNull($one->userAgent);
        self::assertTrue($one->userAgent->isEmpty(), 'empty, as a bogon\'s bot is');
        self::assertTrue($many['10.0.0.2']->userAgent->isEmpty());
        self::assertTrue($many['::ffff:127.0.0.1']->userAgent->isEmpty());
    }

    public function testTheAnswerCarriesTheVerdict(): void
    {
        $stub = new Stub(['/9.9.9.1' => Stub::ok(['ip' => '9.9.9.1', 'is_vpn' => false, 'user_agent' => self::VERDICT])]);
        $result = self::client($stub)->lookup('9.9.9.1', ['userAgent' => 'Googlebot/2.1']);

        self::assertSame('Googlebot', $result->userAgent?->agent);
        self::assertSame('bot', $result->userAgent->kind);
        self::assertSame('verified', $result->userAgent->verdict);

        $plain = self::client(self::stub())->lookup('9.9.9.1');
        self::assertNull($plain->userAgent, 'absent where the answer does not carry it');
    }

    public function testABatchSendsUserAgentsKeyedByTheAddressAsSent(): void
    {
        $stub = self::stub();
        $answers = self::client($stub)->lookupBatch(['::ffff:9.9.9.1', '9.9.9.2', '9.9.9.3'], [
            'userAgents' => ['::ffff:9.9.9.1' => 'A', '9.9.9.2' => '', '9.9.9.3' => null, '9.9.9.9' => 'C'],
        ]);

        self::assertSame(['/batch'], $stub->calls);
        self::assertSame(
            ['ips' => ['9.9.9.1', '9.9.9.2', '9.9.9.3'], 'user_agents' => ['9.9.9.1' => 'A']],
            self::body($stub->requests[0]),
            'an IPv4-mapped address is sent as its IPv4, so its agent is keyed by that; empty ones are none',
        );
        self::assertSame(['::ffff:9.9.9.1', '9.9.9.2', '9.9.9.3'], array_keys($answers));
        self::assertContainsOnlyInstancesOf(Result::class, $answers);
    }

    public function testABatchWithoutAnAgentSendsNoUserAgents(): void
    {
        foreach ([[], ['userAgents' => []], ['userAgents' => ['9.9.9.1' => '', '9.9.9.2' => null]]] as $options) {
            $stub = self::stub();
            self::client($stub)->lookupBatch(['9.9.9.1', '9.9.9.2'], $options);
            $raw = (string) $stub->requests[0]->getBody();
            self::assertStringNotContainsString('user_agents', $raw, json_encode($options) . ": {$raw}");
            self::assertSame(['ips' => ['9.9.9.1', '9.9.9.2']], self::body($stub->requests[0]));
        }
    }

    public function testUserAgentsIsSentPerChunk(): void
    {
        $ips = [];
        $routes = [];
        for ($i = 0; $i < 1500; $i++) {
            $ip = sprintf('9.%d.%d.%d', intdiv($i, 65536) + 1, intdiv($i, 256) % 256, $i % 256);
            $ips[] = $ip;
            $routes['/' . $ip] = Stub::ok(['ip' => $ip, 'is_vpn' => false]);
        }
        $stub = new Stub($routes);
        self::client($stub)->lookupBatch($ips, ['userAgents' => [$ips[1200] => 'A'], 'concurrency' => 1]);

        self::assertSame(['/batch', '/batch'], $stub->calls);
        self::assertArrayNotHasKey('user_agents', self::body($stub->requests[0]));
        self::assertSame([$ips[1200] => 'A'], self::body($stub->requests[1])['user_agents']);
    }

    // No public call overlaps another in a PHP thread, so the in-flight sharing
    // other SDKs pin is a batch's own: one request per address and user agent.
    public function testABatchAsksEachAddressOncePerUserAgent(): void
    {
        $stub = self::stub();
        $same = self::client($stub)->lookupBatch(['9.9.9.1', '::ffff:9.9.9.1'], [
            'userAgents' => ['9.9.9.1' => 'A', '::ffff:9.9.9.1' => 'A'],
        ]);
        self::assertSame(['ips' => ['9.9.9.1'], 'user_agents' => ['9.9.9.1' => 'A']], self::body($stub->requests[0]));
        self::assertCount(2, $same);

        $stub = self::stub();
        $client = self::client($stub);
        $client->lookup('9.9.9.2', ['userAgent' => 'A']);
        $two = $client->lookupBatch(['9.9.9.1', '::ffff:9.9.9.1', '9.9.9.2', '9.9.9.3'], [
            'userAgents' => ['9.9.9.1' => 'A', '::ffff:9.9.9.1' => 'B', '9.9.9.2' => 'A'],
        ]);
        self::assertSame(['/9.9.9.2', '/batch', '/batch'], $stub->calls, '9.9.9.2 with A was cached by its lookup');
        self::assertSame(
            [
                ['ips' => ['9.9.9.1', '9.9.9.3'], 'user_agents' => ['9.9.9.1' => 'A']],
                ['ips' => ['9.9.9.1'], 'user_agents' => ['9.9.9.1' => 'B']],
            ],
            [self::body($stub->requests[1]), self::body($stub->requests[2])],
        );
        self::assertSame(['9.9.9.1', '::ffff:9.9.9.1', '9.9.9.2', '9.9.9.3'], array_keys($two));

        $client->lookup('9.9.9.1', ['userAgent' => 'B']);
        $client->lookup('9.9.9.1', ['userAgent' => 'A']);
        $client->lookup('9.9.9.3');
        self::assertCount(3, $stub->calls, 'the batch cached each pair');
        $client->lookup('9.9.9.1');
        self::assertCount(4, $stub->calls, 'and never the plain answer it did not ask for');
    }

    public function testAUserAgentThatIsNotAStringIsRefusedBeforeAnyRequest(): void
    {
        $stub = self::stub();
        $client = self::client($stub);
        foreach ([
            fn () => $client->lookup('10.0.0.1', ['userAgent' => 5]),
            fn () => $client->myIp(['userAgent' => ['a']]),
            fn () => $client->lookupBatch(['10.0.0.1'], ['userAgents' => 'A']),
            fn () => $client->lookupBatch(['10.0.0.1'], ['userAgents' => ['10.0.0.1' => 5]]),
            fn () => $client->lookupBatch(['10.0.0.1'], ['userAgent' => 'A']),
            fn () => $client->lookup('10.0.0.1', ['userAgents' => ['10.0.0.1' => 'A']]),
        ] as $i => $call) {
            try {
                $call();
                self::fail("call {$i} was accepted");
            } catch (InvalidArgumentException) {
            }
        }
        self::assertSame([], $stub->calls);
    }
}
