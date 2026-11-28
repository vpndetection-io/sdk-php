<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\SimpleCache\CacheInterface;
use VPNDetection\Client;
use VPNDetection\Middleware\Condition;
use VPNDetection\Middleware\Core;
use VPNDetection\Middleware\Lookup;
use VPNDetection\Middleware\Options as MwOptions;
use VPNDetection\Middleware\RequestView;
use VPNDetection\Middleware\Selectors;
use VPNDetection\Options;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * The middleware half of the shared conformance corpus, plus the PHP-specific parts.
 *
 * This SDK is camelCase throughout, so a condition written here says `isVpn` and
 * `hitsDaysPct` while the corpus says `is_vpn` and `hits_days_pct`. The rename is a
 * general snake-to-camel rather than a lookup table, which is why a nested member
 * needs no entry of its own.
 */
final class MiddlewareTest extends TestCase
{
    private const PUBLIC_IP = '45.83.91.1';

    /** @return array<string, mixed> */
    private static function corpus(): array
    {
        /** @var array<string, mixed> $data */
        $data = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        return $data['middleware'];
    }

    /** Turn the corpus's wire names into this SDK's idiom, at every depth. */
    private static function toIdiom(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }
        if (array_is_list($value)) {
            return array_map([self::class, 'toIdiom'], $value);
        }
        $out = [];
        foreach ($value as $key => $entry) {
            $camel = lcfirst(str_replace('_', '', ucwords((string) $key, '_')));
            $out[$camel] = self::toIdiom($entry);
        }
        return $out;
    }

    /** @param array<string, mixed> $body */
    private static function serving(array $body, int $status = 200): Stub
    {
        $ip = $body['ip'] ?? self::PUBLIC_IP;
        return new Stub(Stub::lookups([$ip => ['status' => $status, 'body' => $body]]));
    }

    private static function client(Stub $stub): Client
    {
        return new Client(new Options(cache: false, retries: 0, httpClient: $stub->client));
    }

    private static function selectors(): Selectors
    {
        return new Selectors(fn (Req $request): RequestView => new RequestView(
            header: fn (string $name): ?string => $request->headers[strtolower($name)] ?? null,
            frameworkIp: fn (): ?string => $request->ip,
        ));
    }

    private static function core(MwOptions $options): Core
    {
        return new Core($options, self::selectors()->default());
    }

    public function testCorpusConditions(): void
    {
        // Decoded with objects too, so a detail served as `{}` is not sent as `[]`.
        $wire = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            false,
            512,
            JSON_THROW_ON_ERROR
        )->middleware->conditions;
        foreach (self::corpus()['conditions'] as $i => $case) {
            $why = "{$case['name']}: {$case['why']}";
            $result = isset($case['bogon'])
                ? (new Client(new Options()))->lookup($case['bogon'])
                : self::client(self::serving((array) $wire[$i]->body))->lookup($case['body']['ip']);

            /** @var array<mixed> $condition */
            $condition = self::toIdiom($case['condition']);
            self::assertSame(
                $case['expect']['blocked'],
                Condition::matches($condition, $result),
                $why
            );

            $missing = Condition::missingMembers($condition, $result);
            sort($missing);
            $want = array_map(
                static fn (string $m): string => lcfirst(str_replace('_', '', ucwords($m, '_'))),
                $case['expect']['missing']
            );
            sort($want);
            self::assertSame($want, $missing, $why);
        }
    }

    public function testCorpusRefusesAConditionThatConstrainsNothing(): void
    {
        foreach (self::corpus()['invalidConditions'] as $case) {
            $refused = false;
            try {
                self::core(new MwOptions(blockCondition: self::toIdiom($case['condition'])));
            } catch (\InvalidArgumentException $e) {
                $refused = str_contains($e->getMessage(), 'constrains nothing');
            }
            self::assertTrue($refused, "{$case['name']}: {$case['why']}");
        }
    }

    public function testEnrichesWithoutBlockingWhenNoConditionIsConfigured(): void
    {
        $stub = self::serving(['ip' => self::PUBLIC_IP, 'is_vpn' => true]);
        $core = self::core(new MwOptions(
            client: self::client($stub),
            ipSelector: fn (Req $r): string => self::PUBLIC_IP,
        ));
        $lookup = $core->evaluate(new Req());
        self::assertNotNull($lookup);
        self::assertFalse($lookup->blocked);
        self::assertTrue($lookup->result?->isVpn);
        self::assertSame(self::PUBLIC_IP, $lookup->ip);
    }

    public function testSkipClaimsTheRequest(): void
    {
        $stub = self::serving(['ip' => self::PUBLIC_IP, 'is_vpn' => true]);
        $core = self::core(new MwOptions(
            client: self::client($stub),
            skip: fn (Req $r): bool => true,
        ));
        self::assertNull($core->evaluate(new Req()));
        self::assertSame([], $stub->calls);
    }

    public function testFailsOpenOnALookupErrorAndClosedOnlyWhenAsked(): void
    {
        $failing = self::client(self::serving(['ip' => self::PUBLIC_IP, 'rc' => 'boom'], 500));
        $open = self::core(new MwOptions(
            client: $failing,
            ipSelector: fn (Req $r): string => self::PUBLIC_IP,
            blockCondition: ['isVpn' => true],
        ));
        $lookup = $open->evaluate(new Req());
        self::assertNotNull($lookup);
        self::assertFalse($lookup->blocked);
        self::assertInstanceOf(VPNDetectionException::class, $lookup->error);
        self::assertNull($lookup->result);

        $closed = self::core(new MwOptions(
            client: $failing,
            ipSelector: fn (Req $r): string => self::PUBLIC_IP,
            blockCondition: ['isVpn' => true],
            failClosed: true,
        ));
        self::assertTrue($closed->evaluate(new Req())?->blocked);
    }

    /** A condition on `isBot`, or on the bot's `verified`, blocks a served bot and passes a human. */
    public function testABlockConditionOnIsBotBlocksABotFromAPublicPeer(): void
    {
        $bot = [
            'ip' => self::PUBLIC_IP, 'is_vpn' => false, 'is_bot' => true,
            'bot' => ['provider' => 'google', 'provider_name' => 'Google', 'agents' => ['Googlebot'],
                'categories' => ['search_engine'], 'verified' => true, 'identity' => 'verified',
                'verified_by' => 'list', 'confidence' => 'high', 'first_seen' => '2026-11-21',
                'last_seen' => '2026-11-21'],
        ];
        $human = ['ip' => self::PUBLIC_IP, 'is_vpn' => false, 'is_bot' => false, 'bot' => new \stdClass()];
        foreach ([['isBot' => true], ['bot' => ['verified' => true]]] as $condition) {
            foreach ([[$bot, true], [$human, false]] as [$body, $blocked]) {
                $stub = self::serving($body);
                $core = self::core(new MwOptions(
                    client: self::client($stub),
                    ipSelector: fn (Req $r): string => self::PUBLIC_IP,
                    blockCondition: $condition,
                ));
                $lookup = $core->evaluate(new Req());
                $why = json_encode($condition) . ($blocked ? ' on a bot' : ' on a human');
                self::assertNotNull($lookup, $why);
                self::assertNull($lookup->error, $why);
                self::assertSame($blocked, $lookup->blocked, $why);
                self::assertSame(['/' . self::PUBLIC_IP], $stub->calls, "{$why}: the peer was looked up");
            }
        }
    }

    /**
     * Unlimited leaves out the AS's `type`, which `Asn` holds at `''`, and `isBot`: a condition on
     * either is a plan gap, reported by its path, and never matches, a stored answer's included.
     * The same condition on an answer that serves them blocks.
     */
    public function testAMemberTheAnswerLeavesOutIsReportedAsAPlanGapAndNeverMatches(): void
    {
        $asn = [
            'asn' => 9009, 'name' => 'M247 Europe SRL', 'domain' => 'm247global.com',
            'prefix' => '146.70.116.0/24', 'country' => 'US', 'rpki_status' => 'valid',
        ];
        $unlimited = ['ip' => self::PUBLIC_IP, 'is_vpn' => false, 'asn' => $asn];
        $paid = ['ip' => self::PUBLIC_IP, 'is_vpn' => false, 'is_bot' => true, 'asn' => [...$asn, 'type' => 'hosting']];
        $cases = [
            'asn.type' => [['asn' => ['type' => ['hosting', 'business']]], 'blockCondition names asn.type,'],
            "asn.type ''" => [['asn' => ['type' => ['', 'hosting']]], 'blockCondition names asn.type,'],
            'isBot' => [['isBot' => true], 'blockCondition names isBot,'],
        ];
        $store = new ArrayStore();
        foreach ($cases as $name => [$condition, $message]) {
            foreach ([false, true] as $stored) {
                $warnings = [];
                $core = self::core(new MwOptions(
                    client: new Client(new Options(
                        cacheStore: $store,
                        retries: 0,
                        httpClient: ($stored ? new Stub() : self::serving($unlimited))->client,
                    )),
                    ipSelector: fn (Req $r): string => self::PUBLIC_IP,
                    blockCondition: $condition,
                    onWarn: function (string $m) use (&$warnings): void {
                        $warnings[] = $m;
                    },
                ));
                $why = $name . ($stored ? ' on a stored answer' : '');
                $lookup = $core->evaluate(new Req());
                self::assertNull($lookup?->error, $why);
                self::assertFalse($lookup->blocked, $why);
                self::assertCount(1, $warnings, $why);
                self::assertStringContainsString($message, $warnings[0], $why);
            }
            $store->clear();

            $warnings = [];
            $core = self::core(new MwOptions(
                client: self::client(self::serving($paid)),
                ipSelector: fn (Req $r): string => self::PUBLIC_IP,
                blockCondition: $condition,
                onWarn: function (string $m) use (&$warnings): void {
                    $warnings[] = $m;
                },
            ));
            self::assertTrue($core->evaluate(new Req())?->blocked, "{$name} on an answer that serves it");
            self::assertSame([], $warnings, "{$name} on an answer that serves it");
        }
        self::assertSame('', (self::client(self::serving($unlimited))->lookup(self::PUBLIC_IP))->asn?->type);
    }

    public function testAPrivateClientAddressWarnsOnceAndNeverReachesTheNetwork(): void
    {
        $stub = self::serving(['ip' => '10.0.0.7', 'is_vpn' => true]);
        $warnings = [];
        $core = self::core(new MwOptions(
            client: self::client($stub),
            blockCondition: ['isVpn' => true],
            onWarn: function (string $m) use (&$warnings): void {
                $warnings[] = $m;
            },
        ));
        foreach ([1, 2] as $_) {
            $lookup = $core->evaluate(new Req([], '10.0.0.7'));
            self::assertFalse($lookup?->blocked);
            self::assertTrue($lookup?->result?->isBogon);
        }
        self::assertCount(1, $warnings, 'a per-request warning is an outage of its own');
        self::assertStringContainsString('not a public address', $warnings[0]);
    }

    public function testAMissingMemberWarnsOnceOrThrowsOnRequest(): void
    {
        $free = self::client(self::serving(['ip' => self::PUBLIC_IP, 'is_vpn' => true]));
        $warnings = [];
        $warned = self::core(new MwOptions(
            client: $free,
            ipSelector: fn (Req $r): string => self::PUBLIC_IP,
            blockCondition: ['isHosting' => true],
            onWarn: function (string $m) use (&$warnings): void {
                $warnings[] = $m;
            },
        ));
        $warned->evaluate(new Req());
        $warned->evaluate(new Req());
        self::assertCount(1, $warnings);
        self::assertStringContainsString('isHosting', $warnings[0]);

        $strict = self::core(new MwOptions(
            client: $free,
            ipSelector: fn (Req $r): string => self::PUBLIC_IP,
            blockCondition: ['isHosting' => true],
            onMissingField: 'throw',
        ));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/does not include/');
        $strict->evaluate(new Req());
    }

    public function testSelectorsReadWhatTheySayTheyRead(): void
    {
        $selectors = self::selectors();
        $request = new Req(['x-forwarded-for' => '203.0.113.9, 70.41.3.18, 150.172.238.178'], '10.0.0.1');

        self::assertSame('10.0.0.1', ($selectors->default())($request));
        self::assertSame('203.0.113.9', ($selectors->xff())($request));
        self::assertSame('150.172.238.178', ($selectors->xff(1))($request));
        self::assertSame('70.41.3.18', ($selectors->xff(2))($request));
        self::assertSame('10.0.0.1', ($selectors->header('CF-Connecting-IP'))($request));

        $cf = new Req(['cf-connecting-ip' => '198.51.100.4'], '10.0.0.1');
        self::assertSame('198.51.100.4', ($selectors->header('CF-Connecting-IP'))($cf));
        self::assertSame('10.0.0.1', ($selectors->xff())(new Req([], '10.0.0.1')));
    }

    public function testAnUnresolvableAddressWarnsAndDoesNotBlock(): void
    {
        $warnings = [];
        $core = new Core(
            new MwOptions(
                blockCondition: ['isVpn' => true],
                onWarn: function (string $m) use (&$warnings): void {
                    $warnings[] = $m;
                },
            ),
            fn (Req $r): ?string => null,
        );
        $lookup = $core->evaluate(new Req());
        self::assertFalse($lookup?->blocked);
        self::assertInstanceOf(VPNDetectionException::class, $lookup?->error);
        self::assertStringContainsString('could not resolve a client address', $warnings[0]);
    }

    private const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

    /** @return array<string, mixed> An answer for the public peer carrying this verdict, or none. */
    private static function judged(?string $verdict, bool $isVpn = true): array
    {
        $body = ['ip' => self::PUBLIC_IP, 'is_vpn' => $isVpn];
        if ($verdict !== null) {
            $body['user_agent'] = ['agent' => 'Googlebot', 'kind' => 'bot', 'verdict' => $verdict];
        }
        return $body;
    }

    /** @return array<string, mixed> */
    private static function sentQuery(Stub $stub): array
    {
        parse_str($stub->requests[0]->getUri()->getQuery(), $query);
        return $query;
    }

    public function testAllowBotsSendsTheRequestsOwnUserAgent(): void
    {
        $stub = self::serving(self::judged('verified'));
        $request = new Req(['user-agent' => self::GOOGLEBOT]);
        $lookup = self::core(new MwOptions(client: self::client($stub), allowBots: true))
            ->evaluate($request, $request->headers['user-agent']);

        self::assertSame(['/' . self::PUBLIC_IP], $stub->calls, 'a public peer, looked up');
        self::assertSame(['user_agent' => self::GOOGLEBOT], self::sentQuery($stub));
        self::assertSame('verified', $lookup?->result?->userAgent?->verdict);
    }

    public function testAllowBotsOffSendsNoUserAgent(): void
    {
        $stub = self::serving(self::judged(null));
        self::core(new MwOptions(client: self::client($stub)))->evaluate(new Req(), self::GOOGLEBOT);

        self::assertSame(['/' . self::PUBLIC_IP], $stub->calls);
        self::assertSame([], self::sentQuery($stub));
    }

    public function testAnAbsentOrEmptyUserAgentSendsNoneAndWarnsNothing(): void
    {
        foreach ([null, ''] as $agent) {
            $warnings = [];
            $stub = self::serving(self::judged(null));
            self::core(new MwOptions(
                client: self::client($stub),
                allowBots: true,
                onWarn: function (string $m) use (&$warnings): void {
                    $warnings[] = $m;
                },
            ))->evaluate(new Req(), $agent);

            self::assertSame([], self::sentQuery($stub), var_export($agent, true));
            self::assertSame([], $warnings, var_export($agent, true));
        }
    }

    public function testAVerifiedCrawlerPassesAConditionItOtherwiseMeets(): void
    {
        foreach ([['verified', false], ['spoofed', true], ['not_bot', true], ['unverifiable', true], [null, true]] as [$verdict, $blocked]) {
            $stub = self::serving(self::judged($verdict));
            $lookup = self::core(new MwOptions(
                client: self::client($stub),
                blockCondition: ['isVpn' => true],
                allowBots: true,
                onMissingField: 'ignore',
            ))->evaluate(new Req(), self::GOOGLEBOT);

            $why = var_export($verdict, true);
            self::assertSame($blocked, $lookup?->blocked, $why);
            self::assertTrue($lookup->result?->isVpn, "{$why}: the answer is still attached");
        }
    }

    public function testWithAllowBotsOffAVerifiedAnswerIsStillRefused(): void
    {
        $stub = self::serving(self::judged('verified'));
        $lookup = self::core(new MwOptions(client: self::client($stub), blockCondition: ['isVpn' => true]))
            ->evaluate(new Req(), self::GOOGLEBOT);

        self::assertTrue($lookup?->blocked);
    }

    public function testAConditionNamingTheUserAgentWorksWithAllowBots(): void
    {
        foreach ([['spoofed', true], ['not_bot', false], ['verified', false]] as [$verdict, $blocked]) {
            $stub = self::serving(self::judged($verdict, isVpn: false));
            $lookup = self::core(new MwOptions(
                client: self::client($stub),
                blockCondition: ['userAgent' => ['verdict' => 'spoofed']],
                allowBots: true,
            ))->evaluate(new Req(), self::GOOGLEBOT);

            self::assertSame($blocked, $lookup?->blocked, $verdict);
        }
    }

    public function testAnAnswerWithoutAVerdictWarnsOnceOrThrows(): void
    {
        $warnings = [];
        $stub = self::serving(self::judged(null, isVpn: false));
        $core = self::core(new MwOptions(
            client: self::client($stub),
            allowBots: true,
            onWarn: function (string $m) use (&$warnings): void {
                $warnings[] = $m;
            },
        ));
        $core->evaluate(new Req(), self::GOOGLEBOT);
        $core->evaluate(new Req(), self::GOOGLEBOT);
        self::assertCount(1, $warnings);
        self::assertStringContainsString('user_agent', $warnings[0]);

        $quiet = [];
        self::core(new MwOptions(
            client: self::client($stub),
            allowBots: true,
            onMissingField: 'ignore',
            onWarn: function (string $m) use (&$quiet): void {
                $quiet[] = $m;
            },
        ))->evaluate(new Req(), self::GOOGLEBOT);
        self::assertSame([], $quiet);

        $this->expectException(\RuntimeException::class);
        self::core(new MwOptions(client: self::client($stub), allowBots: true, onMissingField: 'throw'))
            ->evaluate(new Req(), self::GOOGLEBOT);
    }

    private const PEER = '66.249.66.1';
    private const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36';

    private static function crawler(int $n): string
    {
        return "Mozilla/5.0 (compatible; Examplebot/{$n}.0)";
    }

    /** @return array<string, mixed> */
    private static function crawlerCorpus(): array
    {
        /** @var array<string, mixed> $data */
        $data = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        return $data['crawlerAgents'];
    }

    /**
     * A bot's address, answering `verified` to any agent that arrives, with `$extra` members
     * on every answer, and recording the agent each lookup carried (null for none).
     *
     * @param list<?string> $agents
     * @param array<string, mixed> $extra
     * @param string $verdict What an agent that arrives is judged
     * @param ?CacheInterface $store The client's PSR-16 store, when it keeps its answers in one
     */
    private static function botsAddress(
        array &$agents,
        array $extra = [],
        string $verdict = 'verified',
        ?CacheInterface $store = null,
    ): Client {
        $handler = function (RequestInterface $request) use (&$agents, $extra, $verdict) {
            parse_str($request->getUri()->getQuery(), $query);
            $agent = $query['user_agent'] ?? null;
            $agents[] = $agent;
            $body = ['ip' => ltrim($request->getUri()->getPath(), '/'), 'is_vpn' => false, 'is_bot' => true] + $extra;
            if ($agent !== null) {
                $body['user_agent'] = ['agent' => 'Googlebot', 'kind' => 'bot', 'verdict' => $verdict];
            }
            return Create::promiseFor(new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($body, JSON_THROW_ON_ERROR),
            ));
        };
        $http = new GuzzleClient(['handler' => HandlerStack::create($handler)]);
        return new Client($store === null
            ? new Options(cache: false, retries: 0, httpClient: $http)
            : new Options(retries: 0, cacheStore: $store, httpClient: $http));
    }

    public function testOnlyAnAgentNamingACrawlerIsSentAsTheCorpusSays(): void
    {
        $corpus = self::crawlerCorpus();
        self::assertNotEmpty($corpus['crawlers']);
        self::assertNotEmpty($corpus['others']);
        foreach ($corpus['crawlers'] as $agent) {
            self::assertTrue(Core::namesCrawler($agent), $agent);
        }
        foreach ($corpus['others'] as $agent) {
            self::assertFalse(Core::namesCrawler($agent), $agent);
        }
        foreach ($corpus['terms'] as $term) {
            self::assertTrue(Core::namesCrawler('x ' . strtoupper($term) . ' y'), $term);
        }

        $agents = [];
        $lookup = self::core(new MwOptions(
            client: self::botsAddress($agents),
            blockCondition: ['isBot' => true],
            allowBots: true,
            onMissingField: 'ignore',
        ))->evaluate(new Req(ip: self::PEER), self::CHROME);
        self::assertSame([null], $agents, 'a browser\'s agent stays off the lookup');
        self::assertTrue($lookup?->blocked);
    }

    public function testOneAddressIsLookedUpWithAtMostFourCrawlerAgentsAndNonePassesPastThem(): void
    {
        self::assertSame(4, Core::MAX_AGENTS_PER_ADDRESS);
        $agents = [];
        $core = self::core(new MwOptions(
            client: self::botsAddress($agents),
            blockCondition: ['isBot' => true],
            allowBots: true,
            onMissingField: 'ignore',
        ));
        $eval = fn (int $n, string $ip = self::PEER): ?Lookup => $core->evaluate(new Req(ip: $ip), self::crawler($n));

        for ($n = 1; $n <= 4; $n++) {
            self::assertFalse($eval($n)?->blocked, "agent {$n}");
        }
        $past = $eval(5);
        self::assertTrue($past?->blocked, 'an agent past the bound is never let through as verified');
        self::assertNull($past->result?->userAgent);
        self::assertFalse($eval(1)?->blocked, 'a known agent is still sent');
        self::assertSame(
            [self::crawler(1), self::crawler(2), self::crawler(3), self::crawler(4), null, self::crawler(1)],
            $agents,
        );

        self::assertFalse($eval(5, '66.249.66.2')?->blocked, 'each address has its own bound');
        self::assertSame(self::crawler(5), $agents[array_key_last($agents)]);
    }

    /**
     * Under PHP-FPM every request builds its own core, so the record of an address's agents lives in
     * the client's PSR-16 store: one key per address, digests rather than agents, the hour counted
     * from the first.
     */
    public function testAnAddressesCrawlerAgentsOutliveTheCoreInTheClientsStore(): void
    {
        $store = new ArrayStore();
        $agents = [];
        $fresh = static function () use (&$agents, $store): Core {
            return self::core(new MwOptions(
                client: self::botsAddress($agents, store: $store),
                blockCondition: ['isBot' => true],
                allowBots: true,
                onMissingField: 'ignore',
            ));
        };
        $eval = static fn (int $n, string $ip = self::PEER): ?Lookup => $fresh()->evaluate(new Req(ip: $ip), self::crawler($n));
        $keys = static fn (): array => array_values(array_filter(
            array_keys($store->values),
            static fn (string $k): bool => str_starts_with($k, 'vpndetection.agents.'),
        ));

        $until = 0;
        for ($n = 1; $n <= 4; $n++) {
            self::assertFalse($eval($n)?->blocked, "agent {$n}, from a core of its own");
            self::assertCount(1, $keys(), 'one key for the address');
            if ($n === 1) {
                self::assertEqualsWithDelta(time() + 3600, $store->values[$keys()[0]]['until'], 5, 'an hour from the first');
                // Half the hour has gone: the agents that follow must not start it over.
                $store->values[$keys()[0]]['until'] = $until = time() + 1800;
            }
        }
        self::assertSame($until, $store->values[$keys()[0]]['until'], 'an agent added leaves the hour as it was');
        $record = $store->values[$keys()[0]];
        self::assertCount(4, $record['agents']);
        foreach ($record['agents'] as $n => $digest) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $digest);
            self::assertStringNotContainsString(self::crawler($n + 1), json_encode($record, JSON_THROW_ON_ERROR));
        }

        $past = $eval(5);
        self::assertTrue($past?->blocked, 'a fifth agent, from a core that never saw the others, is past the bound');
        self::assertNull($past->result?->userAgent);
        self::assertNull($agents[array_key_last($agents)], 'and none was sent');
        self::assertFalse($eval(1)?->blocked, 'a known agent is sent again');
        self::assertSame($record, $store->values[$keys()[0]], 'neither touched the record');

        self::assertFalse($eval(5, '66.249.66.2')?->blocked, 'each address has its own record');
        self::assertCount(2, $keys());
        self::assertSame(self::crawler(5), $agents[array_key_last($agents)]);

        $store->values[$keys()[0]]['until'] = time() - 1;
        self::assertFalse($eval(5)?->blocked, 'a lapsed record remembers nothing');
        self::assertSame(self::crawler(5), $agents[array_key_last($agents)]);
        self::assertCount(1, $store->values[$keys()[0]]['agents']);
    }

    public function testAStoreThatFailsLeavesTheBoundToTheCore(): void
    {
        $store = new ArrayStore();
        $store->failing = true;
        $agents = [];
        $core = self::core(new MwOptions(
            client: self::botsAddress($agents, store: $store),
            blockCondition: ['isBot' => true],
            allowBots: true,
            onMissingField: 'ignore',
        ));
        for ($n = 1; $n <= 4; $n++) {
            self::assertFalse($core->evaluate(new Req(ip: self::PEER), self::crawler($n))?->blocked, "agent {$n}");
        }
        self::assertTrue($core->evaluate(new Req(ip: self::PEER), self::crawler(5))?->blocked, 'past the bound');
        self::assertNull($agents[array_key_last($agents)]);
    }

    public function testPastTheBoundAnAddressItsOperatorVouchesForStillPasses(): void
    {
        $agents = [];
        $core = self::core(new MwOptions(
            client: self::botsAddress($agents, ['bot' => ['verified' => true]]),
            blockCondition: ['isBot' => true],
            allowBots: true,
            onMissingField: 'ignore',
        ));
        for ($n = 1; $n <= 5; $n++) {
            self::assertFalse($core->evaluate(new Req(ip: self::PEER), self::crawler($n))?->blocked, "agent {$n}");
        }
        self::assertNull($agents[array_key_last($agents)]);
        self::assertTrue(
            $core->evaluate(new Req(ip: self::PEER), self::CHROME)?->blocked,
            'a browser on that address is judged as the condition says',
        );
    }

    public function testAConditionOnTheVerdictIsNoPlanGapForARequestThatSentNoAgent(): void
    {
        $forged = ['userAgent' => ['verdict' => 'spoofed']];
        foreach ([self::CHROME, null] as $header) {
            $warnings = [];
            $agents = [];
            $lookup = self::core(new MwOptions(
                client: self::botsAddress($agents, verdict: 'spoofed'),
                blockCondition: $forged,
                allowBots: true,
                onMissingField: 'throw',
                onWarn: function (string $m) use (&$warnings): void {
                    $warnings[] = $m;
                },
            ))->evaluate(new Req(ip: self::PEER), $header);
            self::assertFalse($lookup?->blocked, var_export($header, true));
            self::assertSame([null], $agents);
            self::assertSame([], $warnings);
        }

        $agents = [];
        $core = self::core(new MwOptions(
            client: self::botsAddress($agents, verdict: 'spoofed'),
            blockCondition: $forged,
            allowBots: true,
            onMissingField: 'throw',
        ));
        for ($n = 1; $n <= 4; $n++) {
            $core->evaluate(new Req(ip: self::PEER), self::crawler($n));
        }
        self::assertFalse(
            $core->evaluate(new Req(ip: self::PEER), self::crawler(5))?->blocked,
            'past the bound, no gap either',
        );

        $warned = [];
        $stub = [];
        self::core(new MwOptions(
            client: self::botsAddress($stub, verdict: 'spoofed'),
            blockCondition: $forged,
            onWarn: function (string $m) use (&$warned): void {
                $warned[] = $m;
            },
        ))->evaluate(new Req(ip: self::PEER));
        self::assertCount(1, $warned, 'off, a condition on the verdict can never match, and says so');
    }

    public function testABogonPeerIsAnsweredLocallyAndLetsNothingThrough(): void
    {
        $warnings = [];
        $stub = self::serving(self::judged('verified'));
        $lookup = self::core(new MwOptions(
            client: self::client($stub),
            ipSelector: fn (Req $r): string => '10.0.0.1',
            blockCondition: ['isBogon' => true],
            allowBots: true,
            onWarn: function (string $m) use (&$warnings): void {
                $warnings[] = $m;
            },
        ))->evaluate(new Req(), self::GOOGLEBOT);

        self::assertSame([], $stub->calls);
        self::assertTrue($lookup?->blocked);
        self::assertCount(1, $warnings, 'the private-address warning alone');
    }

    /**
     * A bogon peer, local development behind no proxy, is answered locally in the widest
     * shape and carries no verdict, and that is no plan gap: onMissingField set to throw
     * answered a crawler's request there with an error.
     */
    public function testABogonPeerWithACrawlerAgentIsNoPlanGap(): void
    {
        $forged = ['userAgent' => ['verdict' => 'spoofed']];
        foreach (['127.0.0.1', '10.0.0.1', '::1'] as $peer) {
            foreach (['throw', 'warn'] as $action) {
                $why = "{$peer}, {$action}";
                $agents = [];
                $warnings = [];
                $core = self::core(new MwOptions(
                    client: self::botsAddress($agents, verdict: 'spoofed'),
                    blockCondition: $forged,
                    allowBots: true,
                    onMissingField: $action,
                    onWarn: function (string $m) use (&$warnings): void {
                        $warnings[] = $m;
                    },
                ));
                try {
                    $lookup = $core->evaluate(new Req(ip: $peer), self::GOOGLEBOT);
                } catch (\RuntimeException $error) {
                    self::fail("{$why}: reported a plan gap for a bogon: {$error->getMessage()}");
                }
                self::assertFalse($lookup?->blocked, $why);
                self::assertTrue($lookup->result?->isBogon, "{$why}: the bogon's own answer");
                self::assertSame([], $agents, "{$why}: a bogon reached the origin");
                self::assertSame([], Condition::missingMembers($forged, $lookup->result), $why);
                foreach ($warnings as $warning) {
                    self::assertStringNotContainsString('does not include', $warning, $why);
                }
            }
        }
    }
}

/** The least a framework can offer, so the core is exercised without one. */
final class Req
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly array $headers = [],
        public readonly string $ip = '45.83.91.1',
    ) {
    }
}
