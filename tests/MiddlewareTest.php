<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\Middleware\Condition;
use VPNDetection\Middleware\Core;
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
        foreach (self::corpus()['conditions'] as $case) {
            $why = "{$case['name']}: {$case['why']}";
            $result = isset($case['bogon'])
                ? (new Client(new Options()))->lookup($case['bogon'])
                : self::client(self::serving($case['body']))->lookup($case['body']['ip']);

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
