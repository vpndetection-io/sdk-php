<?php

declare(strict_types=1);

namespace VPNDetection\Integration;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\RequestInterface;
use VPNDetection\Client;
use VPNDetection\Options;
use VPNDetection\Result;

/**
 * The staging fixtures the test files share: one client per tier, one lookup per
 * tier, and the shape rules that hold whatever the plan.
 */
final class Staging
{
    public const STAGING = 'https://api-staging.vpndetection.io';
    public const STAGING_HOST = 'api-staging.vpndetection.io';

    /** A stable VPN address, and the one the README teaches. */
    public const PROBE = '45.83.91.1';

    /**
     * One entry per dataset the API answers about. `required` is what a
     * POPULATED detail object carries on every tier; `optional` is the max-only
     * remainder, which is absent rather than empty on a lower plan.
     *
     * @var array<string, array{required: list<string>, optional: list<string>}>
     */
    public const MEMBERS = [
        'vpn' => ['required' => ['provider', 'last_seen'], 'optional' => ['confidence', 'method']],
        'hosting' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'relay' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'tor' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'cdn' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'resproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
        'dcproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
        'mobproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
    ];

    private const CLASS_KEYS = ['provider', 'confidence', 'last_seen'];
    private const PROXY_KEYS = ['provider', 'first_seen', 'last_seen', 'hits', 'hits_days_pct', 'providers_num'];

    /** @var array<string, array{rung: array<string, mixed>, result: Result, carriedKey: bool}> */
    private static array $answers = [];

    /**
     * The wire name of each field, mapped to the property the client puts it on.
     * That pairing is what lets one assertion talk about both halves at once.
     *
     * @return array<string, string>
     */
    public static function resultProps(): array
    {
        $props = ['ip' => 'ip', 'is_vpn' => 'isVpn'];
        foreach (array_keys(self::MEMBERS) as $name) {
            $props["is_{$name}"] = self::flagProp($name);
            $props[$name] = $name;
        }
        return $props;
    }

    public static function flagProp(string $name): string
    {
        return 'is' . ucfirst($name);
    }

    /**
     * @param array{tier: string, secret: string|null, widens: bool} $rung
     * @param (callable(array{host: string, path: string, carriedKey: bool}): void)|null $onRequest
     */
    public static function clientFor(array $rung, ?callable $onRequest = null): Client
    {
        $key = Tiers::keyFor($rung);
        $stack = HandlerStack::create();
        $stack->push(Middleware::mapRequest(
            static function (RequestInterface $request) use ($key, $onRequest): RequestInterface {
                if ($onRequest !== null) {
                    $onRequest(self::factsFor($request, $key));
                }
                return $request;
            },
        ));
        return new Client(new Options(
            apiKey: $key === '' ? null : $key,
            baseUrl: self::STAGING,
            httpClient: new GuzzleClient(['handler' => $stack]),
        ));
    }

    /**
     * What a test is allowed to remember about a request it made.
     *
     * Only derived facts leave here. A failing assertion prints its operands, so
     * holding on to the request itself is how a key ends up in a public CI log:
     * whether the key was carried is a boolean, and the caller never sees it.
     *
     * @return array{host: string, path: string, carriedKey: bool}
     */
    public static function factsFor(RequestInterface $request, string $key): array
    {
        $uri = $request->getUri();
        $carried = false;
        if ($key !== '') {
            $carried = str_contains($uri->getQuery(), $key);
            foreach ($request->getHeaders() as $values) {
                foreach ($values as $value) {
                    $carried = $carried || str_contains($value, $key);
                }
            }
        }
        return ['host' => $uri->getHost(), 'path' => $uri->getPath(), 'carriedKey' => $carried];
    }

    /**
     * One lookup per tier for the whole run. The client caches, so a second
     * reader of the same tier costs no request at all.
     *
     * @param array{tier: string, secret: string|null, widens: bool} $rung
     * @return array{rung: array{tier: string, secret: string|null, widens: bool}, result: Result, carriedKey: bool}
     */
    public static function answerFor(array $rung): array
    {
        if (!isset(self::$answers[$rung['tier']])) {
            $facts = [];
            $client = self::clientFor($rung, static function (array $fact) use (&$facts): void {
                $facts[] = $fact;
            });
            self::$answers[$rung['tier']] = [
                'rung' => $rung,
                'result' => $client->lookup(self::PROBE),
                'carriedKey' => array_reduce(
                    $facts,
                    static fn (bool $carried, array $fact): bool => $carried || $fact['carriedKey'],
                    false,
                ),
            ];
        }
        return self::$answers[$rung['tier']];
    }

    /** @param array{rung: array<string, mixed>, result: Result, carriedKey: bool} $fixture */
    public static function assertServedByTier(array $fixture): void
    {
        Assert::assertSame(self::PROBE, $fixture['result']->ip);
        Assert::assertFalse($fixture['result']->isBogon, 'a served answer is not a local one');
        if ($fixture['rung']['secret'] !== null) {
            // Without this the tier is indistinguishable from an unauthenticated
            // one, and every comparison the ladder makes against it is vacuous.
            Assert::assertTrue($fixture['carriedKey'], 'the key never reached the wire');
        }
        self::assertShape($fixture['result']);
    }

    /**
     * Holds on every plan: presence is the plan, the value is the answer.
     *
     * Read off `raw`, which is the wire, then cross-checked against the typed
     * property. That pairing is the positive half of the absent-versus-false
     * contract: a field the plan DOES include must survive the mapping, `false`
     * and all.
     */
    public static function assertShape(Result $r): void
    {
        Assert::assertIsString($r->ip);
        Assert::assertArrayHasKey('is_vpn', $r->raw, 'is_vpn is on every plan');
        Assert::assertIsBool($r->isVpn);

        foreach (self::MEMBERS as $name => $spec) {
            $flag = self::flagProp($name);
            if (array_key_exists("is_{$name}", $r->raw)) {
                Assert::assertIsBool($r->$flag, "{$flag} is served, so the client must map it to a boolean");
            }
            if (!array_key_exists($name, $r->raw)) {
                continue;
            }
            // A detail object without its flag would leave a caller reading the
            // object to find out whether the address is flagged at all.
            Assert::assertNotNull($r->$flag, "{$name} is served without {$flag}");
            self::assertDetail($r, $name, $spec);
        }
    }

    /** @param array{required: list<string>, optional: list<string>} $spec */
    private static function assertDetail(Result $r, string $name, array $spec): void
    {
        $detail = $r->raw[$name];
        Assert::assertIsArray($detail, "{$name} must be an object when present");
        if ($detail === []) {
            Assert::assertFalse($r->{self::flagProp($name)}, "{$name} is empty, so its flag must be false");
            Assert::assertTrue($r->$name->isEmpty(), "{$name} arrived empty and the client filled it in");
            return;
        }
        foreach ($spec['required'] as $key) {
            Assert::assertArrayHasKey($key, $detail, "{$name} is populated but carries no {$key}");
        }
        foreach (array_keys($detail) as $key) {
            Assert::assertContains(
                $key,
                [...$spec['required'], ...$spec['optional']],
                "{$name}.{$key} is not a documented key of this detail object",
            );
        }
    }
}
