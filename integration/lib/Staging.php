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
        'vpn' => ['required' => ['provider', 'provider_name', 'last_seen'], 'optional' => ['confidence', 'method']],
        'hosting' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'relay' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'tor' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'cdn' => ['required' => self::CLASS_KEYS, 'optional' => []],
        'resproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
        'dcproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
        'mobproxy' => ['required' => self::PROXY_KEYS, 'optional' => []],
        'carrier' => ['required' => ['name', 'mcc', 'mnc', 'country', 'confidence'], 'optional' => []],
        'satellite' => [
            'required' => ['provider', 'provider_name', 'orbit', 'segment', 'country', 'asn', 'confidence'],
            'optional' => [],
        ],
        'ssh' => [
            'required' => ['port', 'banner', 'host_key_fp', 'session_ok', 'first_seen', 'last_seen'],
            'optional' => [],
        ],
        'smtp' => ['required' => ['port', 'banner', 'session_ok', 'first_seen', 'last_seen'], 'optional' => []],
        'dns_resolver' => [
            'required' => ['port', 'recursion_available', 'rcode', 'answer_correct', 'first_seen', 'last_seen'],
            'optional' => [],
        ],
        'bittorrent' => [
            'required' => [
                'verified', 'id_matches_ip', 'first_seen', 'last_seen', 'last_reachable', 'days_seen',
                'num_ports', 'peak_num_ports', 'indexer', 'clients',
            ],
            'optional' => [],
        ],
        'bot' => [
            'required' => [
                'provider', 'provider_name', 'agents', 'categories', 'verified', 'identity', 'verified_by',
                'confidence', 'first_seen', 'last_seen',
            ],
            'optional' => [],
        ],
    ];

    /** The keys of each row of `web`, a list with a row per port that answered. */
    public const WEB_KEYS = [
        'port', 'tls_ok', 'session_ok', 'status_code', 'server', 'location', 'title', 'cert_subject_cn',
        'cert_subject_o', 'cert_issuer_dn', 'cert_browser_trusted', 'tls_version', 'first_seen', 'last_seen',
    ];

    /**
     * The objects that are never empty: `required` is on every answer carrying
     * the object, `optional` only on a plan that includes it.
     *
     * @var array<string, array{required: list<string>, optional: list<string>}>
     */
    public const OBJECTS = [
        'location' => [
            'required' => [
                'continent', 'continent_name', 'country', 'country_name', 'timezone', 'currency_code',
                'currency_name', 'currency_symbol', 'flag_emoji', 'flag_unicode',
            ],
            'optional' => [
                'region', 'region_code', 'city', 'postal_code', 'latitude', 'longitude', 'accuracy_radius',
                'geoname_id', 'dma_code', 'last_changed',
            ],
        ],
        // `type` is a paid plan's: Unlimited's answer carries it until the API stops serving it, so a
        // keyless run accepts it present or absent.
        'asn' => [
            'required' => ['asn', 'name', 'domain', 'prefix', 'country', 'rpki_status'],
            'optional' => ['type'],
        ],
        'company' => ['required' => ['name', 'domain'], 'optional' => ['type', 'country']],
        'abuse' => [
            'required' => ['email'],
            'optional' => ['name', 'phone', 'address', 'country', 'network', 'validated', 'unvalidated_since'],
        ],
    ];

    private const CLASS_KEYS = ['provider', 'provider_name', 'confidence', 'last_seen'];
    private const PROXY_KEYS = [
        'provider', 'provider_name', 'first_seen', 'last_seen', 'hits', 'hits_days_pct', 'providers_num',
    ];

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
        $props = [
            'ip' => 'ip', 'is_vpn' => 'isVpn', 'is_anycast' => 'isAnycast', 'is_web' => 'isWeb', 'web' => 'web',
            'hostname' => 'hostname',
        ];
        foreach (array_keys(self::MEMBERS) as $name) {
            $props["is_{$name}"] = self::flagProp($name);
            $props[$name] = self::detailProp($name);
        }
        foreach (array_keys(self::OBJECTS) as $name) {
            $props[$name] = $name;
        }
        return $props;
    }

    public static function flagProp(string $name): string
    {
        return 'is' . ucfirst(self::detailProp($name));
    }

    /** `dns_resolver` is `dnsResolver` on the result. */
    public static function detailProp(string $name): string
    {
        return lcfirst(str_replace('_', '', ucwords($name, '_')));
    }

    /**
     * @param array{tier: string, secret: string|null, widens: bool} $rung
     * @param (callable(array{host: string, path: string, ips: list<string>, carriedKey: bool}): void)|null $onRequest
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
     * @return array{host: string, path: string, ips: list<string>, carriedKey: bool}
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
        // A POST /batch carries its addresses in the body, so the path alone no
        // longer says what was asked about.
        $body = $request->getBody();
        $decoded = json_decode((string) $body, true);
        if ($body->isSeekable()) {
            $body->rewind();
        }
        return [
            'host' => $uri->getHost(),
            'path' => $uri->getPath(),
            'ips' => is_array($decoded['ips'] ?? null) ? array_values($decoded['ips']) : [],
            'carriedKey' => $carried,
        ];
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
        foreach (['is_anycast' => 'isAnycast', 'is_web' => 'isWeb'] as $wire => $flag) {
            if (array_key_exists($wire, $r->raw)) {
                Assert::assertIsBool($r->$flag, "{$wire} is served, so the client must map it to a boolean");
            }
        }
        if (array_key_exists('hostname', $r->raw)) {
            Assert::assertIsString($r->hostname, 'hostname is served, so the client must map it to a string');
        }
        if (array_key_exists('web', $r->raw)) {
            self::assertWeb($r);
        }
        foreach (self::OBJECTS as $name => $spec) {
            if (array_key_exists($name, $r->raw)) {
                Assert::assertNotNull($r->$name, "{$name} is served, so the client must map it");
                self::assertKeys($r->raw[$name], $name, $spec);
            }
        }
        if (array_key_exists('asn', $r->raw)) {
            // The AS's type reads as served, or '' where the answer leaves it out.
            Assert::assertSame($r->raw['asn']['type'] ?? '', $r->asn->type, 'asn.type reads as served, or empty');
        }
    }

    private static function assertWeb(Result $r): void
    {
        $rows = $r->raw['web'];
        Assert::assertIsArray($rows, 'web must be a list when present');
        Assert::assertTrue(array_is_list($rows), 'web must be a list when present');
        Assert::assertNotNull($r->isWeb, 'web is served without isWeb');
        Assert::assertSame($rows !== [], $r->isWeb, 'web has rows exactly when isWeb is true');
        Assert::assertCount(count($rows), $r->web ?? [], 'the client keeps every web row');
        foreach ($rows as $row) {
            self::assertKeys($row, 'web[]', ['required' => self::WEB_KEYS, 'optional' => []]);
        }
    }

    /**
     * @param mixed $object
     * @param array{required: list<string>, optional: list<string>} $spec
     */
    private static function assertKeys(mixed $object, string $name, array $spec): void
    {
        Assert::assertIsArray($object, "{$name} must be an object when present");
        foreach ($spec['required'] as $key) {
            Assert::assertArrayHasKey($key, $object, "{$name} carries no {$key}");
        }
        foreach (array_keys($object) as $key) {
            Assert::assertContains(
                $key,
                [...$spec['required'], ...$spec['optional']],
                "{$name}.{$key} is not a documented key of this object",
            );
        }
    }

    /** @param array{required: list<string>, optional: list<string>} $spec */
    private static function assertDetail(Result $r, string $name, array $spec): void
    {
        $detail = $r->raw[$name];
        Assert::assertIsArray($detail, "{$name} must be an object when present");
        if ($detail === []) {
            Assert::assertFalse($r->{self::flagProp($name)}, "{$name} is empty, so its flag must be false");
            Assert::assertTrue($r->{self::detailProp($name)}->isEmpty(), "{$name} arrived empty and the client filled it in");
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
