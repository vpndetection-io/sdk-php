<?php

declare(strict_types=1);

namespace VPNDetection;

use Composer\InstalledVersions;
use Exception;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Each;
use GuzzleHttp\Promise\PromiseInterface;
use OutOfBoundsException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TypeError;
use ValueError;
use VPNDetection\Internal\Api\EntitlementApi as WireEntitlementApi;
use VPNDetection\Internal\Api\DatabaseApi as WireDatabaseApi;
use VPNDetection\Internal\Api\LookupApi;
use VPNDetection\Internal\Configuration;
use VPNDetection\Internal\Model\BatchLookupRequest;
use VPNDetection\Internal\Model\Entitlement as WireEntitlement;
use VPNDetection\Internal\Model\LookupResponse;

/**
 * A client for the VPNDetection API.
 *
 * The cache is per instance, so an answer is never shared between two clients
 * holding different API keys and therefore entitled to different fields. A
 * PSR-16 store given as `cacheStore` is shared, and keys its entries by the API
 * key as well.
 */
final class Client
{
    public const DEFAULT_BASE_URL = 'https://api.vpndetection.io';

    /** The most addresses POST /batch takes in one call; a larger batch is sent in chunks of this size. */
    private const BATCH_MAX = 1000;

    private readonly LookupApi $lookupApi;
    private readonly WireEntitlementApi $entitlementApi;
    private readonly Transport $transport;
    private readonly ?AnswerCache $cache;
    private readonly int $concurrency;

    /** The licensed dataset downloads, for keys that carry the `db.download` scope. */
    public readonly DatabaseApi $database;

    /**
     * Sign a person in on their own machine with the OAuth device flow, so a
     * program can be handed one of their API keys instead of asking for it.
     */
    public readonly OauthApi $oauth;

    public function __construct(Options $options = new Options())
    {
        $config = (new Configuration())
            ->setHost(rtrim($options->baseUrl, '/'))
            ->setUserAgent(self::userAgent());
        // Set only when there is one: `Authorization: Bearer ` with nothing
        // after it reads as a wrong key rather than as no key, and a key of
        // blanks alone sent just that until it was trimmed (4.11.0).
        $apiKey = trim($options->apiKey ?? '');
        if ($apiKey !== '') {
            $config->setAccessToken($apiKey);
        }

        $http = $options->httpClient ?? new GuzzleClient();
        $this->lookupApi = new LookupApi($http, $config);
        $this->entitlementApi = new WireEntitlementApi($http, $config);
        $this->transport = new Transport($http, $options->retries, $options->timeout);
        $this->cache = match (true) {
            !$options->cache => null,
            $options->cacheStore !== null => new StoreCache(
                $options->cacheStore,
                $options->cacheTtlSeconds,
                $apiKey . "\0" . rtrim($options->baseUrl, '/'),
            ),
            default => new Cache($options->cacheMaxSize, $options->cacheTtlSeconds),
        };
        $this->concurrency = $options->concurrency;
        $this->database = new DatabaseApi(new WireDatabaseApi($http, $config), $this->transport, self::userAgent());
        $this->oauth = new OauthApi($this->transport, rtrim($options->baseUrl, '/'), self::userAgent());
    }

    /**
     * Whether an address is private, loopback, link-local, documentation,
     * multicast or otherwise not routable, including the IPv6 equivalents and
     * the 6to4 and Teredo ranges.
     *
     * These are the addresses `lookup` answers locally. Exposed here so the check
     * is reachable from the client you already hold; `Bogon::isBogon` is the same
     * function without one.
     */
    public function isBogon(string $ip): bool
    {
        return Bogon::isBogon($ip);
    }

    /**
     * Classify one address.
     *
     * A bogon is answered locally and never reaches the network. Everything else
     * is served, then cached for this instance.
     *
     * `userAgent` is the `User-Agent` of the request you are deciding on: with
     * every field the answer then carries `userAgent`, whose bot it names and
     * whether this address bears that out. An empty one is none. The answer is
     * cached apart from the address's plain answer and from another agent's.
     *
     * @param array{retries?: int, timeout?: float, userAgent?: ?string} $options Per-call overrides.
     * @throws VPNDetectionException
     */
    public function lookup(string $ip, array $options = []): Result
    {
        CallOptions::assert($options, ['retries', 'timeout', 'userAgent']);
        return $this->lookupAsync($ip, $options)->wait();
    }

    /**
     * Classify the address this client is calling from.
     *
     * The same answer `lookup` would give for that address, at the same cost
     * against your allowance. The address is the one our edge observed, so a
     * call made through a proxy or a VPN reports the exit it left through -
     * usually the point of asking.
     *
     * Deliberately NOT cached. The cache is keyed by address, and which address
     * this is IS the question: a machine that moves between networks would
     * otherwise be told where it used to be.
     *
     * @param array{retries?: int, timeout?: float, userAgent?: ?string} $options Per-call overrides;
     *     `userAgent` as `lookup` takes it.
     * @throws VPNDetectionException
     */
    public function myIp(array $options = []): Result
    {
        CallOptions::assert($options, ['retries', 'timeout', 'userAgent']);
        $request = self::withUserAgent($this->lookupApi->lookupMyIpRequest(), CallOptions::userAgent($options));
        return $this->transport->sendAsync(
            $request, $options['retries'] ?? null, CallOptions::timeout($options),
            read: self::result(...),
        )->wait();
    }

    /**
     * What this client's key is entitled to, and how much of it has been used.
     *
     * Named for what it answers rather than `me`, which sits one letter from
     * `myIp` and means something quite different: one is which address you are
     * calling FROM, the other is what the key you are calling WITH may spend.
     *
     * Unlike a lookup there is no useful unauthenticated answer, so a client
     * built without an API key gets an unauthorized error rather than a partial
     * one.
     *
     * Usage counts against the ALLOWANCE WINDOW - on a paid plan the
     * anniversary of the subscription, not the calendar month and not the
     * billing period, and on the free plan the UTC day - and it is the same
     * number a lookup is gated on. It can lag by a few seconds, because
     * requests are counted in memory and flushed in aggregate.
     *
     * Deliberately NOT cached: the whole point is what has been spent, and a
     * cached answer is a wrong one within seconds of the next request.
     *
     * @param array{retries?: int, timeout?: float} $options Per-call overrides.
     * @throws VPNDetectionException
     */
    public function myEntitlement(array $options = []): Entitlement
    {
        CallOptions::assert($options, ['retries', 'timeout']);
        $request = $this->entitlementApi->myEntitlementRequest();
        return $this->transport->sendAsync(
            $request, $options['retries'] ?? null, CallOptions::timeout($options),
            read: static fn (ResponseInterface $r): Entitlement => Entitlement::fromWire(
                Transport::toModel((string) $r->getBody(), WireEntitlement::class, $r->getStatusCode()),
            ),
        )->wait();
    }

    /**
     * Classify many addresses in as few requests as possible.
     *
     * Bogons are answered locally and cached answers are reused; everything else
     * goes to the batch endpoint in chunks of up to 1000 addresses, with at most
     * `concurrency` chunks in flight. Keyed by address rather than positional, so
     * duplicates in the input collapse to a single entry and the caller never has
     * to line two lists up. An address that fails carries its error as its value,
     * so one bad entry cannot lose the rest of the answers: the API reports a
     * per-entry failure with the status the single lookup would have answered,
     * and a chunk that fails as a whole marks every address in it. The batch
     * endpoint needs a paid plan: without a key every address in a request of
     * two or more carries an `Unauthorized` error, and a free-plan key's request
     * of two or more a `BadRequest` (HTTP 402). A request of one address is
     * answered as its lookup would be.
     *
     * `userAgents` maps an address, as you pass it in `$ips`, to the `User-Agent`
     * of the request you are deciding on, as `lookup` takes one; an address
     * without one, or with an empty one, is looked up plainly.
     *
     * @param iterable<string> $ips
     * @param array{retries?: int, concurrency?: int, timeout?: float, userAgents?: array<string, ?string>} $options
     *     Per-call overrides.
     * @return array<string, Result|VPNDetectionException> Keyed by address, in input order.
     */
    public function lookupBatch(iterable $ips, array $options = []): array
    {
        CallOptions::assert($options, ['retries', 'concurrency', 'timeout', 'userAgents']);
        $concurrency = $options['concurrency'] ?? $this->concurrency;
        $agents = $options['userAgents'] ?? [];

        $seen = [];
        foreach ($ips as $ip) {
            $seen[$ip] = true;
        }
        // An IPv4-mapped address is looked up as the IPv4 address it carries, and its
        // answer keyed as the caller passed it. Each pair of address and user agent
        // is asked once: an answer with an agent is not the address's plain one.
        $asked = array_map(strval(...), array_keys($seen));
        $keys = [];
        $pairs = [];
        foreach ($asked as $i => $ip) {
            $wire = Bogon::unmapped($ip);
            $agent = $agents[$ip] ?? '';
            $keys[$i] = self::cacheKey($wire, $agent);
            $pairs[$keys[$i]] ??= [$wire, $agent];
        }

        $answers = [];
        $routable = [];
        foreach ($pairs as $key => [$wire, $agent]) {
            if (Bogon::isBogon($wire)) {
                $answers[$key] = Bogon::result($wire);
                continue;
            }
            $routable[(string) $key] = [$wire, $agent];
        }
        // One read for the whole batch, which a store across the network needs.
        $hits = $this->cache?->getMany(array_map(strval(...), array_keys($routable))) ?? [];
        // A request names an address once, so one asked with two user agents
        // goes in a second round of chunks.
        $rounds = [];
        $asks = [];
        foreach ($routable as $key => [$wire, $agent]) {
            if (isset($hits[$key])) {
                $answers[$key] = $hits[$key];
                continue;
            }
            $asks[$wire] = ($asks[$wire] ?? -1) + 1;
            $rounds[$asks[$wire]][] = [$wire, $agent];
        }

        // A generator, so only `concurrency` chunks are in flight at once: creating
        // a promise starts its transfer, and an eagerly built list would put every
        // chunk in flight regardless of the limit.
        $chunks = (function () use ($rounds, $options): iterable {
            foreach ($rounds as $pending) {
                foreach (array_chunk($pending, self::BATCH_MAX) as $chunk) {
                    yield $this->lookupChunkAsync($chunk, $options);
                }
            }
        })();
        Each::ofLimit(
            $chunks,
            $concurrency,
            function (array $value) use (&$answers): void {
                foreach ($value as $key => $answer) {
                    $answers[$key] = $answer;
                }
            },
        )->wait();

        // Reinstated in input order: the callbacks fire in completion order, and
        // a caller iterating the result should see what they passed in.
        $ordered = [];
        foreach ($asked as $i => $ip) {
            $ordered[$ip] = $answers[$keys[$i]];
        }
        return $ordered;
    }

    /**
     * One POST /batch, mapped back onto the addresses it was asked about. A
     * chunk-level failure - the call refused, the transport failing, an answer
     * it cannot read, the retries exhausted - becomes every address's error,
     * exactly as it would have been had each been looked up alone. Never
     * rejects: the failure is the value.
     *
     * `user_agents` is sent only when an address of this chunk carries one, keyed
     * by the address exactly as `ips` sends it: the API matches it by string.
     *
     * @param list<array{0: string, 1: string}> $chunk Each address with its user agent, '' for none.
     * @param array{retries?: int, concurrency?: int, timeout?: float} $options
     * @return PromiseInterface Resolving to array<string, Result|VPNDetectionException>, keyed by `cacheKey`.
     */
    private function lookupChunkAsync(array $chunk, array $options): PromiseInterface
    {
        $ips = array_column($chunk, 0);
        $body = ['ips' => $ips];
        foreach ($chunk as [$ip, $agent]) {
            if ($agent !== '') {
                $body['user_agents'][$ip] = $agent;
            }
        }
        $request = $this->lookupApi->lookupBatchRequest(new BatchLookupRequest($body));
        return $this->transport->sendAsync(
            $request, $options['retries'] ?? null, CallOptions::timeout($options),
            read: static function (ResponseInterface $r) use ($chunk, $ips): array {
                $byAddress = self::chunkAnswers($r, $ips);
                $answers = [];
                foreach ($chunk as [$ip, $agent]) {
                    $answers[self::cacheKey($ip, $agent)] = $byAddress[$ip];
                }
                return $answers;
            },
        )->then(
            function (array $answers): array {
                $this->cache?->setMany(array_filter(
                    $answers,
                    static fn (Result|VPNDetectionException $answer): bool => $answer instanceof Result,
                ));
                return $answers;
            },
            function (mixed $reason) use ($chunk): array {
                $error = Errors::coerce($reason);
                $answers = [];
                foreach ($chunk as [$ip, $agent]) {
                    $answers[self::cacheKey($ip, $agent)] = $error;
                }
                return $answers;
            },
        );
    }

    /** @param array{retries?: int, timeout?: float, userAgent?: ?string} $options */
    private function lookupAsync(string $ip, array $options): PromiseInterface
    {
        // Judged, sent and cached as the IPv4 address an IPv4-mapped one carries.
        $ip = Bogon::unmapped($ip);
        if (Bogon::isBogon($ip)) {
            return Create::promiseFor(Bogon::result($ip));
        }
        $agent = CallOptions::userAgent($options);
        $key = self::cacheKey($ip, $agent);
        $hit = $this->cache?->get($key);
        if ($hit !== null) {
            return Create::promiseFor($hit);
        }
        $request = self::withUserAgent($this->lookupApi->lookupIpRequest($ip), $agent);
        return $this->transport->sendAsync(
            $request, $options['retries'] ?? null, CallOptions::timeout($options),
            read: self::result(...),
        )->then(
            function (Result $result) use ($key): Result {
                $this->cache?->set($key, $result);
                return $result;
            },
        );
    }

    /**
     * Where an answer is cached: the address alone for a plain lookup, and the
     * address with the user agent for one that sent an agent, whose answer
     * carries a verdict the plain one lacks.
     */
    private static function cacheKey(string $ip, string $agent): string
    {
        return $agent === '' ? $ip : "{$ip}\0{$agent}";
    }

    /**
     * The query parameter added here rather than through the generated builder,
     * which refuses an agent past the spec's 1024 characters: the API cuts a
     * longer one and answers, so it is sent. Percent-encoded whole, so a `+` in an
     * agent (`+http://www.google.com/bot.html`) is not read back as a space.
     */
    private static function withUserAgent(RequestInterface $request, string $agent): RequestInterface
    {
        if ($agent === '') {
            return $request;
        }
        $uri = $request->getUri();
        $param = 'user_agent=' . rawurlencode($agent);
        return $request->withUri($uri->withQuery($uri->getQuery() === '' ? $param : "{$uri->getQuery()}&{$param}"));
    }

    private static function result(ResponseInterface $response): Result
    {
        $body = (string) $response->getBody();
        $status = $response->getStatusCode();
        return Result::fromWire(
            Transport::toModel($body, LookupResponse::class, $status),
            Transport::toArray($body, $status),
        );
    }

    /**
     * A batch answer must carry both of its members: without them it is no answer
     * for any address, and is retried like an outage. One entry that cannot be read
     * is that address's error alone, as a per-entry failure from the API is.
     *
     * @param list<string> $chunk
     * @return array<string, Result|VPNDetectionException>
     */
    private static function chunkAnswers(ResponseInterface $response, array $chunk): array
    {
        $status = $response->getStatusCode();
        $text = (string) $response->getBody();
        $body = Transport::toArray($text, $status);
        $results = $body['results'] ?? null;
        $errors = $body['errors'] ?? null;
        if (!is_array($results) || !is_array($errors)) {
            throw Errors::malformed('expected the results and errors of a batch', $status);
        }
        // Each entry is checked as decoded with objects, where `{}` is not `[]`.
        $entries = (array) json_decode($text, false)->results;
        $answers = [];
        foreach ($chunk as $ip) {
            if (array_key_exists($ip, $results)) {
                $answers[$ip] = self::entryResult($entries[$ip], $results[$ip], $status);
            } elseif (isset($errors[$ip]) && is_array($errors[$ip])) {
                $answers[$ip] = Errors::fromEntry(
                    (int) ($errors[$ip]['status'] ?? 500),
                    (string) ($errors[$ip]['error'] ?? ''),
                );
            } else {
                $answers[$ip] = new VPNDetectionException(
                    ErrorKind::ServerError, "the batch answer did not include {$ip}", $status,
                );
            }
        }
        return $answers;
    }

    private static function entryResult(mixed $entry, mixed $raw, int $status): Result|VPNDetectionException
    {
        try {
            return Result::fromWire(Transport::fromDecoded($entry, LookupResponse::class, $status), $raw);
        } catch (VPNDetectionException $e) {
            return $e;
        } catch (Exception | TypeError | ValueError $e) {
            return Errors::malformed($e->getMessage(), $status, $e);
        }
    }

    private static function userAgent(): string
    {
        static $agent = null;
        return $agent ??= sprintf('vpndetection-php/%s php/%s', self::version(), PHP_VERSION);
    }

    // Read from composer's own install metadata rather than a constant, which
    // would be one more thing to remember to bump alongside the release tag.
    private static function version(): string
    {
        if (!class_exists(InstalledVersions::class)) {
            return 'dev';
        }
        try {
            return self::bare(InstalledVersions::getPrettyVersion('vpndetection/vpndetection') ?? 'dev');
        } catch (OutOfBoundsException) {
            return 'dev';
        }
    }

    // Composer names an installed release by its tag, v4.15.0, where every other
    // SDK's User-Agent carries the bare version.
    private static function bare(string $version): string
    {
        return (string) preg_replace('/^v(?=\d)/', '', $version);
    }
}
