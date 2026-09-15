<?php

declare(strict_types=1);

namespace VPNDetection;

use Composer\InstalledVersions;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Each;
use GuzzleHttp\Promise\PromiseInterface;
use InvalidArgumentException;
use OutOfBoundsException;
use Psr\Http\Message\ResponseInterface;
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
 * holding different API keys and therefore entitled to different fields.
 */
final class Client
{
    public const DEFAULT_BASE_URL = 'https://api.vpndetection.io';

    /** The most addresses POST /batch takes in one call; a larger batch is sent in chunks of this size. */
    private const BATCH_MAX = 1000;

    private readonly LookupApi $lookupApi;
    private readonly WireEntitlementApi $entitlementApi;
    private readonly Transport $transport;
    private readonly ?Cache $cache;
    private readonly int $concurrency;

    /** The licensed dataset downloads, for keys that carry the `db.download` scope. */
    public readonly DatabaseApi $database;

    public function __construct(Options $options = new Options())
    {
        $config = (new Configuration())
            ->setHost(rtrim($options->baseUrl, '/'))
            ->setUserAgent(self::userAgent());
        if ($options->apiKey !== null && $options->apiKey !== '') {
            $config->setAccessToken($options->apiKey);
        }

        $http = $options->httpClient ?? new GuzzleClient();
        $this->lookupApi = new LookupApi($http, $config);
        $this->entitlementApi = new WireEntitlementApi($http, $config);
        $this->transport = new Transport($http, $options->retries, $options->timeout);
        $this->cache = $options->cache
            ? new Cache($options->cacheMaxSize, $options->cacheTtlSeconds)
            : null;
        $this->concurrency = $options->concurrency;
        $this->database = new DatabaseApi(new WireDatabaseApi($http, $config), $this->transport);
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
     * @param array{retries?: int} $options Per-call overrides.
     * @throws VPNDetectionException
     */
    public function lookup(string $ip, array $options = []): Result
    {
        self::assertOptions($options, ['retries']);
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
     * @param array{retries?: int} $options Per-call overrides.
     * @throws VPNDetectionException
     */
    public function myIp(array $options = []): Result
    {
        self::assertOptions($options, ['retries']);
        $request = $this->lookupApi->lookupMyIpRequest();
        return $this->transport->sendAsync($request, $options['retries'] ?? null)->then(
            function (ResponseInterface $response): Result {
                $body = (string) $response->getBody();
                $status = $response->getStatusCode();
                return Result::fromWire(
                    Transport::toModel($body, LookupResponse::class, $status),
                    Transport::toArray($body, $status),
                );
            },
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
     * Usage counts against the ALLOWANCE WINDOW - the anniversary of the
     * subscription, not the calendar month and not the billing period - and it
     * is the same number a lookup is gated on. It can lag by a few seconds,
     * because requests are counted in memory and flushed in aggregate.
     *
     * Deliberately NOT cached: the whole point is what has been spent, and a
     * cached answer is a wrong one within seconds of the next request.
     *
     * @param array{retries?: int} $options Per-call overrides.
     * @throws VPNDetectionException
     */
    public function myEntitlement(array $options = []): Entitlement
    {
        self::assertOptions($options, ['retries']);
        $request = $this->entitlementApi->myEntitlementRequest();
        return $this->transport->sendAsync($request, $options['retries'] ?? null)->then(
            function (ResponseInterface $response): Entitlement {
                $body = (string) $response->getBody();
                $status = $response->getStatusCode();
                return Entitlement::fromWire(Transport::toModel($body, WireEntitlement::class, $status));
            },
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
     * and a chunk that fails as a whole marks every address in it.
     *
     * @param iterable<string> $ips
     * @param array{retries?: int, concurrency?: int} $options Per-call overrides.
     * @return array<string, Result|VPNDetectionException> Keyed by address, in input order.
     */
    public function lookupBatch(iterable $ips, array $options = []): array
    {
        self::assertOptions($options, ['retries', 'concurrency']);
        $concurrency = $options['concurrency'] ?? $this->concurrency;
        if ($concurrency < 1) {
            throw new InvalidArgumentException('concurrency must be at least 1');
        }

        $seen = [];
        foreach ($ips as $ip) {
            $seen[$ip] = true;
        }
        $unique = array_map(strval(...), array_keys($seen));

        $answers = [];
        $pending = [];
        foreach ($unique as $ip) {
            if (Bogon::isBogon($ip)) {
                $answers[$ip] = Bogon::result($ip);
                continue;
            }
            $hit = $this->cache?->get($ip);
            if ($hit !== null) {
                $answers[$ip] = $hit;
                continue;
            }
            $pending[] = $ip;
        }

        // A generator, so only `concurrency` chunks are in flight at once: creating
        // a promise starts its transfer, and an eagerly built list would put every
        // chunk in flight regardless of the limit.
        $chunks = (function () use ($pending, $options): iterable {
            foreach (array_chunk($pending, self::BATCH_MAX) as $chunk) {
                yield $this->lookupChunkAsync($chunk, $options);
            }
        })();
        Each::ofLimit(
            $chunks,
            $concurrency,
            function (array $value) use (&$answers): void {
                foreach ($value as $ip => $answer) {
                    $answers[$ip] = $answer;
                }
            },
        )->wait();

        // Reinstated in input order: the callbacks fire in completion order, and
        // a caller iterating the result should see what they passed in.
        $ordered = [];
        foreach ($unique as $ip) {
            $ordered[$ip] = $answers[$ip];
        }
        return $ordered;
    }

    /**
     * One POST /batch, mapped back onto the addresses it was asked about. A
     * chunk-level failure - the call refused, the transport failing, the retries
     * exhausted - becomes every address's error, exactly as it would have been
     * had each been looked up alone. Never rejects: the failure is the value.
     *
     * @param list<string> $chunk
     * @param array{retries?: int, concurrency?: int} $options
     * @return PromiseInterface Resolving to array<string, Result|VPNDetectionException>.
     */
    private function lookupChunkAsync(array $chunk, array $options): PromiseInterface
    {
        $request = $this->lookupApi->lookupBatchRequest(new BatchLookupRequest(['ips' => $chunk]));
        return $this->transport->sendAsync($request, $options['retries'] ?? null)->then(
            function (ResponseInterface $response) use ($chunk): array {
                $status = $response->getStatusCode();
                $body = Transport::toArray((string) $response->getBody(), $status);
                $results = is_array($body['results'] ?? null) ? $body['results'] : [];
                $errors = is_array($body['errors'] ?? null) ? $body['errors'] : [];
                $answers = [];
                foreach ($chunk as $ip) {
                    if (isset($results[$ip]) && is_array($results[$ip])) {
                        $raw = $results[$ip];
                        $encoded = json_encode($raw, JSON_THROW_ON_ERROR);
                        $result = Result::fromWire(
                            Transport::toModel($encoded, LookupResponse::class, $status),
                            $raw,
                        );
                        $this->cache?->set($ip, $result);
                        $answers[$ip] = $result;
                    } elseif (isset($errors[$ip]) && is_array($errors[$ip])) {
                        $answers[$ip] = Errors::fromEntry(
                            (int) ($errors[$ip]['status'] ?? 500),
                            (string) ($errors[$ip]['error'] ?? ''),
                        );
                    } else {
                        $answers[$ip] = new VPNDetectionException(
                            ErrorKind::ServerError, "the batch answer did not include {$ip}", 200,
                        );
                    }
                }
                return $answers;
            },
            function (mixed $reason) use ($chunk): array {
                $error = Errors::coerce($reason);
                $answers = [];
                foreach ($chunk as $ip) {
                    $answers[$ip] = $error;
                }
                return $answers;
            },
        );
    }

    /** @param array{retries?: int, concurrency?: int} $options */
    private function lookupAsync(string $ip, array $options): PromiseInterface
    {
        if (Bogon::isBogon($ip)) {
            return Create::promiseFor(Bogon::result($ip));
        }
        $hit = $this->cache?->get($ip);
        if ($hit !== null) {
            return Create::promiseFor($hit);
        }
        $request = $this->lookupApi->lookupIpRequest($ip);
        return $this->transport->sendAsync($request, $options['retries'] ?? null)->then(
            function (ResponseInterface $response) use ($ip): Result {
                $body = (string) $response->getBody();
                $status = $response->getStatusCode();
                $result = Result::fromWire(
                    Transport::toModel($body, LookupResponse::class, $status),
                    Transport::toArray($body, $status),
                );
                $this->cache?->set($ip, $result);
                return $result;
            },
        );
    }

    /**
     * An option that is accepted and quietly ignored is worse than one that is
     * rejected, so a misspelled key fails loudly instead of leaving the caller
     * to wonder why their override did nothing.
     *
     * @param array<string, mixed> $options
     * @param list<string> $allowed
     */
    private static function assertOptions(array $options, array $allowed): void
    {
        $unknown = array_diff(array_keys($options), $allowed);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf(
                'unknown option(s): %s. Expected any of: %s',
                implode(', ', $unknown),
                implode(', ', $allowed),
            ));
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
            return InstalledVersions::getPrettyVersion('vpndetection/vpndetection') ?? 'dev';
        } catch (OutOfBoundsException) {
            return 'dev';
        }
    }
}
