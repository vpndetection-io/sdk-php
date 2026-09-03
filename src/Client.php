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
use VPNDetection\Internal\Api\DatabaseApi as WireDatabaseApi;
use VPNDetection\Internal\Api\LookupApi;
use VPNDetection\Internal\Configuration;
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

    private readonly LookupApi $lookupApi;
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
        $this->transport = new Transport($http, $options->retries);
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
     * Classify many addresses concurrently.
     *
     * Keyed by address rather than positional, so duplicates in the input
     * collapse to a single request and the caller never has to line two lists up.
     * An address that fails carries its error as its value, so one bad entry
     * cannot lose the rest of the answers.
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

        // A generator, so only `concurrency` promises exist at once: creating one
        // starts its transfer, and an eagerly built list would put every address
        // in flight regardless of the limit.
        $pending = (function () use ($unique, $options): iterable {
            foreach ($unique as $ip) {
                yield $ip => $this->lookupAsync($ip, $options);
            }
        })();

        $answers = [];
        Each::ofLimit(
            $pending,
            $concurrency,
            function (Result $value, string $ip) use (&$answers): void {
                $answers[$ip] = $value;
            },
            function (mixed $reason, string $ip) use (&$answers): void {
                $answers[$ip] = Errors::coerce($reason);
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
