<?php

declare(strict_types=1);

namespace VPNDetection;

use GuzzleHttp\ClientInterface;
use InvalidArgumentException;

/**
 * How a client behaves. Build one with named arguments and pass only what you
 * want to change: `new Options(apiKey: $key, concurrency: 32)`.
 */
final class Options
{
    public function __construct(
        /**
         * Your API key. Omit it entirely to use the free tier, which answers
         * `ip` and `is_vpn` and allows 1000 requests per day per source address.
         */
        public readonly ?string $apiKey = null,
        public readonly string $baseUrl = Client::DEFAULT_BASE_URL,
        /** Pass false to disable caching. */
        public readonly bool $cache = true,
        /** Maximum number of addresses held. */
        public readonly int $cacheMaxSize = 10_000,
        /** How long an answer stays fresh, in seconds. */
        public readonly float $cacheTtlSeconds = 3600.0,
        /** Concurrent batch requests - chunks of up to 1000 addresses - during a batch. */
        public readonly int $concurrency = 8,
        /** Retry attempts for a transient failure. */
        public readonly int $retries = 2,
        /**
         * Seconds one API call may take before it is abandoned, per attempt.
         *
         * **A dataset transfer is deliberately exempt**, keeping only the
         * connect bound: this is the right limit for a lookup and the wrong one
         * for a body that reaches gigabytes.
         */
        public readonly float $timeout = 30.0,
        /**
         * Override the HTTP implementation, mostly for tests.
         *
         * Guzzle rather than PSR-18 because batch lookups need promises, and
         * PSR-18 has no asynchronous half.
         */
        public readonly ?ClientInterface $httpClient = null,
    ) {
        if ($cacheMaxSize < 1) {
            throw new InvalidArgumentException('cacheMaxSize must be at least 1; pass cache: false to disable');
        }
        if ($cacheTtlSeconds <= 0) {
            throw new InvalidArgumentException('cacheTtlSeconds must be positive');
        }
        if ($concurrency < 1) {
            throw new InvalidArgumentException('concurrency must be at least 1');
        }
        if ($retries < 0) {
            throw new InvalidArgumentException('retries cannot be negative');
        }
        if ($timeout < 0) {
            throw new InvalidArgumentException('timeout cannot be negative');
        }
    }
}
