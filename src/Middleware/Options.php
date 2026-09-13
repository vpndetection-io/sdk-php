<?php

declare(strict_types=1);

namespace VPNDetection\Middleware;

use VPNDetection\Client;

/**
 * How a middleware behaves.
 *
 * Everything is optional except that you almost certainly want an `apiKey`: the free
 * allowance is counted per source address, and a server is one source address.
 */
final class Options
{
    public function __construct(
        /**
         * An existing client to use. Prefer this if you already hold one: two clients
         * mean two caches, and a cache is per instance because two keys can be on
         * different plans and entitled to different fields.
         */
        public readonly ?Client $client = null,
        public readonly ?string $apiKey = null,
        public readonly ?string $baseUrl = null,
        /**
         * Seconds a lookup may hold the request. Defaults to 2.5, a much tighter bound
         * than the client's own 30. Ignored when `client` is given.
         */
        public readonly float $timeout = 2.5,
        /** Retry attempts for a transient failure. Defaults to 0, unlike the client's 2. */
        public readonly int $retries = 0,
        /** @var null|callable(mixed): ?string How the client address is decided. */
        public readonly mixed $ipSelector = null,
        /**
         * What to block on, as an array. Leave it null to only enrich the request and
         * leave the decision to your own code.
         *
         * @var array<mixed>|null
         */
        public readonly ?array $blockCondition = null,
        /**
         * Block when the lookup itself fails. Defaults to false, so our outage does
         * not become yours.
         */
        public readonly bool $failClosed = false,
        /** One of `warn`, `throw` or `ignore`. */
        public readonly string $onMissingField = 'warn',
        /** @var null|callable(mixed): bool Skip classification for this request entirely. */
        public readonly mixed $skip = null,
        /** @var null|callable(string): void Where warnings go. Defaults to error_log. */
        public readonly mixed $onWarn = null,
    ) {
    }
}
