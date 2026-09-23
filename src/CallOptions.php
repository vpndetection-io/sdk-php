<?php

declare(strict_types=1);

namespace VPNDetection;

use InvalidArgumentException;

/**
 * @internal
 *
 * The per-call options array every method with one shares.
 */
final class CallOptions
{
    /** A round bound, in seconds, under the ~9.22e15 whose milliseconds overflow PHP's int. */
    private const TIMEOUT_CEILING = 9e15;

    /**
     * An option that is accepted and quietly ignored is worse than one that is
     * rejected, so a misspelled key fails loudly instead of leaving the caller
     * to wonder why their override did nothing.
     *
     * @param array<string, mixed> $options
     * @param list<string> $allowed
     */
    public static function assert(array $options, array $allowed): void
    {
        $unknown = array_diff(array_keys($options), $allowed);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf(
                'unknown option(s): %s. Expected any of: %s',
                implode(', ', $unknown),
                implode(', ', $allowed),
            ));
        }
        $timeout = $options['timeout'] ?? null;
        if ($timeout !== null && !is_int($timeout) && !is_float($timeout)) {
            throw new InvalidArgumentException('timeout must be a number of seconds');
        }
        if ($timeout !== null) {
            self::assertTimeout((float) $timeout);
        }
    }

    /**
     * Refuses a timeout no attempt can meet where it is SET, the client's or a
     * call's. Guzzle reads 0 as no bound and anything else as whole
     * milliseconds, and it refuses NaN, infinity and anything under 1 ms only
     * once a request is built, so every call would fail; past about 9.22e15 s
     * the milliseconds no longer fit an int.
     *
     * @internal
     */
    public static function assertTimeout(float $timeout): void
    {
        if ($timeout < 0) {
            throw new InvalidArgumentException('timeout cannot be negative');
        }
        if (is_nan($timeout) || ($timeout > 0 && $timeout < 0.001) || $timeout >= self::TIMEOUT_CEILING) {
            throw new InvalidArgumentException('timeout must be 0, for no bound, or from 0.001 up to 9e15 seconds');
        }
    }

    /**
     * The per-call bound, in seconds, or null to keep the client's.
     *
     * @param array{timeout?: int|float} $options
     */
    public static function timeout(array $options): ?float
    {
        return isset($options['timeout']) ? (float) $options['timeout'] : null;
    }
}
