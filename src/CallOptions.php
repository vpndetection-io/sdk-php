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
        if ($timeout !== null && $timeout < 0) {
            throw new InvalidArgumentException('timeout cannot be negative');
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
