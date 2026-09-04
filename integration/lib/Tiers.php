<?php

declare(strict_types=1);

namespace VPNDetection\Integration;

/**
 * Which plan tiers this run can observe, and the secret each one needs.
 *
 * Loaded by `scripts/run.php` as well as by the tests, so it must not touch the
 * package under test or the autoloader: the runner reads it BEFORE composer has
 * put anything in `vendor/`.
 *
 * A tier is observable only when its secret holds something non-empty. Actions
 * interpolates a secret that does not exist to an EMPTY STRING rather than
 * leaving the variable unset, and a client built with an empty key sends no
 * credential at all, so an empty key runs as a second unauthenticated client and
 * every comparison against it is vacuously true.
 */
final class Tiers
{
    /**
     * Ascending, one rung per plan tier. `widens` is what the rung promises
     * against whichever observable rung sits below it: a paid tier serves
     * strictly more than the tier under it, while a free key and no key at all
     * are the same entitlement reached two ways.
     *
     * Field COUNTS are deliberately absent. Pinning "starter answers seven
     * fields" turns a pricing change into a red SDK build; the relation between
     * the tiers is what the client actually has to keep.
     *
     * @var list<array{tier: string, secret: string|null, widens: bool}>
     */
    public const RUNGS = [
        ['tier' => 'unauth', 'secret' => null, 'widens' => false],
        ['tier' => 'free', 'secret' => 'VPNDETECTION_STAGING_KEY_FREE', 'widens' => false],
        ['tier' => 'starter', 'secret' => 'VPNDETECTION_STAGING_KEY_STARTER', 'widens' => true],
        ['tier' => 'scale', 'secret' => 'VPNDETECTION_STAGING_KEY_SCALE', 'widens' => true],
        ['tier' => 'max', 'secret' => 'VPNDETECTION_STAGING_KEY_MAX', 'widens' => true],
    ];

    /** @return array{tier: string, secret: string|null, widens: bool} */
    public static function unauth(): array
    {
        return self::RUNGS[0];
    }

    /** @return array{tier: string, secret: string|null, widens: bool} */
    public static function max(): array
    {
        return self::RUNGS[count(self::RUNGS) - 1];
    }

    /** @param array{tier: string, secret: string|null, widens: bool} $rung */
    public static function keyFor(array $rung): string
    {
        if ($rung['secret'] === null) {
            return '';
        }
        return trim((string) getenv($rung['secret']));
    }

    /**
     * A reason to skip, or null when the rung can run.
     *
     * @param array{tier: string, secret: string|null, widens: bool} $rung
     */
    public static function skipFor(array $rung): ?string
    {
        if ($rung['secret'] === null || self::keyFor($rung) !== '') {
            return null;
        }
        return "{$rung['secret']} is not set, so the {$rung['tier']} tier cannot be exercised";
    }

    /** @return list<array{tier: string, secret: string|null, widens: bool}> */
    public static function observable(): array
    {
        return array_values(array_filter(self::RUNGS, static fn (array $r): bool => self::skipFor($r) === null));
    }
}
