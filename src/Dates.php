<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use DateTimeInterface;

/**
 * @internal
 *
 * The generated models parse `format: date` into a mutable `DateTime`. Every
 * value object here is handed out of a shared cache, so it must not be mutable
 * from underneath a later caller.
 */
final class Dates
{
    public static function immutable(?DateTimeInterface $value): ?DateTimeImmutable
    {
        return $value === null ? null : DateTimeImmutable::createFromInterface($value);
    }

    public static function required(DateTimeInterface $value): DateTimeImmutable
    {
        return DateTimeImmutable::createFromInterface($value);
    }
}
