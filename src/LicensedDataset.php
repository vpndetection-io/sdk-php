<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\LicensedDataset as WireLicensedDataset;

/**
 * One dataset FAMILY your organization is licensed for.
 *
 * A license is held against the family, while a download names one version, so
 * the ids you pass to `download`, `downloadBytes`, `downloadUrl` and `checksums`
 * come from `versions` rather than from here.
 */
final class LicensedDataset
{
    public function __construct(
        /** The family, e.g. `vpn_ip`. What the license is held against. */
        public readonly string $base,
        public readonly string $name,
        public readonly ?string $summary,
        /** What your license permits: `evaluation`, `internal` or `redistribute`. */
        public readonly string $license_type,
        public readonly ?DateTimeImmutable $starts,
        /** Null when the license does not expire. */
        public readonly ?DateTimeImmutable $expires,
        /** False when the license has lapsed; downloads are refused. */
        public readonly bool $inTerm,
        /** `licensed`, `expired` for a term that has ended, or `unlicensed`. */
        public readonly string $standing,
        /**
         * Every published version of this family, newest last.
         *
         * @var list<LicensedVersion>
         */
        public readonly array $versions,
    ) {
    }

    /** @internal */
    public static function fromWire(WireLicensedDataset $w): self
    {
        return new self(
            base: $w->getBase(),
            name: $w->getName(),
            summary: $w->getSummary(),
            license_type: $w->getLicenseType(),
            starts: Dates::immutable($w->getStarts()),
            expires: Dates::immutable($w->getExpires()),
            inTerm: $w->getInTerm(),
            standing: $w->getStanding(),
            versions: array_map(LicensedVersion::fromWire(...), $w->getVersions()),
        );
    }
}
