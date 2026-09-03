<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\LicensedDataset as WireLicensedDataset;

/** A dataset your organization is licensed to download. */
final class LicensedDataset
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly ?string $summary,
        /** Licensed but no longer published. Talk to us. */
        public readonly ?bool $retired,
        /** What your license permits: `evaluation`, `internal` or `redistribute`. */
        public readonly string $redistribution,
        public readonly ?DateTimeImmutable $starts,
        public readonly ?DateTimeImmutable $expires,
        /** False when the license has lapsed; downloads are refused. */
        public readonly bool $inTerm,
        /** @var list<DatasetFormatSize> */
        public readonly array $formats,
    ) {
    }

    /** @internal */
    public static function fromWire(WireLicensedDataset $w): self
    {
        return new self(
            id: $w->getId(),
            name: $w->getName(),
            summary: $w->getSummary(),
            retired: $w->getRetired(),
            redistribution: $w->getRedistribution(),
            starts: Dates::immutable($w->getStarts()),
            expires: Dates::immutable($w->getExpires()),
            inTerm: $w->getInTerm(),
            formats: array_map(DatasetFormatSize::fromWire(...), $w->getFormats()),
        );
    }
}
