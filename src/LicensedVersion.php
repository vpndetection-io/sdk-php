<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\LicensedVersion as WireLicensedVersion;

/** One published version of a licensed dataset family. */
final class LicensedVersion
{
    public function __construct(
        /** The versioned dataset id, e.g. `vpn_ip_v1`. This is what a download takes. */
        public readonly string $id,
        public readonly int $version,
        public readonly ?string $summary,
        /**
         * The files this version is published as, and how big each one is.
         *
         * @var list<DatasetFormatSize>
         */
        public readonly array $formats,
        /**
         * The formats an evaluation sample is published in, if any.
         *
         * @var list<string>
         */
        public readonly array $sampleFormats,
    ) {
    }

    /** @internal */
    public static function fromWire(WireLicensedVersion $w): self
    {
        return new self(
            id: $w->getId(),
            version: $w->getVersion(),
            summary: $w->getSummary(),
            formats: array_map(DatasetFormatSize::fromWire(...), $w->getFormats()),
            sampleFormats: $w->getSampleFormats() ?? [],
        );
    }
}
