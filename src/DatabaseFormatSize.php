<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\DatabaseFormatSize as WireDatabaseFormatSize;

/** One published file of a dataset, and how big it is. */
final class DatabaseFormatSize
{
    public function __construct(
        /** `csvgz` or `mmdb`. */
        public readonly string $format,
        /** Size of the published file, or null when it has not been published yet. */
        public readonly ?int $bytes,
    ) {
    }

    /** @internal */
    public static function fromWire(WireDatabaseFormatSize $w): self
    {
        return new self(format: $w->getFormat()->value, bytes: $w->getBytes());
    }
}
