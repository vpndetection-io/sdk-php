<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\DatasetMetadataColumn as WireDatasetMetadataColumn;

/** One column of a dataset, in one format. */
final class DatasetMetadataColumn
{
    public function __construct(
        public readonly string $name,
        public readonly string $type,
        public readonly ?string $description,
    ) {
    }

    /** @internal */
    public static function fromWire(WireDatasetMetadataColumn $w): self
    {
        return new self(name: $w->getName(), type: $w->getType(), description: $w->getDescription());
    }
}
