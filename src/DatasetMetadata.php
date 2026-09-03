<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\DatasetMetadata as WireDatasetMetadata;

/**
 * What is inside one dataset.
 *
 * Poll this to decide whether today's build is worth fetching: `updated` and
 * `entries` come back without downloading anything.
 */
final class DatasetMetadata
{
    public function __construct(
        public readonly string $id,
        /** How often a new build is published. */
        public readonly ?string $updateFreq,
        public readonly DateTimeImmutable $updated,
        /** Row count in the current build. */
        public readonly int $entries,
        /**
         * Columns, keyed by format.
         *
         * @var array<string, list<DatasetMetadataColumn>>
         */
        public readonly array $schema,
        /**
         * A few real rows, keyed by format.
         *
         * @var array<string, list<array<string, mixed>>>
         */
        public readonly array $sample,
        /**
         * Bytes per format.
         *
         * @var array<string, int>
         */
        public readonly array $size,
    ) {
    }

    /** @internal */
    public static function fromWire(WireDatasetMetadata $w): self
    {
        $schema = [];
        foreach ($w->getSchema() as $format => $columns) {
            $schema[$format] = array_map(DatasetMetadataColumn::fromWire(...), $columns);
        }
        return new self(
            id: $w->getId(),
            updateFreq: $w->getUpdateFreq(),
            updated: Dates::required($w->getUpdated()),
            entries: $w->getEntries(),
            schema: $schema,
            // Rows and byte counts are free-form by construction: the spec types
            // them as maps of arbitrary objects, so they arrive already decoded.
            sample: $w->getSample() ?? [],
            size: $w->getSize() ?? [],
        );
    }
}
