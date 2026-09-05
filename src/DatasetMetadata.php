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
            // Byte counts are free-form by construction: the spec types them as a
            // map of arbitrary values, so they arrive already decoded.
            sample: self::rows($w->getSample() ?? []),
            size: $w->getSize() ?? [],
        );
    }

    /**
     * A sample row has no schema to generate against, so it arrives as the
     * `stdClass` the JSON decoder produced - while this property documents
     * arrays, and every other property on this object hands out arrays. A
     * caller following the docblock wrote `$row['country']` and got a fatal.
     */
    private static function rows(mixed $value): mixed
    {
        if (is_object($value)) {
            $value = get_object_vars($value);
        }
        if (!is_array($value)) {
            return $value;
        }
        return array_map(self::rows(...), $value);
    }
}
