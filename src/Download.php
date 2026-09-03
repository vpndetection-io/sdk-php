<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\Download as WireDownload;

/** One download attempt your organization made. */
final class Download
{
    public function __construct(
        public readonly string $datasetId,
        public readonly string $format,
        /** `ok`, `unauthorized`, `denied`, `expired`, `unknown` or `unavailable`. */
        public readonly string $outcome,
        public readonly ?int $bytes,
        public readonly DateTimeImmutable $created,
    ) {
    }

    /** @internal */
    public static function fromWire(WireDownload $w): self
    {
        return new self(
            datasetId: $w->getDatasetId(),
            format: $w->getFormat(),
            outcome: $w->getOutcome(),
            bytes: $w->getBytes(),
            created: Dates::required($w->getCreated()),
        );
    }
}
