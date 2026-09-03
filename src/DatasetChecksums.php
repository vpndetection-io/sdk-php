<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\DatasetChecksums as WireDatasetChecksums;

/**
 * The digests published alongside one dataset file.
 *
 * All four are returned rather than one algorithm: which digests a dataset
 * publishes is the API's choice, not ours, and a property is null when that
 * dataset does not publish it.
 */
final class DatasetChecksums
{
    public function __construct(
        public readonly ?string $md5 = null,
        public readonly ?string $sha1 = null,
        public readonly ?string $sha256 = null,
        public readonly ?string $sha512 = null,
    ) {
    }

    /** @internal */
    public static function fromWire(WireDatasetChecksums $w): self
    {
        return new self(
            md5: $w->getMd5(),
            sha1: $w->getSha1(),
            sha256: $w->getSha256(),
            sha512: $w->getSha512(),
        );
    }
}
