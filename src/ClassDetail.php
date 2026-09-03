<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\ClassDetail as WireClassDetail;

/**
 * The shared detail shape for the hosting, relay, tor and cdn datasets.
 *
 * Every property is populated when the object is populated; the whole object is
 * EMPTY when its flag is false.
 */
final class ClassDetail
{
    public function __construct(
        /** The provider, or an empty string where the dataset has none. */
        public readonly ?string $provider = null,
        /** How strongly the classification is supported. */
        public readonly ?string $confidence = null,
        /** The most recent date this address was observed in this dataset. */
        public readonly ?DateTimeImmutable $lastSeen = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->provider === null && $this->confidence === null && $this->lastSeen === null;
    }

    /** @internal */
    public static function fromWire(WireClassDetail $w): self
    {
        return new self(
            provider: $w->getProvider(),
            confidence: $w->getConfidence(),
            lastSeen: Dates::immutable($w->getLastSeen()),
        );
    }
}
