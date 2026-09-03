<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\ProxyDetail as WireProxyDetail;

/**
 * The shared detail shape for the residential, datacenter and mobile proxy
 * families, measured over a rolling 90 day window.
 *
 * Every property is populated when the object is populated; the whole object is
 * EMPTY when its flag is false.
 */
final class ProxyDetail
{
    public function __construct(
        /** The proxy network, or an empty string where unattributed. */
        public readonly ?string $provider = null,
        /** The earliest date within the window this address was seen in the pool. */
        public readonly ?DateTimeImmutable $firstSeen = null,
        /** The most recent date within the window this address was seen in the pool. */
        public readonly ?DateTimeImmutable $lastSeen = null,
        /** How many times the address was observed in the pool during the window. */
        public readonly ?int $hits = null,
        /**
         * The share of days in the window on which the address was seen, as a
         * percentage. A high value means a stable pool member rather than a
         * one-off sighting.
         */
        public readonly ?int $hitsDaysPct = null,
        /** How many distinct proxy networks this address was seen in. */
        public readonly ?int $providersNum = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->provider === null && $this->firstSeen === null && $this->lastSeen === null
            && $this->hits === null && $this->hitsDaysPct === null && $this->providersNum === null;
    }

    /** @internal */
    public static function fromWire(WireProxyDetail $w): self
    {
        return new self(
            provider: $w->getProvider(),
            firstSeen: Dates::immutable($w->getFirstSeen()),
            lastSeen: Dates::immutable($w->getLastSeen()),
            hits: $w->getHits(),
            hitsDaysPct: $w->getHitsDaysPct(),
            providersNum: $w->getProvidersNum(),
        );
    }
}
