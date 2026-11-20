<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\SatelliteDetail as WireSatelliteDetail;

/**
 * Satellite IP's row for the address.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class SatelliteDetail
{
    public function __construct(
        /** The operator's ID in Satellite IP Provider. */
        public readonly ?string $provider = null,
        /** The operator's name. */
        public readonly ?string $providerName = null,
        /** The orbit: `leo`, `meo` or `geo`. */
        public readonly ?string $orbit = null,
        /** Who the space serves, such as consumer or maritime. */
        public readonly ?string $segment = null,
        /** ISO 3166 country code. */
        public readonly ?string $country = null,
        /** The AS the operator announces it from. */
        public readonly ?int $asn = null,
        /** `high`, `medium` or `low`. */
        public readonly ?string $confidence = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->provider === null && $this->providerName === null && $this->orbit === null
            && $this->segment === null && $this->country === null && $this->asn === null
            && $this->confidence === null;
    }

    /** @internal */
    public static function fromWire(WireSatelliteDetail $w): self
    {
        return new self(
            provider: $w->getProvider(),
            providerName: $w->getProviderName(),
            orbit: $w->getOrbit(),
            segment: $w->getSegment(),
            country: $w->getCountry(),
            asn: $w->getAsn(),
            confidence: $w->getConfidence(),
        );
    }
}
