<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\CarrierDetail as WireCarrierDetail;

/**
 * Carrier IP's row for the address.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class CarrierDetail
{
    public function __construct(
        /** The mobile carrier. */
        public readonly ?string $name = null,
        /** Its mobile country code. */
        public readonly ?string $mcc = null,
        /** Its mobile network code. */
        public readonly ?string $mnc = null,
        /** ISO 3166 country code. */
        public readonly ?string $country = null,
        /** `high`, `medium` or `low`. */
        public readonly ?string $confidence = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->name === null && $this->mcc === null && $this->mnc === null
            && $this->country === null && $this->confidence === null;
    }

    /** @internal */
    public static function fromWire(WireCarrierDetail $w): self
    {
        return new self(
            name: $w->getName(),
            mcc: $w->getMcc(),
            mnc: $w->getMnc(),
            country: $w->getCountry(),
            confidence: $w->getConfidence(),
        );
    }
}
