<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Asn as WireAsn;

/** The AS announcing the address, on every keyed answer: `asn` is 0 where none does. */
final class Asn
{
    public function __construct(
        /** The AS number, or 0 for an address no AS announces. */
        public readonly int $asn = 0,
        /** The organization that operates the AS. */
        public readonly string $name = '',
        /** The AS operator's own registrable domain. */
        public readonly string $domain = '',
        /** `isp`, `hosting`, `education`, `government` or `business`. */
        public readonly string $type = '',
        /** The announced prefix covering the address, the most specific when several do. */
        public readonly string $prefix = '',
    ) {
    }

    /** @internal */
    public static function fromWire(WireAsn $w): self
    {
        return new self(
            asn: $w->getAsn(),
            name: $w->getName(),
            domain: $w->getDomain(),
            type: $w->getType(),
            prefix: $w->getPrefix(),
        );
    }
}
