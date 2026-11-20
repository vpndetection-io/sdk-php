<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Asn as WireAsn;

/** The AS announcing the address, on every answer, with or without a key: `asn` is 0 where none does. */
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
        /** The country the AS's registry assigned it to. Null where the answer leaves it out. */
        public readonly ?string $country = null,
        /** The announcement's RPKI status: `valid`, `invalid` or `not_found`. Null where the answer leaves it out. */
        public readonly ?string $rpkiStatus = null,
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
            country: $w->getCountry(),
            rpkiStatus: $w->getRpkiStatus(),
        );
    }
}
