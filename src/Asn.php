<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Asn as WireAsn;

/**
 * The AS announcing the address, on every answer, with or without a key: `asn` is 0 where none does.
 *
 * `type` excepted, a paid plan's, every member is set whenever the object is. `type` is a plain
 * `string` and never null, but Unlimited's answer leaves it out and it reads `''`, so for `type`
 * `''` can also mean "not in your plan". The answer's own `asn` shows which:
 * `array_key_exists('type', $result->raw['asn'])`.
 */
final class Asn
{
    public function __construct(
        /** The AS number, or 0 for an address no AS announces. */
        public readonly int $asn = 0,
        /** The organization that operates the AS. */
        public readonly string $name = '',
        /** The AS operator's own registrable domain. */
        public readonly string $domain = '',
        /** `isp`, `hosting`, `education`, `government` or `business`. On a paid plan or the trial; `''` where the answer leaves it out. */
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
            type: $w->getType() ?? '',
            prefix: $w->getPrefix(),
            country: $w->getCountry(),
            rpkiStatus: $w->getRpkiStatus(),
        );
    }
}
