<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Company as WireCompany;

/**
 * Who uses the address, from IP Company, on a paid plan's answer.
 *
 * Every property is set whenever the object is, an empty string where no record covers the
 * address.
 */
final class Company
{
    public function __construct(
        /** Who uses the address. */
        public readonly string $name,
        /** Their domain. */
        public readonly string $domain,
        /** What kind of organization: hosting, isp, business, education, government. */
        public readonly ?string $type = null,
        /** ISO 3166 country code. */
        public readonly ?string $country = null,
    ) {
    }

    /** @internal */
    public static function fromWire(WireCompany $w): self
    {
        return new self(
            name: $w->getName(),
            domain: $w->getDomain(),
            type: $w->getType(),
            country: $w->getCountry(),
        );
    }
}
