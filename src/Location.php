<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Location as WireLocation;

/**
 * Where the address is, on every keyed answer.
 *
 * Every property is set whenever the object is, an empty string where it is not
 * known.
 */
final class Location
{
    public function __construct(
        /** The continent code, e.g. `EU`. */
        public readonly string $continent = '',
        public readonly string $continentName = '',
        /** The ISO 3166-1 alpha-2 country code, e.g. `AT`. */
        public readonly string $country = '',
        public readonly string $countryName = '',
        /** The IANA time zone, e.g. `Europe/Vienna`. */
        public readonly string $timezone = '',
        /** The ISO 4217 currency code, e.g. `EUR`. */
        public readonly string $currencyCode = '',
        public readonly string $currencyName = '',
        public readonly string $currencySymbol = '',
        public readonly string $flagEmoji = '',
        /** The flag's code points, e.g. `U+1F1E6 U+1F1F9`. */
        public readonly string $flagUnicode = '',
    ) {
    }

    /** @internal */
    public static function fromWire(WireLocation $w): self
    {
        return new self(
            continent: $w->getContinent(),
            continentName: $w->getContinentName(),
            country: $w->getCountry(),
            countryName: $w->getCountryName(),
            timezone: $w->getTimezone(),
            currencyCode: $w->getCurrencyCode(),
            currencyName: $w->getCurrencyName(),
            currencySymbol: $w->getCurrencySymbol(),
            flagEmoji: $w->getFlagEmoji(),
            flagUnicode: $w->getFlagUnicode(),
        );
    }
}
