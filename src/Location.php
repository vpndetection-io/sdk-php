<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Location as WireLocation;

/**
 * Where the address is, on every answer, with or without a key.
 *
 * The country's properties are set whenever the object is, an empty string where
 * it is not known. The finer ones, from the region down, are a paid plan's: null
 * on an answer without them, which means not in your plan.
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
        /** Region (state or province). On a paid plan. */
        public readonly ?string $region = null,
        /** ISO 3166-2 region code. On a paid plan. */
        public readonly ?string $regionCode = null,
        /** City. On a paid plan. */
        public readonly ?string $city = null,
        /** Postal code. On a paid plan. */
        public readonly ?string $postalCode = null,
        /** Latitude of the city. On a paid plan. */
        public readonly ?float $latitude = null,
        /** Longitude of the city. On a paid plan. */
        public readonly ?float $longitude = null,
        /** Radius in km holding the true location with 67% confidence. On a paid plan. */
        public readonly ?int $accuracyRadius = null,
        /** GeoNames ID of the city. On a paid plan. */
        public readonly ?string $geonameId = null,
        /** US TV market (DMA) code, empty outside the US. On a paid plan. */
        public readonly ?string $dmaCode = null,
        /** The day the range's location last changed. On a paid plan. */
        public readonly ?string $lastChanged = null,
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
            region: $w->getRegion(),
            regionCode: $w->getRegionCode(),
            city: $w->getCity(),
            postalCode: $w->getPostalCode(),
            latitude: $w->getLatitude(),
            longitude: $w->getLongitude(),
            accuracyRadius: $w->getAccuracyRadius(),
            geonameId: $w->getGeonameId(),
            dmaCode: $w->getDmaCode(),
            lastChanged: $w->getLastChanged(),
        );
    }
}
