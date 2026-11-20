<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\AbuseContact as WireAbuseContact;

/**
 * Where to report abuse from the address, from IP Abuse Contact, on a paid plan's answer.
 *
 * Every property is set whenever the object is, an empty string where no record covers the
 * address.
 */
final class AbuseContact
{
    public function __construct(
        /** Where to report abuse from the address. */
        public readonly string $email,
        /** The contact. */
        public readonly ?string $name = null,
        /** Its phone number. */
        public readonly ?string $phone = null,
        /** Its postal address. */
        public readonly ?string $address = null,
        /** ISO 3166 country code. */
        public readonly ?string $country = null,
        /** The registry block it was derived from. */
        public readonly ?string $network = null,
        /** ARIN reports the contact answered its yearly validation. */
        public readonly ?bool $validated = null,
        /** Since when it has not. */
        public readonly ?string $unvalidatedSince = null,
    ) {
    }

    /** @internal */
    public static function fromWire(WireAbuseContact $w): self
    {
        return new self(
            email: $w->getEmail(),
            name: $w->getName(),
            phone: $w->getPhone(),
            address: $w->getAddress(),
            country: $w->getCountry(),
            network: $w->getNetwork(),
            validated: $w->getValidated(),
            unvalidatedSince: $w->getUnvalidatedSince(),
        );
    }
}
