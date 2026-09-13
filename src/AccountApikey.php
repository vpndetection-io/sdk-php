<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\AccountApikey as WireAccountApikey;

/**
 * The credential itself.
 *
 * The key is never echoed back - only its id, which is what the console shows
 * and what you can act on.
 */
final class AccountApikey
{
    public function __construct(
        public readonly string $id,
        /** Null for a key with no end date, which is the normal case. */
        public readonly ?DateTimeImmutable $expires,
        /**
         * The source addresses this key may be used from. EMPTY means
         * unrestricted, never "deny all".
         *
         * @var list<string>
         */
        public readonly array $allowedCidrs,
    ) {
    }

    /** @internal */
    public static function fromWire(WireAccountApikey $w): self
    {
        return new self(
            id: $w->getId(),
            expires: Dates::immutable($w->getExpires()),
            allowedCidrs: array_values($w->getAllowedCidrs()),
        );
    }
}
