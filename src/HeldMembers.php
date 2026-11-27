<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * The lookup member `Asn` holds at its plain type until the next major, though Unlimited's
 * answer leaves it out: the AS's `type`, which reads `''`. One served as null is still refused.
 *
 * @internal
 */
final class HeldMembers
{
    /** The member of an `Asn` the answer may leave out, by wire name. */
    public const ASN = 'type';

    /**
     * Whether a member held at its plain type was left out of the answer the result was read
     * from, by its path in a condition (`asn.type`). A result with no wire answer behind it
     * (`raw` empty: a bogon answered locally) carries every member, so none is unserved.
     */
    public static function unserved(Result $result, string $path): bool
    {
        if ($result->raw === [] || $path !== 'asn.' . self::ASN) {
            return false;
        }
        $asn = $result->raw['asn'] ?? null;
        return is_array($asn) && !array_key_exists(self::ASN, $asn);
    }
}
