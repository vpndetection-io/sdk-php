<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\EntitlementPlan as WireEntitlementPlan;

/** The plan behind the key, and the field tier it buys. */
final class EntitlementPlan
{
    public function __construct(
        /** The plan the organization is on, e.g. `max`. */
        public readonly string $key,
        /**
         * The field tier, which decides how much of a lookup answer comes back:
         * `free`, `starter`, `scale` or `max`. What each tier includes is
         * documented on the lookup endpoint rather than repeated here.
         */
        public readonly string $tier,
    ) {
    }

    /** @internal */
    public static function fromWire(WireEntitlementPlan $w): self
    {
        return new self(key: $w->getKey(), tier: $w->getTier());
    }
}
