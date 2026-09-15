<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\Entitlement as WireEntitlement;

/**
 * What an API key is entitled to, and how much of it has been used.
 *
 * Everything here describes the key that asked: there is no way to enquire
 * about another organization, because the credential IS the question.
 */
final class Entitlement
{
    public function __construct(
        /** The organization the key belongs to. */
        public readonly string $orgId,
        public readonly EntitlementApikey $apikey,
        public readonly EntitlementPlan $plan,
        public readonly EntitlementUsage $usage,
    ) {
    }

    /** @internal */
    public static function fromWire(WireEntitlement $w): self
    {
        return new self(
            orgId: $w->getOrgId(),
            apikey: EntitlementApikey::fromWire($w->getApikey()),
            plan: EntitlementPlan::fromWire($w->getPlan()),
            usage: EntitlementUsage::fromWire($w->getUsage()),
        );
    }
}
