<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\AccountMe as WireAccountMe;

/**
 * What an API key is entitled to, and how much of it has been used.
 *
 * Everything here describes the key that asked: there is no way to enquire
 * about another organization, because the credential IS the question.
 */
final class Account
{
    public function __construct(
        /** The organization the key belongs to. */
        public readonly string $orgId,
        public readonly AccountApikey $apikey,
        public readonly AccountPlan $plan,
        public readonly AccountUsage $usage,
    ) {
    }

    /** @internal */
    public static function fromWire(WireAccountMe $w): self
    {
        return new self(
            orgId: $w->getOrgId(),
            apikey: AccountApikey::fromWire($w->getApikey()),
            plan: AccountPlan::fromWire($w->getPlan()),
            usage: AccountUsage::fromWire($w->getUsage()),
        );
    }
}
