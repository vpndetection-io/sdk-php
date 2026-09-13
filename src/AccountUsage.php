<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\AccountUsage as WireAccountUsage;

/** Consumption against the plan's allowance, in the current window. */
final class AccountUsage
{
    public function __construct(
        /**
         * Requests counted in the current window. The same number a lookup is
         * gated on, and it can lag by a few seconds.
         */
        public readonly int $requests,
        /** What the plan includes. Zero on a plan that includes none. */
        public readonly int $quota,
        /**
         * Where we stop serving. Null means NEVER, which is the normal state of
         * an uncapped paid plan and is not the same as zero. Above the quota and
         * below this, requests are served and billed as overage.
         */
        public readonly ?int $hardLimit,
        /** When the current allowance period began. */
        public readonly DateTimeImmutable $windowStart,
        /** When the allowance next resets. */
        public readonly DateTimeImmutable $windowEnd,
    ) {
    }

    /** @internal */
    public static function fromWire(WireAccountUsage $w): self
    {
        return new self(
            requests: $w->getRequests(),
            quota: $w->getQuota(),
            hardLimit: $w->getHardLimit(),
            windowStart: Dates::required($w->getWindowStart()),
            windowEnd: Dates::required($w->getWindowEnd()),
        );
    }
}
