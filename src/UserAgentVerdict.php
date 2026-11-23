<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\UserAgentVerdict as WireUserAgentVerdict;

/**
 * Whose bot the user agent sent with a lookup names, and whether this address
 * bears that out. Answered only with every field, and only when the lookup sent
 * one.
 */
final class UserAgentVerdict
{
    public function __construct(
        /** The agent the user agent names, such as `Googlebot` or `Chrome`; `Unknown` where it names none. */
        public readonly ?string $agent = null,
        /**
         * What kind of client the user agent says it is: `browser`, `inapp`,
         * `automation`, `bot`, `ai-bot`, `http-client` or `unknown`.
         */
        public readonly ?string $kind = null,
        /**
         * `verified`, `spoofed`, `unverifiable` or `not_bot`, kept as served so a
         * value the API adds later is read rather than refused.
         */
        public readonly ?string $verdict = null,
    ) {
    }

    /** True for a bogon's, which is answered locally and so judges no agent. */
    public function isEmpty(): bool
    {
        return $this->agent === null && $this->kind === null && $this->verdict === null;
    }

    /** @internal */
    public static function fromWire(WireUserAgentVerdict $w): self
    {
        return new self(agent: $w->getAgent(), kind: $w->getKind(), verdict: $w->getVerdict());
    }
}
