<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\BotDetail as WireBotDetail;

/**
 * Bot IP's row: whose bot uses the address, the bots it serves or claimed to be,
 * what they do, and how that is known.
 *
 * Every property is populated when the object is populated; the whole object is
 * EMPTY when `isBot` is false.
 */
final class BotDetail
{
    public function __construct(
        /** The bot operator's ID, empty where no operator is known. */
        public readonly ?string $provider = null,
        /** The operator's name, empty where no operator is known. */
        public readonly ?string $providerName = null,
        /**
         * The bots the address serves, as their user agents name them (`Googlebot`,
         * `GPTBot`); for an address that is not verified, the bots it claimed to be.
         * One address can serve several, and `[]` means none is named.
         *
         * @var list<string>|null
         */
        public readonly ?array $agents = null,
        /**
         * What those bots do: `search_engine`, `ai_training`, `ai_search`,
         * `ai_assistant`, `ai_agent`, `seo`, `ads`, `preview`, `feed`, `monitoring`,
         * `archiver`, `scanner`, `link_security`, `webhook` or `other`; `[]` where
         * unknown.
         *
         * @var list<string>|null
         */
        public readonly ?array $categories = null,
        /** Whether the operator vouches for the address, so the bots in `agents` really are its. */
        public readonly ?bool $verified = null,
        /**
         * `verified` (the operator vouches for the address), `declared` (it names
         * itself a bot that cannot be verified), `spoofed` (it claimed a bot whose
         * operator vouches for other addresses) or `undeclared` (it hides as a
         * browser and behaves as automation).
         */
        public readonly ?string $identity = null,
        /**
         * How a verified address verified: `list` (the operator publishes it),
         * `rdns` (its reverse DNS name ends in a suffix the operator documents and
         * resolves back) or `owner` (the operator's own space, seen claiming its
         * bot); empty when not verified.
         */
        public readonly ?string $verifiedBy = null,
        /** `high`, `medium` or `low`: how sure we are the address is what the row says. */
        public readonly ?string $confidence = null,
        /** The first day the address was seen as such. */
        public readonly ?string $firstSeen = null,
        /** The last day it was. */
        public readonly ?string $lastSeen = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->provider === null && $this->providerName === null
            && $this->agents === null && $this->categories === null
            && $this->verified === null && $this->identity === null
            && $this->verifiedBy === null && $this->confidence === null
            && $this->firstSeen === null && $this->lastSeen === null;
    }

    /** @internal */
    public static function fromWire(WireBotDetail $w): self
    {
        $agents = $w->getAgents();
        $categories = $w->getCategories();
        return new self(
            provider: $w->getProvider(),
            providerName: $w->getProviderName(),
            agents: $agents === null ? null : array_values($agents),
            categories: $categories === null ? null : array_values($categories),
            verified: $w->getVerified(),
            identity: $w->getIdentity(),
            verifiedBy: $w->getVerifiedBy(),
            confidence: $w->getConfidence(),
            firstSeen: $w->getFirstSeen(),
            lastSeen: $w->getLastSeen(),
        );
    }
}
