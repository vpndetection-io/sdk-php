<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\VpnDetail as WireVpnDetail;

/**
 * What is known about the VPN attribution.
 *
 * Every property is populated when the object is populated, empty values
 * included; the whole object is EMPTY when `isVpn` is false. `method` is
 * deprecated: no plan is answered with it since 2026-10-20, so it is null.
 */
final class VpnDetail
{
    public function __construct(
        /** The VPN provider, or an empty string for an unattributed range. */
        public readonly ?string $provider = null,
        /** The most recent date this address was observed as VPN infrastructure. */
        public readonly ?DateTimeImmutable $lastSeen = null,
        /** How strongly the attribution is supported. */
        public readonly ?string $confidence = null,
        /**
         * @deprecated No plan is answered with it since 2026-10-20, so it is
         * always null; read `confidence` instead. It goes in the next major.
         */
        public readonly ?string $method = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->provider === null && $this->lastSeen === null
            && $this->confidence === null && $this->method === null;
    }

    /** @internal */
    public static function fromWire(WireVpnDetail $w): self
    {
        return new self(
            provider: $w->getProvider(),
            lastSeen: Dates::immutable($w->getLastSeen()),
            confidence: $w->getConfidence(),
            method: $w->getMethod(),
        );
    }
}
