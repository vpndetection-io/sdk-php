<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\LookupResponse;

/**
 * What a lookup answers.
 *
 * A NULL property is one your plan does not include. It never means "we could
 * not check", so null and `false` are genuinely different answers: null is "not
 * in your plan", `false` is "checked, and no". Write `$result->isHosting ?? false`
 * when you only care whether the address is flagged.
 *
 * A detail object that is present but empty (`isEmpty()`) means the flag above it
 * is false. A populated one always carries every one of its properties.
 */
final class Result
{
    public function __construct(
        /** The address that was looked up, normalized. */
        public readonly string $ip,
        /** Whether the address is VPN infrastructure. Every plan includes this. */
        public readonly bool $isVpn,
        /** Set when this answer was computed locally rather than served. */
        public readonly bool $isBogon,
        public readonly ?bool $isHosting = null,
        public readonly ?bool $isRelay = null,
        public readonly ?bool $isTor = null,
        public readonly ?bool $isCdn = null,
        public readonly ?bool $isResproxy = null,
        public readonly ?bool $isDcproxy = null,
        public readonly ?bool $isMobproxy = null,
        public readonly ?VpnDetail $vpn = null,
        public readonly ?ClassDetail $hosting = null,
        public readonly ?ClassDetail $relay = null,
        public readonly ?ClassDetail $tor = null,
        public readonly ?ClassDetail $cdn = null,
        public readonly ?ProxyDetail $resproxy = null,
        public readonly ?ProxyDetail $dcproxy = null,
        public readonly ?ProxyDetail $mobproxy = null,
        /**
         * The response exactly as it came off the wire, with its original names.
         *
         * @var array<string, mixed>
         */
        public readonly array $raw = [],
    ) {
    }

    /**
     * @internal
     *
     * The one place the wire's snake_case becomes idiomatic camelCase. The
     * generated model already distinguishes an ABSENT member from one that is
     * present and false, so every assignment here is a straight copy and a plan
     * that includes a field and answers `false` keeps it.
     *
     * @param array<string, mixed> $raw
     */
    public static function fromWire(LookupResponse $w, array $raw): self
    {
        return new self(
            ip: $w->getIp(),
            isVpn: $w->getIsVpn(),
            isBogon: false,
            isHosting: $w->getIsHosting(),
            isRelay: $w->getIsRelay(),
            isTor: $w->getIsTor(),
            isCdn: $w->getIsCdn(),
            isResproxy: $w->getIsResproxy(),
            isDcproxy: $w->getIsDcproxy(),
            isMobproxy: $w->getIsMobproxy(),
            vpn: $w->getVpn() === null ? null : VpnDetail::fromWire($w->getVpn()),
            hosting: $w->getHosting() === null ? null : ClassDetail::fromWire($w->getHosting()),
            relay: $w->getRelay() === null ? null : ClassDetail::fromWire($w->getRelay()),
            tor: $w->getTor() === null ? null : ClassDetail::fromWire($w->getTor()),
            cdn: $w->getCdn() === null ? null : ClassDetail::fromWire($w->getCdn()),
            resproxy: $w->getResproxy() === null ? null : ProxyDetail::fromWire($w->getResproxy()),
            dcproxy: $w->getDcproxy() === null ? null : ProxyDetail::fromWire($w->getDcproxy()),
            mobproxy: $w->getMobproxy() === null ? null : ProxyDetail::fromWire($w->getMobproxy()),
            raw: $raw,
        );
    }
}
