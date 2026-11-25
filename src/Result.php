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
        /**
         * True for reserved space (private, loopback, documentation and the
         * like), which the library answers locally without a request. A served
         * answer carries the API's own `is_bogon`, and this reads it.
         */
        public readonly bool $isBogon,
        public readonly ?bool $isHosting = null,
        public readonly ?bool $isRelay = null,
        public readonly ?bool $isTor = null,
        public readonly ?bool $isCdn = null,
        public readonly ?bool $isResproxy = null,
        public readonly ?bool $isDcproxy = null,
        public readonly ?bool $isMobproxy = null,
        public readonly ?bool $isPubproxy = null,
        public readonly ?VpnDetail $vpn = null,
        public readonly ?ClassDetail $hosting = null,
        public readonly ?ClassDetail $relay = null,
        public readonly ?ClassDetail $tor = null,
        public readonly ?ClassDetail $cdn = null,
        public readonly ?ProxyDetail $resproxy = null,
        public readonly ?ProxyDetail $dcproxy = null,
        public readonly ?ProxyDetail $mobproxy = null,
        public readonly ?PubproxyDetail $pubproxy = null,
        /**
         * The response exactly as it came off the wire, with its original names.
         *
         * @var array<string, mixed>
         */
        public readonly array $raw = [],
        /** Where the address is. Every answer carries it, with or without a key. */
        public readonly ?Location $location = null,
        /** The AS announcing the address. Every answer carries it, with or without a key. */
        public readonly ?Asn $asn = null,
        /**
         * On answers to a key on the free plan only: false while its organization's
         * trial of every field lasts, true once the answer has Unlimited's.
         */
        public readonly ?bool $trialExpired = null,
        /**
         * On answers to a key on a paid plan only: false while the answer has every
         * field, true once its organization's overage cap is reached and the answer
         * has Unlimited's. Lookups answered past the cap are not billed.
         */
        public readonly ?bool $capReached = null,
        /** Whether the address is announced from many places at once. Every plan includes this. */
        public readonly ?bool $isAnycast = null,
        /** Whether the address is a mobile carrier's. On a paid plan. */
        public readonly ?bool $isCarrier = null,
        /** Whether the address is a satellite operator's. On a paid plan. */
        public readonly ?bool $isSatellite = null,
        /** Whether an SSH server answered on the address. On a paid plan. */
        public readonly ?bool $isSsh = null,
        /** Whether a mail server answered on the address. On a paid plan. */
        public readonly ?bool $isSmtp = null,
        /** Whether a web server answered on the address, on port 80 or 443. On a paid plan. */
        public readonly ?bool $isWeb = null,
        /** Whether an open DNS resolver answered on the address. On a paid plan. */
        public readonly ?bool $isDnsResolver = null,
        /** Whether a BitTorrent client was seen on the address in the last 90 days. On a paid plan. */
        public readonly ?bool $isBittorrent = null,
        /** Carrier IP's row, empty when `isCarrier` is false. On a paid plan. */
        public readonly ?CarrierDetail $carrier = null,
        /** Satellite IP's row, empty when `isSatellite` is false. On a paid plan. */
        public readonly ?SatelliteDetail $satellite = null,
        /** SSH IP's row, empty when `isSsh` is false. On a paid plan. */
        public readonly ?SshDetail $ssh = null,
        /** SMTP IP's row, empty when `isSmtp` is false. On a paid plan. */
        public readonly ?SmtpDetail $smtp = null,
        /**
         * A row per port that answered, lowest first; `[]` when `isWeb` is false. On a paid plan.
         *
         * @var list<WebDetail>|null
         */
        public readonly ?array $web = null,
        /** DNS Resolver IP's row, empty when `isDnsResolver` is false. On a paid plan. */
        public readonly ?DnsResolverDetail $dnsResolver = null,
        /** BitTorrent IP's row, empty when `isBittorrent` is false. On a paid plan. */
        public readonly ?BitTorrentDetail $bittorrent = null,
        /** Who uses the address. On a paid plan. */
        public readonly ?Company $company = null,
        /**
         * The name the address's reverse DNS (PTR) record points to, an empty string
         * when it has none. Every plan includes this.
         */
        public readonly ?string $hostname = null,
        /** Where to report abuse from the address. On a paid plan. */
        public readonly ?AbuseContact $abuse = null,
        /**
         * Whether an automated client uses the address, such as a search engine's or
         * an AI company's crawler, an uptime monitor, an internet scanner or a
         * webhook sender. Every plan includes this.
         */
        public readonly ?bool $isBot = null,
        /** Bot IP's row, empty when `isBot` is false. On a paid plan. */
        public readonly ?BotDetail $bot = null,
        /**
         * The verdict on the user agent the lookup sent: null when it sent none or
         * the plan does not include it, empty for a bogon. On a paid plan.
         */
        public readonly ?UserAgentVerdict $userAgent = null,
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
            isBogon: $w->getIsBogon() ?? false,
            isHosting: $w->getIsHosting(),
            isRelay: $w->getIsRelay(),
            isTor: $w->getIsTor(),
            isCdn: $w->getIsCdn(),
            isResproxy: $w->getIsResproxy(),
            isDcproxy: $w->getIsDcproxy(),
            isMobproxy: $w->getIsMobproxy(),
            isPubproxy: $w->getIsPubproxy(),
            vpn: $w->getVpn() === null ? null : VpnDetail::fromWire($w->getVpn()),
            hosting: $w->getHosting() === null ? null : ClassDetail::fromWire($w->getHosting()),
            relay: $w->getRelay() === null ? null : ClassDetail::fromWire($w->getRelay()),
            tor: $w->getTor() === null ? null : ClassDetail::fromWire($w->getTor()),
            cdn: $w->getCdn() === null ? null : ClassDetail::fromWire($w->getCdn()),
            resproxy: $w->getResproxy() === null ? null : ProxyDetail::fromWire($w->getResproxy()),
            dcproxy: $w->getDcproxy() === null ? null : ProxyDetail::fromWire($w->getDcproxy()),
            mobproxy: $w->getMobproxy() === null ? null : ProxyDetail::fromWire($w->getMobproxy()),
            pubproxy: $w->getPubproxy() === null ? null : PubproxyDetail::fromWire($w->getPubproxy()),
            raw: $raw,
            location: $w->getLocation() === null ? null : Location::fromWire($w->getLocation()),
            asn: $w->getAsn() === null ? null : Asn::fromWire($w->getAsn()),
            trialExpired: $w->getTrialExpired(),
            capReached: $w->getCapReached(),
            isAnycast: $w->getIsAnycast(),
            isCarrier: $w->getIsCarrier(),
            isSatellite: $w->getIsSatellite(),
            isSsh: $w->getIsSsh(),
            isSmtp: $w->getIsSmtp(),
            isWeb: $w->getIsWeb(),
            isDnsResolver: $w->getIsDnsResolver(),
            isBittorrent: $w->getIsBittorrent(),
            carrier: $w->getCarrier() === null ? null : CarrierDetail::fromWire($w->getCarrier()),
            satellite: $w->getSatellite() === null ? null : SatelliteDetail::fromWire($w->getSatellite()),
            ssh: $w->getSsh() === null ? null : SshDetail::fromWire($w->getSsh()),
            smtp: $w->getSmtp() === null ? null : SmtpDetail::fromWire($w->getSmtp()),
            web: $w->getWeb() === null
                ? null
                : array_map(WebDetail::fromWire(...), array_values($w->getWeb())),
            dnsResolver: $w->getDnsResolver() === null
                ? null
                : DnsResolverDetail::fromWire($w->getDnsResolver()),
            bittorrent: $w->getBittorrent() === null ? null : BitTorrentDetail::fromWire($w->getBittorrent()),
            company: $w->getCompany() === null ? null : Company::fromWire($w->getCompany()),
            hostname: $w->getHostname(),
            abuse: $w->getAbuse() === null ? null : AbuseContact::fromWire($w->getAbuse()),
            isBot: $w->getIsBot(),
            bot: $w->getBot() === null ? null : BotDetail::fromWire($w->getBot()),
            userAgent: $w->getUserAgent() === null ? null : UserAgentVerdict::fromWire($w->getUserAgent()),
        );
    }
}
