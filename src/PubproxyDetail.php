<?php

declare(strict_types=1);

namespace VPNDetection;

use DateTimeImmutable;
use VPNDetection\Internal\Model\PubproxyDetail as WirePubproxyDetail;

/**
 * The address in Public Proxy IP, open proxies anyone can connect through, over
 * a rolling 90 day window. It covers both ends of a proxy: the address it
 * listens on and the address its traffic leaves from.
 *
 * Every property is populated when the object is populated; the whole object is
 * EMPTY when its flag is false.
 */
final class PubproxyDetail
{
    public function __construct(
        /** Whether a public proxy listens on this address. */
        public readonly ?bool $entry = null,
        /** Whether a public proxy's traffic leaves from this address. */
        public readonly ?bool $exit = null,
        /**
         * The protocols of the proxies listening on or leaving from this address:
         * `http`, `https` (an HTTP proxy that also tunnels HTTPS), `socks4` or
         * `socks5`. Empty where only the address is known.
         *
         * @var list<string>|null
         */
        public readonly ?array $protocols = null,
        /**
         * How many distinct ports a public proxy listens on at this address; 0 when
         * it is only an exit, or its port is not known.
         */
        public readonly ?int $numPorts = null,
        /**
         * How many distinct public proxies' traffic left from this address; 0 when
         * it is only an entry.
         */
        public readonly ?int $numProxies = null,
        /** The most recent date within the window a proxy on this address was seen. */
        public readonly ?DateTimeImmutable $lastSeen = null,
        /**
         * The most recent date within the window a request through a proxy on this
         * address was answered, as YYYY-MM-DD, or an empty string when none was.
         */
        public readonly ?string $lastUsable = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->entry === null && $this->exit === null && $this->protocols === null
            && $this->numPorts === null && $this->numProxies === null
            && $this->lastSeen === null && $this->lastUsable === null;
    }

    /** @internal */
    public static function fromWire(WirePubproxyDetail $w): self
    {
        $protocols = $w->getProtocols();
        return new self(
            entry: $w->getEntry(),
            exit: $w->getExit(),
            protocols: $protocols === null ? null : array_values($protocols),
            numPorts: $w->getNumPorts(),
            numProxies: $w->getNumProxies(),
            lastSeen: Dates::immutable($w->getLastSeen()),
            lastUsable: $w->getLastUsable(),
        );
    }
}
