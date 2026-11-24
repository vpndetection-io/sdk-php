<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\BitTorrentDetail as WireBitTorrentDetail;

/**
 * BitTorrent IP's row for the address, over the last 90 days.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class BitTorrentDetail
{
    public function __construct(
        /** A client here answered, or two or more reported it at once. */
        public readonly ?bool $verified = null,
        /** A client here derived its node ID from the address (BEP 42). */
        public readonly ?bool $idMatchesIp = null,
        /** The first day a client was seen here. */
        public readonly ?string $firstSeen = null,
        /** The last day a client was seen here. */
        public readonly ?string $lastSeen = null,
        /** The last day one answered, empty when none did. */
        public readonly ?string $lastReachable = null,
        /** On how many days a client was seen here. */
        public readonly ?int $daysSeen = null,
        /** Distinct ports over the window. */
        public readonly ?int $numPorts = null,
        /** The most distinct ports on one day. */
        public readonly ?int $peakNumPorts = null,
        /** A DHT indexer rather than people. */
        public readonly ?bool $indexer = null,
        /**
         * The two-letter codes its clients name themselves by.
         *
         * @var list<string>|null
         */
        public readonly ?array $clients = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->verified === null && $this->idMatchesIp === null && $this->firstSeen === null
            && $this->lastSeen === null && $this->lastReachable === null && $this->daysSeen === null
            && $this->numPorts === null && $this->peakNumPorts === null && $this->indexer === null
            && $this->clients === null;
    }

    /** @internal */
    public static function fromWire(WireBitTorrentDetail $w): self
    {
        return new self(
            verified: $w->getVerified(),
            idMatchesIp: $w->getIdMatchesIp(),
            firstSeen: Dates::day($w->getFirstSeen()),
            lastSeen: Dates::day($w->getLastSeen()),
            lastReachable: $w->getLastReachable(),
            daysSeen: $w->getDaysSeen(),
            numPorts: $w->getNumPorts(),
            peakNumPorts: $w->getPeakNumPorts(),
            indexer: $w->getIndexer(),
            clients: $w->getClients() === null ? null : array_values($w->getClients()),
        );
    }
}
