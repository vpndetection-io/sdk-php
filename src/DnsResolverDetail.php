<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\DnsResolverDetail as WireDnsResolverDetail;

/**
 * DNS Resolver IP's row for the address: the open resolver that answered there.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class DnsResolverDetail
{
    public function __construct(
        /** The port it answered on. */
        public readonly ?int $port = null,
        /** It offered recursion. */
        public readonly ?bool $recursionAvailable = null,
        /** Its answer's response code. */
        public readonly ?int $rcode = null,
        /** Its answer was right. */
        public readonly ?bool $answerCorrect = null,
        /** The first day it answered. */
        public readonly ?string $firstSeen = null,
        /** The last day it answered. */
        public readonly ?string $lastSeen = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->port === null && $this->recursionAvailable === null && $this->rcode === null
            && $this->answerCorrect === null && $this->firstSeen === null && $this->lastSeen === null;
    }

    /** @internal */
    public static function fromWire(WireDnsResolverDetail $w): self
    {
        return new self(
            port: $w->getPort(),
            recursionAvailable: $w->getRecursionAvailable(),
            rcode: $w->getRcode(),
            answerCorrect: $w->getAnswerCorrect(),
            firstSeen: Dates::day($w->getFirstSeen()),
            lastSeen: Dates::day($w->getLastSeen()),
        );
    }
}
