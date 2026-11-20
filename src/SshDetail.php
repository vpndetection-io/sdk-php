<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\SshDetail as WireSshDetail;

/**
 * SSH IP's row for the address: the SSH server that answered there.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class SshDetail
{
    public function __construct(
        /** The port the server answered on. */
        public readonly ?int $port = null,
        /** Its banner. */
        public readonly ?string $banner = null,
        /** Its host key's fingerprint. */
        public readonly ?string $hostKeyFp = null,
        /** A session was set up. */
        public readonly ?bool $sessionOk = null,
        /** The first day it answered. */
        public readonly ?string $firstSeen = null,
        /** The last day it answered. */
        public readonly ?string $lastSeen = null,
    ) {
    }

    /** True when the API answered `{}`, which means the flag above it is false. */
    public function isEmpty(): bool
    {
        return $this->port === null && $this->banner === null && $this->hostKeyFp === null
            && $this->sessionOk === null && $this->firstSeen === null && $this->lastSeen === null;
    }

    /** @internal */
    public static function fromWire(WireSshDetail $w): self
    {
        return new self(
            port: $w->getPort(),
            banner: $w->getBanner(),
            hostKeyFp: $w->getHostKeyFp(),
            sessionOk: $w->getSessionOk(),
            firstSeen: $w->getFirstSeen(),
            lastSeen: $w->getLastSeen(),
        );
    }
}
