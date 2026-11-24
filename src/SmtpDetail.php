<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\SmtpDetail as WireSmtpDetail;

/**
 * SMTP IP's row for the address: the mail server that answered there.
 *
 * Every property is set when the object is populated; the whole object is EMPTY (`isEmpty()`) when
 * its flag is false.
 */
final class SmtpDetail
{
    public function __construct(
        /** The port the server answered on. */
        public readonly ?int $port = null,
        /** Its banner. */
        public readonly ?string $banner = null,
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
        return $this->port === null && $this->banner === null && $this->sessionOk === null
            && $this->firstSeen === null && $this->lastSeen === null;
    }

    /** @internal */
    public static function fromWire(WireSmtpDetail $w): self
    {
        return new self(
            port: $w->getPort(),
            banner: $w->getBanner(),
            sessionOk: $w->getSessionOk(),
            firstSeen: Dates::day($w->getFirstSeen()),
            lastSeen: Dates::day($w->getLastSeen()),
        );
    }
}
