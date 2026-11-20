<?php

declare(strict_types=1);

namespace VPNDetection;

use VPNDetection\Internal\Model\WebDetail as WireWebDetail;

/**
 * Web IP's row for one port that answered at the address. Every property is set.
 */
final class WebDetail
{
    public function __construct(
        /** 80 or 443. */
        public readonly int $port,
        /** A TLS handshake completed. */
        public readonly bool $tlsOk,
        /** An HTTP response came back. */
        public readonly bool $sessionOk,
        /** The HTTP status, 0 where none came. */
        public readonly int $statusCode,
        /** The response's `Server` header. */
        public readonly string $server,
        /** Where the response redirected. */
        public readonly string $location,
        /** The page's title. */
        public readonly string $title,
        /** The certificate's subject common name. */
        public readonly string $certSubjectCn,
        /** The certificate's subject organization. */
        public readonly string $certSubjectO,
        /** The certificate's issuer. */
        public readonly string $certIssuerDn,
        /** Browsers trust the certificate. */
        public readonly bool $certBrowserTrusted,
        /** The TLS version negotiated, empty without TLS. */
        public readonly string $tlsVersion,
        /** The first day the port was open. */
        public readonly string $firstSeen,
        /** The last day the port was open. */
        public readonly string $lastSeen,
    ) {
    }

    /** @internal */
    public static function fromWire(WireWebDetail $w): self
    {
        return new self(
            port: $w->getPort(),
            tlsOk: $w->getTlsOk(),
            sessionOk: $w->getSessionOk(),
            statusCode: $w->getStatusCode(),
            server: $w->getServer(),
            location: $w->getLocation(),
            title: $w->getTitle(),
            certSubjectCn: $w->getCertSubjectCn(),
            certSubjectO: $w->getCertSubjectO(),
            certIssuerDn: $w->getCertIssuerDn(),
            certBrowserTrusted: $w->getCertBrowserTrusted(),
            tlsVersion: $w->getTlsVersion(),
            firstSeen: $w->getFirstSeen(),
            lastSeen: $w->getLastSeen(),
        );
    }
}
