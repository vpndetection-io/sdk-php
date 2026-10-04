<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * One sign-in's PKCE pair: `$challenge` goes in the authorization URL, and
 * `$verifier` to `$client->oauth->exchangeAuthorizationCode()`. Made by
 * `$client->oauth->createPkce()`.
 */
final class Pkce
{
    public function __construct(
        /** 32 random bytes as 43 characters of unpadded base64url. */
        #[\SensitiveParameter]
        public readonly string $verifier,
        /** The verifier's SHA-256, as unpadded base64url. */
        public readonly string $challenge,
        /** `S256`, the only method the server accepts. */
        public readonly string $method = 'S256',
    ) {
    }
}
