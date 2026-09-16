<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * What a completed sign-in or a refresh hands back.
 *
 * `$apikeyId` is set when the person picked one of their API keys and may still
 * read it back. `$apikey`, the key itself, also needs a sign-in rather than a
 * refresh and a key whose secret can be shown again, so `$apikeyId` without
 * `$apikey` is normal.
 */
final class TokenResponse
{
    public function __construct(
        public readonly string $accessToken,
        /** Always `Bearer`. */
        public readonly string $tokenType,
        /** Seconds until the access token expires. */
        public readonly int $expiresIn,
        /** Spent by the refresh that presents it, so keep the one each refresh returns. */
        public readonly ?string $refreshToken = null,
        /** The scopes granted, space-delimited. An empty string is present, not absent. */
        public readonly ?string $scope = null,
        public readonly ?string $apikeyId = null,
        public readonly ?string $apikey = null,
    ) {
    }
}
