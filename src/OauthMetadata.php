<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * The authorization server's discovery document. No call on `$client->oauth`
 * needs it: each one builds on the client's base URL.
 */
final class OauthMetadata
{
    /**
     * @param list<string>|null $scopesSupported
     * @param list<string>|null $responseTypesSupported
     * @param list<string>|null $grantTypesSupported
     * @param list<string>|null $codeChallengeMethodsSupported
     * @param list<string>|null $tokenEndpointAuthMethodsSupported
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorizationEndpoint,
        public readonly string $tokenEndpoint,
        public readonly ?string $deviceAuthorizationEndpoint = null,
        public readonly ?string $revocationEndpoint = null,
        public readonly ?array $scopesSupported = null,
        public readonly ?array $responseTypesSupported = null,
        public readonly ?array $grantTypesSupported = null,
        public readonly ?array $codeChallengeMethodsSupported = null,
        public readonly ?array $tokenEndpointAuthMethodsSupported = null,
        public readonly ?bool $authorizationResponseIssParameterSupported = null,
        public readonly ?string $serviceDocumentation = null,
    ) {
    }
}
