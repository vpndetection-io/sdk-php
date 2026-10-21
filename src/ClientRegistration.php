<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * A registered client, from `register`: public and with no secret, it proves
 * each sign-in with PKCE.
 */
final class ClientRegistration
{
    /**
     * @param list<string> $redirectUris
     * @param list<string>|null $grantTypes
     * @param list<string>|null $responseTypes
     */
    public function __construct(
        /** The client ID for `authorizationUrl` and `exchangeAuthorizationCode`. */
        public readonly string $clientId,
        /** When it was issued, in Unix seconds. */
        public readonly int $clientIdIssuedAt,
        /** The name the person will see, a placeholder when none was given or none can be shown. */
        public readonly string $clientName,
        public readonly array $redirectUris,
        /** Always `none`. */
        public readonly string $tokenEndpointAuthMethod,
        public readonly ?array $grantTypes = null,
        public readonly ?array $responseTypes = null,
        /** The most this client may be granted. */
        public readonly ?string $scope = null,
    ) {
    }
}
