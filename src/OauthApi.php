<?php

declare(strict_types=1);

namespace VPNDetection;

use Closure;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

/**
 * Signs a person in on their own machine with the OAuth device flow, so a
 * program can be handed one of their API keys instead of asking them to paste
 * it. Reached as `$client->oauth`.
 *
 * Every call takes a client ID, issued on request from support@vpndetection.io.
 * None of these requests carries the client's API key, and none needs one. Each
 * takes `['timeout' => seconds]`, bounding each request it sends.
 */
final class OauthApi
{
    private const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

    private const METADATA = [
        'issuer' => ['string', true],
        'authorization_endpoint' => ['string', true],
        'token_endpoint' => ['string', true],
        'device_authorization_endpoint' => ['string', false],
        'revocation_endpoint' => ['string', false],
        'scopes_supported' => ['list', false],
        'response_types_supported' => ['list', false],
        'grant_types_supported' => ['list', false],
        'code_challenge_methods_supported' => ['list', false],
        'token_endpoint_auth_methods_supported' => ['list', false],
        'authorization_response_iss_parameter_supported' => ['bool', false],
        'service_documentation' => ['string', false],
    ];

    private const DEVICE_AUTHORIZATION = [
        'device_code' => ['string', true],
        'user_code' => ['string', true],
        'verification_uri' => ['string', true],
        'verification_uri_complete' => ['string', false],
        'expires_in' => ['int', true],
        'interval' => ['int', true],
    ];

    private const TOKEN_RESPONSE = [
        'access_token' => ['string', true],
        'token_type' => ['string', true],
        'expires_in' => ['int', true],
        'refresh_token' => ['string', false],
        'scope' => ['string', false],
        'mslm:apikey_id' => ['string', false],
        'mslm:apikey' => ['string', false],
    ];

    /** @var Closure(): float Monotonic seconds, for the poll's deadline. */
    private Closure $now;

    /** @var Closure(int): void The poll's wait. Replaced together with `$now` in tests. */
    private Closure $sleep;

    /** @internal Built by `Client`. */
    public function __construct(
        private readonly Transport $transport,
        private readonly string $baseUrl,
        private readonly string $userAgent,
    ) {
        $this->now = static fn (): float => hrtime(true) / 1e9;
        $this->sleep = static function (int $seconds): void {
            sleep($seconds);
        };
    }

    /**
     * @param array{timeout?: float} $options
     * @throws VPNDetectionException
     */
    public function metadata(array $options = []): OauthMetadata
    {
        CallOptions::assert($options, ['timeout']);
        $request = new Request('GET', $this->baseUrl . '/.well-known/oauth-authorization-server', [
            'Accept' => 'application/json',
            'User-Agent' => $this->userAgent,
        ]);
        $m = self::members($this->send($request, null, $options), self::METADATA);
        return new OauthMetadata(
            issuer: $m['issuer'],
            authorizationEndpoint: $m['authorization_endpoint'],
            tokenEndpoint: $m['token_endpoint'],
            deviceAuthorizationEndpoint: $m['device_authorization_endpoint'] ?? null,
            revocationEndpoint: $m['revocation_endpoint'] ?? null,
            scopesSupported: $m['scopes_supported'] ?? null,
            responseTypesSupported: $m['response_types_supported'] ?? null,
            grantTypesSupported: $m['grant_types_supported'] ?? null,
            codeChallengeMethodsSupported: $m['code_challenge_methods_supported'] ?? null,
            tokenEndpointAuthMethodsSupported: $m['token_endpoint_auth_methods_supported'] ?? null,
            authorizationResponseIssParameterSupported:
                $m['authorization_response_iss_parameter_supported'] ?? null,
            serviceDocumentation: $m['service_documentation'] ?? null,
        );
    }

    /**
     * Start a device sign-in: show the person `userCode` and `verificationUri`,
     * then hand the answer to `pollDeviceToken`. It consumes nothing, so it is
     * retried like a lookup; a refusal such as `slow_down` is an `OauthException`.
     *
     * @param array{scope?: string, resource?: string, timeout?: float} $options `scope` is
     *        space-delimited and sent as given; the server narrows it to what the client may ask for.
     * @throws VPNDetectionException
     */
    public function deviceAuthorization(string $clientId, array $options = []): DeviceAuthorization
    {
        CallOptions::assert($options, ['scope', 'resource', 'timeout']);
        $form = ['client_id' => $clientId];
        foreach (['scope', 'resource'] as $name) {
            if (isset($options[$name]) && !is_string($options[$name])) {
                throw new InvalidArgumentException("{$name} must be a string");
            }
            // Left out when not given, never sent empty.
            if (($options[$name] ?? '') !== '') {
                $form[$name] = $options[$name];
            }
        }
        $response = $this->send($this->form('/oauth/device_authorization', $form), null, $options);
        $m = self::members($response, self::DEVICE_AUTHORIZATION);
        return new DeviceAuthorization(
            deviceCode: $m['device_code'],
            userCode: $m['user_code'],
            verificationUri: $m['verification_uri'],
            expiresIn: $m['expires_in'],
            interval: $m['interval'],
            verificationUriComplete: $m['verification_uri_complete'] ?? null,
        );
    }

    /**
     * Ask once whether the person has approved a device sign-in. Until they do,
     * it throws an `OauthException` coded `authorization_pending`;
     * `pollDeviceToken` is the loop around it.
     *
     * Never retried: an approved code is spent by the answer carrying the tokens,
     * so a retry after a lost response could only lose them.
     *
     * @param array{timeout?: float} $options
     * @throws VPNDetectionException
     */
    public function exchangeDeviceCode(
        string $clientId,
        string $deviceCode,
        array $options = [],
    ): TokenResponse {
        CallOptions::assert($options, ['timeout']);
        return $this->exchangeDevice($clientId, $deviceCode, $options);
    }

    /**
     * Trade a refresh token for a new pair. The old one is spent whatever happens
     * next, so this is never retried. A refresh names the key the person picked
     * (`apikeyId`) but never reveals it again (`apikey`).
     *
     * @param array{timeout?: float} $options
     * @throws VPNDetectionException
     */
    public function exchangeRefreshToken(
        string $clientId,
        string $refreshToken,
        array $options = [],
    ): TokenResponse {
        CallOptions::assert($options, ['timeout']);
        return $this->exchange([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $clientId,
        ], $options);
    }

    /**
     * End a token. A refresh token ends the whole sign-in and every token it
     * issued, which is how a program signs the machine out; an access token ends
     * only itself. The server answers the same for any token, known or not.
     *
     * @param array{timeout?: float} $options
     * @throws VPNDetectionException
     */
    public function revoke(string $clientId, string $token, array $options = []): void
    {
        CallOptions::assert($options, ['timeout']);
        $form = ['token' => $token, 'client_id' => $clientId];
        $this->send($this->form('/oauth/revoke', $form), null, $options);
    }

    /**
     * Wait for the person to approve a device sign-in, and return its tokens.
     *
     * Waits `$device->interval` seconds (5 when that is below 1) before EVERY
     * request, the first included, and 5 more for the rest of the call each time
     * the server answers `slow_down`. Ends at the first answer that is neither: a
     * denial throws `OauthAccessDeniedException`, a code that ran out
     * `OauthExpiredTokenException` - as does outliving `$device->expiresIn`,
     * counted from this call, with no status - and any other failure as it came.
     * PHP has no cancellation handle, so this blocks until one of those.
     *
     * @param array{timeout?: float} $options The timeout bounds each request, never the poll.
     * @throws VPNDetectionException
     */
    public function pollDeviceToken(
        string $clientId,
        DeviceAuthorization $device,
        array $options = [],
    ): TokenResponse {
        CallOptions::assert($options, ['timeout']);
        $interval = $device->interval >= 1 ? $device->interval : 5;
        $deadline = ($this->now)() + $device->expiresIn;
        while (true) {
            ($this->sleep)($interval);
            if (($this->now)() >= $deadline) {
                throw new OauthExpiredTokenException('expired_token');
            }
            try {
                return $this->exchangeDevice($clientId, $device->deviceCode, $options);
            } catch (OauthException $e) {
                // RFC 8628: slow_down widens the interval for every later request, not just the next.
                if ($e->errorCode === 'slow_down') {
                    $interval += 5;
                } elseif ($e->errorCode !== 'authorization_pending') {
                    throw $e;
                }
            }
        }
    }

    /** @param array{timeout?: float} $options */
    private function exchangeDevice(string $clientId, string $deviceCode, array $options): TokenResponse
    {
        return $this->exchange([
            'grant_type' => self::DEVICE_CODE_GRANT,
            'device_code' => $deviceCode,
            'client_id' => $clientId,
        ], $options);
    }

    /**
     * @param array<string, string> $form
     * @param array{timeout?: float} $options
     */
    private function exchange(array $form, array $options): TokenResponse
    {
        $response = $this->send($this->form('/oauth/token', $form), 0, $options);
        $m = self::members($response, self::TOKEN_RESPONSE);
        return new TokenResponse(
            accessToken: $m['access_token'],
            tokenType: $m['token_type'],
            expiresIn: $m['expires_in'],
            refreshToken: $m['refresh_token'] ?? null,
            scope: $m['scope'] ?? null,
            apikeyId: $m['mslm:apikey_id'] ?? null,
            apikey: $m['mslm:apikey'] ?? null,
        );
    }

    /**
     * Built here rather than through the generated `AuthorizationApi`, whose send
     * path sets no timeout.
     *
     * @param array<string, string> $fields
     */
    private function form(string $path, array $fields): Request
    {
        return new Request(
            'POST',
            $this->baseUrl . $path,
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded',
                'User-Agent' => $this->userAgent,
            ],
            // RFC 3986 encoding sends a `+` in a value as %2B, where a raw one would arrive as a space.
            http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        );
    }

    /** @param array{timeout?: float} $options */
    private function send(Request $request, ?int $retries, array $options): ResponseInterface
    {
        return $this->transport->sendAsync(
            $request, $retries, CallOptions::timeout($options), self::refusal(...),
        )->wait();
    }

    /**
     * Only a 4xx whose body is a JSON object with a STRING `error` is an OAuth
     * refusal. Every 5xx, whatever it says, is the server failing, and is retried
     * wherever the operation retries.
     */
    private static function refusal(ResponseInterface $response): VPNDetectionException
    {
        $error = Errors::fromResponse($response);
        $status = $response->getStatusCode();
        if ($status >= 500) {
            return $error;
        }
        $body = json_decode((string) $response->getBody(), true);
        if (!is_array($body) || !is_string($body['error'] ?? null)) {
            return $error;
        }
        $description = $body['error_description'] ?? null;
        return OauthException::from(
            $body['error'],
            is_string($description) ? $description : null,
            $status,
            $error->kind,
        );
    }

    /**
     * The declared members that are present, each checked against its type, so
     * an absent one stays absent and an empty `scope` stays present. Anything
     * else the server sends is dropped.
     *
     * @param array<string, array{string, bool}> $members
     * @return array<string, mixed>
     */
    private static function members(ResponseInterface $response, array $members): array
    {
        $status = $response->getStatusCode();
        $body = Transport::toArray((string) $response->getBody(), $status);
        $present = [];
        foreach ($members as $name => [$type, $required]) {
            $value = $body[$name] ?? null;
            if ($value === null) {
                if ($required) {
                    throw Errors::malformed("the answer carried no {$name}", $status);
                }
                continue;
            }
            $valid = match ($type) {
                'string' => is_string($value),
                'int' => is_int($value),
                'bool' => is_bool($value),
                'list' => is_array($value) && array_is_list($value)
                    && array_filter($value, is_string(...)) === $value,
            };
            if (!$valid) {
                throw Errors::malformed("the answer's {$name} is not a {$type}", $status);
            }
            $present[$name] = $value;
        }
        return $present;
    }
}
