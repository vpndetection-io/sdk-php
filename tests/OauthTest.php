<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Throwable;
use VPNDetection\Client;
use VPNDetection\DeviceAuthorization;
use VPNDetection\OauthAccessDeniedException;
use VPNDetection\OauthException;
use VPNDetection\OauthExpiredTokenException;
use VPNDetection\Options;
use VPNDetection\TokenResponse;
use VPNDetection\VPNDetectionException;

/**
 * The OAuth accessor against the shared corpus's oauth section. Nothing here
 * reads oauth.deferred: those operations are not in this release.
 */
final class OauthTest extends TestCase
{
    private const BASE_URL = 'https://api.example.test';
    private const DEVICE_CODE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

    // Satisfies every operation's required members at once.
    private const EVERY_REQUIRED_MEMBER = [
        'issuer' => self::BASE_URL,
        'authorization_endpoint' => self::BASE_URL . '/oauth/authorize',
        'token_endpoint' => self::BASE_URL . '/oauth/token',
        'device_code' => 'mo_dc_x',
        'user_code' => 'BCDF-GHJK',
        'verification_uri' => 'https://app.example.test/device',
        'expires_in' => 900,
        'interval' => 5,
        'access_token' => 'mo_at_x',
        'token_type' => 'Bearer',
    ];

    // In the corpus's production document, but no longer advertised or in the
    // pinned spec, so it is not a member of OauthMetadata.
    private const NOT_A_MEMBER = ['client_id_metadata_document_supported'];

    /** @var array<string, mixed> */
    private static array $corpus;

    public static function setUpBeforeClass(): void
    {
        self::$corpus = json_decode(
            (string) file_get_contents(__DIR__ . '/../testdata/testdata.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        )['oauth'];
    }

    public function testNoOauthRequestCarriesTheApiKey(): void
    {
        $rule = self::$corpus['noCredential'];
        $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]]);
        $oauth = self::client($stub, $rule['apiKey'])->oauth;
        $stub->installClock($oauth);

        $device = $oauth->deviceAuthorization('vpndetection-cli', ['scope' => 'account.read']);
        $oauth->metadata();
        $oauth->exchangeDeviceCode('vpndetection-cli', 'mo_dc_x');
        $oauth->exchangeRefreshToken('vpndetection-cli', 'mo_rt_x');
        $oauth->revoke('vpndetection-cli', 'mo_rt_x');
        $oauth->pollDeviceToken('vpndetection-cli', $device);

        self::assertCount(6, $stub->requests);
        foreach ($stub->requests as $request) {
            $label = "{$request['method']} {$request['path']}";
            foreach ($rule['forbiddenHeaders'] as $name) {
                self::assertArrayNotHasKey($name, $request['headers'], "{$label} carried {$name}");
            }
            foreach ($rule['forbiddenQuery'] as $name) {
                self::assertArrayNotHasKey($name, $request['query'], "{$label} carried the {$name} query");
            }
            $values = implode("\n", array_merge(...array_values($request['headers'])));
            $leaked = str_contains($request['url'], $rule['apiKey'])
                || str_contains($request['body'], $rule['apiKey'])
                || str_contains($values, $rule['apiKey']);
            self::assertFalse($leaked, "{$label} carried the API key");
        }
    }

    // Keyless, because nothing about these operations needs a key. Every call
    // also passes a timeout, so an exact field match proves it stays off the wire.
    public function testEachOperationRequestsItsEndpointWithExactlyItsFormFields(): void
    {
        $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]]);
        $client = new Client(new Options(baseUrl: self::BASE_URL . '/', httpClient: $stub->client));
        $client->oauth->metadata(['timeout' => 5]);
        self::assertCount(1, $stub->requests);
        self::assertEndpoint($stub->requests[0], self::$corpus['endpoints']['metadata']);
        $path = self::$corpus['endpoints']['metadata']['path'];
        self::assertSame(self::BASE_URL . $path, $stub->requests[0]['url'], 'one trailing slash dropped');

        foreach (self::$corpus['forms']['cases'] as $case) {
            $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]]);
            self::call(self::client($stub), $case['operation'], $case['args'], ['timeout' => 5]);

            self::assertCount(1, $stub->requests, $case['name']);
            $request = $stub->requests[0];
            self::assertEndpoint($request, self::$corpus['endpoints'][$case['endpoint']], $case['name']);
            $type = self::$corpus['forms']['contentType'];
            self::assertStringStartsWith($type, $request['contentType'], $case['name']);
            self::assertSame(
                self::sorted($case['fields']),
                self::sorted(OauthStub::formFields($request['body'])),
                $case['name'],
            );
        }

        $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]]);
        self::client($stub)->oauth->deviceAuthorization('vpndetection-cli', ['scope' => '', 'resource' => '']);
        $fields = OauthStub::formFields($stub->requests[0]['body']);
        self::assertSame(['client_id' => 'vpndetection-cli'], $fields, 'an empty optional field is left out');
    }

    public function testA2xxDecodesOnPresenceSoAbsentStaysAbsentAndAnEmptyScopePresent(): void
    {
        $operations = ['metadata' => 'metadata', 'deviceAuthorization' => 'deviceAuthorization'];
        $operations['token'] = 'exchangeDeviceCode';
        foreach ($operations as $section => $operation) {
            foreach (self::$corpus['responses'][$section] as $case) {
                $label = "{$section}: {$case['name']}";
                $stub = new OauthStub([$case]);
                $args = ['clientId' => 'vpndetection-cli', 'deviceCode' => 'mo_dc_x'];
                $got = self::call(self::client($stub), $operation, $args);

                foreach ($case['expect']['present'] as $name => $value) {
                    if (!in_array($name, self::NOT_A_MEMBER, true)) {
                        self::assertSame($value, $got->{self::camel($name)}, "{$label}: {$name}");
                    }
                }
                foreach ($case['expect']['absent'] as $name) {
                    self::assertNull($got->{self::camel($name)}, "{$label}: {$name} must be ABSENT");
                }
            }
        }
        foreach (self::$corpus['responses']['revoke'] as $case) {
            $stub = new OauthStub([$case]);
            self::client($stub)->oauth->revoke('vpndetection-cli', 'mo_rt_x');
            self::assertCount(1, $stub->requests, "revoke: {$case['name']}");
        }
    }

    public function testA2xxThatLacksARequiredMemberOrDoesNotParseIsTheOrdinaryError(): void
    {
        $cases = [
            'missing access_token' => [
                'status' => 200,
                'body' => ['token_type' => 'Bearer', 'expires_in' => 3600],
            ],
            'expires_in as a string' => [
                'status' => 200,
                'body' => ['access_token' => 'mo_at_x', 'token_type' => 'Bearer', 'expires_in' => '3600'],
            ],
            'not JSON' => ['status' => 200, 'rawBody' => '<html>'],
        ];
        foreach ($cases as $name => $reply) {
            $stub = new OauthStub([$reply]);
            $outcome = self::exchange($stub);
            self::assertCount(1, $stub->requests, "{$name}: an exchange is never retried");
            $want = ['type' => 'client', 'kind' => 'server_error', 'status' => 200];
            self::assertOutcome($outcome, $want, $name);
        }
    }

    // No corpus case: every response there decodes. One member left out per case,
    // since a body missing several at once passes against a decoder that
    // defaults any single one of them.
    public function testAnAnswerMissingAnyOneRequiredMemberIsTheOrdinaryError(): void
    {
        $required = [
            'metadata' => ['issuer', 'authorization_endpoint', 'token_endpoint'],
            'deviceAuthorization' => ['device_code', 'user_code', 'verification_uri', 'expires_in', 'interval'],
            'exchangeDeviceCode' => ['access_token', 'token_type', 'expires_in'],
        ];
        $args = ['clientId' => 'vpndetection-cli', 'deviceCode' => 'mo_dc_x'];
        foreach ($required as $operation => $members) {
            foreach ($members as $member) {
                $body = self::EVERY_REQUIRED_MEMBER;
                unset($body[$member]);
                $stub = new OauthStub([['status' => 200, 'body' => $body]]);
                // No retries: a server error is retryable, and the stub would answer the retry the same.
                $client = new Client(new Options(baseUrl: self::BASE_URL, retries: 0, httpClient: $stub->client));

                $outcome = self::settle(static fn (): mixed => self::call($client, $operation, $args));

                $want = ['type' => 'client', 'kind' => 'server_error', 'status' => 200];
                self::assertOutcome($outcome, $want, "{$operation} without {$member}");
            }
        }
    }

    // No corpus case: a deadline already behind the clock leaves a negative
    // remainder, which is never the wait.
    public function testAPollPastItsDeadlineWaitsNothingNeverANegativeTime(): void
    {
        $stub = new OauthStub([['status' => 400, 'body' => ['error' => 'authorization_pending']]]);
        $oauth = self::client($stub)->oauth;
        $stub->installClock($oauth);
        $device = self::device([
            'device_code' => 'mo_dc_poll', 'user_code' => 'BCDF-GHJK',
            'verification_uri' => 'https://app.vpndetection.io/device', 'expires_in' => -3, 'interval' => 1,
        ]);

        $outcome = self::settle(static fn (): mixed => $oauth->pollDeviceToken('vpndetection-cli', $device));

        self::assertSame([0.0], $stub->waits);
        self::assertCount(0, $stub->requests);
        self::assertOutcome($outcome, ['type' => 'expiredToken', 'status' => null], 'expires_in -3');
    }

    public function testAFailedAnswerIsAnOauthRefusalOnlyWhenItIsOne(): void
    {
        foreach (self::$corpus['errors']['cases'] as $case) {
            $outcome = self::exchange(new OauthStub([$case]));
            self::assertOutcome($outcome, $case['expect'], $case['name']);
        }
    }

    public function testOnlyWhatConsumesNothingIsRetriedAndNeverAnOauthRefusal(): void
    {
        foreach (self::$corpus['retries']['cases'] as $case) {
            $stub = new OauthStub($case['responses']);
            $outcome = self::settle(static fn (): mixed => self::call(
                self::client($stub),
                $case['operation'],
                $case['args'],
            ));

            self::assertCount($case['expect']['requests'], $stub->requests, "{$case['name']}: requests sent");
            if ($case['expect']['outcome'] === 'ok') {
                self::assertNotInstanceOf(Throwable::class, $outcome, $case['name']);
                continue;
            }
            $want = ['type' => $case['expect']['outcome']] + $case['expect'];
            self::assertOutcome($outcome, $want, $case['name']);
        }
    }

    // Waits are asserted exactly, through the seam that replaces the sleep AND the
    // clock together, so the deadline reads the same time the waits spent.
    public function testPollDeviceTokenWaitsWidensAndEndsAsTheCorpusSays(): void
    {
        foreach (self::$corpus['poll']['cases'] as $case) {
            $stub = new OauthStub($case['responses']);
            $oauth = self::client($stub)->oauth;
            $stub->installClock($oauth);

            $device = self::device($case['device']);
            $outcome = self::settle(static fn (): mixed => $oauth->pollDeviceToken($case['clientId'], $device));

            $name = $case['name'];
            self::assertSame(
                array_map(floatval(...), $case['expect']['waits']),
                $stub->waits,
                "{$name}: waits, in seconds",
            );
            self::assertCount($case['expect']['requests'], $stub->requests, "{$name}: requests sent");
            $form = [
                'client_id' => $case['clientId'],
                'device_code' => $case['device']['device_code'],
                'grant_type' => self::DEVICE_CODE_GRANT,
            ];
            foreach ($stub->requests as $request) {
                self::assertEndpoint($request, self::$corpus['endpoints']['token'], $name);
                self::assertSame($form, self::sorted(OauthStub::formFields($request['body'])), $name);
            }
            if ($case['expect']['outcome'] === 'token') {
                self::assertInstanceOf(TokenResponse::class, $outcome, $name);
                $want = $case['expect']['token']['access_token'] ?? $outcome->accessToken;
                self::assertSame($want, $outcome->accessToken, $name);
                continue;
            }
            self::assertOutcome($outcome, ['type' => $case['expect']['outcome']] + $case['expect'], $name);
        }
    }

    // The seam above proves the schedule; this proves the real wait is one.
    public function testAPollOnTheRealClockWaitsBeforeItsFirstRequest(): void
    {
        $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]], 1);
        $device = new DeviceAuthorization('mo_dc_x', 'BCDF-GHJK', 'https://app.example.test/device', 900, 1);
        $started = microtime(true);

        self::client($stub)->oauth->pollDeviceToken('vpndetection-cli', $device);

        $elapsed = microtime(true) - $started;
        self::assertCount(1, $stub->requests);
        self::assertGreaterThanOrEqual(0.95, $elapsed, 'the first poll did not wait its interval');
        self::assertLessThan(2.5, $elapsed);
    }

    // The time left is rarely whole seconds here, so a sleep dropping the fraction
    // polls again short of the deadline; only such a poll reaches the approval.
    public function testAPollOnTheRealClockSleepsTheFractionLeftBeforeItsDeadline(): void
    {
        $pending = ['status' => 400, 'body' => ['error' => 'authorization_pending']];
        $stub = new OauthStub([$pending, ['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]], 2);
        $device = new DeviceAuthorization('mo_dc_x', 'BCDF-GHJK', 'https://app.example.test/device', 2, 1);
        $started = microtime(true);

        $outcome = self::settle(static fn (): mixed
            => self::client($stub)->oauth->pollDeviceToken('vpndetection-cli', $device));

        $elapsed = microtime(true) - $started;
        self::assertCount(1, $stub->requests, 'polled again before the deadline');
        self::assertOutcome($outcome, ['type' => 'expiredToken', 'status' => null], 'expires_in 2');
        self::assertGreaterThanOrEqual(1.95, $elapsed, 'expired before its deadline');
        self::assertLessThan(3.5, $elapsed);
    }

    public function testEveryOauthCallTakesAPerCallTimeoutBelowTheClients(): void
    {
        foreach (self::timedCalls() as $name => $call) {
            Origin::assertTimesOut(['stallSeconds' => 5], 3.0, static fn (Client $c): mixed
                => $call($c, ['timeout' => 0.25]), $name);
        }
    }

    public function testTheClientsTimeoutBoundsEveryOauthRequest(): void
    {
        foreach (self::timedCalls() as $name => $call) {
            $untimed = static fn (Client $c): mixed => $call($c, []);
            Origin::assertTimesOut(['trickleMs' => 20], 0.25, $untimed, $name);
        }
    }

    public function testAnOptionOauthCannotUseIsRefusedBeforeAnyRequest(): void
    {
        $stub = new OauthStub([['status' => 200, 'body' => self::EVERY_REQUIRED_MEMBER]]);
        $oauth = self::client($stub)->oauth;
        $calls = [
            'retries' => static fn (): mixed => $oauth->metadata(['retries' => 1]),
            'a scope that is not a string' => static fn (): mixed
                => $oauth->deviceAuthorization('vpndetection-cli', ['scope' => ['account.read']]),
            'a negative timeout' => static fn (): mixed
                => $oauth->revoke('vpndetection-cli', 'mo_rt_x', ['timeout' => -1]),
        ];
        foreach ($calls as $name => $call) {
            self::assertInstanceOf(InvalidArgumentException::class, self::settle($call), $name);
        }
        self::assertSame([], $stub->requests);
    }

    /** @return array<string, callable(Client, array<string, mixed>): mixed> */
    private static function timedCalls(): array
    {
        $device = new DeviceAuthorization('mo_dc_x', 'BCDF-GHJK', 'https://app.example.test/device', 900, 1);
        return [
            'metadata' => static fn (Client $c, array $o): mixed => $c->oauth->metadata($o),
            'deviceAuthorization' => static fn (Client $c, array $o): mixed
                => $c->oauth->deviceAuthorization('vpndetection-cli', $o),
            'exchangeDeviceCode' => static fn (Client $c, array $o): mixed
                => $c->oauth->exchangeDeviceCode('vpndetection-cli', 'mo_dc_x', $o),
            'exchangeRefreshToken' => static fn (Client $c, array $o): mixed
                => $c->oauth->exchangeRefreshToken('vpndetection-cli', 'mo_rt_x', $o),
            'revoke' => static fn (Client $c, array $o): mixed
                => $c->oauth->revoke('vpndetection-cli', 'mo_rt_x', $o),
            'pollDeviceToken' => static function (Client $c, array $o) use ($device): mixed {
                (new OauthStub([]))->installClock($c->oauth);
                return $c->oauth->pollDeviceToken('vpndetection-cli', $device, $o);
            },
        ];
    }

    private static function client(OauthStub $stub, ?string $apiKey = null): Client
    {
        return new Client(new Options(apiKey: $apiKey, baseUrl: self::BASE_URL, httpClient: $stub->client));
    }

    /**
     * @param array<string, string> $args
     * @param array<string, mixed> $options
     */
    private static function call(Client $client, string $operation, array $args, array $options = []): mixed
    {
        return match ($operation) {
            'metadata' => $client->oauth->metadata($options),
            'deviceAuthorization' => $client->oauth->deviceAuthorization(
                $args['clientId'],
                array_intersect_key($args, ['scope' => true, 'resource' => true]) + $options,
            ),
            'exchangeDeviceCode' => $client->oauth->exchangeDeviceCode(
                $args['clientId'],
                $args['deviceCode'],
                $options,
            ),
            'exchangeRefreshToken' => $client->oauth->exchangeRefreshToken(
                $args['clientId'],
                $args['refreshToken'],
                $options,
            ),
            'revoke' => $client->oauth->revoke($args['clientId'], $args['token'], $options),
        };
    }

    private static function exchange(OauthStub $stub): mixed
    {
        return self::settle(
            static fn (): mixed => self::client($stub)->oauth->exchangeDeviceCode('vpndetection-cli', 'mo_dc_x'),
        );
    }

    /** The call's value, or what it threw. */
    private static function settle(callable $call): mixed
    {
        try {
            return $call();
        } catch (Throwable $e) {
            return $e;
        }
    }

    /** @param array<string, mixed> $wire */
    private static function device(array $wire): DeviceAuthorization
    {
        return new DeviceAuthorization(
            deviceCode: $wire['device_code'],
            userCode: $wire['user_code'],
            verificationUri: $wire['verification_uri'],
            expiresIn: $wire['expires_in'],
            interval: $wire['interval'],
            verificationUriComplete: $wire['verification_uri_complete'] ?? null,
        );
    }

    /**
     * `type` is oauth (the base class exactly), accessDenied, expiredToken, or
     * client: the ordinary error, which is never an OauthException. A null in the
     * corpus is PHP's null.
     *
     * @param array<string, mixed> $want
     */
    private static function assertOutcome(mixed $outcome, array $want, string $label): void
    {
        self::assertInstanceOf(VPNDetectionException::class, $outcome, "{$label}: settled with a value");
        $class = $outcome::class;
        match ($want['type']) {
            'oauth' => self::assertSame(OauthException::class, $class, $label),
            'accessDenied' => self::assertSame(OauthAccessDeniedException::class, $class, $label),
            'expiredToken' => self::assertSame(OauthExpiredTokenException::class, $class, $label),
            'client' => self::assertSame(VPNDetectionException::class, $class, $label),
        };
        if (array_key_exists('errorCode', $want)) {
            self::assertSame($want['errorCode'], $outcome->errorCode, "{$label}: errorCode");
        }
        if (array_key_exists('errorDescription', $want)) {
            $description = $outcome->errorDescription;
            self::assertSame($want['errorDescription'], $description, "{$label}: errorDescription");
        }
        if (array_key_exists('status', $want)) {
            self::assertSame($want['status'], $outcome->status, "{$label}: status");
        }
        if (array_key_exists('kind', $want)) {
            self::assertSame($want['kind'], $outcome->kind->value, "{$label}: kind");
        }
        if (array_key_exists('retryable', $want)) {
            self::assertSame($want['retryable'], $outcome->isRetryable(), "{$label}: retryable");
        }
        if (array_key_exists('message', $want)) {
            self::assertSame($want['message'], $outcome->getMessage(), "{$label}: message");
        }
    }

    /**
     * @param array{method: string, path: string} $request
     * @param array{method: string, path: string} $want
     */
    private static function assertEndpoint(array $request, array $want, string $label = ''): void
    {
        $got = "{$request['method']} {$request['path']}";
        self::assertSame("{$want['method']} {$want['path']}", $got, $label);
    }

    private static function camel(string $wire): string
    {
        return lcfirst(str_replace('_', '', ucwords($wire, '_')));
    }

    /**
     * @param array<string, string> $fields
     * @return array<string, string>
     */
    private static function sorted(array $fields): array
    {
        ksort($fields);
        return $fields;
    }
}
