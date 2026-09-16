<?php

declare(strict_types=1);

namespace VPNDetection\Integration\Tests;

use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\Integration\Staging;
use VPNDetection\OauthException;
use VPNDetection\OauthExpiredTokenException;
use VPNDetection\Options;

/**
 * The published `oauth` accessor against staging's authorization server, on a
 * client with NO key: none of these requests needs one.
 *
 * Only what is safe to repeat daily. Nothing here polls, since nobody approves a
 * sign-in in CI, and a device authorization is started at most once a run: the
 * server allows 30 a minute per source address, shared with every other SDK's
 * run from the same runner.
 */
final class OauthTest extends TestCase
{
    // Already public in the CLI's source, and the only client staging accepts.
    private const CLIENT_ID = 'vpndetection-cli';

    public function testTheMetadataNamesStagingAsItsIssuer(): void
    {
        $metadata = self::client()->oauth->metadata();

        self::assertSame(Staging::STAGING, $metadata->issuer);
        self::assertNotNull($metadata->deviceAuthorizationEndpoint);
        self::assertContains('S256', $metadata->codeChallengeMethodsSupported ?? []);
    }

    // The server answers 200 for any token, known or not.
    public function testRevokingATokenNobodyHoldsSucceeds(): void
    {
        self::client()->oauth->revoke(self::CLIENT_ID, 'mo_rt_sdk-ci-not-a-token');

        $this->addToAssertionCount(1);
    }

    // An unknown device code is refused before anything is recorded.
    public function testAnUnknownDeviceCodeIsAnExpiredToken(): void
    {
        try {
            self::client()->oauth->exchangeDeviceCode(self::CLIENT_ID, 'mo_dc_sdk-ci-not-a-code');
            self::fail('an unknown device code was exchanged');
        } catch (OauthExpiredTokenException $e) {
            self::assertSame(400, $e->status);
        }
    }

    public function testADeviceAuthorizationStartsOrIsSlowedDown(): void
    {
        try {
            $device = self::client()->oauth->deviceAuthorization(self::CLIENT_ID, ['scope' => 'account.read']);
        } catch (OauthException $e) {
            // Other runs share this runner's address, and slow_down is the server working.
            self::assertSame('slow_down', $e->errorCode);
            return;
        }
        self::assertNotSame('', $device->deviceCode);
        self::assertNotSame('', $device->userCode);
        self::assertStringEndsWith('/device', $device->verificationUri);
        self::assertGreaterThan(0, $device->expiresIn);
        self::assertGreaterThan(0, $device->interval);
    }

    private static function client(): Client
    {
        return new Client(new Options(baseUrl: Staging::STAGING));
    }
}
