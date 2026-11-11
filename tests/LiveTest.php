<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\Options;

/**
 * Hits production. Skipped unless VPNDETECTION_LIVE=1, so the normal suite stays
 * offline and costs no quota.
 *
 *   VPNDETECTION_LIVE=1 ./scripts/test.sh --filter LiveTest
 */
final class LiveTest extends TestCase
{
    protected function setUp(): void
    {
        if (getenv('VPNDETECTION_LIVE') !== '1') {
            self::markTestSkipped('set VPNDETECTION_LIVE=1 to run the live check');
        }
    }

    public function testALookupWithoutAKeyAnswersTheShapeItPromises(): void
    {
        $client = new Client();

        $vpn = $client->lookup('45.83.91.1');
        self::assertSame('45.83.91.1', $vpn->ip);
        self::assertTrue($vpn->isVpn);

        $clean = $client->lookup('1.1.1.1');
        self::assertFalse($clean->isVpn);

        // The assertion a stub cannot make honestly: without a key the members a
        // key adds are ABSENT, which is not the same answer as false.
        self::assertNull($clean->isHosting);
        self::assertNull($clean->hosting);
        self::assertNull($clean->vpn);
        self::assertArrayNotHasKey('is_hosting', $clean->raw);
    }

    public function testAKeyRaisesTheShape(): void
    {
        $key = getenv('VPNDETECTION_API_KEY');
        if ($key === false || $key === '') {
            self::markTestSkipped('set VPNDETECTION_API_KEY to check a keyed plan');
        }
        $client = new Client(new Options(apiKey: $key));

        $result = $client->lookup('45.83.91.1');

        self::assertTrue($result->isVpn);
        self::assertNotNull($result->vpn);
    }
}
