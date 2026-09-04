<?php

declare(strict_types=1);

namespace VPNDetection\Integration\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use VPNDetection\Bogon;
use VPNDetection\Client;
use VPNDetection\Integration\Staging;
use VPNDetection\Integration\Tiers;
use VPNDetection\Options;
use VPNDetection\Result;

/**
 * The published package looking addresses up against the staging API.
 *
 * Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each
 * one serving a superset of the tier below it, so a pricing change stays a
 * pricing change instead of arriving as a red SDK build.
 */
final class LookupTest extends TestCase
{
    public function testAnUnauthenticatedLookupAnswersIpAndIsVpn(): void
    {
        $fixture = Staging::answerFor(Tiers::unauth());

        self::assertSame(Staging::PROBE, $fixture['result']->raw['ip']);
        self::assertIsBool($fixture['result']->raw['is_vpn']);
        Staging::assertServedByTier($fixture);
    }

    /** @param array{tier: string, secret: string|null, widens: bool} $rung */
    #[DataProvider('keyedTiers')]
    public function testAKeyReachesTheWireAndItsAnswerKeepsTheShape(array $rung): void
    {
        $this->skipUnlessObservable($rung);

        Staging::assertServedByTier(Staging::answerFor($rung));
    }

    public function testEachTierServesASupersetOfTheTierBelow(): void
    {
        $this->skipWithoutALadder();

        $below = null;
        foreach (Tiers::observable() as $rung) {
            $fields = array_keys(Staging::answerFor($rung)['result']->raw);
            print "{$rung['tier']}: " . count($fields) . " fields\n";
            if ($below !== null) {
                foreach ($below['fields'] as $field) {
                    self::assertContains($field, $fields, "{$rung['tier']} drops a field {$below['tier']} serves");
                }
                // Without this a run whose keys all resolved to one plan would
                // pass: identical sets satisfy containment in both directions.
                if ($rung['widens']) {
                    self::assertGreaterThan(
                        count($below['fields']),
                        count($fields),
                        "{$rung['tier']} answers no more fields than {$below['tier']}",
                    );
                }
            }
            $below = ['tier' => $rung['tier'], 'fields' => $fields];
        }
    }

    public function testAFieldAHigherTierServesIsAbsentOnALowerOneNeverFalse(): void
    {
        $this->skipWithoutALadder();

        $props = Staging::resultProps();
        $rungs = Tiers::observable();
        $fixtures = array_map(Staging::answerFor(...), $rungs);
        $compared = 0;

        foreach ($fixtures as $i => $fixture) {
            $lower = $fixture['result'];
            $above = [];
            foreach (array_slice($fixtures, $i + 1) as $higher) {
                $above = [...$above, ...array_keys($higher['result']->raw)];
            }
            foreach (array_unique($above) as $field) {
                if (array_key_exists($field, $lower->raw) || !isset($props[$field])) {
                    continue;
                }
                self::assertNull(
                    $lower->{$props[$field]},
                    "{$field} is not in the {$rungs[$i]['tier']} plan, so {$props[$field]} must read as null",
                );
                $compared++;
            }
        }

        // Every tier answering the same fields makes this test a no-op, which is
        // what a run whose keys all resolved to one plan looks like. Say so
        // rather than passing on nothing.
        if ($compared === 0) {
            self::markTestSkipped('no observable tier serves a field another one lacks');
        }
    }

    public function testABogonIsAnsweredWithoutTouchingTheNetwork(): void
    {
        $offline = new Client(new Options(
            baseUrl: Staging::STAGING,
            httpClient: new GuzzleClient(['handler' => HandlerStack::create(
                static function (RequestInterface $request): never {
                    throw new RuntimeException('the bogon path reached the network');
                },
            )]),
        ));

        $r = $offline->lookup('10.0.0.1');

        self::assertTrue($r->isBogon);
        self::assertFalse($r->isVpn);
        self::assertTrue(Bogon::isBogon('10.0.0.1'), 'the standalone form must agree');
        foreach (array_keys(Staging::MEMBERS) as $name) {
            self::assertFalse($r->{Staging::flagProp($name)}, "a bogon must answer {$name} false, not null");
            self::assertTrue($r->$name->isEmpty(), "a bogon must carry an empty {$name}");
        }
    }

    public function testABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire(): void
    {
        // Distinct paths rather than a call count, so a retry against a wobbling
        // staging cannot read as a failure to deduplicate.
        $asked = [];
        $client = Staging::clientFor(Tiers::unauth(), static function (array $fact) use (&$asked): void {
            $asked[$fact['path']] = true;
        });

        $got = $client->lookupBatch([Staging::PROBE, '8.8.8.8', Staging::PROBE, '10.0.0.1', '8.8.8.8']);

        self::assertSame([Staging::PROBE, '8.8.8.8', '10.0.0.1'], array_keys($got));
        $paths = array_keys($asked);
        $wanted = ['/8.8.8.8', '/' . Staging::PROBE];
        sort($paths);
        sort($wanted);
        self::assertSame($wanted, $paths, 'the batch asked for something other than the two servable addresses');
        self::assertTrue($got['10.0.0.1']->isBogon);
        foreach ([Staging::PROBE, '8.8.8.8'] as $ip) {
            self::assertInstanceOf(Result::class, $got[$ip], "{$ip} failed");
            Staging::assertShape($got[$ip]);
        }
    }

    /** @return iterable<string, array{array{tier: string, secret: string|null, widens: bool}}> */
    public static function keyedTiers(): iterable
    {
        foreach (Tiers::RUNGS as $rung) {
            if ($rung['secret'] !== null) {
                yield $rung['tier'] => [$rung];
            }
        }
    }

    /** @param array{tier: string, secret: string|null, widens: bool} $rung */
    private function skipUnlessObservable(array $rung): void
    {
        $reason = Tiers::skipFor($rung);
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
    }

    // The ladder needs two rungs to say anything. The unauthenticated one is
    // always there, so this only fires when no tier secret at all is configured.
    private function skipWithoutALadder(): void
    {
        if (count(Tiers::observable()) < 2) {
            self::markTestSkipped('no tier secret is set, so there is no ladder to compare');
        }
    }
}
