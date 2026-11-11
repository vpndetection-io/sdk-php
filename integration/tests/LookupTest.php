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
use VPNDetection\ErrorKind;
use VPNDetection\Integration\Staging;
use VPNDetection\Integration\Tiers;
use VPNDetection\Options;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * The published package looking addresses up against the staging API.
 *
 * Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each
 * one serving a superset of the tier below it, so a pricing change stays a
 * pricing change instead of arriving as a red SDK build.
 */
final class LookupTest extends TestCase
{
    public function testALookupWithoutAKeyAnswersIpAndIsVpnAtTheLeast(): void
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
            // trial_expired marks a trial key's answers, and no other: it is not a
            // field a tier serves.
            $fields = array_values(array_diff(array_keys(Staging::answerFor($rung)['result']->raw), ['trial_expired']));
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
            if ($rung['tier'] !== 'trial') {
                $below = ['tier' => $rung['tier'], 'fields' => $fields];
            }
        }
    }

    public function testAFreePlanKeysAnswerIsAPaidOneOrUnlimitedsAndSaysWhich(): void
    {
        $reason = Tiers::skipFor(Tiers::trial());
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
        $raw = Staging::answerFor(Tiers::trial())['result']->raw;

        self::assertIsBool($raw['trial_expired'] ?? null, 'a free-plan key answers trial_expired');
        // The organization's first 100 lookups of the UTC day are answered in
        // full, and the rest as Unlimited's: which half a run sees depends on the day.
        self::assertSame(!$raw['trial_expired'], array_key_exists('is_hosting', $raw));
    }

    public function testAFreePlanKeysBatchOfTwoIsRefusedAsABadRequestOnce(): void
    {
        $reason = Tiers::skipFor(Tiers::trial());
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
        $paths = [];
        $client = Staging::clientFor(Tiers::trial(), static function (array $fact) use (&$paths): void {
            $paths[] = $fact['path'];
        });

        $got = $client->lookupBatch([Staging::PROBE, '8.8.8.8']);

        foreach ([Staging::PROBE, '8.8.8.8'] as $ip) {
            $refused = $got[$ip];
            self::assertInstanceOf(VPNDetectionException::class, $refused, "{$ip}: a free-plan key's batch of two must fail");
            self::assertSame(ErrorKind::BadRequest, $refused->kind);
            self::assertSame(402, $refused->status);
            self::assertFalse($refused->isRetryable());
        }
        self::assertSame(['/batch'], $paths, 'one request, never retried');
    }

    public function testAFreePlanKeysBatchOfOneIsAnswered(): void
    {
        $reason = Tiers::skipFor(Tiers::trial());
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
        $got = Staging::clientFor(Tiers::trial())->lookupBatch([Staging::PROBE]);

        $answer = $got[Staging::PROBE];
        self::assertInstanceOf(Result::class, $answer, 'a free-plan key\'s batch of one failed');
        self::assertIsBool($answer->raw['trial_expired'] ?? null, 'the answer carries trial_expired');
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

    public function testABatchWithoutAKeyIsRefusedOnceAndItsBogonStillAnswered(): void
    {
        $paths = [];
        $client = Staging::clientFor(Tiers::unauth(), static function (array $fact) use (&$paths): void {
            $paths[] = $fact['path'];
        });

        $got = $client->lookupBatch([Staging::PROBE, '10.0.0.1']);

        self::assertTrue($got['10.0.0.1']->isBogon);
        $refused = $got[Staging::PROBE];
        self::assertInstanceOf(VPNDetectionException::class, $refused, 'a batch without a key must fail');
        self::assertSame(ErrorKind::Unauthorized, $refused->kind);
        self::assertSame(401, $refused->status);
        self::assertFalse($refused->isRetryable());
        self::assertSame(['/batch'], $paths, 'one request, never retried');
    }

    public function testABatchCollapsesDuplicatesAndKeepsBogonsOffTheWire(): void
    {
        // A batch needs a paid plan, and starter is the cheapest.
        $reason = Tiers::skipFor(Tiers::paid());
        if ($reason !== null) {
            self::markTestSkipped($reason);
        }
        // Distinct requests rather than a call count, so a retry against a
        // wobbling staging cannot read as a failure to deduplicate.
        $asked = [];
        $carried = true;
        $client = Staging::clientFor(Tiers::paid(), static function (array $fact) use (&$asked, &$carried): void {
            $asked[$fact['path'] . ' ' . implode(',', $fact['ips'])] = true;
            $carried = $carried && $fact['carriedKey'];
        });

        $got = $client->lookupBatch([Staging::PROBE, '8.8.8.8', Staging::PROBE, '10.0.0.1', '8.8.8.8']);

        self::assertSame([Staging::PROBE, '8.8.8.8', '10.0.0.1'], array_keys($got));
        self::assertSame(
            ['/batch ' . Staging::PROBE . ',8.8.8.8'],
            array_keys($asked),
            'the batch asked for something other than the two servable addresses, in one POST /batch',
        );
        self::assertTrue($carried, 'the paid key never reached the wire');
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
