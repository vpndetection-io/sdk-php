<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * The first and last seen members of the bot, SSH, SMTP, web, DNS resolver and
 * BitTorrent details are days (`format: date`), read as `YYYY-MM-DD` strings.
 * Through 4.19.0 they were read as any string, so `x` or `tomorrow` came back
 * as a day, sent once, where every other date the API sends is refused.
 */
final class DayMembersTest extends TestCase
{
    /** Each detail as the API serves it, keyed by its member of the answer. */
    private const DETAILS = [
        'bot' => [
            'provider' => 'google', 'provider_name' => 'Google', 'agents' => ['Googlebot'],
            'categories' => ['search_engine'], 'verified' => true, 'identity' => 'verified',
            'verified_by' => 'list', 'confidence' => 'high',
            'first_seen' => '2026-08-04', 'last_seen' => '2026-11-23',
        ],
        'ssh' => [
            'port' => 22, 'banner' => 'SSH-2.0-OpenSSH_9.6', 'host_key_fp' => 'SHA256:x', 'session_ok' => true,
            'first_seen' => '2026-08-05', 'last_seen' => '2026-11-22',
        ],
        'smtp' => [
            'port' => 25, 'banner' => '220 mx ESMTP', 'session_ok' => true,
            'first_seen' => '2026-08-06', 'last_seen' => '2026-11-21',
        ],
        'web' => [[
            'port' => 443, 'tls_ok' => true, 'session_ok' => true, 'status_code' => 200, 'server' => 'nginx',
            'location' => '', 'title' => 'Welcome', 'cert_subject_cn' => 'example.com', 'cert_subject_o' => '',
            'cert_issuer_dn' => 'CN=R3', 'cert_browser_trusted' => true, 'tls_version' => 'TLS 1.3',
            'first_seen' => '2026-08-07', 'last_seen' => '2026-11-20',
        ]],
        'dns_resolver' => [
            'port' => 53, 'recursion_available' => true, 'rcode' => 0, 'answer_correct' => true,
            'first_seen' => '2026-08-08', 'last_seen' => '2026-11-19',
        ],
        'bittorrent' => [
            'verified' => true, 'id_matches_ip' => true, 'first_seen' => '2026-08-09', 'last_seen' => '2026-11-18',
            'last_reachable' => '', 'days_seen' => 40, 'num_ports' => 1, 'peak_num_ports' => 2, 'indexer' => false,
            'clients' => ['qBittorrent 4.6'],
        ],
    ];

    public function testEveryDetailsSeenDaysReadAsServed(): void
    {
        $result = $this->lookup($this->answer([]));

        $read = [
            'bot' => [$result->bot?->firstSeen, $result->bot?->lastSeen],
            'ssh' => [$result->ssh?->firstSeen, $result->ssh?->lastSeen],
            'smtp' => [$result->smtp?->firstSeen, $result->smtp?->lastSeen],
            'web' => [$result->web[0]->firstSeen ?? null, $result->web[0]->lastSeen ?? null],
            'dns_resolver' => [$result->dnsResolver?->firstSeen, $result->dnsResolver?->lastSeen],
            'bittorrent' => [$result->bittorrent?->firstSeen, $result->bittorrent?->lastSeen],
        ];
        foreach (self::DETAILS as $member => $detail) {
            $served = $member === 'web' ? $detail[0] : $detail;
            self::assertSame([$served['first_seen'], $served['last_seen']], $read[$member], $member);
        }
        self::assertSame('', $result->bittorrent?->lastReachable, 'last_reachable stays a plain string');
    }

    /** @return array<string, array{string}> */
    public static function malformedDays(): array
    {
        return [
            'x' => ['x'],
            'tomorrow' => ['tomorrow'],
            'monday' => ['monday'],
            '30 February' => ['2026-02-30'],
            '24:00' => ['2026-11-23T24:00:00Z'],
            'a date with a time' => ['2026-11-23T10:00:00Z'],
            '+05' => ['2026-11-23+05'],
            'a final newline' => ["2026-11-23\n"],
            'another script\'s digit' => ['2026-11-2٣'],
            'empty' => [''],
        ];
    }

    #[DataProvider('malformedDays')]
    public function testABotsFirstSeenTakesTheDateProbe(string $value): void
    {
        $this->assertSame('2026-08-04', $this->lookup($this->answer([]))->bot?->firstSeen, 'the well-formed answer');
        $this->assertUnreadable($this->answer(['bot' => ['first_seen' => $value]]));
    }

    public function testEachOfTheTwelveRefusesAMalformedDay(): void
    {
        foreach (array_keys(self::DETAILS) as $member) {
            foreach (['first_seen', 'last_seen'] as $seen) {
                $this->assertUnreadable($this->answer([$member => [$seen => 'x']]), "{$member}.{$seen}");
            }
        }
    }

    /**
     * A full answer with every detail populated, one member of one detail
     * replaced as `$patch` says (the web list's first entry for `web`).
     *
     * @param array<string, array<string, string>> $patch
     * @return array<string, mixed>
     */
    private function answer(array $patch): array
    {
        $answer = ['ip' => '9.9.9.9', 'is_vpn' => false, 'is_bot' => true, 'is_ssh' => true, 'is_smtp' => true,
            'is_web' => true, 'is_dns_resolver' => true, 'is_bittorrent' => true];
        foreach (self::DETAILS as $member => $detail) {
            $over = $patch[$member] ?? [];
            $answer[$member] = $member === 'web' ? [array_replace($detail[0], $over)] : array_replace($detail, $over);
        }
        return $answer;
    }

    /** @param array<string, mixed> $body */
    private function lookup(array $body): Result
    {
        $stub = new Stub(['/9.9.9.9' => Stub::ok($body)]);
        $result = (new Client(new Options(apiKey: 'k', cache: false, httpClient: $stub->client)))->lookup('9.9.9.9');
        self::assertCount(1, $stub->calls, 'read at once');
        return $result;
    }

    /** @param array<string, mixed> $body */
    private function assertUnreadable(array $body, string $what = ''): void
    {
        $stub = new Stub(['/9.9.9.9' => Stub::ok($body)]);
        $client = new Client(new Options(apiKey: 'k', cache: false, retries: 2, httpClient: $stub->client));
        try {
            $answer = $client->lookup('9.9.9.9');
            self::fail("{$what}: answered " . json_encode($answer));
        } catch (VPNDetectionException $e) {
            self::assertSame(ErrorKind::ServerError, $e->kind, $what);
            self::assertSame(200, $e->status, "{$what}: the status");
        }
        self::assertCount(3, $stub->calls, "{$what}: retried like an outage");
    }
}
