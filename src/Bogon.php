<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * The standalone bogon predicate.
 *
 * PHP forbids a static and an instance method of the same name in one class, so
 * the form that needs no client lives here while `Client::isBogon()` is what the
 * README teaches.
 */
final class Bogon
{
    /**
     * Whether an address is a bogon: private, loopback, link-local,
     * documentation, multicast or otherwise not routable on the public internet,
     * including the IPv6 equivalents and the 6to4 and Teredo ranges that wrap
     * them.
     *
     * These can never be VPN or proxy infrastructure, so the client answers them
     * itself and they never cost a request.
     */
    public static function isBogon(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $packed = inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach (strlen($packed) === 4 ? self::v4() : self::v6() as [$net, $mask]) {
            if (($packed & $mask) === $net) {
                return true;
            }
        }
        return false;
    }

    /**
     * The answer a bogon gets, in the full shape the API serves at its widest
     * plan: every flag present and false, every detail object present and empty.
     *
     * `isBogon` is set so a caller can always tell a locally computed answer from
     * a served one. Note this is deliberately the WIDEST shape regardless of your
     * plan, so do not infer which fields your plan includes from a bogon answer.
     */
    public static function result(string $ip): Result
    {
        return new Result(
            ip: $ip,
            isVpn: false,
            isBogon: true,
            isHosting: false,
            isRelay: false,
            isTor: false,
            isCdn: false,
            isResproxy: false,
            isDcproxy: false,
            isMobproxy: false,
            vpn: new VpnDetail(),
            hosting: new ClassDetail(),
            relay: new ClassDetail(),
            tor: new ClassDetail(),
            cdn: new ClassDetail(),
            resproxy: new ProxyDetail(),
            dcproxy: new ProxyDetail(),
            mobproxy: new ProxyDetail(),
            raw: [],
        );
    }

    /** @var list<array{0: string, 1: string}>|null */
    private static ?array $v4 = null;

    /** @var list<array{0: string, 1: string}>|null */
    private static ?array $v6 = null;

    // Parsed on first use rather than at class load: a consumer that never looks
    // up an address should not pay for the table, which matters more in PHP than
    // elsewhere because a web request pays it again on every hit.

    /** @return list<array{0: string, 1: string}> */
    private static function v4(): array
    {
        return self::$v4 ??= self::parse(Bogons::V4, 4);
    }

    /** @return list<array{0: string, 1: string}> */
    private static function v6(): array
    {
        return self::$v6 ??= self::parse(Bogons::V6, 16);
    }

    /**
     * CIDRs become packed network and mask byte strings, so containment is one
     * bytewise AND rather than any integer arithmetic 32 bits too wide for PHP.
     *
     * @param list<string> $cidrs
     * @return list<array{0: string, 1: string}>
     */
    private static function parse(array $cidrs, int $width): array
    {
        $out = [];
        foreach ($cidrs as $cidr) {
            [$net, $bits] = explode('/', $cidr, 2);
            $mask = self::mask((int) $bits, $width);
            $out[] = [inet_pton($net) & $mask, $mask];
        }
        return $out;
    }

    private static function mask(int $bits, int $width): string
    {
        $full = intdiv($bits, 8);
        $rem = $bits % 8;
        return str_repeat("\xff", $full)
            . ($rem === 0 ? '' : chr((0xff << (8 - $rem)) & 0xff))
            . str_repeat("\x00", $width - $full - ($rem === 0 ? 0 : 1));
    }
}
