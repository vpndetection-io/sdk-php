<?php

declare(strict_types=1);

namespace VPNDetection;

use Psr\SimpleCache\CacheInterface;
use Throwable;
use VPNDetection\Internal\Model\LookupResponse;

/**
 * @internal
 *
 * Answers kept in a PSR-16 store, so they outlive the client: under PHP-FPM and
 * mod_php the application, and every client in it, is built for each request.
 *
 * An entry holds the answer as it came off the wire and is read back the way a
 * response is, so an entry written by another release of this package is read
 * or missed, never half-built. A store that fails is a miss: the lookup it was
 * meant to save is never the thing that breaks.
 */
final class StoreCache implements AnswerCache
{
    private readonly int $ttlSeconds;

    /**
     * @param string $scope What else an answer depends on besides the address:
     *     the API key, whose plan decides the fields served, and the base URL.
     */
    public function __construct(
        private readonly CacheInterface $store,
        float $ttlSeconds,
        private readonly string $scope,
    ) {
        $this->ttlSeconds = max(1, (int) ceil($ttlSeconds));
    }

    public function get(string $ip): ?Result
    {
        return $this->getMany([$ip])[$ip] ?? null;
    }

    public function getMany(array $ips): array
    {
        if ($ips === []) {
            return [];
        }
        $byKey = [];
        foreach ($ips as $ip) {
            $byKey[$this->key($ip)] = $ip;
        }
        $hits = [];
        try {
            foreach ($this->store->getMultiple(array_keys($byKey)) as $key => $raw) {
                $ip = $byKey[$key] ?? null;
                $result = $ip === null || !is_array($raw) ? null : self::read($raw);
                if ($result !== null) {
                    $hits[$ip] = $result;
                }
            }
        } catch (Throwable) {
            return [];
        }
        return $hits;
    }

    public function set(string $ip, Result $value): void
    {
        $this->setMany([$ip => $value]);
    }

    public function setMany(array $values): void
    {
        if ($values === []) {
            return;
        }
        $entries = [];
        foreach ($values as $ip => $result) {
            $entries[$this->key((string) $ip)] = $result->raw;
        }
        try {
            $this->store->setMultiple($entries, $this->ttlSeconds);
        } catch (Throwable) {
        }
    }

    // Within the 64 characters of A-Z, a-z, 0-9, `_` and `.` every PSR-16 store
    // must accept, and with neither the key nor the address in the clear.
    private function key(string $ip): string
    {
        return 'vpndetection.' . substr(hash('sha256', $this->scope . "\0" . $ip), 0, 48);
    }

    /** @param array<mixed> $raw */
    private static function read(array $raw): ?Result
    {
        try {
            return Result::fromWire(
                Transport::toModel(json_encode($raw, JSON_THROW_ON_ERROR), LookupResponse::class, stored: true),
                $raw,
            );
        } catch (Throwable) {
            return null;
        }
    }
}
