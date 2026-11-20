<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * @internal
 *
 * A bounded cache with a TTL, per client instance.
 *
 * PHP arrays are ordered hash maps, so deleting a key and writing it back moves
 * it to the end in O(1). That is the whole LRU: the front of the array is the
 * least recently used entry and eviction is one unset.
 */
final class Cache implements AnswerCache
{
    /** The longest a spent trial's or a reached cap's answer is held, in seconds. */
    public const REDUCED_TTL_SECONDS = 60;

    /** @var array<string, array{0: Result, 1: float}> */
    private array $entries = [];

    public function __construct(
        private readonly int $maxSize,
        private readonly float $ttlSeconds,
    ) {
    }

    public function get(string $ip): ?Result
    {
        $entry = $this->entries[$ip] ?? null;
        if ($entry === null) {
            return null;
        }
        unset($this->entries[$ip]);
        if ($entry[1] <= microtime(true)) {
            return null;
        }
        $this->entries[$ip] = $entry;
        return $entry[0];
    }

    public function getMany(array $ips): array
    {
        $hits = [];
        foreach ($ips as $ip) {
            $hit = $this->get($ip);
            if ($hit !== null) {
                $hits[$ip] = $hit;
            }
        }
        return $hits;
    }

    public function set(string $ip, Result $value): void
    {
        unset($this->entries[$ip]);
        $this->entries[$ip] = [$value, microtime(true) + self::lifeOf($value, $this->ttlSeconds)];
        while (count($this->entries) > $this->maxSize) {
            unset($this->entries[array_key_first($this->entries)]);
        }
    }

    public function setMany(array $values): void
    {
        foreach ($values as $ip => $value) {
            $this->set((string) $ip, $value);
        }
    }

    /** When the answer held for `$ip` goes stale, as `microtime(true)` reads, or null. */
    public function expiry(string $ip): ?float
    {
        return isset($this->entries[$ip]) ? $this->entries[$ip][1] : null;
    }

    /**
     * How long an answer stays: the TTL, or at most a minute for one marked
     * `trialExpired` or `capReached`, which the trial's renewal or a raised cap
     * ends. Still cached, so a busy process does not send every repeat of an
     * address to the API.
     */
    public static function lifeOf(Result $value, float $ttlSeconds): float
    {
        if ($value->trialExpired === true || $value->capReached === true) {
            return min($ttlSeconds, self::REDUCED_TTL_SECONDS);
        }
        return $ttlSeconds;
    }
}
