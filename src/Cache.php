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
        $this->entries[$ip] = [$value, microtime(true) + $this->ttlSeconds];
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
}
