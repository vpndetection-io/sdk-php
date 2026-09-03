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
final class Cache
{
    /** @var array<string, array{0: Result, 1: float}> */
    private array $entries = [];

    public function __construct(
        private readonly int $maxSize,
        private readonly float $ttlSeconds,
    ) {
    }

    public function get(string $key): ?Result
    {
        $entry = $this->entries[$key] ?? null;
        if ($entry === null) {
            return null;
        }
        unset($this->entries[$key]);
        if ($entry[1] <= microtime(true)) {
            return null;
        }
        $this->entries[$key] = $entry;
        return $entry[0];
    }

    public function set(string $key, Result $value): void
    {
        unset($this->entries[$key]);
        $this->entries[$key] = [$value, microtime(true) + $this->ttlSeconds];
        while (count($this->entries) > $this->maxSize) {
            unset($this->entries[array_key_first($this->entries)]);
        }
    }
}
