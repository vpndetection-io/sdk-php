<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use DateInterval;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * A PSR-16 store in memory, standing in for a framework's cache, that records the
 * TTL of every write and can be made to fail as a store across the network does.
 */
final class ArrayStore implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $values = [];

    /** @var list<null|int|DateInterval> */
    public array $ttls = [];

    public int $reads = 0;

    public bool $failing = false;

    public function get(string $key, mixed $default = null): mixed
    {
        $this->fail();
        $this->reads++;
        return $this->values[$key] ?? $default;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->fail();
        $this->values[$key] = $value;
        $this->ttls[] = $ttl;
        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key]);
        return true;
    }

    public function clear(): bool
    {
        $this->values = [];
        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $this->fail();
        $this->reads++;
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $this->values[$key] ?? $default;
        }
        return $out;
    }

    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $this->fail();
        foreach ($values as $key => $value) {
            $this->values[$key] = $value;
        }
        $this->ttls[] = $ttl;
        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            unset($this->values[$key]);
        }
        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    private function fail(): void
    {
        if ($this->failing) {
            throw new RuntimeException('the store is down');
        }
    }
}
