<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * @internal
 *
 * Where a client keeps its answers: its own memory, or a PSR-16 store that
 * outlives it. Keyed by the address, or by the address and the user agent a
 * lookup sent, which the client joins into one string.
 */
interface AnswerCache
{
    public function get(string $ip): ?Result;

    /**
     * @param list<string> $ips
     * @return array<string, Result> The addresses held, each with its answer.
     */
    public function getMany(array $ips): array;

    public function set(string $ip, Result $value): void;

    /** @param array<string, Result> $values Keyed by address. */
    public function setMany(array $values): void;
}
