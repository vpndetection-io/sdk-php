<?php

declare(strict_types=1);

namespace VPNDetection\Middleware;

/**
 * Enough of an incoming request for a selector to work with, whatever framework it
 * came from. An adapter supplies one of these per request.
 */
final class RequestView
{
    public function __construct(
        /** @var callable(string): ?string A request header by name, case-insensitively. */
        public readonly mixed $header,
        /** @var callable(): ?string The framework's own client-address accessor. */
        public readonly mixed $frameworkIp,
    ) {
    }

    public function header(string $name): ?string
    {
        return ($this->header)($name);
    }

    public function frameworkIp(): ?string
    {
        return ($this->frameworkIp)();
    }
}
