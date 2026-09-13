<?php

declare(strict_types=1);

namespace VPNDetection\Middleware;

/**
 * The shared client-address selectors, bound to one framework's request type.
 *
 * An adapter passes a function exposing its request once and gets these back, so a
 * caller writing a custom selector still works with the object they know.
 *
 * There is no portable default: a framework's own accessor may return the socket peer,
 * or may already have walked a proxy chain, depending on the framework and on how the
 * application configured it. You know your framework and your edge.
 */
final class Selectors
{
    /** @param callable(mixed): RequestView $view */
    public function __construct(private readonly mixed $view)
    {
    }

    /** The framework's own client-address accessor. */
    public function default(): callable
    {
        return fn (mixed $request): ?string => ($this->view)($request)->frameworkIp();
    }

    /**
     * An address from `X-Forwarded-For`.
     *
     * The LEFT-MOST entry (depth 0) is whatever the caller sent, because proxies
     * append to this header, so a visitor who sets it themselves appears first and
     * this returns their forgery. It is only trustworthy when an edge you control
     * overwrites the header. When you know how many proxies sit in front, count from
     * the right: depth 1 is the address your nearest proxy saw.
     */
    public function xff(int $depth = 0): callable
    {
        return function (mixed $request) use ($depth): ?string {
            $seen = ($this->view)($request);
            $raw = $seen->header('X-Forwarded-For') ?? '';
            $chain = array_values(array_filter(array_map('trim', explode(',', $raw)), 'strlen'));
            if ($chain === []) {
                return $seen->frameworkIp();
            }
            if ($depth <= 0 || $depth > count($chain)) {
                return $chain[0];
            }
            return $chain[count($chain) - $depth];
        };
    }

    /**
     * An address from a single-value header your edge writes -
     * `header('CF-Connecting-IP')` behind Cloudflare. Falls back to the framework's
     * accessor when the header is absent.
     */
    public function header(string $name): callable
    {
        return function (mixed $request) use ($name): ?string {
            $seen = ($this->view)($request);
            $value = trim($seen->header($name) ?? '');
            return $value !== '' ? $value : $seen->frameworkIp();
        };
    }
}
