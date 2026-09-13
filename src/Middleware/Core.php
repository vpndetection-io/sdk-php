<?php

declare(strict_types=1);

namespace VPNDetection\Middleware;

use VPNDetection\Bogon;
use VPNDetection\Client;
use VPNDetection\ErrorKind;
use VPNDetection\Options as ClientOptions;
use VPNDetection\Result;
use VPNDetection\VPNDetectionException;

/**
 * The framework-agnostic half of a web middleware: resolve a client address, classify
 * it, and decide whether the condition matched.
 *
 * An adapter - vpndetection/laravel, vpndetection/symfony - keeps only the parts that
 * are genuinely framework-shaped and shares everything here, so the shared conformance
 * corpus is asserted once for PHP rather than once per framework.
 */
final class Core
{
    private readonly Client $client;
    /** @var callable(mixed): ?string */
    private readonly mixed $selector;
    /** @var array<string, true> */
    private array $warned = [];

    /** @param callable(mixed): ?string $defaultIpSelector */
    public function __construct(
        private readonly Options $options,
        callable $defaultIpSelector,
    ) {
        Condition::validate($options->blockCondition);
        $this->selector = $options->ipSelector ?? $defaultIpSelector;
        $this->client = $options->client ?? new Client(new ClientOptions(
            apiKey: $options->apiKey,
            baseUrl: $options->baseUrl ?? Client::DEFAULT_BASE_URL,
            retries: $options->retries,
            timeout: $options->timeout,
        ));
    }

    /** Whether a condition was configured at all. */
    public function blocking(): bool
    {
        return $this->options->blockCondition !== null;
    }

    /**
     * Classify one request. Answers null when `skip` claimed it.
     *
     * A failed LOOKUP is not thrown: it lands on `Lookup::$error` and the request is
     * let through. What CAN throw is a misconfiguration - a condition naming a member
     * the plan does not serve, with `onMissingField` set to throw.
     */
    public function evaluate(mixed $request): ?Lookup
    {
        if ($this->options->skip !== null && ($this->options->skip)($request) === true) {
            return null;
        }
        $ip = trim(($this->selector)($request) ?? '');
        if ($ip === '') {
            $this->warn(
                'could not resolve a client address from this request; pass an ipSelector '
                . 'that knows where yours comes from'
            );
            return new Lookup(
                blocked: $this->options->failClosed,
                error: new VPNDetectionException(
                    ErrorKind::BadRequest,
                    'no client address on the request'
                ),
            );
        }
        if (Bogon::isBogon($ip)) {
            // Expected in local development. Anywhere else it means a proxy sits in
            // front and its own address is what reached us.
            $this->warn(
                "resolved the client address as {$ip}, which is not a public address. If "
                . 'this application runs behind a proxy or load balancer, configure its '
                . "trusted-proxy setting or pass an ipSelector that reads your edge's header."
            );
        }

        try {
            $result = $this->client->lookup($ip);
        } catch (VPNDetectionException $error) {
            return new Lookup(blocked: $this->options->failClosed, ip: $ip, error: $error);
        }
        return $this->decide($ip, $result);
    }

    private function decide(string $ip, Result $result): Lookup
    {
        $condition = $this->options->blockCondition;
        if ($condition === null) {
            return new Lookup(blocked: false, ip: $ip, result: $result);
        }
        $this->reportMissing($condition, $result);
        return new Lookup(
            blocked: Condition::matches($condition, $result),
            ip: $ip,
            result: $result,
        );
    }

    /** @param array<mixed> $condition */
    private function reportMissing(array $condition, Result $result): void
    {
        if ($this->options->onMissingField === 'ignore') {
            return;
        }
        $missing = Condition::missingMembers($condition, $result);
        if ($missing === []) {
            return;
        }
        $message = 'blockCondition names ' . implode(', ', $missing) . ', which your plan does '
            . 'not include, so those terms can never match. An absent member means "not in your '
            . 'plan", not "checked, and no".';
        if ($this->options->onMissingField === 'throw') {
            throw new \RuntimeException("vpndetection: {$message}");
        }
        $this->warn($message);
    }

    // A misconfiguration is the same on every request, so saying so once is a warning
    // and saying so a million times is an outage of its own.
    private function warn(string $message): void
    {
        if (isset($this->warned[$message])) {
            return;
        }
        $this->warned[$message] = true;
        if ($this->options->onWarn !== null) {
            ($this->options->onWarn)($message);
            return;
        }
        error_log("[vpndetection] {$message}");
    }
}
