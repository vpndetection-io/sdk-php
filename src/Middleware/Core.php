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
    /** The most crawler agents one address is looked up with while it is remembered. */
    public const MAX_AGENTS_PER_ADDRESS = 4;

    /** How long an address's crawler agents are remembered, from its first: the client's default cache TTL. */
    private const AGENTS_TTL_SECONDS = 3600;
    private const AGENTS_MAX_ADDRESSES = 10_000;
    private const AGENTS_MAX_BYTES = 4_000_000;

    private readonly Client $client;
    /** @var callable(mixed): ?string */
    private readonly mixed $selector;
    /** @var array<string, true> */
    private array $warned = [];
    /**
     * The crawler agents each address was looked up with, least recently used first.
     *
     * @var array<string, array{0: float, 1: list<string>}> Address => [expiry, agents]
     */
    private array $agents = [];
    private int $agentBytes = 0;

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
            cacheStore: $options->cacheStore,
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
     *
     * @param ?string $userAgent The request's own `User-Agent` header, sent with the
     *     lookup when `allowBots` is on and it names a crawler; any other, null or
     *     empty sends none.
     */
    public function evaluate(mixed $request, ?string $userAgent = null): ?Lookup
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

        $claim = $this->options->allowBots ? $this->claim($ip, $userAgent) : null;
        $agent = $claim ?? '';
        try {
            $result = $this->client->lookup($ip, $agent === '' ? [] : ['userAgent' => $agent]);
        } catch (VPNDetectionException $error) {
            return new Lookup(blocked: $this->options->failClosed, ip: $ip, error: $error);
        }
        if ($agent !== '' && $result->userAgent === null) {
            $this->reportUnjudged();
        }
        return $this->decide($ip, $result, $claim);
    }

    /**
     * Whether a `User-Agent` names a crawler, the only kind of agent whose verdict can be
     * `verified` or `spoofed`. It errs toward a match, which costs a lookup.
     */
    public static function namesCrawler(string $agent): bool
    {
        $lower = strtr($agent, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
        foreach (Crawlers::TERMS as $term) {
            if (str_contains($lower, $term)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param ?string $claim What the request's agent came to: null when it names no crawler,
     *     '' when its address is past the bound, else the agent the lookup sent.
     */
    private function decide(string $ip, Result $result, ?string $claim): Lookup
    {
        $condition = $this->options->blockCondition;
        if ($condition === null) {
            return new Lookup(blocked: false, ip: $ip, result: $result);
        }
        // A request that sent no agent has no verdict to lack, whatever the plan serves.
        $this->reportMissing($condition, $result, $this->options->allowBots && ($claim ?? '') === '');
        // A crawler its operator vouches for is let through whatever else matched.
        // Past the bound no agent was sent, so only the operator's own vouching counts.
        $verified = $claim !== null && ($claim === ''
            ? $result->bot?->verified === true
            : $result->userAgent?->verdict === 'verified');
        return new Lookup(
            blocked: !$verified && Condition::matches($condition, $result),
            ip: $ip,
            result: $result,
        );
    }

    /**
     * What this request's agent comes to: null when it names no crawler, '' when its address
     * already sent the bound's worth of others, else the agent, now remembered.
     */
    private function claim(string $ip, ?string $header): ?string
    {
        if ($header === null || $header === '' || !self::namesCrawler($header)) {
            return null;
        }
        $now = microtime(true);
        $expires = $now + self::AGENTS_TTL_SECONDS;
        $known = [];
        if (isset($this->agents[$ip])) {
            [$until, $list] = $this->agents[$ip];
            $this->agentBytes -= self::weigh($list);
            unset($this->agents[$ip]);
            if ($until > $now) {
                [$expires, $known] = [$until, $list];
            }
        }
        $claim = $header;
        if (!in_array($header, $known, true)) {
            if (count($known) >= self::MAX_AGENTS_PER_ADDRESS) {
                $claim = '';
            } else {
                $known[] = $header;
            }
        }
        $this->remember($ip, $expires, $known);
        return $claim;
    }

    /** @param list<string> $agents */
    private function remember(string $ip, float $expires, array $agents): void
    {
        $weight = self::weigh($agents);
        if ($weight > self::AGENTS_MAX_BYTES) {
            return;
        }
        $this->agents[$ip] = [$expires, $agents];
        $this->agentBytes += $weight;
        while (count($this->agents) > self::AGENTS_MAX_ADDRESSES || $this->agentBytes > self::AGENTS_MAX_BYTES) {
            $oldest = array_key_first($this->agents);
            $this->agentBytes -= self::weigh($this->agents[$oldest][1]);
            unset($this->agents[$oldest]);
        }
    }

    /** @param list<string> $agents */
    private static function weigh(array $agents): int
    {
        return array_sum(array_map('strlen', $agents)) ?: 1;
    }

    // A served answer without `user_agent` judged nothing, so allowBots can let no
    // crawler through: only an answer with every field carries the verdict.
    private function reportUnjudged(): void
    {
        $this->reportGap(
            'allowBots sent the request\'s User-Agent, but the answer carried no user_agent '
            . 'verdict, which your plan does not include, so no verified crawler is let through. '
            . 'Only an answer with every field, on a paid plan or the trial, carries it.'
        );
    }

    /**
     * @param array<mixed> $condition
     * @param bool $unsent Whether this request sent no agent, so its answer cannot carry `userAgent`.
     */
    private function reportMissing(array $condition, Result $result, bool $unsent): void
    {
        if ($this->options->onMissingField === 'ignore') {
            return;
        }
        $missing = Condition::missingMembers($condition, $result);
        if ($unsent) {
            $missing = array_values(array_diff($missing, ['userAgent']));
        }
        if ($missing === []) {
            return;
        }
        $message = 'blockCondition names ' . implode(', ', $missing) . ', which your plan does '
            . 'not include, so those terms can never match. An absent member means "not in your '
            . 'plan", not "checked, and no".';
        if (in_array('userAgent', $missing, true) && !$this->options->allowBots) {
            $message .= ' userAgent is answered only when allowBots sends the request\'s User-Agent.';
        }
        $this->reportGap($message);
    }

    /** Warns, throws or keeps quiet about a member the answer lacks, as `onMissingField` says. */
    private function reportGap(string $message): void
    {
        if ($this->options->onMissingField === 'ignore') {
            return;
        }
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
