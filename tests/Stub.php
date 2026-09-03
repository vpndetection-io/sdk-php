<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * An HTTP stand-in that answers from a table and records what it was asked for,
 * so "never touched the network" is asserted rather than assumed.
 *
 * Every response is returned as a promise that only settles when it is waited
 * on, which is what lets a batch put several requests in flight at once without
 * any test sleeping. `peak` is therefore the real maximum concurrency.
 */
final class Stub
{
    /** @var list<string> */
    public array $calls = [];

    /** @var list<int> The `delay` option each call was sent with, in milliseconds. */
    public array $delays = [];

    /** @var list<RequestInterface> Every request as it was actually sent. */
    public array $requests = [];

    public int $inFlight = 0;
    public int $peak = 0;

    public readonly GuzzleClient $client;

    /** @var array<string, list<array<string, mixed>>> */
    private array $routes;

    /** @var array<string, int> */
    private array $served = [];

    /**
     * A route value is either one response spec (`['status' => .., 'headers' => ..,
     * 'body' => ..]`) or a list of them consumed in order, the last repeating.
     *
     * @param array<string, mixed> $routes Keyed by request path.
     */
    public function __construct(array $routes = [])
    {
        $this->routes = [];
        foreach ($routes as $path => $spec) {
            $this->routes[$path] = array_is_list($spec) ? $spec : [$spec];
        }
        $this->client = new GuzzleClient(['handler' => HandlerStack::create($this->handler(...))]);
    }

    /**
     * Routes for the lookup endpoint, which lives at the root of the host.
     *
     * @param array<string, mixed> $byIp
     * @return array<string, mixed>
     */
    public static function lookups(array $byIp): array
    {
        $routes = [];
        foreach ($byIp as $ip => $spec) {
            $routes['/' . $ip] = $spec;
        }
        return $routes;
    }

    /** A 200 carrying a JSON body. */
    public static function ok(mixed $body): array
    {
        return ['status' => 200, 'body' => $body];
    }

    /** A transfer that never produced a response at all. */
    public static function transportFailure(string $message = 'connection refused'): array
    {
        return ['reject' => $message];
    }

    /** @param array<string, mixed> $options */
    private function handler(RequestInterface $request, array $options): PromiseInterface
    {
        $path = rawurldecode($request->getUri()->getPath());
        $this->calls[] = $path;
        $this->delays[] = (int) ($options['delay'] ?? 0);
        $this->requests[] = $request;
        $this->inFlight++;
        $this->peak = max($this->peak, $this->inFlight);

        $outcome = $this->responseFor($path);
        $promise = new Promise(function () use (&$promise, $outcome, $request): void {
            $this->inFlight--;
            if (is_string($outcome)) {
                $promise->reject(new ConnectException($outcome, $request));
                return;
            }
            $promise->resolve($outcome);
        });
        return $promise;
    }

    /** A response, or a message meaning the transfer failed before one arrived. */
    private function responseFor(string $path): Response|string
    {
        $specs = $this->routes[$path] ?? null;
        if ($specs === null) {
            return self::response([
                'status' => 400,
                'body' => ['error' => 'not a valid IP address'],
            ]);
        }
        $n = $this->served[$path] ?? 0;
        $this->served[$path] = $n + 1;
        $spec = $specs[min($n, count($specs) - 1)];
        return $spec['reject'] ?? self::response($spec);
    }

    /** @param array<string, mixed> $spec */
    private static function response(array $spec): Response
    {
        $headers = array_merge(['Content-Type' => 'application/json'], $spec['headers'] ?? []);
        $body = array_key_exists('body', $spec) ? $spec['body'] : null;
        return new Response(
            $spec['status'] ?? 200,
            $headers,
            is_string($body) || $body === null ? $body : json_encode($body, JSON_THROW_ON_ERROR),
        );
    }
}
