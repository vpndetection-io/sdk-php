<?php

declare(strict_types=1);

namespace VPNDetection\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\RequestInterface;
use VPNDetection\OauthApi;

/**
 * The authorization server as a list of replies, answered in order with the last
 * repeating, recording every request exactly as it left the client. It also
 * stands in for the poll's clock.
 *
 * Both are bounded. A loop in the code under test could catch an exception
 * thrown to stop it, so past the bound the stub ends the PROCESS instead, which
 * nothing catches: the run fails rather than hanging while memory grows.
 */
final class OauthStub
{
    public const BOUND = 16;

    /**
     * Header names are lowercased.
     *
     * @var list<array{method: string, path: string, query: array<string, mixed>, url: string,
     *     headers: array<string, list<string>>, body: string, contentType: string}>
     */
    public array $requests = [];

    /** @var list<float> Every wait the poll took, in seconds. */
    public array $waits = [];

    public readonly GuzzleClient $client;

    private float $elapsed = 0.0;
    private int $reads = 0;

    /** @param list<array<string, mixed>> $replies Each `status` plus `body` (sent as JSON) or `rawBody`. */
    public function __construct(private readonly array $replies, private readonly int $limit = self::BOUND)
    {
        $this->client = new GuzzleClient(['handler' => HandlerStack::create($this->handle(...))]);
    }

    /** Replaces the poll's sleep AND its monotonic clock, so the deadline reads the time the waits spent. */
    public function installClock(OauthApi $oauth): void
    {
        $now = function (): float {
            if (++$this->reads > 2 * self::BOUND) {
                self::trip("read the clock {$this->reads} times");
            }
            return $this->elapsed;
        };
        $sleep = function (float $seconds): void {
            if (count($this->waits) === self::BOUND) {
                self::trip('waited more than ' . self::BOUND . ' times');
            }
            $this->waits[] = $seconds;
            $this->elapsed += $seconds;
        };
        (function () use ($now, $sleep): void {
            $this->now = $now;
            $this->sleep = $sleep;
        })->call($oauth);
    }

    /**
     * A form body as a field map, decoded the way a server decodes one (`+` is a
     * space), refusing a field sent twice.
     *
     * @return array<string, string>
     */
    public static function formFields(string $body): array
    {
        $fields = [];
        foreach ($body === '' ? [] : explode('&', $body) as $pair) {
            [$name, $value] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            Assert::assertArrayNotHasKey($name, $fields, "{$name} sent twice");
            $fields[$name] = urldecode($value);
        }
        return $fields;
    }

    /** @param array<string, mixed> $options */
    private function handle(RequestInterface $request, array $options): PromiseInterface
    {
        if (count($this->requests) === $this->limit) {
            self::trip("sent more than {$this->limit} request(s)");
        }
        $uri = $request->getUri();
        parse_str($uri->getQuery(), $query);
        $this->requests[] = [
            'method' => $request->getMethod(),
            'path' => $uri->getPath(),
            'query' => $query,
            'url' => (string) $uri,
            'headers' => array_change_key_case($request->getHeaders()),
            'body' => (string) $request->getBody(),
            'contentType' => $request->getHeaderLine('Content-Type'),
        ];
        $reply = $this->replies[min(count($this->requests), count($this->replies)) - 1];
        // A decoded `{}` is an empty PHP array, which would go back out as `[]`.
        $body = $reply['rawBody']
            ?? ($reply['body'] === [] ? '{}' : json_encode($reply['body'], JSON_THROW_ON_ERROR));
        $headers = ['Content-Type' => 'application/json'];
        return Create::promiseFor(new Response($reply['status'], $headers, $body));
    }

    private static function trip(string $what): never
    {
        fwrite(STDERR, "\n{$what}: the call under test does not end\n");
        exit(97);
    }
}
