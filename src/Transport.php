<?php

declare(strict_types=1);

namespace VPNDetection;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\RequestOptions;
use JsonException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use VPNDetection\Internal\ObjectSerializer;

/**
 * @internal
 *
 * Sends a generated request and retries it when that is worth doing.
 *
 * Nothing in Guzzle knows about a server-supplied `Retry-After`, and honoring it
 * is most of the logic, so the schedule is here rather than in a middleware.
 * Middleware would also be fixed at client construction, and the retry count is
 * overridable per call.
 */
final class Transport
{
    private const BACKOFF_BASE_MS = 250;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly int $defaultRetries,
    ) {
    }

    public function send(RequestInterface $request, ?int $retries = null): ResponseInterface
    {
        // The declared return type is what enforces the narrowing: `wait()` is
        // typed `mixed`, and strict_types turns anything else into a TypeError.
        return $this->sendAsync($request, $retries)->wait();
    }

    public function sendAsync(RequestInterface $request, ?int $retries = null): PromiseInterface
    {
        return $this->attempt($request, $retries ?? $this->defaultRetries, 0, 0);
    }

    /**
     * A GET whose body is read lazily, for the object storage link the download
     * endpoint hands out.
     *
     * Only the headers are awaited, so a retry here cannot duplicate bytes a
     * caller's destination already holds. Redirects are followed, unlike every
     * other request this client makes: this one IS the far side of a redirect,
     * and the guard exists to stop the API's own 302 pulling a dataset into
     * memory. `$errorMessage` stands in for the response body on a failure,
     * which is what keeps an unbounded error page unread.
     */
    public function sendStreaming(
        RequestInterface $request,
        string $errorMessage,
        ?int $retries = null,
    ): ResponseInterface {
        return $this->attempt(
            $request,
            $retries ?? $this->defaultRetries,
            0,
            0,
            [RequestOptions::STREAM => true, RequestOptions::ALLOW_REDIRECTS => true],
            $errorMessage,
        )->wait();
    }

    /** @return array<string, mixed> */
    public static function toArray(string $body, ?int $status = null): array
    {
        try {
            $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw Errors::malformed($e->getMessage(), $status);
        }
        if (!is_array($decoded)) {
            throw Errors::malformed('expected a JSON object', $status);
        }
        return $decoded;
    }

    /**
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    public static function toModel(string $body, string $class, ?int $status = null): object
    {
        try {
            $decoded = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw Errors::malformed($e->getMessage(), $status);
        }
        $model = ObjectSerializer::deserialize($decoded, $class);
        if (!$model instanceof $class) {
            throw Errors::malformed(sprintf('expected %s', $class), $status);
        }
        return $model;
    }

    /** @param array<string, mixed> $extraOptions */
    private function attempt(
        RequestInterface $request,
        int $left,
        int $attempt,
        int $delayMs,
        array $extraOptions = [],
        ?string $errorMessage = null,
    ): PromiseInterface {
        $options = [
            // Errors are classified here rather than thrown by Guzzle, so the
            // retry decision and the exception both come from one place.
            RequestOptions::HTTP_ERRORS => false,
            // The download endpoint answers 302 to object storage, and chasing it
            // would pull a multi-gigabyte dataset into memory. Nothing this
            // client calls is meant to redirect.
            RequestOptions::ALLOW_REDIRECTS => false,
            ...$extraOptions,
        ];
        if ($delayMs > 0) {
            // Guzzle's curl handler SCHEDULES a delayed transfer rather than
            // sleeping, so one address backing off does not stall a whole batch.
            $options[RequestOptions::DELAY] = $delayMs;
        }

        return $this->http->sendAsync($request, $options)->then(
            function (ResponseInterface $response) use (
                $request, $left, $attempt, $extraOptions, $errorMessage,
            ): mixed {
                if ($response->getStatusCode() < 400) {
                    return $response;
                }
                $error = Errors::fromResponse($response, $errorMessage);
                if ($left <= 0 || !$error->isRetryable()) {
                    throw $error;
                }
                return $this->attempt(
                    $request, $left - 1, $attempt + 1, self::delayFor($error, $attempt),
                    $extraOptions, $errorMessage,
                );
            },
            function (mixed $reason) use (
                $request, $left, $attempt, $extraOptions, $errorMessage,
            ): PromiseInterface {
                $error = Errors::coerce($reason);
                if ($left <= 0 || !$error->isRetryable()) {
                    throw $error;
                }
                return $this->attempt(
                    $request, $left - 1, $attempt + 1, self::backoffMs($attempt),
                    $extraOptions, $errorMessage,
                );
            },
        );
    }

    private static function delayFor(VPNDetectionException $error, int $attempt): int
    {
        $seconds = $error->retryAfterSeconds;
        return $seconds === null || $seconds <= 0 ? self::backoffMs($attempt) : $seconds * 1000;
    }

    private static function backoffMs(int $attempt): int
    {
        return self::BACKOFF_BASE_MS << min($attempt, 6);
    }
}
