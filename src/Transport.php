<?php

declare(strict_types=1);

namespace VPNDetection;

use Closure;
use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\RequestOptions;
use JsonException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TypeError;
use ValueError;
use VPNDetection\Internal\Model\ModelInterface;
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

    /**
     * The longest Retry-After honored, in seconds: 2**31 - 1 ms, about 24.8
     * days, the same bound as the .NET SDK's. Past it the wait is the backoff.
     */
    private const LONGEST_RETRY_AFTER = 2_147_483;

    /**
     * RFC 3339's full-date, the spec's `date`, and its date-time, the spec's
     * `date-time`, its `T` and `Z` in either case. Anything else reaches the
     * generated deserializer's `new DateTime()`, which reads `x` as the current
     * time eleven hours west and `tomorrow` as midnight. `\z`, since `$` also
     * matches before a final newline: through 4.11.1 one came back as a date, and
     * a lowercase `t` or `z`, which RFC 3339 allows, failed the call.
     */
    private const DATE = '/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/';

    private const DATE_TIME = '/\A([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:[Zz]|[+-]([0-9]{2}):([0-9]{2}))\z/';

    public function __construct(
        private readonly ClientInterface $http,
        private readonly int $defaultRetries,
        private readonly float $timeout,
    ) {
    }

    public function send(RequestInterface $request, ?int $retries = null): ResponseInterface
    {
        // The declared return type is what enforces the narrowing: `wait()` is
        // typed `mixed`, and strict_types turns anything else into a TypeError.
        return $this->sendAsync($request, $retries)->wait();
    }

    /**
     * Sends a request and reads its answer with `$read`, inside the attempt.
     *
     * An answer under 400 that `$read` cannot turn into what the call returns -
     * a proxy's HTML page, a cut-off or empty body, an object without the member
     * the call returns - is no answer at all. So it is the server_error any other
     * unreadable answer is, carrying the status, and it is retried like an outage
     * rather than reaching the caller as a raw TypeError from a generated model.
     *
     * @template T
     * @param Closure(ResponseInterface): T $read
     * @return T
     */
    public function read(RequestInterface $request, Closure $read): mixed
    {
        return $this->sendAsync($request, read: $read)->wait();
    }

    /**
     * @param float|null $timeout Replaces the client's bound for every attempt of this call.
     * @param (Closure(ResponseInterface): VPNDetectionException)|null $classify Reports a response
     *        of 400 or more, in place of the API's own envelope; what it returns is retried exactly
     *        when it says it is retryable.
     * @param (Closure(ResponseInterface): mixed)|null $read Turns a response under 400 into what the
     *        call returns, inside the attempt; without it the response itself is returned.
     */
    public function sendAsync(
        RequestInterface $request,
        ?int $retries = null,
        ?float $timeout = null,
        ?Closure $classify = null,
        ?Closure $read = null,
    ): PromiseInterface {
        $bound = $timeout === null
            ? []
            : [RequestOptions::TIMEOUT => $timeout, RequestOptions::CONNECT_TIMEOUT => $timeout];
        return $this->attempt(
            $request,
            $retries ?? $this->defaultRetries,
            0,
            0,
            $bound,
            $classify ?? static fn (ResponseInterface $r): VPNDetectionException => Errors::fromResponse($r),
            $read,
        );
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
            [
                RequestOptions::STREAM => true,
                RequestOptions::ALLOW_REDIRECTS => true,
                // 30s is right for an API call and wrong for a body that
                // reaches gigabytes, so only the connect phase keeps it.
                RequestOptions::TIMEOUT => 0,
                RequestOptions::CONNECT_TIMEOUT => $this->timeout,
            ],
            static fn (ResponseInterface $r): VPNDetectionException
                => Errors::fromResponse($r, $errorMessage),
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
     * @param bool $stored Whether the body is an answer this client stored and
     *        re-encoded, where an empty object reads back as `[]`.
     * @return T
     */
    public static function toModel(string $body, string $class, ?int $status = null, bool $stored = false): object
    {
        try {
            $decoded = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw Errors::malformed($e->getMessage(), $status);
        }
        return self::fromDecoded($decoded, $class, $status, $stored);
    }

    /**
     * The model a body decoded with objects reads as, refusing what toModel does.
     *
     * @template T of object
     * @param class-string<T> $class
     * @return T
     */
    public static function fromDecoded(mixed $decoded, string $class, ?int $status = null, bool $stored = false): object
    {
        $wrong = self::nonconforming($decoded, $class, '', null, $stored);
        if ($wrong !== null) {
            throw Errors::malformed(sprintf('the API answered %s of the wrong type', $wrong), $status);
        }
        $model = ObjectSerializer::deserialize($decoded, $class);
        if (!$model instanceof $class) {
            throw Errors::malformed(sprintf('expected %s', $class), $status);
        }
        $unmet = self::unmet($model, $class, '');
        if ($unmet !== null) {
            throw Errors::malformed(sprintf('the API answered %s', $unmet), $status);
        }
        return $model;
    }

    /**
     * Where a decoded answer is not of the type its generated model gives it, by
     * the member's path, or null when it is. The generated deserializer casts a
     * scalar with settype(), so through 4.10.0 `"is_vpn": "false"` came back as
     * true, a version of "x" as 0 and an `ip` of 1 as "1": every member is
     * checked first, at every depth. A null or absent member is left to unmet(),
     * but no list entry or map value the spec describes may be null. A date must
     * be one in the form its `$format` names, on a day that exists: through
     * 4.10.0 `last_seen: "x"` came back as the time of the call, and 30 February
     * as 2 March.
     */
    private static function nonconforming(
        mixed $value,
        string $type,
        string $at,
        ?string $format = null,
        bool $stored = false,
    ): ?string {
        if ($value === null) {
            return null;
        }
        $here = $at === '' ? 'the answer' : $at;
        if (str_ends_with($type, '[]')) {
            if (!is_array($value) || !array_is_list($value)) {
                return $here;
            }
            foreach ($value as $i => $item) {
                $wrong = $item === null
                    ? "{$at}[{$i}]"
                    : self::nonconforming($item, substr($type, 0, -2), "{$at}[{$i}]", null, $stored);
                if ($wrong !== null) {
                    return $wrong;
                }
            }
            return null;
        }
        // PHP's arrays cannot tell `{}` from `[]`, so a stored answer that held an
        // empty object reads back as an empty list, and is read as the object.
        $object = $value instanceof \stdClass || ($stored && $value === []);
        if (preg_match('/^array<string,(.+)>$/', $type, $m) === 1) {
            if (!$object) {
                return $here;
            }
            foreach ((array) $value as $key => $item) {
                $wrong = $item === null
                    ? "{$at}.{$key}"
                    : self::nonconforming($item, $m[1], "{$at}.{$key}", null, $stored);
                if ($wrong !== null) {
                    return $wrong;
                }
            }
            return null;
        }
        $scalar = match ($type) {
            'int' => is_int($value),
            'float' => is_int($value) || is_float($value),
            'bool' => is_bool($value),
            'string' => is_string($value),
            '\DateTime' => is_string($value) && self::isDate($value, $format),
            'object' => $object,
            'mixed' => true,
            default => null,
        };
        if ($scalar !== null) {
            return $scalar ? null : $here;
        }
        if (is_subclass_of($type, \BackedEnum::class)) {
            return is_string($value) ? null : $here;
        }
        if (is_subclass_of($type, ModelInterface::class)) {
            if (!$object) {
                return $here;
            }
            $wire = $type::attributeMap();
            $formats = $type::openAPIFormats();
            $members = (array) $value;
            foreach ($type::openAPITypes() as $property => $memberType) {
                $name = $wire[$property];
                $path = $at === '' ? $name : "{$at}.{$name}";
                $wrong = self::nonconforming(
                    $members[$name] ?? null, $memberType, $path, $formats[$property] ?? null, $stored,
                );
                if ($wrong !== null) {
                    return $wrong;
                }
            }
            return null;
        }
        return null;
    }

    private static function isDate(string $value, ?string $format): bool
    {
        $m = [];
        if (preg_match($format === 'date' ? self::DATE : self::DATE_TIME, $value, $m) !== 1
            || !checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            return false;
        }
        // An hour of 24 or a minute of 60 rolls over the way a missing day does.
        return $format === 'date'
            || ((int) $m[4] < 24 && (int) $m[5] < 60 && (int) $m[6] < 60
                && (int) ($m[7] ?? 0) < 24 && (int) ($m[8] ?? 0) < 60);
    }

    /**
     * Where a deserialized answer lacks a member the spec requires, or holds one
     * it never sends as null, by the member's path, or null when none does. A
     * typed getter refuses such a member only when something reads it, and
     * nothing reads a checksum answer's `id` or `format`, so through 4.10.0 an
     * answer without them came back as one.
     *
     * Only those two rules of the generated listInvalidProperties() are kept. Its
     * enum checks would add nothing: the generated setters already refuse a
     * `license_type`, `outcome` or `tier` outside the pinned spec's values while
     * ObjectSerializer::deserialize() runs, before this does, so a value the API
     * adds fails the call as a retried server_error until a release re-pins.
     */
    private static function unmet(mixed $value, string $type, string $at): ?string
    {
        if ($value === null) {
            return null;
        }
        $children = [];
        if (str_ends_with($type, '[]')) {
            foreach ($value as $i => $item) {
                $children["{$at}[{$i}]"] = [$item, substr($type, 0, -2)];
            }
        } elseif (preg_match('/^array<string,(.+)>$/', $type, $m) === 1) {
            foreach ($value as $key => $item) {
                $children["{$at}.{$key}"] = [$item, $m[1]];
            }
        } elseif ($value instanceof ModelInterface) {
            foreach ($value->listInvalidProperties() as $invalid) {
                if (str_ends_with($invalid, "can't be null") || str_ends_with($invalid, 'is required')) {
                    return sprintf('%s that breaks the spec (%s)', $at === '' ? 'an answer' : $at, $invalid);
                }
            }
            $wire = $value::attributeMap();
            foreach ($value::openAPITypes() as $property => $memberType) {
                $children[$at === '' ? $wire[$property] : "{$at}.{$wire[$property]}"] = [$value[$property], $memberType];
            }
        }
        foreach ($children as $path => [$item, $itemType]) {
            $wrong = self::unmet($item, $itemType, $path);
            if ($wrong !== null) {
                return $wrong;
            }
        }
        return null;
    }

    /**
     * @param array<string, mixed> $extraOptions
     * @param Closure(ResponseInterface): VPNDetectionException $classify
     * @param (Closure(ResponseInterface): mixed)|null $read
     */
    private function attempt(
        RequestInterface $request,
        int $left,
        int $attempt,
        int $delayMs,
        array $extraOptions,
        Closure $classify,
        ?Closure $read = null,
    ): PromiseInterface {
        $options = [
            // Errors are classified here rather than thrown by Guzzle, so the
            // retry decision and the exception both come from one place.
            RequestOptions::HTTP_ERRORS => false,
            // The download endpoint answers 302 to object storage, and chasing it
            // would pull a multi-gigabyte dataset into memory. Nothing this
            // client calls is meant to redirect.
            RequestOptions::ALLOW_REDIRECTS => false,
            // Guzzle defaults both of these to 0, meaning unlimited, so without
            // them a hung API holds the caller until the process is killed.
            RequestOptions::TIMEOUT => $this->timeout,
            RequestOptions::CONNECT_TIMEOUT => $this->timeout,
            ...$extraOptions,
        ];
        if ($delayMs > 0) {
            // Guzzle's curl handler SCHEDULES a delayed transfer rather than
            // sleeping, so one address backing off does not stall a whole batch.
            $options[RequestOptions::DELAY] = $delayMs;
        }

        return $this->http->sendAsync($request, $options)->then(
            function (ResponseInterface $response) use (
                $request, $left, $attempt, $extraOptions, $classify, $read,
            ): mixed {
                if ($response->getStatusCode() >= 400) {
                    $error = $classify($response);
                } elseif ($read === null) {
                    return $response;
                } else {
                    try {
                        return $read($response);
                    } catch (VPNDetectionException $e) {
                        $error = $e;
                    } catch (Exception | TypeError | ValueError $e) {
                        // What the generated models throw for an answer that is not
                        // the shape they declare: a TypeError from a typed getter, an
                        // InvalidArgumentException from the deserializer.
                        $error = Errors::malformed($e->getMessage(), $response->getStatusCode(), $e);
                    }
                }
                if ($left <= 0 || !$error->isRetryable()) {
                    throw $error;
                }
                return $this->attempt(
                    $request, $left - 1, $attempt + 1, self::delayFor($error, $attempt),
                    $extraOptions, $classify, $read,
                );
            },
            function (mixed $reason) use (
                $request, $left, $attempt, $extraOptions, $classify, $read,
            ): PromiseInterface {
                $error = Errors::coerce($reason);
                if ($left <= 0 || !$error->isRetryable()) {
                    throw $error;
                }
                return $this->attempt(
                    $request, $left - 1, $attempt + 1, self::backoffMs($attempt),
                    $extraOptions, $classify, $read,
                );
            },
        );
    }

    private static function delayFor(VPNDetectionException $error, int $attempt): int
    {
        // Unbounded, the product overflowed into a float and the int return type
        // threw a raw TypeError, and a smaller one scheduled a wait of millennia.
        $seconds = $error->retryAfterSeconds;
        return $seconds === null || $seconds <= 0 || $seconds > self::LONGEST_RETRY_AFTER
            ? self::backoffMs($attempt)
            : $seconds * 1000;
    }

    private static function backoffMs(int $attempt): int
    {
        return self::BACKOFF_BASE_MS << min($attempt, 6);
    }
}
