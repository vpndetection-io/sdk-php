<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * The authorization server refused an OAuth request, with the reason it gave.
 *
 * `$kind` follows the status like any other failure's, and a 401 here means the
 * client ID is not registered, never the API key, which these requests do not
 * carry. Never retryable: every refusal answers the request as it was sent.
 * `OauthAccessDeniedException` and `OauthExpiredTokenException` are the two
 * refusals that end a sign-in.
 */
class OauthException extends VPNDetectionException
{
    public function __construct(
        /** The OAuth `error` code, such as `slow_down` or `invalid_grant`. */
        public readonly string $errorCode,
        /** The server's `error_description`, when it sent one. */
        public readonly ?string $errorDescription = null,
        /** Null for a refusal made locally, as when a poll outlives its device code. */
        ?int $status = null,
        ErrorKind $kind = ErrorKind::BadRequest,
    ) {
        parent::__construct(
            $kind,
            $errorDescription === null ? $errorCode : "{$errorCode}: {$errorDescription}",
            $status,
        );
    }

    /** @internal The subtype for a refusal, keeping a code we have never seen as this base type. */
    public static function from(
        string $errorCode,
        ?string $errorDescription,
        ?int $status,
        ErrorKind $kind,
    ): self {
        return match ($errorCode) {
            'access_denied' => new OauthAccessDeniedException($errorCode, $errorDescription, $status, $kind),
            'expired_token' => new OauthExpiredTokenException($errorCode, $errorDescription, $status, $kind),
            default => new self($errorCode, $errorDescription, $status, $kind),
        };
    }

    public function isRetryable(): bool
    {
        return false;
    }
}
