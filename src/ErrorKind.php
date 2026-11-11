<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * Why a request failed.
 *
 * `RateLimited` and `QuotaExceeded` both arrive as HTTP 429 and are NOT the same
 * thing. A rate limit is the API protecting itself and carries `Retry-After`;
 * retrying works. A spent quota carries no such header and retrying will not
 * help until the window rolls over or the limit is raised. The header is the
 * only thing that distinguishes them.
 */
enum ErrorKind: string
{
    case BadRequest = 'bad_request';
    case Unauthorized = 'unauthorized';
    case Forbidden = 'forbidden';
    case RateLimited = 'rate_limited';
    case QuotaExceeded = 'quota_exceeded';
    case ServerError = 'server_error';
    case Network = 'network';
}
