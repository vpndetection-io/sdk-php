<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * The device code is no longer valid: it expired, or was already exchanged or
 * refused. A poll that outlives the code's `expiresIn` raises this itself, with
 * no status.
 */
final class OauthExpiredTokenException extends OauthException
{
}
