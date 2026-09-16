<?php

declare(strict_types=1);

namespace VPNDetection;

/**
 * A started device sign-in: show the person `$userCode` and `$verificationUri`,
 * then hand this to `$client->oauth->pollDeviceToken()`. Constructible, so a
 * program can resume a poll from values it stored.
 */
final class DeviceAuthorization
{
    public function __construct(
        public readonly string $deviceCode,
        /** What the person types in at `$verificationUri`. */
        public readonly string $userCode,
        public readonly string $verificationUri,
        /** Seconds until the codes stop working. */
        public readonly int $expiresIn,
        /** Seconds to wait between polls. */
        public readonly int $interval,
        /** `$verificationUri` with the code already in it, for a program that can open a browser. */
        public readonly ?string $verificationUriComplete = null,
    ) {
    }
}
