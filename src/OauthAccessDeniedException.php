<?php

declare(strict_types=1);

namespace VPNDetection;

/** The person refused the sign-in. The device code is spent, so start a new one to ask again. */
final class OauthAccessDeniedException extends OauthException
{
}
