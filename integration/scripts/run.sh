#!/bin/bash

# The integration suite in docker, because the dev box has no PHP and no
# composer. CI runs `php scripts/run.php` directly; this is the same entry point
# with an interpreter around it.
#
#   ./scripts/run.sh
#
# The four tier keys are read from the environment and passed through by NAME, so
# no key ever reaches a command line. Only the integration directory is mounted:
# the suite must see the published package rather than the source beside it.

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSER_IMAGE="${COMPOSER_IMAGE:-composer:2}"
CACHE_DIR="${COMPOSER_CACHE_ROOT:-${HOME}/.composer-vpndetection}"
HOME_DIR="${CACHE_DIR}/home-integration"

mkdir -p "${HOME_DIR}" "${CACHE_DIR}/cache"

docker run --rm \
    -v "$PWD:/app" -w /app \
    -v "${HOME_DIR}:/composer" \
    -v "${CACHE_DIR}/cache:/composer-cache" \
    -e COMPOSER_HOME=/composer \
    -e COMPOSER_CACHE_DIR=/composer-cache \
    -e COMPOSER_ALLOW_SUPERUSER=1 \
    -e VPNDETECTION_STAGING_KEY_FREE \
    -e VPNDETECTION_STAGING_KEY_STARTER \
    -e VPNDETECTION_STAGING_KEY_SCALE \
    -e VPNDETECTION_STAGING_KEY_MAX \
    "$COMPOSER_IMAGE" php scripts/run.php "$@"
