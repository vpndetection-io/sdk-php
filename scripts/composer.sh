#!/bin/bash

# Runs composer for a target PHP version, in docker.
#
# Neither PHP nor composer is installed on the dev box, and two facts make the
# obvious `docker run composer:2` wrong:
#
#   1. The version composer resolves FOR decides the dependency set. PHPUnit 13
#      needs PHP 8.4.1 and PHPUnit 10.5 is the last that runs on 8.1, so
#      resolving under the composer image's own PHP and then testing on 8.1
#      proves nothing. `config.platform.php` in a per-version COMPOSER_HOME pins
#      the target without touching the committed composer.json.
#   2. php:X-cli carries no zip extension, no unzip and no git, so composer
#      running there cannot extract anything it downloads. It runs in the
#      composer image, which has all three.
#
#   ./scripts/composer.sh update
#   PHP_VERSION=8.1 ./scripts/composer.sh update
#
# Both the composer home and the download cache live under the HOST's composer
# directory, so neither lands in the working tree.

set -euo pipefail

cd "$(dirname "$0")/.."

PHP_VERSION="${PHP_VERSION:-8.3}"
COMPOSER_IMAGE="${COMPOSER_IMAGE:-composer:2}"
CACHE_DIR="${COMPOSER_CACHE_ROOT:-${HOME}/.composer-vpndetection}"
HOME_DIR="${CACHE_DIR}/home-php${PHP_VERSION}"

mkdir -p "${HOME_DIR}" "${CACHE_DIR}/cache"
# A high patch level, so a constraint like PHPUnit 13's `>=8.4.1` is satisfied on
# the 8.4 leg rather than excluded by an assumed 8.4.0.
printf '{"config":{"platform":{"php":"%s.99"}}}\n' "$PHP_VERSION" > "${HOME_DIR}/config.json"

docker run --rm \
    -v "$PWD:/app" -w /app \
    -v "${HOME_DIR}:/composer" \
    -v "${CACHE_DIR}/cache:/composer-cache" \
    -e COMPOSER_HOME=/composer \
    -e COMPOSER_CACHE_DIR=/composer-cache \
    -e COMPOSER_ALLOW_SUPERUSER=1 \
    "$COMPOSER_IMAGE" "$@"
