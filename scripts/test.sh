#!/bin/bash

# The whole suite, against one PHP version, in docker.
#
#   ./scripts/test.sh                       # 8.3
#   PHP_VERSION=8.1 ./scripts/test.sh       # the floor
#   VPNDETECTION_LIVE=1 ./scripts/test.sh   # plus the live check against production
#
# Dependencies are resolved fresh for the requested interpreter, because the
# PHPUnit major that supports 8.1 is not the one that supports 8.5.

set -euo pipefail

cd "$(dirname "$0")/.."

PHP_VERSION="${PHP_VERSION:-8.3}"

./scripts/composer.sh update --no-interaction --no-progress

docker run --rm \
    -v "$PWD:/app" -w /app \
    -e "VPNDETECTION_LIVE=${VPNDETECTION_LIVE:-}" \
    -e "VPNDETECTION_API_KEY=${VPNDETECTION_API_KEY:-}" \
    "php:${PHP_VERSION}-cli" \
    php vendor/bin/phpunit "$@"
