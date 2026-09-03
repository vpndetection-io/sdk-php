#!/bin/bash

# Refreshes the pinned OpenAPI spec from the published one.
#
# The copy in spec/ is what codegen reads, so a build stays reproducible and
# offline and the diff shows exactly which spec version produced the client.
# Run this deliberately, then commit the spec change alongside the regenerated
# client, so a reviewer sees both.

set -euo pipefail

cd "$(dirname "$0")/.."

SPEC_URL="${SPEC_URL:-https://s3.vpndetection.io/vpndetection-public/openapi/openapi.yaml}"

curl -fsS "$SPEC_URL" -o spec/openapi.yaml
echo "spec/openapi.yaml <- ${SPEC_URL}"
grep -m1 '^  version:' spec/openapi.yaml
