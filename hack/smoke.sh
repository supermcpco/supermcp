#!/usr/bin/env bash
# The serve smoke test: a running instance is ready, serves the catalog
# it embeds, and publishes its API description. Shared by the
# go-integration job (the binary on the runner) and the kind install
# (the chart on a cluster, through a port-forward), so a check added
# here is made against both.
#
#   hack/smoke.sh http://localhost:18080
#
# Waits up to SMOKE_WAIT seconds (default 30) for /readyz, then fails on
# the first check that does not hold.
set -euo pipefail

base="${1:?usage: hack/smoke.sh BASE_URL}"
base="${base%/}"
wait="${SMOKE_WAIT:-30}"

for cmd in curl jq; do
  command -v "$cmd" >/dev/null || { echo "smoke: $cmd is not on PATH" >&2; exit 2; }
done

for _ in $(seq 1 "$wait"); do
  curl -fs "$base/readyz" >/dev/null && break
  sleep 1
done

check() {
  local what=$1; shift
  if "$@"; then
    echo "ok   $what"
  else
    echo "FAIL $what" >&2
    exit 1
  fi
}

check "/readyz answers 200"               curl -fsS -o /dev/null "$base/readyz"
check "keyless catalog is not empty"      bash -o pipefail -c "curl -fsS '$base/api/v1/catalog?keyless=true' | jq -e '.count > 0' >/dev/null"
check "kaufland adapter uses hmac auth"   bash -o pipefail -c "curl -fsS '$base/api/v1/catalog/kaufland' | jq -e '.auth.type == \"hmac\"' >/dev/null"
check "OpenAPI document is served"        bash -o pipefail -c "curl -fsS '$base/api/openapi.json' | jq -e '.openapi' >/dev/null"
