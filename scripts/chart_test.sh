#!/usr/bin/env bash
# Renders charts/supermcp with and without the optional master key
# values and checks each rendered object carries exactly what those values
# promise: the key file mount and ENCRYPTION_KEK_FILE when a key file is
# named, SUPERMCP_KEK_PREVIOUS when a previous-key Secret is named, and
# none of them otherwise. Schema validation is kubeconform's job in CI;
# this checks the chart says what the documentation says it does.
#
#   scripts/chart_test.sh            (needs helm on PATH)
set -euo pipefail

command -v helm >/dev/null || { echo "FAIL: helm is not on PATH"; exit 1; }

chart=$(cd "$(dirname "$0")/.." && pwd)/charts/supermcp
[ -f "$chart/Chart.yaml" ] || { echo "FAIL: no chart at $chart"; exit 1; }

failures=0
checks=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

base=(--set publicUrl=https://mcp.example.com --set database.existingSecret=db)

# render NAME TEMPLATE ARGS...: one template's output, or the render error.
render() {
  local tpl=$1; shift
  helm template supermcp "$chart" "${base[@]}" --show-only "templates/$tpl" "$@"
}

# has / lacks TEMPLATE LABEL PATTERN RENDERED
has() {
  checks=$((checks + 1))
  grep -qE -- "$3" <<<"$4" || fail "$1 ($2): expected /$3/"
}
lacks() {
  checks=$((checks + 1))
  if grep -qE -- "$3" <<<"$4"; then fail "$1 ($2): unexpected /$3/"; fi
}

for tpl in deployment.yaml job-migrate.yaml; do
  # The default: the key in the environment, nothing mounted.
  out=$(render "$tpl" --set encryption.local.existingSecret=kek-env)
  has   "$tpl" default 'name: ENCRYPTION_KEK$' "$out"
  lacks "$tpl" default 'ENCRYPTION_KEK_FILE' "$out"
  lacks "$tpl" default 'SUPERMCP_KEK_PREVIOUS' "$out"
  lacks "$tpl" default '/etc/supermcp/kek' "$out"
  lacks "$tpl" default 'name: kek$' "$out"

  # The key as a file: mounted read-only, the variable names the file, the
  # environment form is gone, and the Secret volume asks for 0400.
  out=$(render "$tpl" --set encryption.local.file.secretName=kek-file --set encryption.local.file.key=KEK_2026_09)
  has   "$tpl" file 'name: ENCRYPTION_KEK_FILE$' "$out"
  has   "$tpl" file 'value: "/etc/supermcp/kek/KEK_2026_09"' "$out"
  has   "$tpl" file 'mountPath: /etc/supermcp/kek$' "$out"
  has   "$tpl" file 'readOnly: true' "$out"
  has   "$tpl" file 'secretName: kek-file$' "$out"
  has   "$tpl" file 'defaultMode: 0400$' "$out"
  has   "$tpl" file 'key: KEK_2026_09$' "$out"
  lacks "$tpl" file 'name: ENCRYPTION_KEK$' "$out"
  lacks "$tpl" file 'SUPERMCP_KEK_PREVIOUS' "$out"

  # The previous key, from its own Secret, with either form of the active key.
  out=$(render "$tpl" --set encryption.local.existingSecret=kek-env --set encryption.previous.secretName=kek-old)
  has   "$tpl" previous 'name: SUPERMCP_KEK_PREVIOUS$' "$out"
  has   "$tpl" previous 'name: kek-old$' "$out"
  lacks "$tpl" previous '/etc/supermcp/kek' "$out"

  # Under KMS the file values mean nothing and render nothing, while a
  # previous local key still does: that is how local moves to KMS.
  out=$(render "$tpl" --set encryption.provider=awskms --set encryption.awskms.keyId=alias/supermcp \
        --set encryption.local.file.secretName=kek-file --set encryption.previous.secretName=kek-old)
  lacks "$tpl" awskms 'ENCRYPTION_KEK' "$out"
  lacks "$tpl" awskms '/etc/supermcp/kek' "$out"
  has   "$tpl" awskms 'name: SUPERMCP_KEK_PREVIOUS$' "$out"
done

# Neither form of the local key is a render error that names both values.
checks=$((checks + 1))
if out=$(render deployment.yaml 2>&1); then
  fail "no local key: rendered without error"
elif ! grep -q 'encryption.local.file.secretName' <<<"$out"; then
  fail "no local key: error does not name encryption.local.file.secretName: $out"
fi

echo "chart: $checks checks, $failures failed"
[ "$failures" -eq 0 ]
