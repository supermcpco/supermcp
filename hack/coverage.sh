#!/usr/bin/env bash
# Fails when coverage of internal/ and pkg/ drops below the floor.
#
# The floor sits just under where the tree stands rather than where anyone
# wishes it stood: a gate that already fails teaches people to argue with
# the gate. Raise it when a milestone lands; never lower it to make a
# branch green.
set -euo pipefail

floor="${COVERAGE_FLOOR:-60}"
profile="${COVERAGE_PROFILE:-coverage.out}"

if [[ ! -f "$profile" ]]; then
  echo "no coverage profile at $profile; run go test -coverprofile first" >&2
  exit 2
fi

total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
if [[ -z "$total" ]]; then
  echo "could not read a total out of $profile" >&2
  exit 2
fi

printf 'coverage %.1f%% (floor %s%%)\n' "$total" "$floor"
awk -v t="$total" -v f="$floor" 'BEGIN { exit (t + 0 >= f + 0) ? 0 : 1 }' || {
  echo "coverage fell below the floor; add tests, or raise the case for lowering it in the pull request" >&2
  exit 1
}
