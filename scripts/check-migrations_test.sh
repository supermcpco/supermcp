#!/usr/bin/env bash
# Proves scripts/check-migrations.sh refuses what it should and allows what
# it should, against the fixtures in scripts/testdata/check-migrations.
#
#   fail/*.sql  must be refused (exit 1). Every "-- expect: LINE: TEXT" in
#               the fixture must be printed as FILE:LINE: TEXT..., nothing
#               else may be refused, and every "-- expect-note: TEXT" must
#               appear somewhere in the output.
#   pass/*.sql  must be allowed (exit 0).
#
# Then --since is exercised against a throwaway git repository.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
check=$here/check-migrations.sh
data=$here/testdata/check-migrations
notes=$data/UPGRADING.md
failures=0
ran=0

fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

[ -x "$check" ] || { echo "FAIL: $check is missing or not executable"; exit 1; }

# The checker is run from the fixture directory so the paths it prints are
# the bare file names the expectations use.
run() { (cd "$data/$1" && "$check" --upgrading "$notes" "$2") 2>&1; }

nfail=0
for f in "$data"/fail/*.sql; do
  [ -f "$f" ] || continue
  nfail=$((nfail + 1)); ran=$((ran + 1))
  name=$(basename "$f")
  before=$failures
  set +e; out=$(run fail "$name"); status=$?; set -e
  if [ $status -ne 1 ]; then
    fail "$name: exit $status, want 1 (refused)"; echo "$out"; continue
  fi
  want=0
  while IFS= read -r exp; do
    want=$((want + 1))
    line=${exp%%: *}; text=${exp#*: }
    grep -qF -- "$name:$line: $text" <<<"$out" || fail "$name: want \"$name:$line: $text\""
  done < <(sed -n 's/^-- expect: //p' "$f")
  got=$(grep -c -E "^$name:[0-9]+: " <<<"$out" || true)
  [ "$got" -eq "$want" ] || fail "$name: $got refusal(s) printed, want $want"
  while IFS= read -r note; do
    grep -qF -- "$note" <<<"$out" || fail "$name: want a line containing \"$note\""
  done < <(sed -n 's/^-- expect-note: //p' "$f")
  [ $failures -eq "$before" ] || echo "$out"
done

npass=0
for f in "$data"/pass/*.sql; do
  [ -f "$f" ] || continue
  npass=$((npass + 1)); ran=$((ran + 1))
  name=$(basename "$f")
  set +e; out=$(run pass "$name"); status=$?; set -e
  [ $status -eq 0 ] || { fail "$name: exit $status, want 0 (allowed)"; echo "$out"; }
done

# A fixture directory that went missing must not look like a pass.
[ $nfail -ge 10 ] || fail "only $nfail refusal fixtures found in $data/fail"
[ $npass -ge 4 ] || fail "only $npass allowed fixtures found in $data/pass"

# --since: a shipped migration that breaks the rule is not re-checked, a
# new one is, and a changed shipped one is again.
repo=$(mktemp -d "${TMPDIR:-/tmp}/check-migrations.XXXXXX")
trap 'rm -rf "$repo"' EXIT
g() { git -C "$repo" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }
g init -q
cp "$notes" "$repo/UPGRADING.md"
cp "$data/fail/90001_drop_table.sql" "$repo/00001_shipped.sql"
g add . && g commit -qm shipped && g tag shipped
cp "$data/pass/90104_expand_statements.sql" "$repo/00002_new.sql"
since() { "$check" --dir "$repo" --upgrading "$repo/UPGRADING.md" "$@" 2>&1; }

ran=$((ran + 1))
set +e; out=$(since --since shipped); status=$?; set -e
{ [ $status -eq 0 ] && grep -q '1 migration(s) checked' <<<"$out"; } ||
  fail "--since: a new expand-only migration next to a shipped breaking one: exit $status, want 0 and one checked"$'\n'"$out"

ran=$((ran + 1))
set +e; out=$(since); status=$?; set -e
[ $status -eq 1 ] || fail "full check over the same directory: exit $status, want 1"$'\n'"$out"

ran=$((ran + 1))
g add . && g commit -qm new
echo "DROP TABLE gadgets;" >>"$repo/00002_new.sql"
set +e; out=$(since --since shipped); status=$?; set -e
{ [ $status -eq 1 ] && grep -q '00002_new.sql:' <<<"$out"; } ||
  fail "--since: a committed migration changed after REF: exit $status, want 1"$'\n'"$out"

ran=$((ran + 1))
set +e; out=$(since --since does-not-exist); status=$?; set -e
[ $status -eq 2 ] || fail "--since with a ref that does not resolve: exit $status, want 2"$'\n'"$out"

ran=$((ran + 1))
set +e; out=$("$check" --dir "$repo/empty" --upgrading "$notes" 2>&1); status=$?; set -e
[ $status -eq 2 ] || fail "a missing migrations directory: exit $status, want 2"$'\n'"$out"

if [ $failures -gt 0 ]; then
  echo "check-migrations_test: $failures failure(s) in $ran case(s)"
  exit 1
fi
echo "check-migrations_test: $ran case(s) passed ($nfail refused, $npass allowed, $((ran - nfail - npass)) --since and setup)"
