#!/usr/bin/env bash
# Refuses a schema migration that would break pods still running the
# previous release.
#
# Upgrades are rolling: the migration Job runs first, then new pods replace
# old ones, and for a while old pods run against the new schema. A migration
# may therefore only add (tables, nullable or defaulted columns, indexes,
# functions). The `-- +goose Up` section of every migration is checked for:
#
#   DROP TABLE, DROP SCHEMA, ALTER TABLE ... DROP [COLUMN],
#   ALTER ... RENAME, ALTER COLUMN ... TYPE, ALTER COLUMN ... SET NOT NULL,
#   ADD COLUMN ... NOT NULL (or PRIMARY KEY) without DEFAULT,
#   DROP INDEX of an index this migration does not also create,
#   ALTER TABLE ... DROP CONSTRAINT of a constraint this migration does not
#   add back (ADD CONSTRAINT, same table and name, after the drop),
#   TRUNCATE, DELETE FROM.
#
# The Down section is not checked: it is allowed to remove what Up added.
# Comments and string literals are skipped. DELETE and TRUNCATE inside a
# CREATE FUNCTION body run when the function is called, not when the
# migration applies, so they are not refused there; everything else is,
# including inside DO blocks. SQL built at run time (EXECUTE 'DROP ...') is
# not seen. A constraint added back under the same name is not compared
# with the one dropped: that it accepts every row the previous release
# writes (a superset, as 00014, 00017 and 00028 widen a CHECK list) is for
# review to see.
#
# A migration that has to break the rule carries a line
#
#   -- supermcp:breaking
#
# and docs/UPGRADING.md names its number (e.g. 00019) in a section telling
# the operator what to do. Both are required.
#
# Usage:
#   scripts/check-migrations.sh                 every migration
#   scripts/check-migrations.sh --since REF     only migrations added or
#                                               changed since REF (merge base)
#   scripts/check-migrations.sh FILE...         these files
# Options:
#   --dir DIR          migrations directory (default internal/store/migrations)
#   --upgrading FILE   upgrade notes (default docs/UPGRADING.md)
#
# Exit status: 0 all allowed, 1 a migration was refused, 2 usage or setup
# error (no migrations found, REF does not resolve).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
dir=$root/internal/store/migrations
upgrading=$root/docs/UPGRADING.md
since=""
files=()

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "check-migrations: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case $1 in
    --since) [ $# -ge 2 ] || die "--since needs a git ref"; since=$2; shift 2 ;;
    --since=*) since=${1#--since=}; shift ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a directory"; dir=$2; shift 2 ;;
    --upgrading) [ $# -ge 2 ] || die "--upgrading needs a file"; upgrading=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) files+=("$1"); shift ;;
  esac
done

[ -f "$upgrading" ] || die "no upgrade notes at $upgrading"

if [ ${#files[@]} -eq 0 ]; then
  [ -d "$dir" ] || die "no migrations directory at $dir"
  if [ -n "$since" ]; then
    git -C "$dir" rev-parse --verify --quiet "$since^{commit}" >/dev/null ||
      die "--since $since does not name a commit here (a shallow clone has no history: fetch with depth 0)"
    base=$(git -C "$dir" merge-base "$since" HEAD) ||
      die "no common ancestor between $since and HEAD"
    # Changed since the branch left REF, committed or not, plus new files
    # not yet added.
    while IFS= read -r f; do
      [ -n "$f" ] && [ -f "$dir/$f" ] && files+=("$dir/$f")
    done < <(
      {
        git -C "$dir" diff --relative --name-only --diff-filter=ACMR "$base" -- '*.sql'
        git -C "$dir" ls-files --others --exclude-standard -- '*.sql'
      } | sort -u
    )
    if [ ${#files[@]} -eq 0 ]; then
      echo "check-migrations: no migration added or changed since $since"
      exit 0
    fi
  else
    for f in "$dir"/*.sql; do
      [ -f "$f" ] && files+=("$f")
    done
    [ ${#files[@]} -gt 0 ] || die "no migrations in $dir"
  fi
fi

# The checker proper. Portable awk (macOS awk, mawk, gawk): no gawk
# extensions. Prints one "LINE<TAB>MESSAGE" per refusal, sorted by line.
read -r -d '' checker <<'AWK' || true
function addtok(t) { n++; tok[n] = t; tline[n] = NR; tok[n + 1] = ""; tok[n + 2] = ""; tok[n + 3] = "" }

function refuse(line, msg) { nv++; vline[nv] = line; vmsg[nv] = msg }

# Reads a possibly schema-qualified name starting at token j; sets nx to
# the token after it and returns the last component.
function readname(j,   name) {
  name = tok[j]; j++
  while (tok[j] == "." && j < n) { name = tok[j + 1]; j += 2 }
  nx = j
  return name
}

function bodykind() {
  if (tok[1] == "DO") return "do"
  if (tok[1] != "CREATE") return ""
  if (tok[2] == "FUNCTION" || tok[2] == "PROCEDURE") return "fn"
  if (tok[2] == "OR" && tok[3] == "REPLACE" && (tok[4] == "FUNCTION" || tok[4] == "PROCEDURE")) return "fn"
  return ""
}

function altertable(k,   j, a, b, depth, s1, col, tbl, hasnn, hasdef, m, sep, key) {
  j = k + 2
  if (tok[j] == "IF" && tok[j + 1] == "EXISTS") j += 2
  if (tok[j] == "ONLY") j++
  tbl = tolower(readname(j)); j = nx
  if (tok[j] == "*") j++
  a = j
  while (a <= n) {
    # One subcommand: up to the next comma outside parentheses.
    depth = 0
    for (b = a; b <= n; b++) {
      if (tok[b] == "(") depth++
      else if (tok[b] == ")") depth--
      else if (tok[b] == "," && depth == 0) break
    }
    sep = b; b--
    s1 = tok[a]
    if (s1 == "RENAME") {
      refuse(tline[a], "ALTER TABLE " tbl " RENAME: the previous release still uses the old name")
    } else if (s1 == "DROP" && tok[a + 1] != "CONSTRAINT") {
      m = a + 1
      if (tok[m] == "COLUMN") m++
      if (tok[m] == "IF" && tok[m + 1] == "EXISTS") m += 2
      refuse(tline[a], "DROP COLUMN " tolower(tok[m]) " on " tbl ": the previous release still reads and writes it")
    } else if (s1 == "ALTER" && tok[a + 1] != "CONSTRAINT") {
      m = a + 1
      if (tok[m] == "COLUMN") m++
      col = tolower(tok[m]); m++
      if (tok[m] == "TYPE" || (tok[m] == "SET" && tok[m + 1] == "DATA" && tok[m + 2] == "TYPE"))
        refuse(tline[a], "ALTER COLUMN " col " TYPE on " tbl ": rewrites the table under a lock and changes what the previous release reads")
      else if (tok[m] == "SET" && tok[m + 1] == "NOT" && tok[m + 2] == "NULL")
        refuse(tline[a], "ALTER COLUMN " col " SET NOT NULL on " tbl ": the previous release still writes rows without it")
    } else if (s1 == "DROP") {
      # DROP CONSTRAINT: refused at the end unless added back.
      m = a + 2
      if (tok[m] == "IF" && tok[m + 1] == "EXISTS") m += 2
      # One this migration created itself was never seen by the previous
      # release.
      key = tbl SUBSEP tolower(tok[m])
      if (!(key in cstate)) { ncd++; cdrop[ncd] = key }
      if (cstate[key] != "created") { cstate[key] = "dropped"; cline[key] = tline[a] }
    } else if (s1 == "ADD" && tok[a + 1] == "CONSTRAINT") {
      key = tbl SUBSEP tolower(tok[a + 2])
      cstate[key] = ((key in cstate) && cstate[key] != "created") ? "added" : "created"
    } else if (s1 == "ADD") {
      m = a + 1
      if (tok[m] == "COLUMN") m++
      if (!(tok[m] ~ /^(CONSTRAINT|PRIMARY|UNIQUE|CHECK|FOREIGN|EXCLUDE)$/)) {
        if (tok[m] == "IF" && tok[m + 1] == "NOT" && tok[m + 2] == "EXISTS") m += 3
        col = tolower(tok[m])
        hasnn = 0; hasdef = 0; depth = 0
        for (j = m; j <= b; j++) {
          if (tok[j] == "(") depth++
          else if (tok[j] == ")") depth--
          else if (depth == 0) {
            if (tok[j] == "NOT" && tok[j + 1] == "NULL") hasnn = 1
            if (tok[j] == "PRIMARY" && tok[j + 1] == "KEY") hasnn = 1
            if (tok[j] == "DEFAULT" || tok[j] == "GENERATED") hasdef = 1
          }
        }
        if (hasnn && !hasdef)
          refuse(tline[a], "ADD COLUMN " col " NOT NULL without DEFAULT on " tbl ": fails on a table with rows, and the previous release does not set it")
      }
    }
    a = sep + 1
  }
}

function check(   k, j, first, name, seenalter) {
  if (n == 0) return
  first = tok[1]
  seenalter = 0
  for (k = 1; k <= n; k++) {
    if (tok[k] == "DROP" && (tok[k + 1] == "TABLE" || tok[k + 1] == "SCHEMA")) {
      j = k + 2
      if (tok[j] == "IF" && tok[j + 1] == "EXISTS") j += 2
      refuse(tline[k], "DROP " tok[k + 1] " " tolower(readname(j)) ": the previous release still reads it")
    }
    if (tok[k] == "DROP" && tok[k + 1] == "INDEX") {
      j = k + 2
      if (tok[j] == "CONCURRENTLY") j++
      if (tok[j] == "IF" && tok[j + 1] == "EXISTS") j += 2
      while (j <= n) {
        nd++; dropname[nd] = readname(j); dropline[nd] = tline[k]; j = nx
        if (tok[j] != ",") break
        j++
      }
    }
    if (tok[k] == "CREATE") {
      j = k + 1
      if (tok[j] == "UNIQUE") j++
      if (tok[j] == "INDEX") {
        j++
        if (tok[j] == "CONCURRENTLY") j++
        if (tok[j] == "IF" && tok[j + 1] == "NOT" && tok[j + 2] == "EXISTS") j += 3
        if (tok[j] != "ON") created[tok[j]] = 1
      }
    }
    if (tok[k] == "ALTER" && !seenalter) {
      seenalter = 1
      if (tok[k + 1] == "TABLE") altertable(k)
      else for (j = k + 1; j <= n; j++) if (tok[j] == "RENAME") {
        refuse(tline[j], "ALTER " tok[k + 1] " ... RENAME: the previous release still uses the old name")
        break
      }
    }
    if (ctx != "fn" && tok[k] == "DELETE" && tok[k + 1] == "FROM") {
      j = k + 2
      if (tok[j] == "ONLY") j++
      refuse(tline[k], "DELETE FROM " tolower(readname(j)) ": removes rows no later step can give back")
    }
    if (ctx != "fn" && tok[k] == "TRUNCATE" && !(first ~ /^(GRANT|REVOKE|CREATE|ALTER|COMMENT)$/)) {
      j = k + 1
      if (tok[j] == "TABLE") j++
      if (tok[j] == "ONLY") j++
      refuse(tline[k], "TRUNCATE " tolower(readname(j)) ": removes every row")
    }
  }
}

function flush() { check(); n = 0 }

function lex(s,   i, L, c, t, rest, tg, k, w) {
  i = 1; L = length(s)
  while (i <= L) {
    if (mode == "bcomment") {
      t = substr(s, i, 2)
      if (t == "/*") { bdepth++; i += 2 }
      else if (t == "*/") { bdepth--; i += 2; if (bdepth == 0) mode = "code" }
      else i++
      continue
    }
    if (mode == "squote") {
      c = substr(s, i, 1)
      if (esc && c == "\\") { i += 2; continue }
      if (c == "'") {
        if (substr(s, i + 1, 1) == "'") { i += 2; continue }
        mode = "code"
      }
      i++
      continue
    }
    if (mode == "dquote") {
      c = substr(s, i, 1)
      if (c == "\"") {
        if (substr(s, i + 1, 1) == "\"") { qid = qid "\""; i += 2; continue }
        mode = "code"; addtok(toupper(qid)); i++
        continue
      }
      qid = qid c; i++
      continue
    }
    if (mode == "dollar") {
      k = index(substr(s, i), strtag)
      if (k == 0) { i = L + 1; continue }
      i += k - 1 + length(strtag); mode = "code"
      continue
    }
    c = substr(s, i, 1)
    if (c == " " || c == "\t" || c == "\r" || c == "\f") { i++; continue }
    t = substr(s, i, 2)
    if (t == "--") break
    if (t == "/*") { mode = "bcomment"; bdepth = 1; i += 2; continue }
    if (c == "'") { esc = 0; mode = "squote"; addtok("<STR>"); i++; continue }
    if (c == "\"") { mode = "dquote"; qid = ""; i++; continue }
    rest = substr(s, i)
    if (c == "$") {
      if (match(rest, /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/)) {
        tg = substr(rest, 1, RLENGTH); i += RLENGTH
        if (ctx != "top" && tg == bodytag) { flush(); ctx = "top"; bodytag = ""; continue }
        if (ctx == "top") {
          k = bodykind()
          if (k != "") { flush(); ctx = k; bodytag = tg; continue }
        }
        addtok("<STR>"); mode = "dollar"; strtag = tg
        continue
      }
      addtok("$"); i++
      continue
    }
    if (match(rest, /^[A-Za-z_][A-Za-z0-9_$]*/)) {
      w = toupper(substr(rest, 1, RLENGTH))
      if (w == "E" && substr(rest, 2, 1) == "'") { esc = 1; mode = "squote"; addtok("<STR>"); i += 2; continue }
      addtok(w); i += RLENGTH
      continue
    }
    if (match(rest, /^[0-9][0-9.]*/)) { addtok("<NUM>"); i += RLENGTH; continue }
    if (c == ";") { flush(); i++; continue }
    addtok(c); i++
  }
}

BEGIN { inup = 0; mode = "code"; ctx = "top"; n = 0; nv = 0; nd = 0; ncd = 0 }

/^[ \t]*--[ \t]*\+goose[ \t]+[Uu][Pp][ \t\r]*$/ { inup = 1; next }
/^[ \t]*--[ \t]*\+goose[ \t]+[Dd][Oo][Ww][Nn][ \t\r]*$/ { if (inup) { flush(); inup = 0 } next }
inup { lex($0) }

END {
  if (inup) flush()
  for (k = 1; k <= nd; k++)
    if (!(dropname[k] in created))
      refuse(dropline[k], "DROP INDEX " tolower(dropname[k]) ": not created by this migration, and queries of the previous release may rely on it")
  # A constraint counts as added back only if its last change in the Up
  # section is an ADD: dropping it again afterwards leaves it gone.
  for (k = 1; k <= ncd; k++)
    if (cstate[cdrop[k]] == "dropped") {
      split(cdrop[k], cparts, SUBSEP)
      refuse(cline[cdrop[k]], "DROP CONSTRAINT " cparts[2] " on " cparts[1] ": not added back under the same name by this migration, and the previous release may rely on what it enforced")
    }
  # Insertion sort by line; there are only ever a handful.
  for (k = 2; k <= nv; k++) {
    l = vline[k]; m = vmsg[k]
    for (j = k - 1; j >= 1 && vline[j] > l; j--) { vline[j + 1] = vline[j]; vmsg[j + 1] = vmsg[j] }
    vline[j + 1] = l; vmsg[j + 1] = m
  }
  for (k = 1; k <= nv; k++) printf "%d\t%s\n", vline[k], vmsg[k]
}
AWK

gha=${GITHUB_ACTIONS:-}
upgrading_rel=${upgrading#"$root"/}
checked=0
refused=0

for f in "${files[@]}"; do
  [ -f "$f" ] || die "no such file: $f"
  rel=${f#"$root"/}
  base=$(basename "$f")
  num=${base%%_*}
  case $num in
    ''|*[!0-9]*) die "$rel: a migration file name starts with its number (00024_name.sql)" ;;
  esac
  checked=$((checked + 1))

  if ! grep -Eq '^[[:space:]]*--[[:space:]]*\+goose[[:space:]]+[Uu][Pp][[:space:]]*$' "$f"; then
    refused=$((refused + 1))
    echo "$rel:1: no '-- +goose Up' line: goose cannot apply this file, and no marker allows that"
    [ "$gha" = true ] && echo "::error file=$rel,line=1::no '-- +goose Up' line"
    continue
  fi

  violations=$(awk "$checker" "$f")
  marked=no
  grep -Eq '^[[:space:]]*--[[:space:]]*supermcp:breaking([[:space:]]|$)' "$f" && marked=yes
  noted=no
  grep -Eq "(^|[^0-9])${num}([^0-9]|\$)" "$upgrading" && noted=yes

  if [ -z "$violations" ] && [ $marked = no ]; then
    continue
  fi
  if [ $marked = yes ] && [ $noted = yes ]; then
    echo "allowed: $rel is marked supermcp:breaking and $upgrading_rel names $num"
    continue
  fi

  refused=$((refused + 1))
  if [ -n "$violations" ]; then
    while IFS=$'\t' read -r line msg; do
      echo "$rel:$line: $msg"
      [ "$gha" = true ] && echo "::error file=$rel,line=$line::$msg"
    done <<<"$violations"
  fi
  if [ $marked = yes ]; then
    echo "$rel: marked supermcp:breaking, but $upgrading_rel does not mention $num. Add a section there telling the operator what this migration does to their data and what to do."
  else
    missing="the line '-- supermcp:breaking' in the migration"
    [ $noted = no ] && missing="$missing, and a section in $upgrading_rel that names $num"
    echo "$rel: not expand-only. Add now and remove in a later release, once no running version uses what goes; or, if it must break, add $missing."
  fi
done

if [ $refused -gt 0 ]; then
  echo "check-migrations: refused $refused of $checked migration(s)"
  exit 1
fi
echo "check-migrations: $checked migration(s) checked, all expand-only or marked"
