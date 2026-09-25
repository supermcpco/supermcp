#!/usr/bin/env bash
# Installs charts/supermcp on a kind cluster against a real Postgres and
# checks that it starts, then upgrades it in place and checks that it
# keeps answering. The helm-install CI job runs this; so does
# `make kind-test`.
#
#   hack/kind/test.sh
#
# What it proves, in order:
#   1. `helm install --wait` succeeds: the pre-install migrate Job ran to
#      completion and the Deployment became Available in a namespace that
#      enforces the restricted Pod Security Standard.
#   2. The schema in the database is the one the binary expects.
#   3. /readyz, the catalog and the OpenAPI document answer through a
#      port-forward (hack/smoke.sh, the same checks go-integration runs
#      against the bare binary).
#   4. `helm upgrade --wait` with one changed pod annotation runs the
#      pre-upgrade migrate Job again, replaces every pod, and /readyz,
#      polled from inside the cluster through the Service for the whole
#      rollout, never answers anything but 200.
#
# Environment:
#   KIND_CLUSTER   cluster name (default supermcp). Reused if it exists,
#                  created otherwise; a cluster this script created is
#                  deleted at the end unless KEEP_CLUSTER=1.
#   IMAGE          image to load, as name:tag (default supermcp:kind).
#   BUILD_IMAGE    1 (default) builds IMAGE from the Dockerfile first; CI
#                  sets 0 because the image is already built and loaded.
#   NAMESPACE      namespace for the release (default supermcp-kind); it
#                  and NAMESPACE-db are deleted and recreated every run.
#   LOCAL_PORT     local end of the port-forward (default 18080).
#
# Exit status: 0 passed, 1 a check failed, 2 a tool is missing.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
here="$root/hack/kind"
cluster="${KIND_CLUSTER:-supermcp}"
image="${IMAGE:-supermcp:kind}"
build="${BUILD_IMAGE:-1}"
ns="${NAMESPACE:-supermcp-kind}"
dbns="$ns-db"
port="${LOCAL_PORT:-18080}"
release=supermcp
ctx="kind-$cluster"
work=$(mktemp -d)

missing=0
need() {
  command -v "$1" >/dev/null && return
  echo "missing: $1 ($2)" >&2
  missing=1
}
need kind    "https://kind.sigs.k8s.io/docs/user/quick-start/#installation, e.g. brew install kind or go install sigs.k8s.io/kind@latest"
need kubectl "https://kubernetes.io/docs/tasks/tools/"
need helm    "https://helm.sh/docs/intro/install/"
need docker  "kind runs its nodes as Docker containers"
need curl    "used by hack/smoke.sh"
need jq      "used by hack/smoke.sh"
need openssl "generates the throwaway master key"
[ "$missing" = 0 ] || exit 2
case "$image" in
  *:*) ;;
  *) echo "IMAGE must be name:tag, got $image" >&2; exit 2 ;;
esac

k() { kubectl --context "$ctx" "$@"; }
h() { helm --kube-context "$ctx" "$@"; }
step() { echo; echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

created=""
pf_pid=""
stop_port_forward() {
  if [ -n "$pf_pid" ]; then kill "$pf_pid" 2>/dev/null || true; wait "$pf_pid" 2>/dev/null || true; fi
  pf_pid=""
}

# Everything needed to tell why a run failed, printed into the log that
# already shows the failure, because the cluster is gone once the CI
# runner is.
diagnose() {
  echo
  echo "================ diagnostics ================"
  k get all -A -o wide || true
  echo "---- events ($ns)"
  k -n "$ns" get events --sort-by=.lastTimestamp || true
  echo "---- helm"
  h -n "$ns" history "$release" || true
  echo "---- describe pods ($ns)"
  k -n "$ns" describe pods || true
  echo "---- describe pods ($dbns)"
  k -n "$dbns" describe pods || true
  for pod in $(k -n "$ns" get pods -o name 2>/dev/null); do
    echo "---- logs $pod (last 200 lines)"
    k -n "$ns" logs "$pod" --all-containers --tail=200 || true
    if k -n "$ns" logs "$pod" --all-containers --previous --tail=200 >"$work/prev.log" 2>/dev/null; then
      echo "---- logs $pod, previous container (last 200 lines)"
      cat "$work/prev.log"
    fi
  done
  echo "---- logs postgres (last 50 lines)"
  k -n "$dbns" logs deploy/postgres --tail=50 || true
  if [ -s "$work/port-forward.log" ]; then
    echo "---- port-forward"
    cat "$work/port-forward.log"
  fi
}

finish() {
  status=$?
  stop_port_forward
  [ "$status" = 0 ] || diagnose
  if [ -n "$created" ] && [ "${KEEP_CLUSTER:-}" != 1 ]; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
  if [ "$status" = 0 ]; then echo; echo "PASS: kind install and upgrade"; fi
  exit "$status"
}
trap finish EXIT

port_forward() {
  stop_port_forward
  # kubectl itself, not the k function: a function in the background is a
  # subshell, and killing that leaves kubectl holding the port.
  kubectl --context "$ctx" -n "$ns" port-forward "svc/$release" "$port:80" >"$work/port-forward.log" 2>&1 &
  pf_pid=$!
  for _ in $(seq 1 20); do
    grep -q 'Forwarding from' "$work/port-forward.log" && return
    sleep 0.5
  done
  fail "port-forward to svc/$release did not start"
}

# The completed-Job events for the migrate hook. The hook deletes its Job
# once it succeeds, so the events are what is left to read.
migrate_completions() {
  k -n "$ns" get events \
    --field-selector "involvedObject.kind=Job,involvedObject.name=$release-migrate,reason=Completed" \
    -o name | wc -l | tr -d ' '
}

schema_matches() {
  local out have want
  out=$(k -n "$ns" exec "deploy/$release" -c supermcp -- /supermcp migrate --status)
  echo "$out"
  have=$(sed -nE 's/^schema version: ([0-9]+) .*/\1/p' <<<"$out")
  want=$(sed -nE 's/.*binary expects ([0-9]+)\).*/\1/p' <<<"$out")
  [ -n "$have" ] && [ "$have" -gt 0 ] && [ "$have" = "$want" ] \
    || fail "schema version $have in the database, binary expects $want"
}

step "cluster $cluster"
if kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  echo "reusing existing cluster"
else
  kind create cluster --name "$cluster" --wait 2m
  created=1
fi
k cluster-info >/dev/null

if [ "$build" = 1 ]; then
  step "build $image"
  docker build -t "$image" "$root"
fi
step "load $image into $cluster"
kind load docker-image "$image" --name "$cluster"

step "namespaces $ns (restricted) and $dbns"
k delete namespace "$ns" "$dbns" --ignore-not-found --wait --timeout=2m
k create namespace "$dbns"
k create namespace "$ns"
# The chart claims restricted Pod Security; a pod that is not would be
# refused here and the install would time out naming it.
k label namespace "$ns" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest

step "postgres"
k -n "$dbns" apply -f "$here/postgres.yaml"
k -n "$dbns" rollout status deploy/postgres --timeout=3m

step "secrets"
# The same fixed test credentials as the go-integration job, and a master
# key that exists only for this run.
url="postgres://supermcp:supermcp@postgres.$dbns.svc.cluster.local:5432/supermcp?sslmode=disable"
k -n "$ns" create secret generic supermcp-db \
  --from-literal=DATABASE_URL="$url" --from-literal=MAINT_DATABASE_URL="$url" >/dev/null
k -n "$ns" create secret generic supermcp-kek \
  --from-literal=ENCRYPTION_KEK="$(openssl rand -base64 32)" >/dev/null

chart_args=(
  "$root/charts/supermcp" -n "$ns" -f "$here/values.yaml"
  --set "image.repository=${image%:*}" --set-string "image.tag=${image##*:}"
  --wait --timeout 5m
)

step "helm install"
start=$(date +%s)
h install "$release" "${chart_args[@]}"
echo "installed in $(( $(date +%s) - start ))s"

step "assert: migrate Job completed"
n=$(migrate_completions)
[ "$n" -ge 1 ] || fail "no Completed event for Job $release-migrate"
echo "ok   $release-migrate completed"

step "assert: Deployment Available"
k -n "$ns" wait --for=condition=Available "deploy/$release" --timeout=60s

step "assert: schema matches the binary"
schema_matches

step "smoke through a port-forward"
port_forward
"$root/hack/smoke.sh" "http://127.0.0.1:$port"
stop_port_forward

step "helm upgrade: one changed annotation, rolling"
before=$(k -n "$ns" get pods -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=supermcp" \
  --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}')
# Polls /readyz through the Service from inside the cluster for the whole
# rollout. A port-forward cannot do this: it is pinned to one pod and dies
# with it.
k -n "$ns" apply -f - <<PROBE
apiVersion: v1
kind: Pod
metadata:
  name: readyz-probe
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 100
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: probe
      image: curlimages/curl:8.16.0
      command:
        - sh
        - -c
        - |
          while true; do
            if curl -fsS -o /dev/null --max-time 2 http://$release.$ns.svc.cluster.local/readyz; then
              echo ok
            else
              echo "FAIL \$(date -u +%H:%M:%S)"
            fi
            sleep 0.5
          done
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
      resources:
        requests: { cpu: 10m, memory: 16Mi }
PROBE
k -n "$ns" wait --for=condition=Ready pod/readyz-probe --timeout=2m
sleep 3
k -n "$ns" logs readyz-probe | grep -q '^ok' || fail "readyz-probe saw no 200 before the upgrade"

start=$(date +%s)
h upgrade "$release" "${chart_args[@]}" --set-string "podAnnotations.kind-test/rollout=$start"
echo "upgraded in $(( $(date +%s) - start ))s"
k -n "$ns" rollout status "deploy/$release" --timeout=2m

step "assert: every pod was replaced"
# The rollout reports done while the old pods are still in their preStop
# pause and drain. Each must be gone well inside its grace period, and the
# probe keeps polling until it is, which is the window that matters.
for p in $before; do
  k -n "$ns" wait --for=delete "pod/$p" --timeout=60s >/dev/null 2>&1 \
    || fail "pod $p from before the upgrade is still there a minute later"
done
after=$(k -n "$ns" get pods -l "app.kubernetes.io/instance=$release,app.kubernetes.io/name=supermcp" \
  -o jsonpath='{.items[*].metadata.name}')
[ -n "$after" ] || fail "no pods after the upgrade"
got=$(k -n "$ns" get "deploy/$release" -o jsonpath='{.spec.template.metadata.annotations.kind-test/rollout}')
[ "$got" = "$start" ] || fail "Deployment template annotation is '$got', want $start"
echo "ok   pods before: $before; after: $after"

# A few more polls after the old pod is gone, where a node still sending
# to it would show.
sleep 3
k -n "$ns" logs readyz-probe >"$work/probe.log"
k -n "$ns" delete pod readyz-probe --wait=false >/dev/null

step "assert: the upgrade ran the migrate hook again"
n=$(migrate_completions)
[ "$n" -ge 2 ] || fail "expected a second Completed event for Job $release-migrate, found $n"
echo "ok   $release-migrate completed on install and on upgrade"

step "assert: /readyz stayed 200 through the rollout"
oks=$(grep -c '^ok' "$work/probe.log" || true)
fails=$(grep -c '^FAIL' "$work/probe.log" || true)
echo "readyz-probe: $oks answered 200, $fails did not"
[ "$fails" = 0 ] || { grep -B1 '^FAIL' "$work/probe.log"; fail "/readyz did not answer 200 during the rollout"; }
[ "$oks" -ge 10 ] || fail "readyz-probe recorded only $oks polls; the rollout was not observed"

step "assert: schema still matches, smoke after the upgrade"
schema_matches
port_forward
"$root/hack/smoke.sh" "http://127.0.0.1:$port"
