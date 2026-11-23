#!/usr/bin/env bash
# Runtime detection demo: proves that Falco, as installed by
# scripts/ci/deploy.sh, detects attacker-like activity in DocVault.
#
# Usage: scripts/security/detection-demo.sh
#   Needs a cluster deployed by `scripts/ci/deploy.sh up` (same KIND_CLUSTER).
#
# For each DocVault rule (deploy/falco/docvault_rules.yaml), it does something
# harmless that the rule must catch, with kubectl exec into the running pods:
#   DV-R1  a shell in the app container and in the database container
#   DV-R2  `id` in the app container
#   DV-R3  reading /etc/shadow (refused: the app runs as UID 10001), the
#          service account token path (not mounted) and the app's secret
#          file (opened and closed, never printed)
#   DV-R4  a connection to a documentation address (203.0.113.10, RFC 5737),
#          which the network policy blocks
# It then reads Falco's JSON alerts with kubectl logs and prints, for each
# check, DETECTED or MISSED with the matching alert.
#
# Exits non-zero if a DV-R1, DV-R2 or DV-R3 check is missed. DV-R4 is
# reported but not required (see deploy/README.md, known limits).
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-docvault}"
NAMESPACE="docvault"
FALCO_NAMESPACE="falco"
# Seconds to wait for the alerts to reach Falco's log.
WAIT_SECONDS=30

REPO_ROOT="$(git rev-parse --show-toplevel)"
REPORT_DIR="$REPO_ROOT/reports/falco"
TOOLS_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/docvault/bin"
# The kubectl that deploy.sh downloaded and verified, so the version is read
# from there.
KUBECTL_VERSION="$(sed -nE 's/^KUBECTL_VERSION="([^"]+)".*/\1/p' "$REPO_ROOT/scripts/ci/deploy.sh")"
KUBECTL_BIN="$TOOLS_DIR/kubectl-$KUBECTL_VERSION"
if [ ! -x "$KUBECTL_BIN" ]; then
  echo "kubectl $KUBECTL_VERSION not found in $TOOLS_DIR. Run scripts/ci/deploy.sh up first." >&2
  exit 1
fi
KUBECTL=("$KUBECTL_BIN" --context "kind-$CLUSTER")

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
checks="$work_dir/checks.tsv"
falco_log="$work_dir/falco.log"
: > "$checks"

# The pods under test: the running app pod and the database pod.
app_pod="$("${KUBECTL[@]}" -n "$NAMESPACE" get pods -l app=docvault \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
db_pod="db-0"
if [ -z "$app_pod" ]; then
  echo "No running DocVault app pod in cluster '$CLUSTER'. Run scripts/ci/deploy.sh up first." >&2
  exit 1
fi
"${KUBECTL[@]}" -n "$FALCO_NAMESPACE" wait pod -l app.kubernetes.io/name=falco \
  --for=condition=Ready --timeout=60s >/dev/null

falco_logs() {
  "${KUBECTL[@]}" -n "$FALCO_NAMESPACE" logs -l app.kubernetes.io/name=falco -c falco \
    --tail=-1 "$@"
}

# Matches Falco's JSON alerts (file $2) against the expected detections (file
# $3, one per line: name, required, rule ID, pod, container, field, operator
# "=" or "~" (contains), value, separated by tabs).
#   check   exit 0 once every expected alert is present, print nothing
#   report  print DETECTED or MISSED per check, exit 1 if a required one is
#           missed
match_alerts() {
  python3 -I - "$@" <<'PY'
import json
import sys

mode, log_path, checks_path = sys.argv[1:4]
alerts = []
with open(log_path, encoding="utf-8", errors="replace") as log:
    for line in log:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        if str(alert.get("rule", "")).startswith("DV-R"):
            alerts.append(alert)

missed_required = missed_any = 0
with open(checks_path, encoding="utf-8") as checks:
    for row in checks:
        name, required, rule, pod, container, field, op, value = row.rstrip("\n").split("\t")
        found = None
        for alert in alerts:
            fields = alert.get("output_fields") or {}
            if not alert["rule"].startswith(rule + " "):
                continue
            if fields.get("k8s.pod.name") != pod or fields.get("container.name") != container:
                continue
            actual = str(fields.get(field, ""))
            if (op == "=" and actual == value) or (op == "~" and value in actual):
                found = alert
                break
        if found is None:
            missed_any += 1
            missed_required += required == "yes"
        if mode != "report":
            continue
        status = "DETECTED" if found else "MISSED  "
        note = "" if required == "yes" else " (optional)"
        print(f"{status} {rule}  {name}{note}")
        if found:
            print(f"         falco: {found.get('output', '').strip()}")

if mode == "report":
    counts = {}
    for alert in alerts:
        rule_id = alert["rule"].split(" ", 1)[0]
        counts[rule_id] = counts.get(rule_id, 0) + 1
    summary = ", ".join(f"{rule_id}: {count}" for rule_id, count in sorted(counts.items()))
    print(f"\nDocVault alerts raised during the demo: {summary or 'none'}")
    sys.exit(1 if missed_required else 0)
sys.exit(1 if missed_any else 0)
PY
}

# Runs a command in a container and records the alert it must raise.
#   trigger NAME REQUIRED RULE POD CONTAINER FIELD OP VALUE -- COMMAND...
trigger() {
  local name="$1" required="$2" rule="$3" pod="$4" container="$5" field="$6" op="$7" value="$8"
  shift 9
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$required" "$rule" "$pod" "$container" "$field" "$op" "$value" >> "$checks"
  echo "--> $rule $name"
  echo "    kubectl exec $pod -c $container -- $*"
  local output status=0
  output="$("${KUBECTL[@]}" -n "$NAMESPACE" exec "$pod" -c "$container" -- "$@" 2>&1)" || status=$?
  if [ -n "$output" ]; then
    head -n 3 <<<"$output" | sed 's/^/    | /'
  fi
  if [ "$status" -ne 0 ]; then
    echo "    (exit status $status)"
  fi
}

# Alerts raised before the demo, for example during the ZAP scan in CI. They
# are shown, not counted: the demo only checks its own actions.
since="$(date -u -d '-1 second' +%Y-%m-%dT%H:%M:%SZ)"
falco_logs > "$falco_log"
earlier="$(grep -F '"rule":"DV-R' "$falco_log" || true)"
echo "==> Falco on cluster '$CLUSTER': DocVault alerts before the demo"
if [ -n "$earlier" ]; then
  echo "    $(wc -l <<<"$earlier") earlier alert(s), from a previous run of this demo or other activity (last 10):"
  python3 -I -c '
import json, sys
for line in sys.stdin:
    print("    " + json.loads(line).get("output", "").strip())
' <<<"$earlier" | tail -n 10
else
  echo "    none"
fi

echo "==> Triggering each rule (app pod $app_pod, database pod $db_pod)"
marker="dv-demo-$(date +%s)"
trigger "shell in the app container" yes DV-R1 "$app_pod" app \
  proc.cmdline "~" "$marker" -- sh -c "echo $marker"
trigger "shell in the database container" yes DV-R1 "$db_pod" postgres \
  proc.cmdline "~" "$marker" -- sh -c "echo $marker"
trigger "unexpected program (id) in the app container" yes DV-R2 "$app_pod" app \
  proc.name "=" id -- id
trigger "read /etc/shadow in the app container" yes DV-R3 "$app_pod" app \
  fs.path.name "=" /etc/shadow -- cat /etc/shadow
trigger "read the service account token path in the app container" yes DV-R3 "$app_pod" app \
  fs.path.name "~" /secrets/kubernetes.io/serviceaccount/token \
  -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Opened and closed, never read or printed.
trigger "open the app's secret file from another process" yes DV-R3 "$app_pod" app \
  fs.path.name "=" /run/secrets/docvault/SECRET_KEY \
  -- python -c "open('/run/secrets/docvault/SECRET_KEY').close()"
trigger "outbound connection from the app container" no DV-R4 "$app_pod" app \
  fd.name "~" "203.0.113.10:443" \
  -- python -c "import socket; s = socket.socket(); s.settimeout(2); print('connect:', s.connect_ex(('203.0.113.10', 443)))"

echo "==> Waiting up to ${WAIT_SECONDS}s for Falco's alerts"
for _ in $(seq "$WAIT_SECONDS"); do
  falco_logs --since-time="$since" > "$falco_log"
  if match_alerts check "$falco_log" "$checks"; then break; fi
  sleep 1
done

echo "==> Results"
# The DocVault alerts are kept as evidence (CI uploads them).
mkdir -p "$REPORT_DIR"
grep -F '"rule":"DV-R' "$falco_log" > "$REPORT_DIR/demo-alerts.jsonl" || true
printf '%s\n' "$earlier" | grep -v '^$' > "$REPORT_DIR/earlier-alerts.jsonl" || true
result=0
match_alerts report "$falco_log" "$checks" | tee "$REPORT_DIR/demo-results.txt" || result=$?
echo "Falco's alerts are in ${REPORT_DIR#"$REPO_ROOT"/}/."
if [ "$result" -ne 0 ]; then
  echo "A required DocVault detection was missed." >&2
  exit 1
fi
echo "All required DocVault detections fired."
