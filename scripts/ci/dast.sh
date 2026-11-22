#!/usr/bin/env bash
# Authenticated OWASP ZAP scan of DocVault, as deployed by deploy.sh.
# CI and local runs use this same script.
#
# Usage: scripts/ci/dast.sh
#   Needs SEED_PASSWORD in the environment (the test users' password).
#   Reports go to reports/zap/ (ignored by Git).
#
# Blocking condition: any High risk alert (see docs/security-policy.md).
set -euo pipefail

ZAP_IMAGE="zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"

REPO_ROOT="$(git rev-parse --show-toplevel)"
APP_TEST_PORT="${APP_TEST_PORT:-18000}"
TARGET="http://127.0.0.1:$APP_TEST_PORT"
REPORT_DIR="$REPO_ROOT/reports/zap"

: "${SEED_PASSWORD:?Set SEED_PASSWORD}"

if [ "$(curl -fsS "$TARGET/healthz" 2>/dev/null)" != "ok" ]; then
  echo "DocVault is not answering on $TARGET. Run scripts/ci/deploy.sh up first." >&2
  exit 1
fi

# Give the scan something to find: a fresh database has no documents, so
# the document pages, preview and sharing forms would never be reached.
echo "==> Uploading a sample document as alice"
cookie_jar="$(mktemp)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$cookie_jar" "$work_dir"' EXIT
# The password is read from standard input, so it never appears in the
# process list.
printf '%s' "$SEED_PASSWORD" | curl -fsS -o /dev/null -c "$cookie_jar" "$TARGET/login" \
  --data-urlencode "username=alice" --data-urlencode "password@-"
printf 'Quarterly figures, test data only.\n' \
  | curl -fsS -o /dev/null -b "$cookie_jar" "$TARGET/documents" \
    -F "title=Quarterly report" -F "file=@-;filename=quarterly-report.txt"

echo "==> ZAP: authenticated spider and active scan of $TARGET"
# ZAP runs as its own unprivileged user, so its work folder must be writable
# by that user. It is a fresh temporary folder, deleted on exit.
chmod 0777 "$work_dir"
# ZAP does not expand environment variables in every field (the login check
# URL stayed literal), so write the target into a copy of the plan. The
# password is still read from the environment by ZAP.
sed "s|\${DAST_TARGET}|$TARGET|g" "$REPO_ROOT/scripts/ci/zap/plan.yaml" > "$work_dir/plan.yaml"
# Host networking lets ZAP reach the app on this machine's loopback address.
# SEED_PASSWORD is passed by name, so its value is not on the command line.
zap_status=0
docker run --rm \
  --network host \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -e SEED_PASSWORD \
  -v "$work_dir:/zap/wrk" \
  "$ZAP_IMAGE" \
  zap.sh -cmd -autorun /zap/wrk/plan.yaml || zap_status=$?

mkdir -p "$REPORT_DIR"
cp "$work_dir"/zap-report.* "$REPORT_DIR/" 2>/dev/null || true
if [ ! -f "$REPORT_DIR/zap-report.json" ]; then
  echo "ZAP did not produce a report (exit status $zap_status)." >&2
  exit 1
fi
# The plan sets failOnError, so status 1 means the scan itself failed, for
# example because sign-in did not work. Status 2 only flags plan warnings.
if [ "$zap_status" -eq 1 ]; then
  echo "ZAP reported a plan error; the results may be incomplete." >&2
  exit 1
fi

echo "==> Reports in $REPORT_DIR"
python3 "$REPO_ROOT/scripts/ci/zap_gate.py" "$REPORT_DIR/zap-report.json"
