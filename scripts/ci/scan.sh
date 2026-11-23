#!/usr/bin/env bash
# Runs DocVault's security scanners from pinned container images.
# CI and local runs use this same script, so results match.
#
# Usage: scripts/ci/scan.sh [gitleaks|semgrep|trivy|image|checkov|all]
#
# Blocking conditions (the script exits non-zero when any is met):
#   gitleaks  any secret in the working tree or git history
#   semgrep   any ERROR-severity finding
#   trivy     any HIGH or CRITICAL vulnerability that has a fix available
#   image     the same as trivy, on the built application image
#   checkov   any failed check on a Dockerfile or Kubernetes manifest
set -euo pipefail

GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
SEMGREP_IMAGE="semgrep/semgrep:1.182.0@sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af"
TRIVY_IMAGE="aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
CHECKOV_IMAGE="bridgecrew/checkov:3.4.3@sha256:bfe9d70bb7f044aba49bd99675813445f106dee6072da583f51008cb667f3a63"

# Local tag for the image under test. It is never pushed.
APP_IMAGE="docvault-app:scan"

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Scanners run unprivileged and can only read the repository.
RUN=(docker run --rm
  --user "$(id -u):$(id -g)"
  --cap-drop ALL
  --security-opt no-new-privileges
  -e HOME=/tmp
  -v "$REPO_ROOT:/repo:ro"
  -w /repo)

scan_gitleaks() {
  # The local .env holds test passwords, is ignored by Git and is never
  # committed. Hide it here only: the history scan below still covers it.
  local mask_env=()
  if [ -f "$REPO_ROOT/.env" ] && git -C "$REPO_ROOT" check-ignore -q .env; then
    mask_env=(--mount "type=bind,src=/dev/null,dst=/repo/.env,readonly")
  fi

  echo "==> Gitleaks: working tree"
  "${RUN[@]}" "${mask_env[@]}" --network none "$GITLEAKS_IMAGE" \
    dir --no-banner --redact --verbose --exit-code 1 /repo

  if git -C "$REPO_ROOT" rev-parse --quiet --verify HEAD >/dev/null; then
    echo "==> Gitleaks: git history"
    "${RUN[@]}" --network none "$GITLEAKS_IMAGE" \
      git --no-banner --redact --verbose --exit-code 1 /repo
  else
    echo "==> Gitleaks: no commits yet, skipping history scan"
  fi
}

scan_semgrep() {
  echo "==> Semgrep: source code"
  # docs/evidence holds saved scan logs and reports, not code. Scanning them
  # is slow and made a rule time out.
  "${RUN[@]}" "$SEMGREP_IMAGE" \
    semgrep scan \
    --config p/default \
    --config p/owasp-top-ten \
    --exclude docs/evidence \
    --severity ERROR \
    --error \
    --metrics off \
    --disable-version-check \
    /repo
}

TRIVY_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/docvault/trivy"

# Same thresholds for dependencies and the image: see docs/security-policy.md.
TRIVY_GATE=(--cache-dir /trivy-cache
  --scanners vuln
  --severity "HIGH,CRITICAL"
  --ignore-unfixed
  --exit-code 1
  --no-progress)

scan_trivy() {
  echo "==> Trivy: dependencies"
  mkdir -p "$TRIVY_CACHE"
  "${RUN[@]}" -v "$TRIVY_CACHE:/trivy-cache" "$TRIVY_IMAGE" \
    fs "${TRIVY_GATE[@]}" /repo
}

scan_image() {
  echo "==> Trivy: application image"
  docker build --pull -t "$APP_IMAGE" "$REPO_ROOT/backend"

  # Scan an exported copy so the scanner never gets the Docker socket,
  # which would give it control of the host.
  local export_dir
  export_dir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: export_dir is local to this function.
  trap "rm -rf '$export_dir'" EXIT
  docker save -o "$export_dir/image.tar" "$APP_IMAGE"

  mkdir -p "$TRIVY_CACHE"
  "${RUN[@]}" -v "$TRIVY_CACHE:/trivy-cache" -v "$export_dir:/image:ro" "$TRIVY_IMAGE" \
    image "${TRIVY_GATE[@]}" --input /image/image.tar
}

scan_checkov() {
  echo "==> Checkov: Dockerfiles and Kubernetes manifests"
  "${RUN[@]}" --network none "$CHECKOV_IMAGE" \
    --directory /repo \
    --framework dockerfile kubernetes \
    --skip-download \
    --compact \
    --quiet
}

case "${1:-all}" in
  gitleaks) scan_gitleaks ;;
  semgrep) scan_semgrep ;;
  trivy) scan_trivy ;;
  image) scan_image ;;
  checkov) scan_checkov ;;
  all)
    scan_gitleaks
    scan_semgrep
    scan_trivy
    scan_image
    scan_checkov
    ;;
  *)
    echo "Usage: $0 [gitleaks|semgrep|trivy|image|checkov|all]" >&2
    exit 2
    ;;
esac
