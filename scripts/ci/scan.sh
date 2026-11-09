#!/usr/bin/env bash
# Runs PipelineX's security scanners from pinned container images.
# CI and local runs use this same script, so results match.
#
# Usage: scripts/ci/scan.sh [gitleaks|semgrep|trivy|all]
#
# Blocking conditions (the script exits non-zero when any is met):
#   gitleaks  any secret in the working tree or git history
#   semgrep   any ERROR-severity finding
#   trivy     any HIGH or CRITICAL vulnerability that has a fix available
set -euo pipefail

GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
SEMGREP_IMAGE="semgrep/semgrep:1.182.0@sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af"
TRIVY_IMAGE="aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"

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
  echo "==> Gitleaks: working tree"
  "${RUN[@]}" --network none "$GITLEAKS_IMAGE" \
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
  "${RUN[@]}" "$SEMGREP_IMAGE" \
    semgrep scan \
    --config p/default \
    --config p/owasp-top-ten \
    --severity ERROR \
    --error \
    --metrics off \
    --disable-version-check \
    /repo
}

scan_trivy() {
  echo "==> Trivy: dependencies"
  local cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/pipelinex/trivy"
  mkdir -p "$cache_dir"
  "${RUN[@]}" -v "$cache_dir:/trivy-cache" "$TRIVY_IMAGE" \
    fs \
    --cache-dir /trivy-cache \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1 \
    --no-progress \
    /repo
}

case "${1:-all}" in
  gitleaks) scan_gitleaks ;;
  semgrep) scan_semgrep ;;
  trivy) scan_trivy ;;
  all)
    scan_gitleaks
    scan_semgrep
    scan_trivy
    ;;
  *)
    echo "Usage: $0 [gitleaks|semgrep|trivy|all]" >&2
    exit 2
    ;;
esac
