#!/usr/bin/env bash
# Deploys DocVault to a throwaway kind cluster on this machine, for DAST and
# demos. CI and local runs use this same script.
#
# Usage: scripts/ci/deploy.sh [up|logs|down]
#   up    create the cluster if needed, build and load the image, deploy,
#         then check that the app answers and that a test user can sign in.
#         Needs POSTGRES_PASSWORD and SEED_PASSWORD in the environment.
#         The app is then reachable on http://127.0.0.1:$APP_TEST_PORT only.
#   logs  print pod status, events and logs, for debugging a failed deploy
#   down  delete the cluster
set -euo pipefail

CLUSTER="docvault"
NAMESPACE="docvault"
APP_IMAGE="docvault-app:dev"
APP_TEST_PORT="${APP_TEST_PORT:-18000}"
NODE_PORT=30080 # Must match deploy/test/access.yaml.

# Pinned tools, verified against the checksums published with each release.
KIND_VERSION="v0.33.0"
KIND_SHA256="aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
KUBECTL_VERSION="v1.37.0"
KUBECTL_SHA256="6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f"
NODE_IMAGE="kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"

REPO_ROOT="$(git rev-parse --show-toplevel)"
TOOLS_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/docvault/bin"

# Downloads a tool once, refusing it unless its checksum matches.
fetch_tool() {
  local name="$1" version="$2" sha256="$3" url="$4"
  local path="$TOOLS_DIR/$name-$version"
  if [ ! -x "$path" ]; then
    mkdir -p "$TOOLS_DIR"
    curl -fsSL -o "$path.tmp" "$url"
    echo "$sha256  $path.tmp" | sha256sum --check --quiet
    chmod +x "$path.tmp"
    mv "$path.tmp" "$path"
  fi
  echo "$path"
}

setup_tools() {
  if [ "$(uname -sm)" != "Linux x86_64" ]; then
    echo "deploy.sh supports Linux x86_64 only (WSL works)." >&2
    exit 1
  fi
  KIND="$(fetch_tool kind "$KIND_VERSION" "$KIND_SHA256" \
    "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64")"
  KUBECTL_BIN="$(fetch_tool kubectl "$KUBECTL_VERSION" "$KUBECTL_SHA256" \
    "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl")"
  # Always target this cluster, whatever the current kubectl context is.
  KUBECTL=("$KUBECTL_BIN" --context "kind-$CLUSTER")
}

up() {
  : "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD}" "${SEED_PASSWORD:?Set SEED_PASSWORD}"

  if "$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "==> Using existing kind cluster '$CLUSTER'"
  else
    echo "==> Creating kind cluster '$CLUSTER'"
    # Map the test node port to the host's loopback interface only.
    "$KIND" create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 120s --config - <<KIND
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: $NODE_PORT
        hostPort: $APP_TEST_PORT
        listenAddress: 127.0.0.1
KIND
  fi

  echo "==> Building $APP_IMAGE"
  docker build -t "$APP_IMAGE" "$REPO_ROOT/backend"

  # Pull every other image on the host and load it into the cluster, so the
  # cluster never downloads anything itself. DNS inside the kind node can be
  # unreliable (seen on WSL), and this also avoids registry rate limits.
  local image
  local images=("$APP_IMAGE")
  while read -r image; do
    [ "$image" = "$APP_IMAGE" ] && continue
    docker pull --quiet --platform linux/amd64 "$image"
    images+=("$image")
  done < <(sed -nE 's/^[[:space:]]*image:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' \
    "$REPO_ROOT"/deploy/k8s/*.yaml | sort -u)
  echo "==> Loading into the cluster: ${images[*]}"
  "$KIND" load docker-image --name "$CLUSTER" "${images[@]}"

  # Passwords go through files, not command-line arguments, so other
  # processes cannot read them from the process list.
  local secret_dir
  secret_dir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: secret_dir is local to this function.
  trap "rm -rf '$secret_dir'" EXIT
  printf '%s' "$POSTGRES_PASSWORD" > "$secret_dir/POSTGRES_PASSWORD"
  printf '%s' "$SEED_PASSWORD" > "$secret_dir/SEED_PASSWORD"

  echo "==> Deploying"
  "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/k8s/00-namespace.yaml"
  "${KUBECTL[@]}" -n "$NAMESPACE" create secret generic docvault-secrets \
    --from-file="$secret_dir" --dry-run=client -o yaml \
    | "${KUBECTL[@]}" apply -f -
  "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/k8s/"
  "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/test/access.yaml"
  # The image tag does not change between builds, so restart to pick up a new one.
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout restart deployment/docvault
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status statefulset/db --timeout=300s
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/docvault --timeout=300s

  smoke_test "$secret_dir/SEED_PASSWORD"
}

smoke_test() {
  local password_file="$1"
  local base="http://127.0.0.1:$APP_TEST_PORT"
  echo "==> Smoke test on $base"

  # The baseline has no readiness probe, so the pod counts as ready before
  # the app listens. Wait for /healthz instead.
  local ok=""
  for _ in $(seq 90); do
    if [ "$(curl -fsS "$base/healthz" 2>/dev/null)" = "ok" ]; then ok=1; break; fi
    sleep 2
  done
  if [ -z "$ok" ]; then
    echo "Smoke test failed: /healthz did not answer within 3 minutes." >&2
    echo "A cluster created before the port mapping existed needs '$0 down' first." >&2
    exit 1
  fi
  echo "    /healthz answered ok"

  # A successful sign-in redirects and sets the session cookie.
  local headers
  headers="$(curl -sS -o /dev/null -D - "$base/login" \
    --data-urlencode "username=alice" \
    --data-urlencode "password@$password_file")"
  if ! grep -qiE '^HTTP/[0-9.]+ 30[23]' <<<"$headers" || ! grep -qi '^set-cookie:' <<<"$headers"; then
    echo "Smoke test failed: test user could not sign in" >&2
    exit 1
  fi
  echo "    test user 'alice' signed in"
}

logs() {
  "${KUBECTL[@]}" -n "$NAMESPACE" get pods -o wide || true
  "${KUBECTL[@]}" -n "$NAMESPACE" get events --sort-by=.lastTimestamp || true
  "${KUBECTL[@]}" -n "$NAMESPACE" logs deployment/docvault --tail=100 || true
  "${KUBECTL[@]}" -n "$NAMESPACE" logs statefulset/db --tail=50 || true
}

down() {
  "$KIND" delete cluster --name "$CLUSTER"
}

case "${1:-up}" in
  up) setup_tools; up ;;
  logs) setup_tools; logs ;;
  down) setup_tools; down ;;
  *)
    echo "Usage: $0 [up|logs|down]" >&2
    exit 2
    ;;
esac
