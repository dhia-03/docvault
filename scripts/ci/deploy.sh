#!/usr/bin/env bash
# Deploys DocVault to a throwaway kind cluster on this machine, for DAST and
# demos. CI and local runs use this same script.
#
# Usage: scripts/ci/deploy.sh [up|logs|down]
#   up    create the cluster if needed, install Kyverno and its policies,
#         check that a non-compliant pod is rejected, build and load the
#         images, deploy, check the network policies, then check that the app
#         answers and that a test user can sign in.
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
# Kyverno publishes no checksum for install.yaml in this release, so this
# SHA-256 was recorded on first download (2026-11-23).
KYVERNO_VERSION="v1.19.2"
KYVERNO_SHA256="4f785937dc7fe49a0731108b15def1538923c73d9236255bc69d94d498037969"

REPO_ROOT="$(git rev-parse --show-toplevel)"
TOOLS_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/docvault/bin"

# Downloads a file once, refusing it unless its checksum matches.
fetch_file() {
  local path="$TOOLS_DIR/$1" sha256="$2" url="$3"
  if [ ! -f "$path" ]; then
    mkdir -p "$TOOLS_DIR"
    curl -fsSL -o "$path.tmp" "$url"
    echo "$sha256  $path.tmp" | sha256sum --check --quiet
    mv "$path.tmp" "$path"
  fi
  echo "$path"
}

fetch_tool() {
  local path
  path="$(fetch_file "$1-$2" "$3" "$4")"
  chmod +x "$path"
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
  KYVERNO_MANIFEST="$(fetch_file "kyverno-install-$KYVERNO_VERSION.yaml" "$KYVERNO_SHA256" \
    "https://github.com/kyverno/kyverno/releases/download/$KYVERNO_VERSION/install.yaml")"
  # Always target this cluster, whatever the current kubectl context is.
  KUBECTL=("$KUBECTL_BIN" --context "kind-$CLUSTER")
}

# Prints every image referenced by the given manifests.
images_in() {
  sed -nE 's/^[[:space:]]*image:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$@" | sort -u
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

  # Pull images referenced by tag on the host and load them into the cluster,
  # so the cluster does not download them itself: DNS inside the kind node can
  # be unreliable (seen on WSL), and this also avoids registry rate limits.
  # Images pinned by digest are left for the cluster to pull, because it then
  # checks the digest; an exported copy gets a different digest and would not
  # match the pin.
  local image
  local images=("$APP_IMAGE")
  while read -r image; do
    [ "$image" = "$APP_IMAGE" ] && continue
    if [[ "$image" == *@sha256:* ]]; then
      echo "    $image: pulled and verified by the cluster"
      continue
    fi
    docker pull --quiet --platform linux/amd64 "$image" >/dev/null
    images+=("$image")
  done < <(images_in "$REPO_ROOT"/deploy/k8s/*.yaml "$KYVERNO_MANIFEST")
  echo "==> Loading into the cluster: ${images[*]}"
  "$KIND" load docker-image --name "$CLUSTER" "${images[@]}"

  install_kyverno

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
  check_admission
  "${KUBECTL[@]}" -n "$NAMESPACE" create secret generic docvault-secrets \
    --from-file="$secret_dir" --dry-run=client -o yaml \
    | "${KUBECTL[@]}" apply -f -
  local existing=""
  "${KUBECTL[@]}" -n "$NAMESPACE" get deployment/docvault >/dev/null 2>&1 && existing=1
  "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/k8s/"
  "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/test/access.yaml"
  # The image tag does not change between builds, so restart an existing
  # deployment to pick up a new one. A new deployment needs no restart, and a
  # restart would run a second seeding init container at the same time.
  if [ -n "$existing" ]; then
    "${KUBECTL[@]}" -n "$NAMESPACE" rollout restart deployment/docvault
  fi
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status statefulset/db --timeout=300s
  "${KUBECTL[@]}" -n "$NAMESPACE" rollout status deployment/docvault --timeout=300s

  check_network_policy
  smoke_test "$secret_dir/SEED_PASSWORD"
}

install_kyverno() {
  echo "==> Installing Kyverno $KYVERNO_VERSION and the DocVault policies"
  # Server-side apply: the CRDs are too large for client-side apply.
  "${KUBECTL[@]}" apply --server-side --force-conflicts -f "$KYVERNO_MANIFEST" >/dev/null
  "${KUBECTL[@]}" -n kyverno wait deployment --all --for=condition=Available --timeout=300s
  # The deployments report Available a little before the webhook serves, and
  # applying a policy goes through that webhook, so retry for a while.
  local attempt
  for attempt in $(seq 24); do
    if "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/kyverno/" 2>/dev/null; then break; fi
    if [ "$attempt" -eq 24 ]; then
      "${KUBECTL[@]}" apply -f "$REPO_ROOT/deploy/kyverno/" # Show the error.
    fi
    sleep 5
  done
  "${KUBECTL[@]}" wait clusterpolicy --all --for=condition=Ready --timeout=120s
}

# Proves the policies are enforced: a pod like the baseline's, with no
# security context, must be refused at admission.
check_admission() {
  echo "==> Kyverno: a pod with no security context must be rejected"
  local output
  if output="$("${KUBECTL[@]}" -n "$NAMESPACE" run kyverno-check --image="$APP_IMAGE" \
    --restart=Never --dry-run=server -o name 2>&1)"; then
    echo "Kyverno admitted a non-compliant pod." >&2
    exit 1
  fi
  if ! grep -q 'admission webhook "validate.kyverno.svc' <<<"$output"; then
    echo "The pod was refused, but not by Kyverno:" >&2
    echo "$output" >&2
    exit 1
  fi
  grep -oE '(pod-security-restricted|require-read-only-root-filesystem|require-resource-limits|disallow-service-account-token)' \
    <<<"$output" | sort -u | sed 's/^/    rejected by policy: /'
}

# Proves the network policies are enforced: a pod outside the namespace must
# not reach the database, which only accepts connections from the app.
check_network_policy() {
  echo "==> Network policy: the database must be unreachable from another namespace"
  local check_ns="netpol-check" db_image
  db_image="$(images_in "$REPO_ROOT/deploy/k8s/10-db.yaml" | head -1)"
  "${KUBECTL[@]}" create namespace "$check_ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" -n "$check_ns" delete pod probe --ignore-not-found >/dev/null
  "${KUBECTL[@]}" -n "$check_ns" apply -f - >/dev/null <<POD
apiVersion: v1
kind: Pod
metadata:
  name: probe
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: $db_image
      imagePullPolicy: IfNotPresent
      # -U is needed: UID 10001 has no user entry to take a default name from.
      command: ["pg_isready", "-U", "docvault", "-h", "db.$NAMESPACE.svc.cluster.local", "-p", "5432", "-t", "5"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: 100m
          memory: 64Mi
POD
  "${KUBECTL[@]}" -n "$check_ns" wait pod/probe --for=jsonpath='{.status.phase}'=Succeeded --timeout=60s >/dev/null 2>&1 \
    || "${KUBECTL[@]}" -n "$check_ns" wait pod/probe --for=jsonpath='{.status.phase}'=Failed --timeout=30s >/dev/null
  local result
  result="$("${KUBECTL[@]}" -n "$check_ns" logs probe)"
  "${KUBECTL[@]}" delete namespace "$check_ns" --wait=false >/dev/null
  if ! grep -q 'no response' <<<"$result"; then
    echo "The database answered a pod outside the namespace: $result" >&2
    exit 1
  fi
  echo "    blocked: $result"
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
