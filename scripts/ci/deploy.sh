#!/usr/bin/env bash
# Deploys DocVault to a throwaway kind cluster on this machine, for DAST and
# demos. CI and local runs use this same script.
#
# Usage: scripts/ci/deploy.sh [up|logs|down]
#   up    create the cluster if needed, build and load the images, install
#         Kyverno and its policies, install Falco and the DocVault detection
#         rules, check that a non-compliant pod is rejected, deploy, check the
#         network policies, check that the app answers and that a test user
#         can sign in, then check that Falco raised no DocVault alert during
#         all of that.
#         Needs POSTGRES_PASSWORD, SEED_PASSWORD and SECRET_KEY in the
#         environment.
#         The app is then reachable on http://127.0.0.1:$APP_TEST_PORT only.
#   logs  print pod status, events and logs, for debugging a failed deploy
#   down  delete the cluster
#
# KIND_CLUSTER names the cluster (default docvault), so a second cluster, on
# another APP_TEST_PORT, can run next to the first one.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-docvault}"
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
# Falco is installed by rendering its Helm chart with `helm template`. Helm's
# checksum is the one published next to the release archive on get.helm.sh.
# The chart's checksum is the digest listed for it in the chart repository's
# index (https://falcosecurity.github.io/charts/index.yaml). The image is
# pulled by its digest (the multi-platform index digest) and tagged on the
# host, because an image referenced by digest in the manifest could not be
# loaded into the cluster (see up()).
HELM_VERSION="v4.3.1" # Released 2026-10-15.
HELM_SHA256="0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b"
FALCO_CHART_VERSION="9.2.2" # Released 2026-10-30, for Falco 0.45.2.
FALCO_CHART_SHA256="b8a1aa984c3d513ab1639be760e6a07a9eb203d4da77a45a1512d382b6d3687d"
FALCO_IMAGE="docker.io/falcosecurity/falco:0.45.2" # Released 2026-10-29.
FALCO_IMAGE_DIGEST="sha256:1562a643953f938e02f47319b5214d93a235f11f646d60e9b8a516fd5a64698e"
FALCO_NAMESPACE="falco"

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
  FALCO_CHART="$(fetch_file "falco-chart-$FALCO_CHART_VERSION.tgz" "$FALCO_CHART_SHA256" \
    "https://github.com/falcosecurity/charts/releases/download/falco-$FALCO_CHART_VERSION/falco-$FALCO_CHART_VERSION.tgz")"
  local helm_archive
  helm_archive="$(fetch_file "helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_SHA256" \
    "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz")"
  HELM="$TOOLS_DIR/helm-$HELM_VERSION"
  if [ ! -x "$HELM" ]; then
    tar -xzf "$helm_archive" -O linux-amd64/helm > "$HELM.tmp"
    chmod +x "$HELM.tmp"
    mv "$HELM.tmp" "$HELM"
  fi
  # Always target this cluster, whatever the current kubectl context is.
  KUBECTL=("$KUBECTL_BIN" --context "kind-$CLUSTER")
}

# Prints every image referenced by the given manifests.
images_in() {
  sed -nE 's/^[[:space:]]*image:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$@" | sort -u
}

up() {
  : "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD}" "${SEED_PASSWORD:?Set SEED_PASSWORD}"
  : "${SECRET_KEY:?Set SECRET_KEY (see .env.example)}"

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

  # Passwords go through files, not command-line arguments, so other
  # processes cannot read them from the process list.
  local work_dir secret_dir
  work_dir="$(mktemp -d)"
  # shellcheck disable=SC2064 # Expand now: work_dir is local to this function.
  trap "rm -rf '$work_dir'" EXIT
  secret_dir="$work_dir/secrets"
  mkdir "$secret_dir"
  printf '%s' "$POSTGRES_PASSWORD" > "$secret_dir/POSTGRES_PASSWORD"
  printf '%s' "$SEED_PASSWORD" > "$secret_dir/SEED_PASSWORD"
  printf '%s' "$SECRET_KEY" > "$secret_dir/SECRET_KEY"

  local falco_manifest="$work_dir/falco.yaml"
  render_falco "$falco_manifest" "$work_dir/helm"

  echo "==> Building $APP_IMAGE"
  docker build -t "$APP_IMAGE" "$REPO_ROOT/backend"

  # Pull images referenced by tag on the host and load them into the cluster,
  # so the cluster does not download them itself: DNS inside the kind node can
  # be unreliable (seen on WSL), and this also avoids registry rate limits.
  # Images pinned by digest are left for the cluster to pull, because it then
  # checks the digest; an exported copy gets a different digest and would not
  # match the pin. Falco's image is the exception: it is referenced by tag so
  # that it can be loaded, and pulled here by its digest, which Docker checks.
  local image
  local images=("$APP_IMAGE")
  while read -r image; do
    [ "$image" = "$APP_IMAGE" ] && continue
    if [[ "$image" == *@sha256:* ]]; then
      echo "    $image: pulled and verified by the cluster"
      continue
    fi
    if [ "$image" = "$FALCO_IMAGE" ]; then
      docker pull --quiet --platform linux/amd64 "${FALCO_IMAGE%:*}@$FALCO_IMAGE_DIGEST" >/dev/null
      docker tag "${FALCO_IMAGE%:*}@$FALCO_IMAGE_DIGEST" "$FALCO_IMAGE"
    else
      docker pull --quiet --platform linux/amd64 "$image" >/dev/null
    fi
    images+=("$image")
  done < <(images_in "$REPO_ROOT"/deploy/k8s/*.yaml "$KYVERNO_MANIFEST" "$falco_manifest")
  echo "==> Loading into the cluster: ${images[*]}"
  "$KIND" load docker-image --name "$CLUSTER" "${images[@]}"

  install_kyverno
  # Before the application, so its whole start-up is watched.
  install_falco "$falco_manifest"
  # One second early, so an alert in the same second is not missed.
  local falco_since
  falco_since="$(date -u -d '-1 second' +%Y-%m-%dT%H:%M:%SZ)"

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
  check_falco_quiet "$falco_since"
}

# Renders the Falco chart into a manifest, with the DocVault rules added as a
# custom rules file. Helm only renders: it keeps no state in the cluster, and
# its configuration and cache stay in a temporary directory.
render_falco() {
  local output="$1" helm_home="$2"
  HELM_CONFIG_HOME="$helm_home/config" HELM_CACHE_HOME="$helm_home/cache" \
    HELM_DATA_HOME="$helm_home/data" \
    "$HELM" template falco "$FALCO_CHART" --namespace "$FALCO_NAMESPACE" \
    --values "$REPO_ROOT/deploy/falco/values.yaml" \
    --set "image.tag=${FALCO_IMAGE##*:}" \
    --set-file "customRules.docvault_rules\.yaml=$REPO_ROOT/deploy/falco/docvault_rules.yaml" \
    > "$output"
  # Only the image verified in up() may be deployed.
  local rendered
  rendered="$(images_in "$output")"
  if [ "$rendered" != "$FALCO_IMAGE" ]; then
    echo "The Falco manifest uses unexpected images: $rendered" >&2
    exit 1
  fi
}

install_falco() {
  local manifest="$1"
  echo "==> Installing Falco ${FALCO_IMAGE##*:} (modern eBPF probe) and the DocVault rules"
  "${KUBECTL[@]}" create namespace "$FALCO_NAMESPACE" --dry-run=client -o yaml \
    | "${KUBECTL[@]}" apply -f - >/dev/null
  "${KUBECTL[@]}" apply -f "$manifest" >/dev/null
  "${KUBECTL[@]}" -n "$FALCO_NAMESPACE" rollout status daemonset/falco --timeout=300s
  # Ready only means Falco's web server answers. Wait until the probe is
  # attached, so the deploy below is watched from its start.
  local attempt log=""
  for attempt in $(seq 30); do
    log="$("${KUBECTL[@]}" -n "$FALCO_NAMESPACE" logs daemonset/falco -c falco --tail=-1 2>/dev/null || true)"
    if grep -q "Opening 'syscall' source with modern BPF probe" <<<"$log"; then break; fi
    if [ "$attempt" -eq 30 ]; then
      echo "Falco did not start its modern eBPF probe:" >&2
      tail -n 30 <<<"$log" >&2
      exit 1
    fi
    sleep 2
  done
  grep -E "Opening 'syscall' source|docvault_rules.yaml" <<<"$log" | sed -E 's/^[^ ]+: /    /' | sort -u
}

# Proves the rules are quiet on normal activity: the deploy (init container,
# database initialisation, migrations, seeding), the checks and the smoke
# test must not raise any DocVault alert.
check_falco_quiet() {
  local since="$1" alerts
  echo "==> Falco: no DocVault alert during the deploy and the smoke test"
  # Alerts reach the log within a second or two.
  sleep 5
  alerts="$("${KUBECTL[@]}" -n "$FALCO_NAMESPACE" logs -l app.kubernetes.io/name=falco -c falco \
    --since-time="$since" --tail=-1 | grep -F '"rule":"DV-R' || true)"
  if [ -n "$alerts" ]; then
    echo "Falco raised DocVault alerts during a normal deploy (false positives):" >&2
    echo "$alerts" >&2
    exit 1
  fi
  echo "    no DV-R alert since $since"
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

  # A successful sign-in redirects and sets the session cookie. The form
  # needs the CSRF cookie and the matching token from the login page.
  local headers jar token
  jar="$(dirname "$password_file")/cookies"
  token="$(curl -fsS -c "$jar" "$base/login" \
    | sed -nE 's/.*name="csrf_token" value="([^"]*)".*/\1/p' | head -1)"
  headers="$(curl -sS -o /dev/null -D - -b "$jar" "$base/login" \
    --data-urlencode "csrf_token=$token" \
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
  "${KUBECTL[@]}" -n "$FALCO_NAMESPACE" get pods -o wide || true
  "${KUBECTL[@]}" -n "$FALCO_NAMESPACE" logs daemonset/falco -c falco --tail=100 || true
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
