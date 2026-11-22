# Deployment

Kubernetes manifests for DocVault. Kyverno admission policies will go in `kyverno/`.

## Current state: deliberately weak baseline

The manifests in `k8s/` mirror `docker-compose.yml` and have no hardening: no security context, no resource limits, no network policy, and image tags instead of digests. This is the Kubernetes half of flaw F07 (see the [vulnerability register](../docs/vulnerability-register.md)). Checkov fails on them in CI, which is expected and kept as evidence.

## Deploying locally

[`scripts/ci/deploy.sh`](../scripts/ci/deploy.sh) deploys to a throwaway [kind](https://kind.sigs.k8s.io/) cluster. CI runs the same script before the ZAP scan. It needs Docker on Linux x86_64 (WSL works). It downloads pinned versions of kind and kubectl and checks their checksums, so nothing else needs installing.

```bash
set -a; . ./.env; set +a          # test passwords, never committed
scripts/ci/deploy.sh up            # cluster, image, deploy, smoke test
```

`up` builds the app image, pulls the PostgreSQL image on the host and loads both into the cluster, so the cluster downloads nothing itself. It ends with a smoke test: `/healthz` must answer and the test user `alice` must be able to sign in.

The app is then reachable on http://127.0.0.1:18000, from this machine only. [`test/access.yaml`](test/access.yaml) exposes it as a node port, which the kind cluster maps to the host's loopback address. It is test access only, not part of the application deployment.

To run the authenticated ZAP scan that CI runs after the deploy (reports go to `reports/zap/`):

```bash
scripts/ci/dast.sh
```

`scripts/ci/deploy.sh logs` prints pod status, events and logs. `scripts/ci/deploy.sh down` deletes the cluster.

The app container may restart a few times while PostgreSQL starts, because nothing makes it wait for the database yet.
