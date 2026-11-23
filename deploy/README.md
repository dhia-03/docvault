# Deployment

Kubernetes manifests and Kyverno admission policies for DocVault.

## Hardening (F07 fix)

The baseline manifests (tag `v0-vulnerable`) had no hardening. They are now hardened:

- [`k8s/`](k8s/): both workloads run as UID 10001 with no privilege escalation, no capabilities, the default seccomp profile, a read-only root filesystem, no service account token, resource limits, probes and passwords mounted as files. Network policies deny all traffic except users to the app and the app to the database.
- [`kyverno/`](kyverno/): admission policies that reject any pod outside these rules, in every namespace except the system ones.

Checkov passes with two recorded exceptions (E1, E2 in [the security policy](../docs/security-policy.md)), both caused by having no image registry.

## Deploying locally

[`scripts/ci/deploy.sh`](../scripts/ci/deploy.sh) deploys to a throwaway [kind](https://kind.sigs.k8s.io/) cluster. CI runs the same script before the ZAP scan. It also installs Kyverno and the policies. It needs Docker on Linux x86_64 (WSL works). It downloads pinned versions of kind and kubectl and checks their checksums, so nothing else needs installing.

```bash
set -a; . ./.env; set +a          # test passwords, never committed
scripts/ci/deploy.sh up            # cluster, image, deploy, smoke test
```

`up` then runs these checks, and stops at the first failure:

1. Kyverno must refuse a pod with no security context.
2. The database must not answer a pod from another namespace.
3. `/healthz` must answer, and the test user `alice` must be able to sign in.

The app and Kyverno images are pulled on the host and loaded into the cluster. PostgreSQL is pinned by digest, so the cluster pulls it itself and checks the digest. On WSL, DNS inside the kind node is sometimes unreliable; if PostgreSQL stays in `ImagePullBackOff`, run `up` again.

The app is then reachable on http://127.0.0.1:18000, from this machine only. [`test/access.yaml`](test/access.yaml) exposes it as a node port, which the kind cluster maps to the host's loopback address. It is test access only, not part of the application deployment.

To run the authenticated ZAP scan that CI runs after the deploy (reports go to `reports/zap/`):

```bash
scripts/ci/dast.sh
```

`scripts/ci/deploy.sh logs` prints pod status, events and logs. `scripts/ci/deploy.sh down` deletes the cluster.

An init container waits for the database and runs the migrations before the app starts.

## Docker Compose after the F07 fix

The image now runs as UID 10001. A `documents` volume created by the old root image is owned by root, so uploads fail. Recreating the volumes fixes it, and deletes the local test data:

```bash
docker compose down -v && docker compose up -d --build
```
