# Deployment

Kubernetes manifests for DocVault. Kyverno admission policies will go in `kyverno/`.

## Current state: deliberately weak baseline

The manifests in `k8s/` mirror `docker-compose.yml` and have no hardening: no security context, no resource limits, no network policy, and image tags instead of digests. This is the Kubernetes half of flaw F07 (see the [vulnerability register](../docs/vulnerability-register.md)). Checkov fails on them in CI, which is expected and kept as evidence.

## Deploying locally

Requires a local cluster such as Minikube, and the passwords from `.env`.

```bash
# 1. Build the image inside Minikube, so no registry is needed.
minikube image build -t docvault-app:dev backend

# 2. Namespace and secrets. The passwords are never written to a file in Git.
kubectl apply -f deploy/k8s/00-namespace.yaml
set -a; . ./.env; set +a
kubectl -n docvault create secret generic docvault-secrets \
  --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=SEED_PASSWORD="$SEED_PASSWORD"

# 3. Database and application.
kubectl apply -f deploy/k8s/
kubectl -n docvault rollout status deploy/docvault

# 4. Reach the app on this machine only.
kubectl -n docvault port-forward svc/docvault 8000:8000
```

The app container may restart a few times while PostgreSQL starts, because nothing makes it wait for the database yet.
