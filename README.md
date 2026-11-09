# PipelineX

PipelineX is a secure CI/CD management platform. It runs build and deployment pipelines for registered projects and blocks any release that fails its security policies.

The project is in early development. See [docs/DEVELOPMENT_PROGRESS.md](docs/DEVELOPMENT_PROGRESS.md) for its current status.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI service, Celery workers and database migrations |
| `frontend/` | React and TypeScript dashboard |
| `deploy/k8s/` | Kubernetes manifests |
| `deploy/helm/` | Helm chart for PipelineX |
| `deploy/kyverno/` | Kyverno admission policies |
| `samples/` | Applications and scanner reports used for testing and demos |
| `scripts/ci/` | Scripts shared by CI and local development |
| `docs/` | Architecture, security and deployment documentation |
| `.github/workflows/` | CI/CD for PipelineX itself |

## Security checks

Every push to `main` and every pull request runs three scanners. Run the same checks locally with Docker:

```bash
bash scripts/ci/scan.sh all
```

| Scanner | Checks | Fails on |
| --- | --- | --- |
| Gitleaks | Working tree and git history | Any detected secret |
| Semgrep | Source code | Any `ERROR`-severity finding |
| Trivy | Dependencies | Any `HIGH` or `CRITICAL` vulnerability with a fix available |
