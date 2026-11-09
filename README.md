# DocVault

DocVault is a web application for storing and sharing confidential documents. It is built for a DevSecOps course project: it starts with deliberate security flaws, then is secured across its lifecycle, from source code to runtime monitoring.

The project is in early development. See [docs/DEVELOPMENT_PROGRESS.md](docs/DEVELOPMENT_PROGRESS.md) for its current status.

> Deliberately vulnerable versions of this application must only run locally or in a dedicated test environment.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI application, server-rendered pages and database migrations |
| `deploy/k8s/` | Kubernetes manifests |
| `deploy/kyverno/` | Kyverno admission policies |
| `scripts/ci/` | Scripts shared by CI and local development |
| `docs/` | Threat model, security policy and project records |
| `.github/workflows/` | CI pipeline |

## Security checks

Every push to `main` and every pull request runs the scanners below. Run the same checks locally with Docker:

```bash
bash scripts/ci/scan.sh all
```

The blocking rules and their justification are in [docs/security-policy.md](docs/security-policy.md).

## Project documents

- [Threat model](docs/threat-model.md)
- [Security policy](docs/security-policy.md)
- [AI usage declaration](docs/ai-usage.md)
