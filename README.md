# DocVault

DocVault is a web application for storing and sharing confidential documents. It is built for a DevSecOps course project: it starts with deliberate security flaws, then is secured across its lifecycle, from source code to runtime monitoring.

`main` holds the secured application: the seven planted flaws are fixed, the CI blocks on seven security checks, and the Kubernetes deployment is hardened and watched at runtime. The deliberately vulnerable starting point is kept as the tag `v0-vulnerable`. See [docs/DEVELOPMENT_PROGRESS.md](docs/DEVELOPMENT_PROGRESS.md) for the status and the evidence, and [docs/rapport/](docs/rapport/) for the final report.

> The deliberately vulnerable version (tag `v0-vulnerable`) must only run locally or in a dedicated test environment.

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI application, server-rendered pages and database migrations |
| `deploy/k8s/` | Kubernetes manifests |
| `deploy/kyverno/` | Kyverno admission policies |
| `scripts/ci/` | Scripts shared by CI and local development |
| `docs/` | Threat model, security policy and project records |
| `.github/workflows/` | CI pipeline |

## Run locally

```bash
cp .env.example .env   # then set local test passwords
docker compose up -d --build
```

The application listens on `127.0.0.1` at the port set by `APP_PORT`. The demo accounts are `admin`, `alice`, `bob` and `auditor`, and they all use `SEED_PASSWORD`. Stop it with `docker compose down`.

## Security checks

Every push to `main` and every pull request runs the scanners below. Run the same checks locally with Docker:

```bash
bash scripts/ci/scan.sh all
```

The blocking rules and their justification are in [docs/security-policy.md](docs/security-policy.md).

## Project documents

- [Threat model](docs/threat-model.md)
- [Vulnerability register](docs/vulnerability-register.md)
- [Security policy](docs/security-policy.md)
- [AI usage declaration](docs/ai-usage.md)
