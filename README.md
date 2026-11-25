# DocVault

DocVault is a web application for storing and sharing confidential documents. It is built for a DevSecOps course project: it starts with deliberate security flaws, then is secured across its lifecycle, from source code to runtime monitoring.

`main` holds the secured application (tag `v1-secure`): the seven planted flaws and the three weaknesses found on the way are fixed, the CI blocks on seven security checks, the Kubernetes deployment is hardened and watched at runtime, and an incident response plan has been exercised. The deliberately vulnerable starting point is kept as the tag `v0-vulnerable`.

> The deliberately vulnerable version (tag `v0-vulnerable`) must only run locally or in a dedicated test environment.

## Deliverables

| Deliverable | Where |
| --- | --- |
| Final report (French) | [docs/rapport/rapport.md](docs/rapport/rapport.md) |
| Defence slides and talk script (French) | [docs/presentation/DocVault-soutenance.pptx](docs/presentation/DocVault-soutenance.pptx), [texte-oral-soutenance.md](docs/presentation/texte-oral-soutenance.md) |
| Contribution sheet template (Annexe B) | [docs/rapport/annexe-b-modele.md](docs/rapport/annexe-b-modele.md) |
| AI usage declaration | [docs/ai-usage.md](docs/ai-usage.md) |
| Status, tests executed and evidence | [docs/DEVELOPMENT_PROGRESS.md](docs/DEVELOPMENT_PROGRESS.md), [docs/evidence/](docs/evidence/) |

## Repository layout

| Path | Contents |
| --- | --- |
| `backend/` | FastAPI application, server-rendered pages and database migrations |
| `backend/tests/` | pytest suite: one or more tests per flaw, detection, account controls |
| `deploy/k8s/` | Hardened Kubernetes manifests and network policies |
| `deploy/kyverno/` | Kyverno admission policies |
| `deploy/falco/` | Falco rules and settings for runtime detection |
| `scripts/ci/` | Scripts shared by CI and local development: scans, deploy to kind, ZAP |
| `scripts/exploits/` | `run_all.py`, which replays the seven planted flaws against localhost |
| `scripts/security/` | Detection demos and the secret purge script |
| `docs/` | Threat model, security policy, registers, plans, report and evidence |
| `.github/` | CI pipeline and Dependabot configuration |

## Run locally

```bash
cp .env.example .env   # then set local test passwords and a SECRET_KEY (see the file)
docker compose up -d --build
```

The application listens on `127.0.0.1` at the port set by `APP_PORT`. To deploy it to a throwaway Kubernetes cluster with Kyverno and Falco, as CI does, see [deploy/README.md](deploy/README.md). The demo accounts are `admin`, `alice`, `bob` and `auditor`, and they all use `SEED_PASSWORD`. Stop it with `docker compose down`.

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
- [F05: revoke, then purge](docs/f05-revoke-then-purge.md)
- [Runtime detection](docs/runtime-detection.md)
- [Incident response plan](docs/incident-response-plan.md) and the [drill record](docs/evidence/drills/2026-11-24-p1-p2.md)
- [AI usage declaration](docs/ai-usage.md)
