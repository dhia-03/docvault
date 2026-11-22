# Development progress

Last updated: 2026-11-22

## Current status

The deliberately vulnerable DocVault application works locally with Docker Compose and on Kubernetes, and all seven planted flaws are confirmed exploitable. All five blocking checks run in CI, and `main` only accepts merges that pass them. The theme is pending validation by the professor.

| Step | Status |
| --- | --- |
| 1. Theme reservation (Annexe A) | Drafted, not submitted |
| 2. Threat model and blocking policy | Drafted, awaiting review |
| 3. Vulnerable application, with flaws documented | Built on `vulnerable-baseline`; flaws documented |
| 4. Hardened container and five-check CI, with proof that it blocks | Five checks active and blocking; container not hardened yet |
| 5. Hardened Kubernetes deployment and Kyverno | Baseline manifests only |
| 6. Authenticated ZAP in the pipeline | Not started |
| 7. Fix each flaw and re-test | Not started |
| 8. Revoke-then-purge demonstration | Not started |
| 9. Runtime detection and incident response plan | Not started |
| 10. Report, slides, contribution sheet and AI declaration | AI log started |

## Completed

- Repository layout, merged to `main`
- CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images; first GitHub run passed on 2026-11-09 (before any application code existed)
- Vulnerable application with login, three roles, upload, search, sharing, admin pages and an audit log
- Vulnerability register for F01 to F07
- Repository made public on 2026-11-22, so that `main` can require the checks (branch protection is not available on private repositories in the free plan)
- `main` protection: pull request required, all five checks must pass, applies to admins
- `vulnerable-baseline` pushed and tagged `v0-vulnerable`; draft pull request #2 kept open as CI evidence, never to be merged
- Image scan (Trivy) and deployment-file scan (Checkov) added to CI
- Baseline Kubernetes manifests in `deploy/k8s/`, including the Kubernetes half of F07

## Tests executed

Run locally with Docker on 2026-11-09, unless dated otherwise.

| Check | Result |
| --- | --- |
| `scripts/exploits/run_all.py` | 7 of 7 flaws exploitable |
| Exploit script against a non-local target | Refused |
| Members and auditors requesting `/admin/users` | HTTP 403 |
| Members requesting `/audit` | HTTP 403 |
| Unshared document's detail page, and sharing another user's document | HTTP 403 |
| Sharing a document, then reading it as the recipient | Works |
| Gitleaks on the application | Blocked: F05 found, value redacted |
| Semgrep on the application | Blocked: F02 and F07 found; F03 and F04 missed |
| Trivy on the application | Blocked: 2 critical CVEs in PyYAML (F06) |
| CI on pull request #2, 2026-11-22 | Gitleaks, Semgrep and Trivy failed as expected; log and screenshots in `docs/evidence/` |
| Trivy image scan, 2026-11-22 | Blocked: 189 OS vulnerabilities with a fix in `python:3.12` (13 critical), plus PyYAML (F06) |
| Checkov, 2026-11-22 | Blocked: 2 failed checks on the Dockerfile, 39 on the manifests; works with networking disabled |
| Manifests on a throwaway k3s cluster, 2026-11-22 | Deployed; app pod runs as UID 0; `run_all.py` found 7 of 7 flaws exploitable |
| actionlint and ShellCheck, 2026-11-22 | No errors |

## Known limitations

- The image scan and Checkov have run locally but not yet on GitHub.
- The manifests were tested on k3s, not yet on Minikube.
- ZAP has not been run.
- The current Semgrep rule packs miss F03 and F04.
- No automated test suite exists yet; the exploit script is the only repeatable check.

## Open questions

- Has DocVault been validated by the professor?
- Which GitHub account should get access to the repository?
- What is the submission deadline? The course document has no sections 7 and 8.

## Security issues

Seven planted flaws and five unplanned weaknesses are open. See the [vulnerability register](vulnerability-register.md).

## Next steps

1. Capture the five failing checks on pull request #2, then make the two new checks required on `main`.
2. Deploy on Minikube, then harden the container and manifests and add Kyverno.
3. Add an authenticated ZAP scan, then fix each flaw on its own branch.
