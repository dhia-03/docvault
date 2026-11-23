# Development progress

Last updated: 2026-11-22

## Current status

The deliberately vulnerable DocVault application works locally with Docker Compose and on Kubernetes, and all seven planted flaws are confirmed exploitable. All five blocking checks run in CI, and `main` only accepts merges that pass them. The theme is pending validation by the professor.

| Step | Status |
| --- | --- |
| 1. Theme reservation (Annexe A) | Drafted, not submitted |
| 2. Threat model and blocking policy | Drafted, awaiting review |
| 3. Vulnerable application, with flaws documented | Built on `vulnerable-baseline`; flaws documented |
| 4. Hardened container and five-check CI, with proof that it blocks | Done; hardened container on `fix/f07-hardening` |
| 5. Hardened Kubernetes deployment and Kyverno | Done on `fix/f07-hardening`, not merged yet |
| 6. Authenticated ZAP in the pipeline | Done: F02, F03 and F04 confirmed on the baseline |
| 7. Fix each flaw and re-test | F07 fixed and re-tested; F01 to F06 open |
| 8. Revoke-then-purge demonstration | Not started |
| 9. Runtime detection and incident response plan | Not started |
| 10. Report, slides, contribution sheet and AI declaration | AI log started |

## Completed

- Repository layout, merged to `main`
- CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images; first GitHub run passed on 2026-11-09 (before any application code existed)
- Vulnerable application with login, three roles, upload, search, sharing, admin pages and an audit log
- Vulnerability register for F01 to F07
- Repository made public on 2026-11-22, so that `main` can require the checks (branch protection is not available on private repositories in the free plan)
- `main` protection: pull request required, all six checks (five static, plus ZAP) must pass, applies to admins
- `vulnerable-baseline` pushed and tagged `v0-vulnerable`; draft pull request #2 kept open as CI evidence, never to be merged
- Image scan (Trivy) and deployment-file scan (Checkov) added to CI
- Baseline Kubernetes manifests in `deploy/k8s/`, including the Kubernetes half of F07
- Deploy stage in CI: `scripts/ci/deploy.sh` deploys to a throwaway kind cluster on the runner and signs in as a test user
- Authenticated ZAP scan after the deploy (`scripts/ci/dast.sh`), blocking on any High alert; reports kept as CI artifacts

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
| Authenticated ZAP scan on kind, 2026-11-23 | Blocked: 4 High alerts confirming F02, F03 and F04; 3 Medium, including missing CSRF tokens (O1) |
| Hardened deploy on a fresh kind cluster, 2026-11-23 | Kyverno refused a pod with no security context (4 policies); the database did not answer a pod from another namespace; app and database started with 0 restarts |
| `run_all.py` on the hardened deploy and on Compose, 2026-11-23 | 6 of 7 exploitable; F07 not exploitable (UID 10001); F04 can no longer write outside storage |
| CI run 45083855384, 2026-11-23 | ZAP blocked with the same 4 High alerts, plus one false positive on `/documents/1/share`; report in `docs/evidence/` |
| CI run 45071375296 on pull request #2, 2026-11-22 | All five checks failed with the same results as locally; log in `docs/evidence/` |

## Known limitations

- The image scan and Checkov have run locally but not yet on GitHub.
- The deploy stage uses kind, not Minikube. The same script runs locally, so Minikube is no longer needed.
- The deploy stage does not wait for the static checks, so the vulnerable baseline can be scanned by ZAP. Merging still needs every check.
- ZAP scans as one user, so it cannot find F01 (access between users), and it missed the stored XSS.
- The current Semgrep rule packs miss F03 and F04.
- No automated test suite exists yet; the exploit script is the only repeatable check.

## Open questions

- Has DocVault been validated by the professor?
- Which GitHub account should get access to the repository?
- What is the submission deadline? The course document has no sections 7 and 8.

## Security issues

Seven planted flaws and five unplanned weaknesses are open. See the [vulnerability register](vulnerability-register.md).

## Next steps

1. Screenshot the merge box of pull request #2, showing the merge blocked by the six failing checks.
2. Review and merge the F07 hardening, then fix F01 to F06, each on its own branch.
