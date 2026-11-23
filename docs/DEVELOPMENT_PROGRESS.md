# Development progress

Last updated: 2026-11-23

## Current status

All seven planted flaws were documented, exploited, then fixed and re-tested. The fixes are merged into `secure`, and the leaked key was revoked, then purged from history. Seven checks run in CI (the five required by the course, ZAP and the tests), and `main` only accepts merges that pass all of them. The vulnerable baseline stays available as tag `v0-vulnerable`. The theme is pending validation by the professor.

| Step | Status |
| --- | --- |
| 1. Theme reservation (Annexe A) | Drafted, not submitted |
| 2. Threat model and blocking policy | Drafted, awaiting review |
| 3. Vulnerable application, with flaws documented | Built on `vulnerable-baseline`; flaws documented |
| 4. Hardened container and five-check CI, with proof that it blocks | Done |
| 5. Hardened Kubernetes deployment and Kyverno | Done |
| 6. Authenticated ZAP in the pipeline | Done: F02, F03 and F04 confirmed on the baseline |
| 7. Fix each flaw and re-test | Done: all seven fixed and re-tested, merged into `secure` |
| 8. Revoke-then-purge demonstration | Done: revoked, verified, purged and verified (`docs/f05-revoke-then-purge.md`) |
| 9. Runtime detection and incident response plan | Built on `feat/app-detection`, not merged yet; plan written, drills planned |
| 10. Report, slides, contribution sheet and AI declaration | AI log started |

## Completed

- Repository layout, merged to `main`
- CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images; first GitHub run passed on 2026-11-09 (before any application code existed)
- Vulnerable application with login, three roles, upload, search, sharing, admin pages and an audit log
- Vulnerability register for F01 to F07
- Runtime detection: application alerts DV-A1 to DV-A4 and Falco rules DV-R1 to DV-R4, each proven by a demo in the `DAST (ZAP)` job ([runtime-detection.md](runtime-detection.md))
- Incident response plan with seven playbooks ([incident-response-plan.md](incident-response-plan.md)); no drill run yet
- Repository made public on 2026-11-22, so that `main` can require the checks (branch protection is not available on private repositories in the free plan)
- `main` protection: pull request required, all seven checks (five static, ZAP and the tests) must pass, applies to admins
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
| F06 fix on Compose and on kind (with F07), 2026-11-23 | F06 not exploitable; dependency scan and image scan pass with 0 findings |
| F05 revocation on Compose and kind, 2026-11-23 | Session forged with the leaked key refused (HTTP 303); Gitleaks clean on the working tree, history still holds the key |
| Purge dry run, 2026-11-23 | Rewritten history has no leak; 4 branches and 1 tag would change; `main` unchanged |
| F02 fix on Compose, 2026-11-23 | Not exploitable; search behaviour checked; Semgrep 0 findings |
| F04 fix on Compose, 2026-11-23 | Not exploitable; no file written outside storage; preview, download and access check work |
| F03 fix on Compose, 2026-11-23 | Not exploitable; CSP and other headers present; cookie `HttpOnly` |
| F01 fix on Compose, 2026-11-23 | Not exploitable; sharing rules checked; `run_all.py`: 0 of 6 tested flaws exploitable |
| ZAP on Compose with F02, F03 and F04 fixed, 2026-11-23 | Passed: no High alert; only the CSRF `Medium` alert (O1) left |
| pytest suite (`backend/tests/`), 2026-11-23 | 37 passed on the fixed code; on `secure` before the F01 and F03 fixes, exactly the 7 F01/F03 tests failed |
| History purge, 2026-11-23 | Fresh clone: old value found 0 times in any commit; Gitleaks clean on working tree and 22 commits |
| Step 9 end to end on a fresh kind cluster, 2026-11-23 | Deploy checks passed with Falco quiet; app demo: DV-A1 to DV-A4 detected; ZAP passed; Falco demo: DV-R1 to DV-R4 detected (7 of 7 checks) |
| CI run 45083855384, 2026-11-23 | ZAP blocked with the same 4 High alerts, plus one false positive on `/documents/1/share`; report in `docs/evidence/` |
| CI run 45071375296 on pull request #2, 2026-11-22 | All five checks failed with the same results as locally; log in `docs/evidence/` |

## Known limitations

- The image scan and Checkov have run locally but not yet on GitHub.
- The deploy stage uses kind, not Minikube. The same script runs locally, so Minikube is no longer needed.
- The deploy stage does not wait for the static checks, so the vulnerable baseline can be scanned by ZAP. Merging still needs every check.
- ZAP scans as one user, so it cannot find F01 (access between users), and it missed the stored XSS.
- The current Semgrep rule packs miss F03 and F04.
- The pytest suite runs on SQLite, so it checks the secure query logic, not PostgreSQL-specific behaviour. The exploit script and ZAP cover the real database.

## Open questions

- Has DocVault been validated by the professor?
- Which GitHub account should get access to the repository?
- What is the submission deadline? The course document has no sections 7 and 8.

## Security issues

The seven planted flaws and O4, O5 are fixed. Three unplanned weaknesses are open: O1 (no CSRF tokens), O2 (no login rate limit) and O3 (no upload size limit). See the [vulnerability register](vulnerability-register.md).

## Next steps

1. Merge the step 9 pull request into `secure`, then `secure` into `main`.
2. Run the two planned drills (P2 with the Falco demo, P1 with a forged session) and record them in the plan.
3. Decide on the gaps the incident response plan found: no password reset or account disable, no way to sign out one user, audit log without client address or correlation ID, Dependabot off, `secure` not protected.
4. Fix O1 to O3.
5. Step 10: report, slides, Annexe B sheets and the AI declaration.
