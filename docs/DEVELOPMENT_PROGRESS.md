# Development progress

Last updated: 2026-11-23

## Current status

Dates are local time (UTC+1) unless marked UTC; GitHub shows CI run times in UTC, so a run can appear one day earlier there.

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
| 9. Runtime detection and incident response plan | Done (merged into `main` through #11 and #12); P1 and P2 drills run as technical run-throughs on 2026-11-24, team rehearsal planned |
| 10. Report, slides, contribution sheet and AI declaration | Report written (`docs/rapport/`), only team information left; defence deck and talk script built (`docs/presentation/DocVault-soutenance.pptx`), visual check in PowerPoint pending; Annexe B template ready, sheets to fill; AI log up to date |

## Completed

- Repository layout, merged to `main`
- CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images; first GitHub run passed on 2026-11-09 (before any application code existed)
- Vulnerable application with login, three roles, upload, search, sharing, admin pages and an audit log
- Vulnerability register for F01 to F07
- Runtime detection: application alerts DV-A1 to DV-A4 and Falco rules DV-R1 to DV-R4, each proven by a demo in the `DAST (ZAP)` job ([runtime-detection.md](runtime-detection.md))
- Dependabot (alerts, security updates and weekly version updates with a 14-day cooldown) and protection of `secure` with the same seven required checks as `main` (2026-11-24)
- Account controls for incident response: admin password reset, disable and enable, sign one user out everywhere (session version in the cookie), own password change; audit log with client address and request ID, CSV export (on `feat/account-controls`, not merged yet)
- Incident response plan with seven playbooks ([incident-response-plan.md](incident-response-plan.md)); no drill run yet
- Repository made public on 2026-11-22, so that `main` can require the checks (branch protection is not available on private repositories in the free plan)
- `main` protection: pull request required, all seven checks (five static, ZAP and the tests) must pass, applies to admins
- `vulnerable-baseline` pushed and tagged `v0-vulnerable`; draft pull request #2 kept as CI evidence and never merged by hand. GitHub now shows it as "Merged" (2026-11-23 02:19 UTC): `secure` was built on top of `vulnerable-baseline`, so when `secure` was merged into `main` (#10), the baseline commit became part of `main`'s history and GitHub closed #2 automatically. Its failing checks and screenshots remain valid evidence of the blocking pipeline
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
| Purge dry run, 2026-11-23 | Rewritten history has no leak; 4 branches and 1 tag would change at that time; `main` unchanged (the real purge, after more fix branches existed, rewrote 9 branches and the tag) |
| F02 fix on Compose, 2026-11-23 | Not exploitable; search behaviour checked; Semgrep 0 findings |
| F04 fix on Compose, 2026-11-23 | Not exploitable; no file written outside storage; preview, download and access check work |
| F03 fix on Compose, 2026-11-23 | Not exploitable; CSP and other headers present; cookie `HttpOnly` |
| F01 fix on Compose, 2026-11-23 | Not exploitable; sharing rules checked; `run_all.py`: 0 of 6 tested flaws exploitable |
| ZAP on Compose with F02, F03 and F04 fixed, 2026-11-23 | Passed: no High alert; only the CSRF `Medium` alert (O1) left |
| pytest suite (`backend/tests/`), 2026-11-23 | 37 passed on the fixed code; on `secure` before the F01 and F03 fixes, exactly the 7 F01/F03 tests failed |
| History purge, 2026-11-23 | Fresh clone: old value found 0 times in any commit; Gitleaks clean on working tree and 22 commits |
| Step 9 end to end on a fresh kind cluster, 2026-11-23 | Deploy checks passed with Falco quiet; app demo: DV-A1 to DV-A4 detected; ZAP passed; Falco demo: DV-R1 to DV-R4 detected (7 of 7 checks) |
| O1 to O3 on a fresh kind cluster, 2026-11-24 | Deploy checks passed, Falco quiet; DV-A1 to DV-A4 and DV-R1 to DV-R4 detected; ZAP passed. ZAP's fuzzing of the login form locked `alice` (209 failures, then 213 attempts refused with 429), while ZAP kept its session (582 authenticated page loads) |
| Account controls, 2026-11-24 | 76 tests passed; upgrade from migration 0001 to 0003 on PostgreSQL with existing data; on Compose: revoke, disable, enable, CSV export with address and request ID checked; `run_all.py` 0 tested flaws exploitable; DV-A1 to DV-A4 detected |
| Drills P1 and P2 on kind, 2026-11-24 | Scripted run-throughs: alert within 0.2 s, containment within 2.4 s, recovery verified (0 tested flaws exploitable); two findings fed back into the playbooks ([record](evidence/drills/2026-11-24-p1-p2.md)) |
| CI run 45083855384, 2026-11-23 | ZAP blocked with the same 4 High alerts, plus one false positive on `/documents/1/share`; report in `docs/evidence/` |
| CI run 45071375296 on pull request #2, 2026-11-22 | All five checks failed with the same results as locally; log in `docs/evidence/` |

## Known limitations

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

The seven planted flaws and the five unplanned weaknesses (O1 to O5) are fixed; O1 to O3 on `fix/o1-o3`, not merged yet. See the [vulnerability register](vulnerability-register.md).

## Next steps

1. Merge #13 (O1 to O3), #14 (account controls) and the repository hygiene pull request into `secure`, then `secure` into `main`.
2. Rehearse P1 and P2 as a team, without the scripts, and record the times.
3. Step 10, team only: fill in the report's placeholders, the Annexe B sheets and the AI log's validation column; open the deck in PowerPoint and check every slide; rehearse the talk.
