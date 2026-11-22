# Development progress

Last updated: 2026-11-09

## Current status

The deliberately vulnerable DocVault application works locally, and all seven planted flaws are confirmed exploitable. The theme is pending validation by the professor.

| Step | Status |
| --- | --- |
| 1. Theme reservation (Annexe A) | Drafted, not submitted |
| 2. Threat model and blocking policy | Drafted, awaiting review |
| 3. Vulnerable application, with flaws documented | Built on `vulnerable-baseline`; flaws documented |
| 4. Hardened container and five-check CI, with proof that it blocks | In progress: 3 of 5 checks active |
| 5. Hardened Kubernetes deployment and Kyverno | Not started |
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

## Tests executed

Run locally with Docker on 2026-11-09.

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

## Known limitations

- The application has not yet been run through CI on GitHub.
- The Kubernetes part of F07 is not built yet.
- ZAP, the image scan and Checkov have not been run.
- The current Semgrep rule packs miss F03 and F04.
- No automated test suite exists yet; the exploit script is the only repeatable check.

## Open questions

- Has DocVault been validated by the professor?
- The course requires 3 to 4 students. Is a one-person team allowed?
- What is the submission deadline? The course document has no sections 7 and 8.

## Security issues

Seven planted flaws and three unplanned weaknesses are open. See the [vulnerability register](vulnerability-register.md).

## Next steps

1. Push `vulnerable-baseline` and capture the failing pipeline as evidence.
2. Add the image scan and Checkov to CI, with baseline Kubernetes manifests.
3. Add ZAP, then fix each flaw on its own branch.
