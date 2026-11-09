# Development progress

Last updated: 2026-11-09

## Current status

The project theme is DocVault, pending validation by the professor. The repository layout, part of the security CI, and draft design documents exist. No application code has been written.

| Step | Status |
| --- | --- |
| 1. Theme reservation (Annexe A) | Drafted, not submitted |
| 2. Threat model and blocking policy | Drafted, awaiting review |
| 3. Vulnerable application, with flaws documented | Not started |
| 4. Hardened container and five-check CI, with proof that it blocks | In progress: 3 of 5 checks active |
| 5. Hardened Kubernetes deployment and Kyverno | Not started |
| 6. Authenticated ZAP in the pipeline | Not started |
| 7. Fix each flaw and re-test | Not started |
| 8. Revoke-then-purge demonstration | Not started |
| 9. Runtime detection and incident response plan | Not started |
| 10. Report, slides, contribution sheet and AI declaration | AI log started |

## Completed

- Repository layout
- Security CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images

## Tests executed

Run locally with Docker on 2026-11-09, using `scripts/ci/scan.sh`. The planted problems were placed in a throwaway copy of the repository.

| Check | Input | Result |
| --- | --- | --- |
| Gitleaks | Planted token in the working tree | Blocked, exit 1 |
| Gitleaks | Planted token only in Git history | Blocked, exit 1 |
| Gitleaks | Scan output for a planted token | Token redacted |
| Semgrep | Flask route with shell command injection | Blocked, 3 findings |
| Trivy | `pyyaml==5.3` in `requirements.txt` | Blocked, 2 critical CVEs |
| actionlint | `.github/workflows/ci.yml` | No errors |
| ShellCheck | `scripts/ci/scan.sh` | No errors |

## Known limitations

- The workflow has not yet run on GitHub.
- Trivy has nothing to scan until dependency files exist, so its pass on the current repository proves nothing yet.
- Semgrep downloads its rule packs at scan time, so those rules are not version-pinned.

## Open questions

- Has DocVault been validated by the professor?
- The course requires 3 to 4 students. Is a one-person team allowed?
- What is the submission deadline? The course document has no sections 7 and 8.

## Security issues

None recorded.

## Next steps

1. Review the threat model and security policy.
2. Build the vulnerable application and document each flaw before fixing it.
3. Add the image scan and Checkov to CI once there is an image and manifests to scan.
