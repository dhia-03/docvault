# Development progress

Last updated: 2026-11-09

## Current status

Step 1 (Foundations) is in progress. The repository layout and security CI exist. No application code has been written.

| Step | Status |
| --- | --- |
| 1. Foundations | In progress |
| 2. Risk tests | Not started |
| 3. Backend core | Not started |
| 4. First end-to-end path | Not started |
| 5. Security breadth | Not started |
| 6. Kubernetes and secrets | Not started |
| 7. Frontend completion | Not started |
| 8. Monitoring and incidents | Not started |
| 9. Vulnerable baseline and proof | Not started |
| 10. Audit and delivery | Not started |

## Completed

- Repository layout
- Security CI workflow running Gitleaks, Semgrep and Trivy from digest-pinned images

## Tests executed

Run locally with Docker on 2026-11-09, using `scripts/ci/scan.sh`. The planted problems were placed in a throwaway copy of the repository.

| Check | Input | Result |
| --- | --- | --- |
| Gitleaks | Planted token in the working tree | Blocked, exit 1 |
| Gitleaks | Planted token only in git history | Blocked, exit 1 |
| Gitleaks | Scan output for a planted token | Token redacted |
| Semgrep | Flask route with shell command injection | Blocked, 3 findings |
| Trivy | `pyyaml==5.3` in `requirements.txt` | Blocked, 2 critical CVEs |
| actionlint | `.github/workflows/ci.yml` | No errors |
| ShellCheck | `scripts/ci/scan.sh` | No errors |

## Known limitations

- The workflow has not yet run on GitHub.
- Trivy has nothing to scan until dependency files exist, so its pass on the current repository proves nothing yet.
- Semgrep downloads its rule packs at scan time, so those rules are not version-pinned.

## Security issues

None recorded.

## Next steps

1. Check the requirements against the professor's PDF.
2. Write the architecture, database, permissions and threat model documents.
3. Add linting, tests, image build and Checkov to CI once there is code to run them on.
