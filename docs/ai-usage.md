# AI usage declaration

The course requires every use of AI tools to be declared, including what they produced and what was validated by a person. Tool used: Claude Code (model Claude Opus 5.5).

The last column is for the student to complete after reviewing each item.

| Date | What the AI produced | Checks the AI ran | Validated by the student |
| --- | --- | --- | --- |
| 2026-11-09 | Project approach and comparison of the initial specification with the course requirements | None | To complete |
| 2026-11-09 | Repository layout, `.gitignore`, `scripts/ci/scan.sh` and `.github/workflows/ci.yml` | Each scanner blocked a planted problem in a throwaway copy; actionlint and ShellCheck passed | To complete |
| 2026-11-09 | Draft threat model and security policy | Reviewed against the course requirements and the OWASP Top 10:2025 list | To complete |
| 2026-11-09 | Draft of Annexe A (theme reservation) | None | To complete |
| 2026-11-09 | Vulnerable DocVault application, Dockerfile, Compose file, exploit script and vulnerability register | App ran locally; all 7 flaws exploited on localhost; role restrictions tested; Gitleaks, Semgrep and Trivy run | To complete |
| 2026-11-22 | Branch protection settings for `main`; image scan and Checkov in `scan.sh` and CI; baseline Kubernetes manifests; updates to the policy, register and progress documents | Both new checks blocked locally; manifests deployed to a throwaway k3s cluster and all 7 flaws exploited through it; actionlint and ShellCheck passed | To complete |
| 2026-11-23 | Deploy stage: `scripts/ci/deploy.sh` and the `Deploy (kind)` CI job; deployment README | Deployed locally to kind, from scratch and on an existing cluster; smoke test signed in as a test user; actionlint and ShellCheck passed | To complete |
