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
| 2026-11-23 | Authenticated ZAP stage: `scripts/ci/dast.sh`, `scripts/ci/zap/plan.yaml`, `scripts/ci/zap_gate.py`, node-port test access and the `DAST (ZAP)` CI job | Scan run locally on kind: signed in as `alice`, 4 High alerts confirming F02, F03 and F04; ShellCheck and actionlint passed | To complete |
| 2026-11-23 | F07 fix: hardened Dockerfile, `wait_for_db.py`, secrets read from files, hardened manifests, network policies, Kyverno policies and their checks in `deploy.sh`; F04 check in `run_all.py` made to report a refused write; exceptions E1 and E2 | Fresh kind deploy: Kyverno refused a non-compliant pod, network policy blocked another namespace, app started with no restarts; `run_all.py` on kind and Compose: F07 fixed; Checkov 0 failed; image scan 0 OS vulnerabilities; ShellCheck passed | To complete |
| 2026-11-23 | F06 fix: PyYAML 6.0.3 and `yaml.safe_load`; `run_all.py` reports F07 as not tested when F06 is fixed | Payload refused by `safe_load`; dependency and image scans 0 findings; `run_all.py` on Compose and kind: F06 not exploitable | To complete |
| 2026-11-23 | F05 revocation: signing key read at runtime, lazy loading in `auth.py`, key in Compose, Kubernetes, `deploy.sh` and CI; F05 check in `run_all.py` that reads the leaked key from Git history; purge script and `docs/f05-revoke-then-purge.md` | Forged session with the leaked key refused on Compose and kind; start-up refused with no key or a short one; purge dry run: no leak, `main` unchanged; ShellCheck and actionlint passed | To complete |
| 2026-11-23 | F02 fix: parameterized search query with escaped wildcards | `run_all.py`: not exploitable; search checked with own, shared and private documents, wildcards and quotes; Semgrep 0 findings | To complete |
