# Security policy

The build fails on any exposed secret and on any high-impact issue that we can actually fix. This policy states what breaks the pipeline, why, which exceptions are allowed and for how long.

## What breaks the build

| Control | Tool | Build fails on | Why this threshold | Status |
| --- | --- | --- | --- | --- |
| Secret detection, with redaction | Gitleaks | Any finding in the working tree or Git history | One valid credential is enough for a compromise, so severity levels do not apply | Active |
| Static analysis | Semgrep | Any `ERROR`-severity finding | These rules target directly exploitable classes such as injection. Lower severities produce more false positives, and blocking on them would encourage blanket exceptions | Active |
| Dependencies | Trivy | `HIGH` or `CRITICAL` with a fix available | These can lead to remote compromise or data loss, and an upgrade path exists. Blocking on unfixable issues would stop delivery with no action available to the developer | Active |
| Container image | Trivy | `HIGH` or `CRITICAL` with a fix available | Same reasoning as dependencies. It also covers operating-system packages that a dependency scan cannot see | Planned |
| Deployment files | Checkov | Any failed check on the Dockerfile or Kubernetes manifests | These files are ours and small, and each failure can be fixed by a configuration change without waiting for anyone | Planned |
| Dynamic testing, after deployment | OWASP ZAP | Any `High` risk alert | This covers exploitable behavior on the running application, such as SQL injection. `Medium` alerts are often missing headers and are tracked instead of blocking | Planned |

## Deliberately vulnerable version

The initial version is expected to fail this pipeline. Those failures are kept as evidence, and no exception is used to make that version pass.

## Exceptions

An exception is allowed only when all of these are recorded in the register below: the finding, the reason, a compensating control, an owner and an expiry date.

| Finding type | Exception allowed? | Maximum duration | Reason |
| --- | --- | --- | --- |
| Real secret | No | None | Revoke it first, then purge it from history |
| Secret false positive | Yes, by fingerprint | Reviewed before final submission | The value is confirmed not to be a credential |
| Critical, fix available | No | None | Upgrading is cheaper than accepting the risk |
| Critical, no fix available | Yes | 7 days | Enough time to mitigate or replace the component, while keeping the exposure short |
| High | Yes | 14 days | Allows for an upgrade that breaks compatibility, provided a compensating control is in place |
| ZAP `Medium` alert | Yes | 30 days | Usually hardening rather than direct exploitation |

These durations are judgments sized to a short project and are not an external benchmark. No exception may remain open at final submission.

Each exception is approved by the project owner. In a one-person project the author also approves the exception, so there is no separation of duties. This is a known weakness.

## Exception register

| ID | Finding | Reason | Compensating control | Owner | Expires |
| --- | --- | --- | --- | --- | --- |
| None yet | | | | | |

## Exposed secret procedure

1. Revoke or rotate the secret first, because anyone may already have copied it.
2. Confirm that the old value no longer works.
3. Purge it from Git history.
4. Run Gitleaks across the whole history to confirm it is gone.
5. Record the event in the vulnerability register.

## What this policy does not prove

A passing pipeline does not mean DocVault is secure.

- Scanners do not reliably find business-logic flaws such as broken access control. F01 depends on automated tests.
- Semgrep's `WARNING` and `INFO` rules are not run in the blocking stage.
- Semgrep rule packs are downloaded at scan time and are not version-pinned, so results can change between runs.
- `--ignore-unfixed` hides vulnerabilities that have no fix yet. A critical issue with no fix does not fail the build.
- Vulnerability scanners only find publicly known issues.
- ZAP only tests the pages and inputs it reaches.
