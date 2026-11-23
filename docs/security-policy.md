# Security policy

The build fails on any exposed secret and on any high-impact issue that we can actually fix. This policy states what breaks the pipeline, why, which exceptions are allowed and for how long.

## What breaks the build

| Control | Tool | Build fails on | Why this threshold | Status |
| --- | --- | --- | --- | --- |
| Secret detection, with redaction | Gitleaks | Any finding in the working tree or Git history | One valid credential is enough for a compromise, so severity levels do not apply | Active |
| Static analysis | Semgrep | Any `ERROR`-severity finding | These rules target directly exploitable classes such as injection. Lower severities produce more false positives, and blocking on them would encourage blanket exceptions | Active |
| Dependencies | Trivy | `HIGH` or `CRITICAL` with a fix available | These can lead to remote compromise or data loss, and an upgrade path exists. Blocking on unfixable issues would stop delivery with no action available to the developer | Active |
| Container image | Trivy | `HIGH` or `CRITICAL` with a fix available | Same reasoning as dependencies. It also covers operating-system packages that a dependency scan cannot see | Active |
| Deployment files | Checkov | Any failed check on the Dockerfile or Kubernetes manifests | These files are ours and small, and each failure can be fixed by a configuration change without waiting for anyone | Active |
| Dynamic testing, after deployment to a throwaway kind cluster | OWASP ZAP | Any `High` risk alert | This covers exploitable behavior on the running application, such as SQL injection. `Medium` alerts are often missing headers and are tracked instead of blocking | Active |

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
| E1 | Checkov `CKV_K8S_15`: image pull policy is `IfNotPresent`, not `Always`, on both workloads | Images are built or pulled on the host and loaded into the kind cluster by `deploy.sh`. There is no registry for the cluster to pull from, so `Always` would make every pod fail | The cluster never pulls anything; PostgreSQL is pinned by digest and the app image is rebuilt and scanned on every run | M3 (container and Kubernetes) | Final submission, or earlier if a registry is added |
| E2 | Checkov `CKV_K8S_43`: the app image `docvault-app:dev` is referenced by tag, not digest | The image is built locally on each run, so it has no registry digest to pin | The image is built from the reviewed commit in the same job, scanned by Trivy, and loaded directly into the cluster | M3 (container and Kubernetes) | Final submission, or earlier if a registry is added |

## Exposed secret procedure

1. Revoke or rotate the secret first, because anyone may already have copied it.
2. Confirm that the old value no longer works.
3. Purge it from Git history.
4. Run Gitleaks across the whole history to confirm it is gone.
5. Record the event in the vulnerability register.

## What this policy does not prove

A passing pipeline does not mean DocVault is secure.

- Scanners do not reliably find business-logic flaws such as broken access control. F01 is covered by the pytest suite (`Tests (pytest)` in CI), which signs in as two users.
- The current Semgrep rule packs missed two planted flaws, F03 (XSS) and F04 (path traversal), at every severity. ZAP found both.
- Semgrep's `WARNING` and `INFO` rules are not run in the blocking stage.
- Semgrep rule packs are downloaded at scan time and are not version-pinned, so results can change between runs.
- Checkov's "any failed check" threshold includes checks that are good practice rather than security, such as liveness probes. Some will not fit a local cluster: an `Always` pull policy and image digests need a registry. These will be handled through recorded exceptions, not by lowering the threshold.
- The image scan only covers the application image. The PostgreSQL image is pulled as-is and is not scanned.
- Kyverno publishes no checksum for `install.yaml` in v1.19.2. `deploy.sh` checks it against a SHA-256 recorded on first download, which only proves the file has not changed since then.
- The Kyverno policies use the `kyverno.io/v1` `ClusterPolicy` format, which Kyverno 1.19 marks as deprecated in favour of CEL-based policies. It still works; migrating is future work.
- Kyverno and the network policies are tested on kind only. Whether a given cluster enforces network policies depends on its network plugin.
- Checkov exceptions are recorded as `checkov.io/skip` annotations on the resources, which point to the register above. Anyone who can edit a manifest can add one, so each new annotation must be reviewed in the pull request.
- `--ignore-unfixed` hides vulnerabilities that have no fix yet. A critical issue with no fix does not fail the build.
- Vulnerability scanners only find publicly known issues.
- ZAP only tests the pages and inputs it reaches, as the single test user `alice`. It does not test access between users, so it cannot find F01.
- ZAP did not report the stored XSS in document titles, only the reflected one.
- The ZAP environment is a throwaway kind cluster, not the final deployment. Hardening differences between the two are not tested.
