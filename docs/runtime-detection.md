# Runtime detection

Prevention (the CI checks, the hardened deployment, Kyverno, the network policies) can fail, or miss a flaw nobody has found yet. Runtime detection notices an attack while it happens, and starts the [incident response plan](incident-response-plan.md). DocVault has two layers, and every alert has a stable ID that the plan's playbooks start from.

## Layer 1: the application (DV-A1 to DV-A4)

The app writes each security event as one JSON line on its standard output: failed and successful sign-ins, rejected session cookies, refused documents and refused admin pages. Rules turn repeated events into alerts, written the same way with `"event": "security_alert"`. Code: [`security_events.py`](../backend/app/security_events.py).

| ID | Name | Fires when | Severity | Scenario |
| --- | --- | --- | --- | --- |
| DV-A1 | `brute_force_suspected` | 5 failed sign-ins for one username or one address within 60 s | Medium | Password guessing (T01, O2) |
| DV-A2 | `forged_session` | A session cookie with a bad signature. An expired cookie is logged but is not an alert. | High | Forged sessions or a leaked signing key (F05) |
| DV-A3 | `access_probing` | 3 refused or missing documents for one user within 60 s | Medium | Trying other users' documents by ID (F01) |
| DV-A4 | `privilege_probe` | A user without the role opens an admin or audit page | Low | Looking for admin functions (T16) |

Each alert fires at most once per minute for the same rule and source, so an attack gives one alert, not one per request.

Only fields on an allowed list are logged, and text is cut to 100 characters. Passwords, cookies, tokens and document contents can never reach the logs (threat T13); a test checks this.

Read the alerts with `kubectl -n docvault logs deploy/docvault -c app` or `docker compose logs app`.

## Layer 2: the containers (DV-R1 to DV-R4)

[Falco](https://falco.org/) watches the system calls of the DocVault containers in the Kubernetes cluster. The rules and their exclusions are in [`deploy/falco/docvault_rules.yaml`](../deploy/falco/docvault_rules.yaml), and explained in [`deploy/README.md`](../deploy/README.md#runtime-detection-falco).

| ID | Fires when | Severity |
| --- | --- | --- |
| DV-R1 | A shell starts in a DocVault container | Warning |
| DV-R2 | Any program other than Python or uvicorn starts in the app container | Warning |
| DV-R3 | A container tries to open account files, a service account token, or the app's secrets from another process | Critical |
| DV-R4 | The app container tries to connect anywhere other than the database or DNS | Warning |

Falco is installed by `deploy.sh up` before the application, so the whole deploy is watched. The last check of `up` fails if a normal deploy raised any DocVault alert, which protects against noisy rules.

## How it is demonstrated

The course requires the detection to be shown, not only described. Both layers are proven on every CI run, inside the required `DAST (ZAP)` job, against the deployed application:

1. [`app_detection_demo.py`](../scripts/security/app_detection_demo.py) triggers DV-A1 to DV-A4 harmlessly (wrong passwords, a cookie signed with a made-up key, requests for documents that don't exist, a member opening an admin page), then reads the app's logs. It fails if any alert is missing. It runs before the ZAP scan, whose attacks raise the same alerts.
2. [`detection-demo.sh`](../scripts/security/detection-demo.sh) triggers DV-R1 to DV-R4 harmlessly with `kubectl exec`, then reads Falco's alerts. It fails if DV-R1, DV-R2 or DV-R3 is missing. It runs after the scan, so it also lists any alert the scan raised. The alerts are kept as the `falco-alerts` CI artifact.

The pytest suite also checks each application rule at its threshold, one event below it, and that normal use raises no alert ([`test_detection.py`](../backend/tests/test_detection.py)).

## Limits

- The application counters are kept in memory by one process. That fits the single replica DocVault runs; several replicas would need shared counters, or detection on collected logs.
- Behind the kind node port, every client may appear with the same address, which makes the per-address part of DV-A1 coarse.
- DV-A2 cannot see a forgery made with the *current* key. And after the key is rotated, users' old cookies raise DV-A2 until they sign in again.
- Alerts stay in the pod logs and are lost with the pod. Nothing forwards or stores them centrally, and nobody is paged. A real deployment would add log collection and alert routing (for example Falcosidekick and a SIEM).
- Falco runs only in the kind cluster, not with Docker Compose. Its other limits are listed in [`deploy/README.md`](../deploy/README.md#runtime-detection-falco).
