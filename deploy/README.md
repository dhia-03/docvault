# Deployment

Kubernetes manifests and Kyverno admission policies for DocVault.

## Hardening (F07 fix)

The baseline manifests (tag `v0-vulnerable`) had no hardening. They are now hardened:

- [`k8s/`](k8s/): both workloads run as UID 10001 with no privilege escalation, no capabilities, the default seccomp profile, a read-only root filesystem, no service account token, resource limits, probes and passwords mounted as files. Network policies deny all traffic except users to the app and the app to the database.
- [`kyverno/`](kyverno/): admission policies that reject any pod outside these rules, in every namespace except the system ones and `falco` (see [Runtime detection](#runtime-detection-falco)).

Checkov passes with two recorded exceptions (E1, E2 in [the security policy](../docs/security-policy.md)), both caused by having no image registry.

## Deploying locally

[`scripts/ci/deploy.sh`](../scripts/ci/deploy.sh) deploys to a throwaway [kind](https://kind.sigs.k8s.io/) cluster. CI runs the same script before the ZAP scan. It also installs Kyverno and the policies, and Falco. It needs Docker on Linux x86_64 (WSL works). It downloads pinned versions of kind, kubectl, Helm and the Falco chart and checks their checksums, so nothing else needs installing.

```bash
set -a; . ./.env; set +a          # test passwords, never committed
scripts/ci/deploy.sh up            # cluster, image, deploy, smoke test
```

`up` then runs these checks, and stops at the first failure:

1. Kyverno must refuse a pod with no security context.
2. The database must not answer a pod from another namespace.
3. `/healthz` must answer, and the test user `alice` must be able to sign in.
4. Falco must have raised no DocVault alert during all of this (see [Runtime detection](#runtime-detection-falco)).

The app, Kyverno and Falco images are pulled on the host and loaded into the cluster (Falco's by digest, then tagged). PostgreSQL is pinned by digest, so the cluster pulls it itself and checks the digest. On WSL, DNS inside the kind node is sometimes unreliable; if PostgreSQL stays in `ImagePullBackOff`, run `up` again.

The app is then reachable on http://127.0.0.1:18000, from this machine only. [`test/access.yaml`](test/access.yaml) exposes it as a node port, which the kind cluster maps to the host's loopback address. It is test access only, not part of the application deployment.

To run the authenticated ZAP scan that CI runs after the deploy (reports go to `reports/zap/`):

```bash
scripts/ci/dast.sh
```

`scripts/ci/deploy.sh logs` prints pod status, events and logs. `scripts/ci/deploy.sh down` deletes the cluster.

An init container waits for the database and runs the migrations before the app starts.

`KIND_CLUSTER` names the cluster (default `docvault`). With a different `APP_TEST_PORT`, a second cluster can run next to the first, for example `KIND_CLUSTER=docvault-2 APP_TEST_PORT=18200 scripts/ci/deploy.sh up`. Pass the same `KIND_CLUSTER` to `logs`, `down` and the detection demo, and the same `APP_TEST_PORT` to `dast.sh`.

## Runtime detection (Falco)

Kyverno and the network policies prevent; [Falco](https://falco.org/) detects what still happens inside the running containers. `deploy.sh up` installs it in the cluster before the application, so the whole deploy is watched:

- Falco 0.45.2, from its Helm chart 9.2.2 rendered with `helm template` (Helm 4.3.1) and [`falco/values.yaml`](falco/values.yaml). Helm, the chart and the image are pinned and checked by SHA-256 or digest.
- The modern eBPF probe: no kernel module, nothing downloaded at start-up. It needs a kernel with BTF (`/sys/kernel/btf/vmlinux`), which WSL2 and GitHub's Ubuntu runners have.
- Container and pod names come from the kind node's containerd (`/run/containerd/containerd.sock`).
- Falco's default rules, plus the DocVault rules in [`falco/docvault_rules.yaml`](falco/docvault_rules.yaml). Alerts are JSON lines on Falco's standard output (`kubectl -n falco logs daemonset/falco`).
- Falco runs privileged in its own namespace, `falco`, which the Kyverno policies exclude: a node-level security agent needs that access, and nothing else runs there.

The DocVault rules only look at the `docvault` namespace. Each rule name starts with its ID, also present as a tag, so the incident response plan can refer to it.

| ID | Detects | Why it matters | How normal activity is excluded |
| --- | --- | --- | --- |
| DV-R1 | A shell (`sh`, `bash`, `dash`, `ash`...) starting in any DocVault container | `kubectl exec` or an attacker with code execution (command injection, `COPY ... FROM PROGRAM` in PostgreSQL) | The init container's exact command and PostgreSQL's entrypoint script, each as PID 1 of its container, and shells descended from `initdb` and `pg_ctl` during database creation and start-up (including `sh -c locale -a`). Shells started by the running PostgreSQL server are reported. |
| DV-R2 | Any program other than Python or uvicorn starting in the `app` container (`id`, `cat`, `curl`, `wget`, `apt`...) | Reconnaissance, data access or tools brought in. The app never starts programs. | Shells are left to DV-R1, so one command raises one alert. For DV-R1 and DV-R2, the runtime's own helpers seen inside the container are ignored: `runc init` on each `kubectl exec`, and kind's container-creation hook (`mount-product-files.sh`, with `jq` and `cp`). |
| DV-R3 | An attempt, successful or not, to open `/etc/shadow` and similar account files or a Kubernetes service account token, in any DocVault container; or to open the app's secrets (`/run/secrets/docvault/`) from any process other than the app | Credential access. A failed attempt counts: the app runs as UID 10001 and has no token, so a real attacker would fail too. | The app's own process (PID 1 in its container, uvicorn runs a single process) reads its secrets at start-up. The init container and PostgreSQL are not covered by the secrets part, because several of their start-up processes read secrets. |
| DV-R4 | A connection attempt from the `app` container to anything other than port 5432 (PostgreSQL) or 53 (DNS) on a private address | Exfiltration, a reverse shell or downloading tools. The network policy blocks it, but does not record it. | Loopback is ignored. |

At the end of `up`, check 4 makes sure the rules are quiet: the deploy (database creation, migrations, seeding), the checks and the smoke test must raise no DocVault alert.

[`scripts/security/detection-demo.sh`](../scripts/security/detection-demo.sh) proves the detection. It triggers each rule harmlessly with `kubectl exec` (a shell in the app and database containers, `id`, `cat /etc/shadow`, the token path, opening the secret file without reading it, a connection to the documentation address 203.0.113.10), then reads Falco's alerts and prints `DETECTED` or `MISSED` for each, with the matching alert. It fails if a DV-R1 to DV-R3 check is missed. CI runs it after the ZAP scan, which also lists any DocVault alert the scan's attacks raised. The alerts are saved in `reports/falco/` (a CI artifact).

```bash
scripts/security/detection-demo.sh
```

Known limits:

- Falco sees every system call on the machine's kernel, not only the kind cluster's. With two kind clusters on one machine, each cluster's Falco also sees the other's containers, but without their names, so the DocVault rules, which need the namespace, only match their own cluster.
- Names can be faked: a shell copied under another name escapes DV-R1 (DV-R2 still catches it in the app container, not in PostgreSQL's). A process inside the app (Python code run by an exploit within uvicorn itself) is the app's own process, so DV-R3 does not see it read the secrets; DV-R1, DV-R2 and DV-R4 still catch what such an exploit usually does next.
- DV-R4 is reported by the demo but not required, and port-based: a connection to another private address on port 5432 or 53 is not reported.
- Alerts only go to Falco's log, which is lost with the pod. A real deployment would forward them (Falcosidekick, a SIEM).
- The modern eBPF probe needs BTF and a recent kernel (5.8 or later). Without them Falco does not start and `up` fails.

## Docker Compose after the F07 fix

The image now runs as UID 10001. A `documents` volume created by the old root image is owned by root, so uploads fail. Recreating the volumes fixes it, and deletes the local test data:

```bash
docker compose down -v && docker compose up -d --build
```
