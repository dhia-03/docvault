# Incident response plan

This plan says what the team does when DocVault may be under attack or a secret may be exposed: who leads, how fast, which commands to run, and how to prove the problem is fixed. It covers the project period and the demo. It is written for a four-person student team with no on-call rota, so the response targets are best effort during working hours.

Status on 2026-11-23: draft, not yet exercised. No drill has been run (see [Drills](#9-drills)). The application alerts (DV-A1 to DV-A4) and the Falco rules (DV-R1 to DV-R4) are being built in parallel and are not in `main` yet. Commands marked *(untested)* have not been run against a live environment; the first drills must confirm them.

The phases follow the classic cycle from NIST SP 800-61. The assets (AS1 to AS6) and threats (T01 to T18) are those of the [threat model](threat-model.md). Fixed flaws (F01 to F07) and open weaknesses (O1 to O3) are in the [vulnerability register](vulnerability-register.md).

## 1. Scope and goals

### Environments covered

DocVault has no production server. Every environment is a test environment, and most of them live on one person's machine.

| Environment | Where | Who controls it | Secrets |
| --- | --- | --- | --- |
| Docker Compose | Each member's machine, `127.0.0.1` only | That member | That member's `.env` (never committed) |
| kind test cluster `docvault` | Each member's machine, `http://127.0.0.1:18000` only | That member | `docvault-secrets` in namespace `docvault`, created by `deploy.sh` from the environment |
| CI runners | GitHub Actions, deleted after each run | Nobody keeps them | Random values generated per run and masked; the repository has 0 Actions secrets (checked 2026-11-23) |
| GitHub repository | Public since 2026-11-22 | The repository owner account | None in the repository; each member's own GitHub credentials |
| Demo machine | The presenter's machine | The presenter | Same as Compose and kind |

All documents are test data. The plan still treats them as confidential (AS1), because that is what DocVault is for and what the course grades.

### Goals

1. Stop the damage to documents, credentials and the delivery chain (AS1 to AS6).
2. Keep the evidence before changing anything.
3. Return to a known-good state: a reviewed commit, a freshly built image, new secrets.
4. Learn from it: every incident ends with a review and, where needed, a new entry in the vulnerability register.

### Incident or normal event

An **incident** is an event that has, or may have, harmed the confidentiality, integrity or availability of an asset, and that nobody on the team can explain by their own actions.

| Normal event: record nothing, or a line in the team channel | Incident: open one |
| --- | --- |
| One failed login, or a user who mistypes a few times | Repeated failed logins that nobody on the team made (DV-A1), or a success right after them |
| A member gets 403 once on a document or admin page | Repeated denials by the same account (DV-A3, DV-A4) that the account owner did not cause |
| A scanner fails on a pull request and the author fixes it before merging. That is the pipeline doing its job | A real secret in any commit, pull request, chat or log (Gitleaks, GitHub secret scanning) |
| Kyverno refuses the `kyverno-check` pod during `deploy.sh up`. That check is deliberate | Kyverno refuses a pod that nobody on the team tried to create |
| DV-R1 or DV-R2 at the minute a team member ran `kubectl exec`, and they confirm it | Any DV-R1, DV-R2 or DV-R3 that no team member can match to their own action within 15 minutes |
| DV-A2 in the 8 hours after a planned key rotation: browsers still send cookies signed with the old key | DV-A2 with no rotation in the last 8 hours, or any sign that a forged session was accepted |
| Alerts raised by `run_all.py`, ZAP (`dast.sh`), the detection demo or a drill, at the time the person running it announced | An unexpected change to `.github/workflows/`, branch protection or a pinned digest |
| A new CVE in a component with no fix and no reachable use, already handled under the [exception rules](security-policy.md#exceptions) | A `HIGH` or `CRITICAL` CVE with a fix in what we deploy, found after merge |

Rule of thumb: **announce in the team channel before running anything noisy** (exploit script, ZAP, drills, `kubectl exec`), with the start time. Most false alarms are then explained in seconds.

## 2. Roles and contacts

### Owners

| Role | Area | Leads the playbooks | Can do today |
| --- | --- | --- | --- |
| M1 | Application and AppSec | P3, P4, P5 | Fix application code through a pull request; use the `admin` account in their own environments |
| M2 | CI and secrets | P1, P6 (dependencies), P7 | Rotate secrets in their own environments; run Gitleaks and the purge script |
| M3 | Container, Kubernetes and DAST | P2, P6 (image) | Own kind cluster, Kyverno, network policies, ZAP |
| M4 | Observability, detection and report coordination | Default incident lead for all; keeps the timeline, the drill record and the evidence | Falco and the alert rules; writes the incident notes |

### Incident lead

- **M4 leads by default.** If M4 is not available within the response target, the owner of the affected area leads (table above). If neither is, whoever saw the alert leads until one of them takes over.
- The lead decides the severity, keeps the timeline, posts the updates and closes the incident. The lead does not have to do the technical work.
- **Rotation for drills:** a different member leads each drill, so all four have led at least once before the demo.

### Who can change what

| Action | Who | Note |
| --- | --- | --- |
| Rotate a secret in a Compose or kind environment | The member whose machine it is | Each environment has its own values (F05 fix), so a leak from one `.env` does not expose the others unless a value was reused |
| Secrets in CI | Nobody needs to | Generated per run and masked. There are no stored Actions secrets |
| Change `main` | Anyone, through a pull request that passes the seven required checks | Branch protection, checked 2026-11-23: 7 required checks, branch up to date, applies to admins, no force-push, no deletion, 0 approvals required |
| Change repository settings, branch protection, disable Actions | The repository owner account | On 2026-11-23 the GitHub API lists one collaborator, the owner (admin). The other three members cannot change settings |
| Force-push a rewritten branch | The repository owner, after the team agrees | `main` refuses force-pushes, even from admins. `secure` and `vulnerable-baseline` are not protected |
| Revoke a GitHub token or SSH key | Each member, for their own account | Settings, then Developer settings and SSH keys |

### Escalation

| To | When | How |
| --- | --- | --- |
| The teacher | See [section 6](#6-communication) | Message or e-mail, using the incident note template |
| GitHub Support | A secret was pushed and must be removed from pull request references or cached views; or an account compromise needs GitHub's help | GitHub Support form. Asking for the F05 commits is still an open team decision (see [f05-revoke-then-purge.md](f05-revoke-then-purge.md#after-the-purge)) |

## 3. Severity levels

| Level | Meaning | Acknowledge | Contain | Update the team |
| --- | --- | --- | --- | --- |
| **SEV1** | Confirmed or very likely harm to AS1 (documents) or AS3 (signing key, database password), a compromised container, or a compromised delivery chain (AS6) | Within 1 hour while any member is working on the project; immediately during the demo | Within 4 hours | Every 2 hours until contained |
| **SEV2** | A likely attack or exposure with no confirmed harm yet | Within 1 working day | Within 2 working days | Daily |
| **SEV3** | A probe that the controls stopped, or a weakness with a known fix | At the next team meeting, or within 3 days | Within a week, or under a recorded exception | In the weekly progress note |

These targets are sized for students working part-time and are not a service commitment. When in doubt, choose the higher level and lower it later.

### Default severity per alert

| Source | ID | Alert severity | Default level | Raise when |
| --- | --- | --- | --- | --- |
| App | DV-A1 `brute_force_suspected` | Medium | SEV3 | SEV2 if a `login` for the targeted account follows the failures; SEV1 if that account then did something its owner denies |
| App | DV-A2 `forged_session` | High | SEV2 | SEV1 if the current signing key may be exposed, or the audit log shows actions nobody on the team made |
| App | DV-A3 `access_probing` | Medium | SEV2 | SEV1 if the account obtained a document it had no right to |
| App | DV-A4 `privilege_probe` | Low | SEV3 | SEV2 if it comes with DV-A3 or an unexpected role change; SEV1 if a non-admin got an admin page |
| Falco | DV-R1 shell in a DocVault container | High | SEV1 | Not an incident if a team member's `kubectl exec` explains it |
| Falco | DV-R2 unexpected program in the app container | High | SEV1 | Same |
| Falco | DV-R3 sensitive file read | High | SEV1 | Same |
| Falco | DV-R4 unexpected outbound connection *(may not exist)* | Medium | SEV2 | SEV1 if the connection succeeded, because the network policy then failed |
| CI | Gitleaks finds a real secret | n/a | SEV1 | A confirmed false positive is not an incident: record an exception by fingerprint |
| GitHub | Secret scanning alert or push protection block | n/a | SEV1 if the value is real | Enabled on 2026-11-23 |
| CI | Trivy `HIGH` or `CRITICAL` with a fix, on `main` | n/a | SEV2 (`CRITICAL`), SEV3 (`HIGH`) | SEV1 if it is exploitable in DocVault, like F06 was |
| CI | ZAP `High` alert on `main` | n/a | SEV2 | SEV1 if confirmed exploitable |
| CI | Semgrep `ERROR` or Checkov failure on `main` | n/a | SEV3 | |
| Kyverno | Admission denial | n/a | SEV3 (the control worked) | SEV2 if nobody on the team created the refused resource |
| GitHub | Unexpected change to workflows, branch protection or a pinned digest | n/a | SEV1 | |
| Audit log | Role change or new user that nobody made | n/a | SEV1 | |

## 4. Lifecycle

| Phase | What it means here |
| --- | --- |
| Prepare | This plan, the tools in the repository (`deploy.sh`, `run_all.py`, `scan.sh`, `dast.sh`, the purge script), the alert rules, and the drills |
| Detect and analyse | An alert or report arrives. The lead opens an incident, picks a severity, and answers the playbook's triage questions |
| Contain | Stop the damage without destroying evidence: rotate the key, isolate the pod, cut access |
| Eradicate | Remove the cause: fix the flaw, rebuild from a clean image, purge the secret |
| Recover | Restore service with new secrets, then prove the fix with the listed checks |
| Post-incident review | Within 3 working days for SEV1 and SEV2, using the [template](#8-post-incident-review). Action items go to the vulnerability register |

**Evidence before change.** In every playbook, save logs and state before restarting or deleting anything. A pod restart erases its logs, and DocVault has no central log storage.

## 5. Playbooks

### Command conventions

Run these once per shell, from the repository root. The kubectl binary is the pinned one that `deploy.sh` downloads; the explicit context means a command can never hit another cluster.

```bash
# Pinned kubectl, always against the kind test cluster.
kc() { ~/.cache/docvault/bin/kubectl-v1.37.0 --context kind-docvault "$@"; }

# Evidence folder for this incident, outside the repository so it cannot be committed.
IR=~/docvault-incidents/IR-$(date -u +%Y%m%d-%H%M)
mkdir -p "$IR" && chmod 700 "$IR"

# Timeline: one UTC line per action.
note() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$IR/timeline.txt"; }
note "incident opened"
```

Reading the alerts:

```bash
# Application alerts (DV-A1 to DV-A4), kind and Compose:
kc -n docvault logs deploy/docvault -c app --timestamps | grep security_alert
docker compose logs --timestamps app | grep security_alert

# Falco alerts (DV-R1 to DV-R4). With a label selector kubectl shows only the
# last 10 lines unless --tail is given.
kc -n falco logs -l app.kubernetes.io/name=falco --tail=-1 --timestamps
```

Exporting the audit log. The `/audit` page shows only the latest 200 entries, so export the whole table *(untested on PostgreSQL)*:

```bash
AUDIT_SQL="COPY (SELECT id, created_at, actor, action, target FROM audit_logs ORDER BY id) TO STDOUT WITH CSV HEADER"
# kind:
kc -n docvault exec statefulset/db -c postgres -- psql -U docvault -d docvault -c "$AUDIT_SQL" > "$IR/audit_logs.csv"
# Compose:
docker compose exec -T db psql -U docvault -d docvault -c "$AUDIT_SQL" > "$IR/audit_logs.csv"
```

The audit log records `login`, `login_failed`, `upload`, `download`, `share`, `update_metadata`, `delete`, `create_user` and `change_role`, with the actor, the target and the time. It does not record the client address, detail-page views, previews or refused requests.

At the end of evidence capture, fingerprint the files so later changes can be detected:

```bash
(cd "$IR" && sha256sum -- * > SHA256SUMS)
```

### P1: leaked or forged signing key

**Trigger:** DV-A2; Gitleaks fails on a real secret (CI `Secret scan (Gitleaks)` or `bash scripts/ci/scan.sh gitleaks`); a GitHub secret scanning alert or push protection block; a member reports pasting a key or `.env` somewhere.

**What DV-A2 does and does not tell you.** DV-A2 fires when a cookie's signature does not match the current key, so the forged session was *refused*. The most likely source is the old F05 key, which anyone could copy while the repository was public; seeing it means the revocation is working. The dangerous case is the opposite: if the *current* key leaks, forged cookies are valid and raise no alert. That case is found through Gitleaks, GitHub secret scanning, or audit entries nobody made.

**First 15 minutes**

1. Open the incident and note the time. Default SEV2; SEV1 if the current key may be exposed.
2. Save the application logs now. The rotation restarts the pod and erases them.
   ```bash
   kc -n docvault logs deploy/docvault -c app --timestamps > "$IR/app.log"
   # or: docker compose logs --timestamps app > "$IR/app.log"
   ```
3. Was the key rotated in the last 8 hours? If so, and the alerts stop within 8 hours of the rotation, these are old browser cookies: close as a normal event.
4. If the current key may be exposed, **rotate it now** (below). Do not wait for the analysis: anyone may already have copied it.

**Triage questions**

- Which secret, and which environments use that exact value?
- Where was it exposed: a commit (which branches, did it reach `main`?), a pull request, the chat, a screenshot, a log? Since when?
- Did a forged session succeed? Look in the audit export for `create_user`, `change_role`, `share` or `download` entries that nobody on the team made, especially by `admin`.
- How many DV-A2 alerts, at what times, and with which details (user ID in the cookie, client address, if the alert gives them)?

**Containment: rotate the key**

Docker Compose:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
# Paste the new value into SECRET_KEY in .env with an editor, then:
docker compose up -d app    # recreates the container with the new key
```

Kubernetes (kind). The app reads the key once at start, so the pod must restart. The simplest way is `deploy.sh`, which re-creates the `docvault-secrets` secret from the environment and runs `rollout restart` on an existing deployment (it also rebuilds the image):

```bash
# After updating SECRET_KEY in .env:
set -a; . ./.env; set +a
scripts/ci/deploy.sh up
```

Without rebuilding, the same steps by hand. Values go through files, as in `deploy.sh`, so they never appear in the process list:

```bash
set -a; . ./.env; set +a
d=$(mktemp -d) && chmod 700 "$d"
printf '%s' "$POSTGRES_PASSWORD" > "$d/POSTGRES_PASSWORD"
printf '%s' "$SEED_PASSWORD" > "$d/SEED_PASSWORD"
printf '%s' "$SECRET_KEY" > "$d/SECRET_KEY"
kc -n docvault create secret generic docvault-secrets --from-file="$d" --dry-run=client -o yaml \
  | kc -n docvault apply -f -
rm -rf "$d"
kc -n docvault rollout restart deployment/docvault
kc -n docvault rollout status deployment/docvault --timeout=300s
note "SECRET_KEY rotated"
```

**Consequence:** every user is signed out, because every cookie was signed with the old key. Sessions are stateless signed cookies with no server-side list, so rotating the key is the only way to end a stolen or forged session. Expect DV-A2 from old cookies for up to 8 hours (the cookie lifetime). Record the rotation time, so those alerts can be told apart.

**Confirm the old key no longer works**

`run_all.py` forges an administrator session with a key and expects to be refused. After the F05 purge the key is no longer in history, so supply it through `DOCVAULT_LEAKED_KEY`. `read -rs` keeps it out of the shell history and the screen.

```bash
read -rs DOCVAULT_LEAKED_KEY && export DOCVAULT_LEAKED_KEY
uv run --with httpx --with itsdangerous python scripts/exploits/run_all.py --base-url http://127.0.0.1:18000
# Compose: --base-url http://127.0.0.1:${APP_PORT:-8000}
unset DOCVAULT_LEAKED_KEY
```

Expected: F05 not exploitable (HTTP 303 to the login page), and one DV-A2 alert for the attempt.

**Eradication: purge, in this order**

The procedure was really executed for F05 on 2026-11-23 and is recorded in [f05-revoke-then-purge.md](f05-revoke-then-purge.md). In short:

1. **Revoke first.** The key was moved out of the code and replaced per environment. Purging alone is useless: clones, forks and caches keep the old value.
2. **Confirm** that the old key is refused (HTTP 303 on Compose and on kind).
3. **Purge.** [`purge-leaked-key.sh`](../scripts/security/purge-leaked-key.sh) works on a fresh copy, replaces the value with `REMOVED-F05-SIGNING-KEY` in every commit that `main` does not contain, runs Gitleaks on the result, lists the refs, and force-pushes only with `--push`. Every teammate pushes their work first and stops pushing until it is done. It rewrote 9 branches and the tag `v0-vulnerable`; `main` was untouched.
4. **Verify** in a fresh clone: the old value appears 0 times, and Gitleaks finds nothing in the tree or the history.
5. **Afterwards:** everyone re-clones; GitHub keeps old commits reachable through pull request references until GitHub Support removes them (not requested yet).

For a new leak:

- The script is written for F05: it reads the value from the tag `v0-vulnerable` and the file `backend/app/config.py`. Adapt a copy to the new source of the value, and keep its safeguards (fresh copy, dry run first, Gitleaks check, list of refs).
- If the secret reached `main`, a purge means rewriting `main`. Branch protection refuses force-pushes even from admins, so the owner would have to lift it, and the signed merge commits would lose their signatures. That is a team decision, and the teacher is told first.
- If the leak was in chat or a screenshot, there is nothing to purge in Git: rotate, and delete the message.

**Verification**

- `bash scripts/ci/scan.sh gitleaks`, then the `Secret scan (Gitleaks)` check passes in CI. It scans the working tree and the full history.
- In a fresh clone, `read -rs OLD && git log --all -S "$OLD" --oneline` prints nothing.
- `python -m pytest backend/tests -q -k f05`: a cookie signed with another key is refused, short and missing keys are refused.
- `run_all.py` as above: F05 not exploitable.
- The event is recorded in the vulnerability register, as the [security policy](security-policy.md#exposed-secret-procedure) requires.

### P2: compromised container

**Trigger:** DV-R1, DV-R2, DV-R3 or DV-R4 from Falco. Falco runs only in the kind test cluster. In Compose there is no runtime detection; a container is suspected only from the application alerts or by a person.

**First 15 minutes**

1. Ask in the team channel: did anyone run `kubectl exec`, `kubectl cp` or the detection demo just now? If someone confirms within 15 minutes, close it as a normal event.
2. Otherwise, open a SEV1. Note the pod name from the alert and the time.
3. Save the Falco and application logs (cheap, and they change nothing).
4. Isolate the pod (below). Isolation is reversible; deleting the pod is not.

**Triage questions**

- Which container: `app`, the `prepare` init container, or `postgres`? Which process, user and file, according to Falco?
- What could it reach? The app container can read the database password and the signing key (mounted files), and the documents volume. It cannot read the seed password, which only the init container gets.
- What could it write? The root filesystem is read-only, so only `/tmp` (an `emptyDir`) and `/data/documents`.
- How did it get in? Look at the application log around the first alert for unusual requests, and compare with known flaw classes (F02, F04, F06).
- Did the hardening hold? The pod should run as UID 10001 with no service account token, and the network policies should have blocked any outbound connection.

**Containment: isolate without destroying evidence**

Kubernetes network policies only *add* allowed traffic. A "deny all" policy for quarantined pods does not cancel another policy that also selects them. DocVault's `allow-dns` policy selects every pod, so it is narrowed as well.

```bash
POD=<pod name from the alert>
note "isolating $POD"

# 1. Quarantine policy: selected pods get no allowed traffic from this policy.
kc apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine
  namespace: docvault
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes: ["Ingress", "Egress"]
EOF

# 2. Stop allow-dns from applying to quarantined pods (DNS can carry data out).
kc -n docvault patch networkpolicy allow-dns --type merge \
  -p '{"spec":{"podSelector":{"matchExpressions":[{"key":"quarantine","operator":"DoesNotExist"}]}}}'

# 3. Label the pod out of the Deployment. Removing app=docvault takes it out of
#    the ReplicaSet (which starts a replacement), out of the Service, and out
#    of the "app" policy that allowed port 8000 in and the database out.
kc -n docvault label pod "$POD" quarantine=true app-

# 4. Check: the Service now points only at the replacement pod.
kc -n docvault get pods --show-labels
kc -n docvault get endpointslices -l kubernetes.io/service-name=docvault -o wide
```

If the entry point is unknown, the replacement pod runs the same image and may be attacked the same way. Then also stop the service, which means downtime: `kc -n docvault scale deployment/docvault --replicas=0`. Label first, then scale, or the scale-down deletes the evidence.

The quarantined pod still has its mounted secrets and the documents volume. Isolation stops the network, not local reads. Capture evidence quickly and then delete it.

**Evidence to preserve, before deleting anything**

```bash
kc -n falco logs -l app.kubernetes.io/name=falco --tail=-1 --timestamps > "$IR/falco.log"
kc -n docvault logs "$POD" -c app --timestamps > "$IR/app.log"
kc -n docvault logs "$POD" -c prepare --timestamps > "$IR/prepare.log"
kc -n docvault get pod "$POD" -o yaml > "$IR/pod.yaml"     # includes the image ID
kc -n docvault describe pod "$POD" > "$IR/pod-describe.txt"
kc -n docvault get events --sort-by=.lastTimestamp > "$IR/events.txt"
kc -n docvault get all,networkpolicy,pvc -o wide > "$IR/namespace.txt"
kc get clusterpolicy > "$IR/kyverno-policies.txt"
kc get policyreport -A > "$IR/kyverno-reports.txt" 2>&1
docker exec docvault-control-plane crictl ps -a > "$IR/node-containers.txt"   # (untested)
# audit log export: see "Command conventions"
```

These copy files out of the pod. They run programs in the container, so Falco will raise DV-R1 or DV-R2 for them: note the time before running them *(untested)*.

```bash
note "evidence capture inside the pod starts (expect DV-R1/DV-R2)"
kc -n docvault exec "$POD" -c app -- tar -C /tmp -cf - . > "$IR/pod-tmp.tar"
kc -n docvault exec "$POD" -c app -- ls -la /data/documents > "$IR/documents-listing.txt"
kc -n docvault exec "$POD" -c app -- sh -c \
  'for p in /proc/[0-9]*; do echo "${p#/proc/}: $(tr "\0" " " < "$p/cmdline")"; done' > "$IR/processes.txt"
note "evidence capture inside the pod ends"
(cd "$IR" && sha256sum -- * > SHA256SUMS)
```

Do not copy document contents into the evidence folder unless the review needs them; a listing is enough to see whether files were added or changed.

Then delete the pod. It is no longer owned by the ReplicaSet, so it does not come back.

```bash
kc -n docvault delete pod "$POD"
note "$POD deleted"
```

Compose has no quarantine, but a stopped container keeps its filesystem: `docker compose stop app`, then `docker diff "$(docker compose ps -aq app)" > "$IR/diff.txt"` and `docker compose logs --timestamps app > "$IR/app.log"`, then `docker compose rm -f app`.

**Eradication**

- Find and fix the entry point before restoring the service: `run_all.py`, `scripts/ci/dast.sh` and `bash scripts/ci/scan.sh all` help to rule known classes in or out. A new flaw gets a register entry, a fix and a regression test in `backend/tests`, through a pull request.
- Rotate every secret the pod could read:
  - **Signing key:** as in P1.
  - **Database password.** `POSTGRES_PASSWORD` is only read when the database is first created, so changing the secret alone does nothing. Change it in the database first, then in `.env`, then redeploy *(untested)*:
    ```bash
    kc -n docvault exec -it statefulset/db -c postgres -- psql -U docvault -d docvault -c '\password docvault'
    # Put the same new value in POSTGRES_PASSWORD in .env, then:
    set -a; . ./.env; set +a
    scripts/ci/deploy.sh up
    ```
    In Compose: `docker compose exec db psql -U docvault -d docvault -c '\password docvault'`, update `.env`, then `docker compose up -d`.
  - **User passwords.** With the database password, the attacker could read the Argon2 hashes (AS2). Change the demo accounts' passwords (see P3). Changing `SEED_PASSWORD` alone does not, because seeding only creates missing accounts.
- **Rebuild from a clean image.** Check that the working tree is a reviewed commit (`git status` clean, `git fetch && git diff origin/main` empty), remove the old local image with `docker image rm docvault-app:dev`, then `scripts/ci/deploy.sh up`, which builds, loads and restarts.
- **When the scope is unclear**, rebuild the whole cluster: `scripts/ci/deploy.sh down`, then `up`. All test data is lost, and the quarantine policy and Falco must be reinstalled.

**Recovery**

```bash
# Undo the DNS change. kubectl apply keeps fields added by a patch, so remove it explicitly.
kc -n docvault patch networkpolicy allow-dns --type json \
  -p '[{"op":"remove","path":"/spec/podSelector/matchExpressions"}]'
kc -n docvault scale deployment/docvault --replicas=1     # if it was scaled to 0
```

The `quarantine` policy can stay: it selects no pod once the quarantined one is gone.

**Verification: did Kyverno and the network policies hold?**

- `scripts/ci/deploy.sh up` ends with its own checks: Kyverno must refuse a pod with no security context, the database must not answer a pod from another namespace, and `alice` must sign in.
- `kc get clusterpolicy`: all four policies `Ready`. `kc -n docvault get networkpolicy`: `default-deny`, `allow-dns`, `app`, `db` (and `quarantine`).
- In `$IR/pod.yaml`: `runAsUser: 10001`, `readOnlyRootFilesystem: true`, `automountServiceAccountToken: false`. If any is missing, Kyverno failed and that becomes its own finding.
- Egress from the new app pod is blocked; this should time out, and Falco should raise DV-R2 (and DV-R4 if it exists) *(untested)*:
  `kc -n docvault exec deploy/docvault -c app -- python -c "import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)"`
- `run_all.py` against `http://127.0.0.1:18000`: 0 tested flaws exploitable. It reports F07 as "not tested" since F06 is fixed, so check the user directly: `kc -n docvault exec deploy/docvault -c app -- id -u` must print 10001 (this raises DV-R2, as expected).

### P3: brute force or credential stuffing

**Trigger:** DV-A1 (5 or more failed logins for the same username or client address within 60 seconds).

**Automatic response (O2 fix).** After 5 failed sign-ins for one username within 5 minutes, that username is locked for 5 minutes: every attempt, even with the right password, gets HTTP 429 and an `account_locked`, then `login_throttled`, event. DV-A1 fires at the same 5th failure. Guessing is limited to about 1,400 tries a day per account, but anyone can lock a known username on purpose (the lock is short for that reason).

**First 15 minutes**

1. Ask in the team channel whether anyone is testing. ZAP and drills cause failed logins too.
2. Save the application log and export the audit log.
3. Check for a success after the failures:
   ```bash
   grep -E ',(login|login_failed),' "$IR/audit_logs.csv" | tail -50
   ```
   A `login` for the targeted username right after a run of `login_failed` means the guess may have worked: SEV2, and treat that account as compromised.

**Triage questions**

- Which usernames and which client address does the alert name? Are they real accounts (`admin`, `alice`, `bob`, `auditor`) or a list of invented names (credential stuffing)?
- Did any login succeed for a targeted account, and what did that account do next (`download`, `share`, `change_role`)?
- Where can the traffic come from? Compose and the kind test access listen on `127.0.0.1` only, so the source is a process on that machine.

**Containment options available today**

| Option | Exists? | How |
| --- | --- | --- |
| Reset the account's password from the admin page | **No.** `/admin/users` can only create users and change roles. There is no password change, reset or account disable route | — |
| Change the password directly in the database | Yes, by hand *(tested on SQLite only)* | Snippet below. The account owner chooses the new password and runs it, so it never goes through chat |
| Sign out an attacker who already got in | Only by rotating the signing key, which signs out everyone | P1 rotation |
| Block the source address | Not in the current setups: there is no reverse proxy or firewall in front of the app, and in kind the app may see the node address for every client (not verified) | — |
| Lift a lock early (the real owner is locked out) | Only by restarting the app, which clears the in-memory counters: `kc -n docvault rollout restart deployment/docvault`. Otherwise wait 5 minutes | — |
| Cut access entirely | Yes | kind: `kc -n docvault delete service docvault-test-access` (restore with `kc apply -f deploy/test/access.yaml`). Compose: `docker compose stop app` |

Emergency password change. The first line of standard input is the username, the second the new password; nothing appears in the process list. In kind it runs in the app container, which has the database password *(untested in a container)*:

```bash
kc -n docvault exec -i deploy/docvault -c app -- python -c '
import sys
from sqlalchemy import select
from app.auth import hash_password
from app.db import SessionLocal
from app.models import User

username, password = sys.stdin.read().splitlines()[:2]
with SessionLocal() as session:
    user = session.scalar(select(User).where(User.username == username))
    if user is None:
        sys.exit("No such user")
    user.password_hash = hash_password(password)
    session.commit()
print("Password changed for", username)
'
# Type the username, Enter, the new password, Enter, then Ctrl-D.
# Compose: replace the first line with  docker compose exec -T app python -c '...
```

This runs a program in the app container, so Falco will raise DV-R2: announce it first. A password change does not end existing sessions; rotate the key if the account was used by someone else.

**Eradication**

The per-username lock (O2 fix, [`login_throttle.py`](../backend/app/login_throttle.py)) is already in place. If the guesses come from many usernames (credential stuffing), each name is only tried a few times and the lock does not trigger: then the only lever left is blocking the source, which needs a proxy or firewall in front of the app (not in the current setups).

**Verification**

- Six failed logins in a row for one username raise one DV-A1 alert, and the sixth gets HTTP 429.
- `python -m pytest backend/tests -q` passes, including the O2 tests in `test_weaknesses.py`.
- The audit export shows no further `login` for the targeted account by anyone but its owner.

### P4: document access probing or data exposure

**Trigger:** DV-A3 (3 or more denied or missing document accesses by the same user within 60 seconds), which is the F01 pattern: trying document IDs one after another. Also: a report that a user saw a document not shared with them.

**First 15 minutes**

1. Save the application log and export the audit log.
2. Note the account named in the alert and the document IDs in the log.
3. Check whether any access succeeded (query below). If one did, raise to SEV1: an access-control flaw is back.

**Triage questions**

- Which account, and does its owner admit to the requests?
- Did the account download any document it neither owns nor has a share for? Run *(tested on SQLite only)*:
  ```bash
  kc -n docvault exec -i statefulset/db -c postgres -- psql -U docvault -d docvault <<'SQL'
  SELECT a.created_at, a.actor, a.target, o.username AS owner
  FROM audit_logs a
  JOIN users u ON u.username = a.actor
  LEFT JOIN documents d ON a.target = 'document:' || d.id
  LEFT JOIN users o ON o.id = d.owner_id
  WHERE a.action = 'download'
    AND (d.id IS NULL
         OR (d.owner_id <> u.id
             AND NOT EXISTS (SELECT 1 FROM shares s
                             WHERE s.document_id = d.id AND s.user_id = u.id)))
  ORDER BY a.id;
  SQL
  ```
  Each row is a download by someone without a current right to the document. Rows with no owner are deleted documents: check them by hand.
- Detail pages and previews are not in the audit log. Look for successful ones in uvicorn's access log, which records the path and status but not the user:
  `grep -E '"GET /documents/[0-9]+(/preview|/download)? HTTP/[0-9.]+" 200' "$IR/app.log"`
- Which owners are affected? The query's `owner` column lists them.

**Containment**

- If an access succeeded, the access check has a hole. Cut access (`kc -n docvault delete service docvault-test-access`, or `docker compose stop app`) until it is fixed.
- If the account is misused by someone else: change its password (P3) and rotate the key to end its session (P1). There is no way to disable an account.
- If only denials were seen, the control held: keep watching and record it.

**Eradication**

Fix the route in a pull request. Every route that shows or serves a document must go through `get_readable_document`, and every route that changes one through `get_owned_document` (the F01 fix). A route that skips them is the bug. Add a two-user test for it.

**Recovery and notification**

Tell each affected owner which documents were read, when, and by which account (in this project the owners are the demo accounts, so the team). Never paste the document contents into the note.

**Verification**

- `python -m pytest backend/tests -q -k f01`: the other user gets 403 on the detail page, download and preview; the owner and a share recipient still get the document.
- `run_all.py`: F01 not exploitable (Bob gets HTTP 403).
- The `Tests (pytest)` check passes in CI.

### P5: privilege probing

**Trigger:** DV-A4 (a user without the required role requests `/admin/users` or `/audit`).

The navigation shows the Users link only to admins and the Audit log link only to admins and auditors. A member reaching these pages typed or replayed the URL, or the role changed while the page was open.

**First 15 minutes**

1. Ask the account owner. One request after a role change is a normal event.
2. Export the audit log and check for role changes and new accounts:
   ```bash
   grep -E ',(change_role|create_user),' "$IR/audit_logs.csv"
   kc -n docvault exec statefulset/db -c postgres -- psql -U docvault -d docvault -c 'SELECT id, username, role FROM users ORDER BY id'
   ```
   Expected roles: `admin` admin, `alice` and `bob` member, `auditor` auditor, plus any account the team created on purpose.

**Triage questions**

- Did it come with DV-A3 from the same account? Then it is one probing session: handle it with P4 as well.
- Did any account gain a role nobody gave it, or did an unknown account appear? Then SEV1. An `admin` action that no admin made points to a forged or stolen session: follow P1.
- Did any non-admin request get HTTP 200 on an admin page? Then the role check failed: SEV1.

**Containment**

- Revert a wrong role on `/admin/users` (this route exists).
- If an admin session may be stolen or forged, rotate the signing key (P1).

**Verification**

- `python -m pytest backend/tests -q -k "roles or anonymous"`: members get 403 on both pages, the auditor gets the audit log only, the admin gets both, and a visitor who is not signed in is sent to the login page.
- The `users` query shows the expected roles.

### P6: vulnerable dependency or image disclosed

**Trigger:** the `Dependency scan (Trivy)` or `Image scan (Trivy)` check fails on `main` or on a pull request that did not change dependencies; a new CVE is published for a component we use. Dependabot alerts are off for this repository (checked 2026-11-23), so new advisories are not pushed to us. CI has no scheduled run, so Trivy only finds them on the next push to `main` or pull request.

**First 15 minutes**

1. Reproduce locally: `bash scripts/ci/scan.sh trivy` and `bash scripts/ci/scan.sh image`.
2. Note the package, installed version, fixed version, CVE and severity.

**Triage questions**

- Does DocVault use the vulnerable function with input an attacker controls? F06 was critical because user input reached `FullLoader`.
- Is there a fix? With no fix, `--ignore-unfixed` hides it from the gate, so it must be judged by hand.
- Is it in our dependencies (`backend/requirements.txt`) or in the base image's operating system packages?
- The PostgreSQL image is not scanned by CI. If the advisory concerns PostgreSQL, check the pinned image by hand.

**Containment and exceptions** (from the [security policy](security-policy.md#exceptions))

| Finding | Exception? | Maximum |
| --- | --- | --- |
| Critical, fix available | No | Upgrade now |
| Critical, no fix | Yes | 7 days |
| High | Yes | 14 days, with a compensating control |

An exception is recorded in the exception register with the finding, the reason, a compensating control, an owner and an expiry date. None may remain open at final submission. As a compensating control, disabling the affected feature is often enough.

**Eradication**

- Dependency: pin the fixed version in `backend/requirements.in` with a comment, as for PyYAML, and update `backend/requirements.txt` to match. The repository does not record which tool produced `requirements.txt`; the team should write it down.
- Base image: update the `python:3.12-slim-trixie` digest in `backend/Dockerfile`. The build already applies Debian security updates.
- PostgreSQL: update the digest in `deploy/k8s/10-db.yaml`.

**Recovery**

`scripts/ci/deploy.sh up` rebuilds and redeploys. Docker Compose: `docker compose up -d --build`.

**Verification**

- Both Trivy checks pass locally and in CI.
- `python -m pytest backend/tests -q` and `run_all.py` still pass, so the upgrade broke nothing.

### P7: CI or supply-chain compromise

**Trigger:** an unexpected change to `.github/workflows/`, `scripts/ci/`, a pinned action SHA or a pinned image digest; a CI run nobody started; a change to branch protection; a member's GitHub account acting on its own.

**First 15 minutes**

1. Open a SEV1. Ask the team who made the change.
2. Save the current state:
   ```bash
   gh api 'repos/{owner}/{repo}/branches/main/protection' > "$IR/protection.json"
   gh run list --limit 50 > "$IR/runs.txt"
   git fetch origin && git log --format='%h %G? %an %ad %s' --date=iso origin/main -- .github/workflows scripts/ci > "$IR/ci-history.txt"
   ```
3. If a malicious workflow may still run, the owner disables it: `gh workflow disable ci.yml`. This also blocks merges, because the required checks cannot run. That is accepted during the incident.

**What to check**

| Check | Command | Expected (2026-11-23) |
| --- | --- | --- |
| Branch protection on `main` | `gh api 'repos/{owner}/{repo}/branches/main/protection'` | 7 required checks, strict, admins included, no force-push, no deletion |
| Required checks | Same output, `required_status_checks.contexts` | `Secret scan (Gitleaks)`, `SAST (Semgrep)`, `Dependency scan (Trivy)`, `Image scan (Trivy)`, `IaC scan (Checkov)`, `DAST (ZAP)`, `Tests (pytest)` |
| Every action pinned by full SHA | `grep -nE 'uses:' .github/workflows/*.yml \| grep -vE '@[0-9a-f]{40}'` | No output (checked 2026-11-23) |
| Every scanner and tool image pinned by digest | `grep -nE '_IMAGE=' scripts/ci/*.sh scripts/security/*.sh` | Every line has `@sha256:`, except the two `APP_IMAGE` tags, which are built locally (exception E2) |
| kind, kubectl, Kyverno checksums | `grep -nE '_SHA256=' scripts/ci/deploy.sh` | Unchanged from the reviewed commit |
| Workflow token | `gh api 'repos/{owner}/{repo}/actions/permissions/workflow'` | `default_workflow_permissions: read`; `ci.yml` sets `contents: read` |
| Who changed what | `git log -p origin/main -- .github/workflows scripts/ci` | Each change came through a reviewed pull request |
| Collaborators and keys | `gh api 'repos/{owner}/{repo}/collaborators' --jq '.[].login'`, `gh api 'repos/{owner}/{repo}/keys'` | Only expected accounts, no unknown deploy keys |

**Containment: revoke tokens**

- Each member checks their own GitHub account: `gh auth status`, then on github.com the personal access tokens, SSH keys, authorized OAuth and GitHub apps, and the security log. Revoke anything unknown, and sign in again with `gh auth login`.
- CI has no stored secrets to rotate, and its token is read-only. A compromised run could still read the repository and change what it built in that run. Images are never pushed to a registry, so nothing built in CI reaches a cluster.

**Eradication**

Revert the change through a pull request (`main` accepts nothing else), with the pins restored to their reviewed values. If an action or image was replaced upstream behind the same tag, our SHA pins protect us; if a pin itself changed, check the new value against the publisher's release before keeping it.

**Recovery**

Re-enable the workflow (`gh workflow enable ci.yml`), then run it on `main` and check that all seven checks pass.

**Verification**

- The protection output matches the table above.
- The pin checks print nothing unexpected.
- A full CI run on `main` passes.

## 6. Communication

### Inside the team

- All incident traffic goes in the team's group chat, in one thread per incident, named with the incident ID (`IR-YYYYMMDD-HHMM`).
- Announce before running anything that raises alerts: exploit script, ZAP, drills, `kubectl exec`.
- The lead posts the first note as soon as the incident is opened, then updates at the rate in [section 3](#3-severity-levels).

### Incident note template

```text
[IR-20261123-1430] SEV2 - forged session cookies refused (DV-A2)
What: 14 DV-A2 alerts on the kind cluster of M3; cookies signed with an unknown key.
When: first 14:28 UTC, last 14:36 UTC; detected 14:30 UTC.
Impact: none confirmed. No unexpected admin actions in the audit log.
Actions: logs saved; SECRET_KEY rotated 14:52 UTC (everyone signed out).
Next: check for a leaked current key (Gitleaks, chat history). Lead: M4.
Next update: 16:00 UTC.
```

Never put a secret, a cookie value or document contents in a note. See [section 7](#7-evidence-handling).

### When to tell the teacher

- Any SEV1, the same day.
- Any decision that rewrites `main`, changes branch protection, or asks GitHub Support for something.
- Any exposure of real personal data, such as a member's address in a log or screenshot.
- Anything that may affect the demo or the submission date.

The note template above is enough. Drills are reported in the progress notes, not as incidents.

## 7. Evidence handling

### What never goes in a ticket, chat, pull request or commit

- Secret values: `SECRET_KEY`, `POSTGRES_PASSWORD`, `SEED_PASSWORD`, any `.env`, any GitHub token.
- Session cookies (`docvault_session` values): a valid one is a password for up to 8 hours.
- Password hashes.
- Document contents and file names that reveal them.
- Full Falco output with environment variables, if any appear.

### How to redact

| Item | Write instead |
| --- | --- |
| A secret | `<redacted SECRET_KEY, sha256 1a2b3c4d5e6f>`, where the hash is `printf '%s' "$VALUE" \| sha256sum \| cut -c1-12`. It identifies the value without revealing it |
| A cookie | `session cookie for uid 1, signature invalid` |
| A document | `document:12, owner alice, title withheld` |
| A password hash | `<argon2 hash>` |
| Gitleaks output | Already redacted: `scan.sh` runs Gitleaks with `--redact` |

### Where evidence is stored

- **Raw evidence** stays in `~/docvault-incidents/<incident ID>/` on the machine where it was captured: outside the repository, mode 700, with `timeline.txt` and `SHA256SUMS`. It is deleted after the review, and at the latest after final submission.
- **Redacted, non-sensitive artefacts** (an incident summary, a redacted alert excerpt, a screenshot with no secret) may go in [`docs/evidence/`](evidence/), through a pull request like any other change. Gitleaks scans that folder too.
- Times are recorded in UTC. `kubectl logs --timestamps` already gives UTC.

## 8. Post-incident review

Within 3 working days for SEV1 and SEV2, and for every drill. The review is blameless: it asks what in the system, the tools or this plan let the problem happen or slowed the response, not who made a mistake.

```markdown
## Review: IR-YYYYMMDD-HHMM

- Severity: SEV1 / SEV2 / SEV3 (initial -> final)
- Lead: M?   Participants: M?, M?
- Detected by: alert ID or source

### Timeline (UTC)
| Time | Event |
| --- | --- |
| | First malicious or unexpected action (if known) |
| | Alert fired |
| | Incident opened |
| | Contained |
| | Recovered and verified |

Time to detect: ...   Time to contain: ...

### What happened
Short, factual. Root cause, not just the trigger.

### Impact
Assets affected (AS1-AS6), documents read, accounts used, secrets exposed.

### What went well
### What went wrong or was slow
### Was this plan right?
Commands that failed, missing steps, wrong severity.

### Action items
| ID | Action | Owner | Due | Goes to |
| --- | --- | --- | --- | --- |
| | | M? | | Vulnerability register (new O-row) / exception register / this plan / tests |
```

Action items feed the [vulnerability register](vulnerability-register.md): a new weakness gets an `O` row in "Unplanned weaknesses", with how it was found and the planned action; a fix is recorded with its verification, as for F01 to F07. An accepted risk goes in the exception register of the security policy, with an expiry. Changes to this plan go through a pull request.

## 9. Drills

Each drill follows the relevant playbook for real, with real evidence capture, and ends with a review. Nothing below has been run yet.

| Date | Scenario | Alert that fired | Time to detect | Time to contain | What went wrong | Status |
| --- | --- | --- | --- | --- | --- | --- |
| To be scheduled | P2 drill using the detection demo (`scripts/security/detection-demo.sh`, being built) | | | | | Planned, not done |
| To be scheduled | P1 drill: DV-A2 forged session (`run_all.py` with a random `DOCVAULT_LEAKED_KEY`, then a key rotation) | | | | | Planned, not done |

## 10. Known limits

- **No real production.** Every environment is a local test environment or a throwaway CI runner. The plan has never been tested against an outside attacker.
- **Application alerts use in-memory counters** in a single replica. A restart resets them, and a second replica would split the counts, so attacks spread over restarts or replicas may stay under the thresholds.
- **A valid forgery is silent.** DV-A2 sees only cookies with a bad signature. If the current key leaks, forged sessions look legitimate.
- **No central log storage, retention or paging.** Alerts are lines on stdout. They are lost when the pod or container is deleted, and nobody is woken up. Someone must be watching.
- **Falco runs only in the kind test cluster.** Compose and CI have no runtime detection. Our own `kubectl exec` commands also trigger DV-R1 and DV-R2, and the `prepare` init container starts a shell (`sh -c`) at each pod start, which DV-R1 must not count.
- **The audit log is incomplete and not tamper-proof.** It has no client address, no correlation ID (planned under T08), no record of views, previews or refused requests, and it lives in the same database the app account can write. A compromised app pod could edit it. The `/audit` page shows only the latest 200 entries.
- **No account controls.** There is no password change, reset, lockout or disable feature, and no way to end one user's session: rotating the key signs everyone out.
- **Login lock per username only (O2 fix).** It stops guessing against one account, not credential stuffing spread over many usernames, and anyone can lock a known account for 5 minutes.
- **No HTTPS locally.** Compose and kind run on plain HTTP with `SESSION_COOKIE_SECURE=false`, so cookies are not protected in transit there.
- **Network blocking is coarse.** There is no reverse proxy or firewall in front of the app. Blocking one address is not possible in the current setups, and in kind the app may not see real client addresses.
- **Network policies only add allowed traffic.** The quarantine policy in P2 is not in the manifests and needs the `allow-dns` patch to isolate a pod completely. Enforcement depends on the cluster's network plugin and is tested on kind only.
- **GitHub keeps copies after a purge.** Pull request references and cached views keep old commits until GitHub Support removes them. Anyone who cloned while the repository was public keeps the history. This is why every leaked secret is rotated first.
- **Dependabot alerts are off.** New advisories reach us only when Trivy runs. `--ignore-unfixed` hides critical issues with no fix, and the PostgreSQL image is not scanned.
- **One repository admin.** Only the owner account can change settings, disable Actions or lift branch protection. Pull requests need 0 approvals, so one member can merge alone once the checks pass.
- **Several commands are untested,** as marked. The drills are where they get confirmed or corrected.
