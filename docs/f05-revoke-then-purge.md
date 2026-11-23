# F05: revoke, then purge

The signing key for session cookies was committed in `backend/app/config.py` (commit `3e82f9a`, tag `v0-vulnerable`). The repository has been public since 2026-11-22, so the key must be treated as known to anyone. This page is the procedure, and the record of when each step was done.

The order matters. Purging Git history does not remove copies that people already cloned, forked or cached. Only revoking the key makes those copies useless, so it comes first.

## Step 1: revoke the key

Done on branch `fix/f05-signing-key`, 2026-11-23.

- The key is no longer in the code. [`config.py`](../backend/app/config.py) reads it at runtime from `SECRET_KEY` or the file named by `SECRET_KEY_FILE`, and refuses to start with a missing key or one shorter than 32 characters.
- Each environment has its own key: `.env` for Docker Compose, the `docvault-secrets` Kubernetes secret (mounted only into the app container), and a random key per CI run.
- Every session signed with the old key is now invalid, so every user has to sign in again.

## Step 2: confirm the old key no longer works

[`run_all.py`](../scripts/exploits/run_all.py) reads the leaked key from Git history, as an attacker would, and forges an administrator session with it.

| Date | Target | Result |
| --- | --- | --- |
| 2026-11-23 | Docker Compose, new random key | Refused: HTTP 303 to the login page |
| 2026-11-23 | Hardened kind deployment, new random key | Refused: HTTP 303 to the login page |

After the purge, the old value is no longer in history. To repeat this test, set `DOCVAULT_LEAKED_KEY` to the old value from a private record.

## Step 3: purge the key from Git history

Not done yet. It rewrites shared branches, so it needs the team's agreement.

[`scripts/security/purge-leaked-key.sh`](../scripts/security/purge-leaked-key.sh) works on a fresh copy of the repository in a temporary folder:

1. It reads the leaked value from the tag, so the script itself does not contain it.
2. It replaces the value with `REMOVED-F05-SIGNING-KEY` in every commit that `main` does not contain. The key never reached `main`, and `main` must stay untouched: its GitHub merge commit is signed, and rewriting would drop the signature and break the shared history.
3. It runs Gitleaks on the rewritten history and stops if anything is found.
4. It lists the branches and tags that change, and checks that each branch still contains `main`.
5. Only with `--push`, it force-pushes them.

Before running it with `--push`:

- Every teammate pushes their work and stops pushing until the purge is done.
- `fix/f05-signing-key` is pushed, so it is rewritten too.
- Run it once without `--push` and check the list of refs.

The dry run on 2026-11-23 found no leak in the rewritten history. It would rewrite `vulnerable-baseline`, `secure`, `fix/f07-hardening`, `fix/f06-pyyaml` and the tag `v0-vulnerable`, and leave `main` unchanged.

## Step 4: verify

- The **Secret scan (Gitleaks)** check passes on the next CI run. It scans the working tree and the full history.
- `git log --all -S '<old value>'` finds nothing in a fresh clone.

## After the purge

- **Everyone re-clones.** An old clone still contains the key, and pushing from it would bring the key back.
- **GitHub keeps old commits** reachable through pull request references (#2, #3, #4) and cached pages. Only GitHub Support can remove these; see GitHub's guide [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository). This is why the key was revoked first.
- **Commit IDs change** on the rewritten branches. Logs saved earlier in `docs/evidence/` keep the old IDs as a historical record.
- **The merge commit of #3 loses its GitHub signature**, because it comes after the leak and has to be rewritten.
- **No forks** existed on 2026-11-23. Any copy made while the repository was public still contains the key, which no longer works.
