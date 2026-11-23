#!/usr/bin/env bash
# Purges the leaked F05 signing key from the Git history on GitHub.
# Step 2 of the revoke-then-purge procedure in docs/f05-revoke-then-purge.md.
# Run it only after the key has been revoked (step 1).
#
# Usage: scripts/security/purge-leaked-key.sh [--push]
#   Without --push (the default), it rewrites a fresh copy of the repository
#   in a temporary folder, checks it with Gitleaks and lists the branches and
#   tags that would be force-pushed. Nothing on GitHub changes.
#   With --push, it then force-pushes those branches and tags.
#
# The leaked value is read from the tag below at run time, so this script
# does not itself contain the secret.
set -euo pipefail

LEAKED_TAG="v0-vulnerable"
LEAKED_FILE="backend/app/config.py"
REPLACEMENT="REMOVED-F05-SIGNING-KEY"
FILTER_REPO="git-filter-repo==2.47.0"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
PROTECTED_BRANCH="main"

push=""
case "${1:-}" in
  "") ;;
  --push) push=1 ;;
  *) echo "Usage: $0 [--push]" >&2; exit 2 ;;
esac

REPO_ROOT="$(git rev-parse --show-toplevel)"
REMOTE_URL="$(git -C "$REPO_ROOT" remote get-url origin)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> Fresh copy of $REMOTE_URL (branches and tags only)"
# A bare clone holds every branch and tag as a local ref, and no pull
# request refs, which GitHub does not allow anyone to push.
git clone --quiet --bare "$REMOTE_URL" "$work/repo.git"
git -C "$work/repo.git" ls-remote --heads --tags "$REMOTE_URL" | sort -k2 > "$work/before.txt"

echo "==> Reading the leaked value from $LEAKED_TAG:$LEAKED_FILE"
leaked="$(git -C "$work/repo.git" show "$LEAKED_TAG:$LEAKED_FILE" \
  | sed -nE 's/^SECRET_KEY = "([^"]+)"$/\1/p')"
if [ -z "$leaked" ]; then
  echo "No hard-coded key in $LEAKED_TAG: it seems to be purged already." >&2
  exit 1
fi
# filter-repo's format: literal text, then ==>, then the replacement.
umask 077
printf '%s==>%s\n' "$leaked" "$REPLACEMENT" > "$work/replacements.txt"
unset leaked

echo "==> Rewriting history: every copy of the value becomes $REPLACEMENT"
# Only commits that $PROTECTED_BRANCH does not contain are rewritten. The key
# never reached it, and its GitHub merge commit is signed: rewriting would drop
# the signature, change its hash and leave the branches with no common history.
ranges=()
while read -r _ ref; do
  [[ "$ref" == *'^{}' || "$ref" == "refs/heads/$PROTECTED_BRANCH" ]] && continue
  ranges+=("refs/heads/$PROTECTED_BRANCH..$ref")
done < "$work/before.txt"
(cd "$work/repo.git" && uv tool run --quiet "$FILTER_REPO" --force \
  --replace-text "$work/replacements.txt" --refs "${ranges[@]}")
rm -f "$work/replacements.txt"

echo "==> Gitleaks on the rewritten history"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges -e HOME=/tmp -v "$work/repo.git:/repo:ro" \
  "$GITLEAKS_IMAGE" git --no-banner --redact --exit-code 1 /repo
echo "    no leaks in the rewritten history"

echo "==> Refs that change"
changed=()
while read -r old_sha ref; do
  # ls-remote also lists peeled tags (name^{}); the tag itself is enough.
  [[ "$ref" == *'^{}' ]] && continue
  # Compare raw values: for an annotated tag, both are the tag object.
  new_sha="$(git -C "$work/repo.git" rev-parse --verify --quiet "$ref" || true)"
  if [ "$new_sha" != "$old_sha" ]; then
    echo "    $ref ${old_sha:0:7} -> ${new_sha:0:7}"
    changed+=("$ref")
  fi
done < "$work/before.txt"

if [ "${#changed[@]}" -eq 0 ]; then
  echo "Nothing to push."
  exit 0
fi
for ref in "${changed[@]}"; do
  if [ "$ref" = "refs/heads/$PROTECTED_BRANCH" ]; then
    echo "Refusing: $PROTECTED_BRANCH would be rewritten. Stop and investigate." >&2
    exit 1
  fi
  # Each branch must still share history with the protected branch, or it
  # could no longer be merged into it.
  if [[ "$ref" == refs/heads/* ]] && ! git -C "$work/repo.git" merge-base --is-ancestor \
    "refs/heads/$PROTECTED_BRANCH" "$ref"; then
    echo "Refusing: $ref no longer contains $PROTECTED_BRANCH." >&2
    exit 1
  fi
done
echo "    every rewritten branch still contains $PROTECTED_BRANCH"

if [ -z "$push" ]; then
  echo "Dry run: nothing was pushed. Re-run with --push to force-push the refs above."
  exit 0
fi

echo "==> Force-pushing the rewritten refs"
for ref in "${changed[@]}"; do
  git -C "$work/repo.git" push --force "$REMOTE_URL" "$ref:$ref"
done
echo "Done. Follow the after-purge steps in docs/f05-revoke-then-purge.md."
