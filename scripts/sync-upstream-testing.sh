#!/usr/bin/env bash
# Safely preview or perform an upstream testing merge for the public Smart
# branch. It never rewrites the current checkout and leaves a concise
# conflict report when human policy is required.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/sync-upstream-testing.sh [--apply] [--upstream REMOTE/REF] [--branch BRANCH]

Creates a disposable worktree, fetches the upstream testing ref, performs a
three-way merge, then runs the Smart regression gate. Without --apply it only
reports whether the merge is clean. With --apply it fast-forwards the selected
local branch after all gates pass; it never pushes.
EOF
}

apply=0
upstream=upstream/testing
branch=$(git branch --show-current)
while (($#)); do
  case "$1" in
    --apply) apply=1 ;;
    --upstream) upstream=${2:?missing upstream ref}; shift ;;
    --branch) branch=${2:?missing branch}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

root=$(git rev-parse --show-toplevel)
git -C "$root" diff --quiet || { echo "refusing: working tree has changes" >&2; exit 2; }
git -C "$root" diff --cached --quiet || { echo "refusing: index has changes" >&2; exit 2; }
git -C "$root" fetch --quiet "${upstream%/*}" "${upstream#*/}" || true

base=$(git -C "$root" rev-parse "$branch")
target=$(git -C "$root" rev-parse "$upstream")
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sing-box-testing-merge.XXXXXX")
cleanup() { git -C "$root" worktree remove --force "$scratch" >/dev/null 2>&1 || true; }
trap cleanup EXIT
git -C "$root" worktree add --quiet --detach "$scratch" "$base"

if ! git -C "$scratch" merge --no-commit --no-ff "$target"; then
  echo "UPSTREAM_MERGE=conflict"
  echo "BASE=$base"
  echo "UPSTREAM=$target"
  echo "DECISIONS_REQUIRED:"
  git -C "$scratch" diff --name-only --diff-filter=U | sed 's/^/  - /'
  exit 1
fi

git -C "$scratch" diff --check
(cd "$scratch" && go test ./adapter/outbound ./protocol/group ./provider/... ./route ./experimental/clashapi)
merged=$(git -C "$scratch" write-tree)
echo "UPSTREAM_MERGE=clean"
echo "MERGED_TREE=$merged"
if ((apply)); then
  git -C "$scratch" commit -m "merge: sync upstream testing"
  commit=$(git -C "$scratch" rev-parse HEAD)
  git -C "$root" update-ref "refs/heads/$branch" "$commit" "$base"
  echo "APPLIED_COMMIT=$commit"
fi
