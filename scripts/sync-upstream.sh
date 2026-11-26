#!/bin/sh
set -eu

branch=${1:?usage: sync-upstream.sh main-or-develop}
case "$branch" in main|develop) ;; *) exit 2 ;; esac
upstream=https://github.com/ComodoSecurity/openedr.git
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
git fetch --no-tags "$upstream" "refs/heads/$branch:refs/remotes/upstream/$branch"
git switch --detach "refs/remotes/origin/$branch"
incoming="refs/remotes/upstream/$branch"
if git merge-base --is-ancestor "$incoming" HEAD; then
    printf '%s contains the current upstream commit.\n' "$branch"
    exit 0
fi
base=$(git merge-base HEAD "$incoming")
if [ "$branch" = main ]; then
    baseline=30b36f203afbe5106c61812832bcd302d16c38fb
else
    baseline=6426e53f3e02eda319d896eaecbfc21d3fdc3e99
fi
if ! git merge-base --is-ancestor "$baseline" "$incoming"; then
    printf 'Upstream history diverges from the imported baseline for %s.\n' "$branch" >&2
    exit 1
fi
if ! git diff --quiet "$base" "$incoming" -- .github AGENTS.md LICENSE.md NOTICE.md \
    .dockerignore all_os_openedr deploy integrations packaging scripts; then
    printf 'Upstream changed protected project paths on %s. Review the diff manually.\n' "$branch" >&2
    exit 1
fi
git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    merge --no-ff --no-edit "$incoming"
git diff --check "refs/remotes/origin/$branch" HEAD
git push origin "HEAD:refs/heads/$branch"
