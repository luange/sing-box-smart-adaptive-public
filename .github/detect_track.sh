#!/usr/bin/env bash
set -euo pipefail

branches=$(git branch -r --contains HEAD)
track=""
if echo "$branches" | grep -q 'origin/stable'; then
  track=stable
elif echo "$branches" | grep -q 'origin/testing'; then
  track=testing
elif echo "$branches" | grep -q 'origin/oldstable'; then
  track=oldstable
fi

# The adaptive fork may run package jobs from its development branch or a
# SemVer prerelease tag. They are beta-track artifacts, not upstream stable
# packages. Capabilities belong to build tags, never to the version string.
if [[ -z "$track" ]]; then
  ref="${GITHUB_REF_NAME:-}"
  if [[ "$ref" == adaptive/* || "$ref" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]; then
    track=beta
  fi
fi

if [[ -z "$track" ]]; then
  echo "ERROR: HEAD is not on any known release branch (stable/testing/oldstable)" >&2
  exit 1
fi

if [[ "$track" == "stable" ]]; then
  tag=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
  if [[ -n "$tag" && "$tag" == *"-"* ]]; then
    track=beta
  fi
fi

case "$track" in
  stable)    name=sing-box;           docker_tag=latest ;;
  beta)      name=sing-box-beta;      docker_tag=latest-beta ;;
  testing)   name=sing-box-testing;   docker_tag=latest-testing ;;
  oldstable) name=sing-box-oldstable; docker_tag=latest-oldstable ;;
esac

echo "track=${track} name=${name} docker_tag=${docker_tag}" >&2
echo "TRACK=${track}" >> "$GITHUB_ENV"
echo "NAME=${name}" >> "$GITHUB_ENV"
echo "DOCKER_TAG=${docker_tag}" >> "$GITHUB_ENV"
