#!/usr/bin/env bash
# Validate the version used by package and release workflows.
# Keep product capabilities in build tags/metadata, never in the version.
set -euo pipefail

version="${1:-}"
if [[ -z "$version" ]]; then
  echo "version is required (expected MAJOR.MINOR.PATCH, optionally -alpha.N/-beta.N/-rc.N)" >&2
  exit 2
fi

if [[ "$version" == v* ]]; then
  echo "version must not include the v prefix: $version" >&2
  exit 2
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]; then
  echo "invalid version '$version'; use MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-(alpha|beta|rc).N" >&2
  exit 2
fi

printf 'validated version=%s\n' "$version"
