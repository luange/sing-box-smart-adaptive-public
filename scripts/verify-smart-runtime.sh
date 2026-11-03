#!/usr/bin/env bash
# Read-only post-deploy gate. Requires a Clash API endpoint and its bearer
# token via environment, never writes configuration or changes selection.
set -euo pipefail

: "${CLASH_API_URL:?set CLASH_API_URL, e.g. http://10.20.20.4:9091}"
: "${CLASH_API_SECRET:?set CLASH_API_SECRET}"
groups=${SMART_GROUPS:-HK,US}
min_candidates=${SMART_MIN_CANDIDATES:-1}

auth="Authorization: Bearer $CLASH_API_SECRET"
proxies=$(mktemp)
trap 'rm -f "$proxies"' EXIT
curl --fail --silent --show-error --max-time 15 -H "$auth" "$CLASH_API_URL/proxies" -o "$proxies"

IFS=, read -r -a names <<< "$groups"
for name in "${names[@]}"; do
  count=$(jq --arg name "$name" '.proxies[$name].all | length' "$proxies")
  type=$(jq -r --arg name "$name" '.proxies[$name].type // empty' "$proxies")
  if [[ "$type" != Smart || "$count" -lt "$min_candidates" ]]; then
    echo "SMART_GATE=failed group=$name type=$type candidates=$count" >&2
    exit 1
  fi
  echo "SMART_GATE=ok group=$name candidates=$count selected=$(jq -r --arg name "$name" '.proxies[$name].now // empty' "$proxies")"
done
