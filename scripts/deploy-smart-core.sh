#!/usr/bin/env bash
# Atomic sing-box deployment with target-side verification and rollback.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/deploy-smart-core.sh --artifact FILE --revision REV --target HOST,API_URL [--target ...]

Options: --binary PATH --config PATH --service NAME --groups HK,US
         --min-candidates N --listener-ports 8888,9091 --dry-run

Each target is deployed in order. The previous binary is retained only while
the replacement is being verified, restored on failure, and deleted on success.
The Clash token is read on the target from its runtime config and never printed.
EOF
}

artifact= revision= binary=/root/singbox/sing-box config=/run/singbox/config.runtime.json
service=singbox groups=HK,US min_candidates=1 ports=8888,9091 dry_run=0
declare -a targets=()
while (($#)); do
  case "$1" in
    --artifact) artifact=${2:?}; shift ;;
    --revision) revision=${2:?}; shift ;;
    --target) targets+=("${2:?}"); shift ;;
    --binary) binary=${2:?}; shift ;;
    --config) config=${2:?}; shift ;;
    --service) service=${2:?}; shift ;;
    --groups) groups=${2:?}; shift ;;
    --min-candidates) min_candidates=${2:?}; shift ;;
    --listener-ports) ports=${2:?}; shift ;;
    --dry-run) dry_run=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ -x "$artifact" && -n "$revision" && ${#targets[@]} -gt 0 ]] || { usage >&2; exit 2; }
[[ "$revision" =~ ^[A-Za-z0-9._-]+$ && "$min_candidates" =~ ^[1-9][0-9]*$ ]] || { echo "invalid revision or count" >&2; exit 2; }
[[ "$binary" =~ ^/[A-Za-z0-9_./-]+$ && "$config" =~ ^/[A-Za-z0-9_./-]+$ && "$service" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "unsafe path or service" >&2; exit 2; }
[[ "$groups" =~ ^[A-Za-z0-9_-]+(,[A-Za-z0-9_-]+)*$ && "$ports" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "unsafe groups or ports" >&2; exit 2; }

sha=$(sha256sum "$artifact" | awk '{print $1}')
echo "ARTIFACT_SHA256=$sha"
if ((dry_run)); then printf 'PLAN %s\n' "${targets[@]}"; exit 0; fi

deploy_one() {
  local spec=$1 host api stage
  host=${spec%%,*}; api=
  [[ "$spec" == *,* ]] && api=${spec#*,}
  [[ "$host" =~ ^[A-Za-z0-9_.@:-]+$ && "$api" =~ ^[A-Za-z0-9:/._-]*$ ]] || { echo "unsafe target" >&2; return 2; }
  stage="${binary%/*}/.sing-box.stage-${revision}-$$"
  echo "DEPLOY_START target=$host"
  scp -q "$artifact" "$host:$stage"
  ssh "$host" /bin/sh -s -- "$stage" "$binary" "$config" "$service" "$sha" "$api" "$groups" "$min_candidates" "$ports" "$revision" <<'REMOTE'
set -eu
stage=$1; binary=$2; config=$3; service=$4; expected_sha=$5; api=$6; groups=$7; minimum=$8; ports=$9; revision=${10}
dir=${binary%/*}; backup="$dir/.sing-box.rollback-${revision}-$$"; committed=0; step=preflight
rollback() {
  status=$?
  if [ "$committed" = 1 ] && [ -f "$backup" ]; then
    rc-service "$service" stop >/dev/null 2>&1 || true
    rm -f "$binary"; mv "$backup" "$binary"; chmod 0755 "$binary"
    rc-service "$service" start >/dev/null 2>&1 || true
    echo "DEPLOY_ROLLBACK=done step=$step status=$status" >&2
  fi
  rm -f "$stage"
  exit "$status"
}
trap rollback HUP INT TERM EXIT
step=artifact_sha; test "$(sha256sum "$stage" | awk '{print $1}')" = "$expected_sha"
chmod 0755 "$stage"
# The caller may be macOS while the artifact is Linux; validate revision on
# the target instead of attempting to execute the cross-platform artifact
# locally.
step=artifact_revision; "$stage" version | grep -F "Revision: $revision" >/dev/null
step=config_check; timeout 90 "$stage" check -c "$config"
step=stop_service; rc-service "$service" stop
step=swap_binary; mv "$binary" "$backup"; committed=1
mv "$stage" "$binary"; step=start_service; rc-service "$service" start; step=warmup; sleep 12
step=live_sha; test "$(sha256sum "$binary" | awk '{print $1}')" = "$expected_sha"
step=service_status; rc-service "$service" status >/dev/null
step=listeners; IFS=,; for port in $ports; do ss -ltn | grep -Eq ":${port}[[:space:]]"; done; unset IFS
if [ -n "$api" ]; then
  step=api_secret; secret=$(jq -r '.experimental.clash_api.secret // empty' "$config")
  step=api_request; response=$(mktemp)
  if [ -n "$secret" ]; then
    curl --fail --silent --show-error --max-time 15 -H "Authorization: Bearer $secret" "$api/proxies" -o "$response"
  else
    curl --fail --silent --show-error --max-time 15 "$api/proxies" -o "$response"
  fi
  step=smart_groups
  IFS=,; for group in $groups; do
    group_type=$(jq -r --arg name "$group" '.proxies[$name].type // empty' "$response")
    candidate_count=$(jq -r --arg name "$group" '(.proxies[$name].all // []) | length' "$response")
    if [ "$group_type" != Smart ] || [ "$candidate_count" -lt "$minimum" ]; then
      # Safe deployment evidence: group name, reported kind, and candidate
      # count only. Never print the response because it can contain node
      # metadata from the Clash API.
      echo "SMART_GROUP_INVALID group=$group type=${group_type:-missing} candidates=$candidate_count minimum=$minimum" >&2
      false
    fi
  done; unset IFS; rm -f "$response"
fi
rm -f "$backup" "$stage"
find "$dir" -maxdepth 1 -type f \( -name '.sing-box.stage-*' -o -name '.sing-box.rollback-*' \) -delete
committed=0; trap - HUP INT TERM EXIT
echo "DEPLOY_OK revision=$revision sha256=$expected_sha"
REMOTE
  echo "DEPLOY_OK target=$host"
}

for target in "${targets[@]}"; do deploy_one "$target"; done
