#!/usr/bin/env bash

set -e -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
export SING_BOX_BUILD_TAGS_FILE="$PROJECT_DIR/release/DEFAULT_BUILD_TAGS_LOCAL_SLIM"
source "$SCRIPT_DIR/common.sh"

setup_environment
BUILD_TAGS=$(get_build_tags)
build_sing_box "$BUILD_TAGS"
install_binary
setup_config
setup_systemd

echo "Slim installation complete (WireGuard/Tailscale, QUIC, uTLS, Clash API)."
echo "Build tags: $(cat "$SING_BOX_BUILD_TAGS_FILE")"
echo "To enable and start the service, run: $SCRIPT_DIR/enable.sh"
