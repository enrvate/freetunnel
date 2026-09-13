#!/usr/bin/env bash
# Verify every patch in vendor/trusttunnel/ applies to the pinned upstream ref,
# in filename order — they build on each other, see setup-upstream-tree.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="$(tr -d '[:space:]' < "$ROOT/scripts/upstream_ref.txt")"
PATCHES=("$ROOT"/vendor/trusttunnel/*.patch)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --filter=blob:none --no-checkout \
  https://github.com/TrustTunnel/TrustTunnelClient.git "$TMP/upstream"
git -C "$TMP/upstream" fetch --depth 1 origin "$REF"
git -C "$TMP/upstream" checkout FETCH_HEAD

for p in "${PATCHES[@]}"; do
  echo "==> $(basename "$p")"
  patch -p1 -d "$TMP/upstream" < "$p"
done

# A patch that applies but lands the wrong thing is still broken, so assert the
# symbol each one exists for. grep -q on the file the patch claims to change.
grep -q 'tunnel_stats_handler' \
  "$TMP/upstream/trusttunnel/include/vpn/trusttunnel/client.h"
grep -q 'm_callbacks.tunnel_stats_handler' \
  "$TMP/upstream/trusttunnel/src/client.cpp"
grep -q 'connect_request_handler' \
  "$TMP/upstream/trusttunnel/include/vpn/trusttunnel/client.h"
grep -q 'ft_fill_connect_snapshot' \
  "$TMP/upstream/trusttunnel/src/client.cpp"

echo "upstream patches verified for ${REF} (${#PATCHES[@]} applied)"
