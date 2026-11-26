#!/bin/bash
# Isolated source-level tests only. Never modifies the normal core checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PIN=bca4bf029237e444104626bb25f947dda90b06b5
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q --no-checkout https://github.com/sagernet/sing-tun.git "$TMP/sing-tun"
git -C "$TMP/sing-tun" checkout -q --detach "$PIN"
test "$(git -C "$TMP/sing-tun" rev-parse HEAD)" = "$PIN"
git -C "$TMP/sing-tun" apply --check "$ROOT/native-tun-lifecycle.patch"
git -C "$TMP/sing-tun" apply "$ROOT/native-tun-lifecycle.patch"
cp "$ROOT"/root_tether*_linux*.go "$TMP/sing-tun/"
(cd "$TMP/sing-tun" && gofmt -w root_tether*_linux*.go && go test -race -count=1 -run '^TestNieFiggerRootTether' .)
