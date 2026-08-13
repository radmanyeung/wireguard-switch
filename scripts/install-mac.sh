#!/usr/bin/env bash
# One-line install & update for the macOS Apple Silicon package.
#
#   curl -fsSL https://raw.githubusercontent.com/radmanyeung/wireguard-switch/main/scripts/install-mac.sh | bash
#
# Re-run the same command anytime to update to the latest Release.
set -euo pipefail

REPO="radmanyeung/wireguard-switch"
ASSET="wireguard-split-tunnel-mac-arm64.zip"
DEST="$HOME/Applications/wireguard-split-tunnel-mac-arm64"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This installer is for macOS only." >&2
  exit 1
fi
if [ "$(uname -m)" != "arm64" ]; then
  echo "This package is for Apple Silicon (arm64) Macs only." >&2
  exit 1
fi

echo "==> Resolving latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
URL="https://github.com/$REPO/releases/latest/download/$ASSET"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading ${TAG:-latest}..."
curl -fSL --retry 3 -o "$TMP/$ASSET" "$URL"

echo "==> Extracting..."
unzip -q -o "$TMP/$ASSET" -d "$TMP/extract"

SRC="$TMP/extract/wireguard-split-tunnel-mac-arm64"
[ -d "$SRC/WireguardSplitTunnel.app" ] || SRC="$TMP/extract"
if [ ! -d "$SRC/WireguardSplitTunnel.app" ]; then
  echo "Extracted package is missing WireguardSplitTunnel.app" >&2
  exit 1
fi

echo "==> Installing to $DEST ..."
mkdir -p "$HOME/Applications"
if [ -d "$DEST" ]; then
  rm -rf "${DEST}.old"
  mv "$DEST" "${DEST}.old"
fi
cp -R "$SRC" "$DEST"
rm -rf "${DEST}.old" 2>/dev/null || true

echo "==> Removing quarantine flag..."
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true

echo ""
echo "Installed ${TAG:-latest} to:"
echo "  $DEST"
echo ""

if ! command -v wg-quick >/dev/null 2>&1; then
  echo "Reminder: WireGuard tools not found. Install them with:"
  echo "  brew install wireguard-tools bash"
  echo ""
fi
if [ ! -d /opt/homebrew/etc/wireguard ]; then
  echo "Reminder: create the config directory and copy your .conf into it:"
  echo "  sudo mkdir -p /opt/homebrew/etc/wireguard"
  echo "  sudo cp /path/to/your-vpn.conf /opt/homebrew/etc/wireguard/"
  echo "  sudo chown \"\$USER\" /opt/homebrew/etc/wireguard/*.conf"
  echo "  sudo chmod 600 /opt/homebrew/etc/wireguard/*.conf"
  echo ""
fi

echo "Start the app with:"
echo "  open \"$DEST/WireguardSplitTunnel.app\""
