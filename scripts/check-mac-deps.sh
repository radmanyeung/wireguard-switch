#!/bin/zsh
set -u

failures=0

require_executable() {
  local path="$1"
  local label="$2"
  if [ -x "$path" ]; then
    echo "OK: $label ($path)"
  else
    echo "MISSING: $label ($path)"
    failures=$((failures + 1))
  fi
}

echo "WireGuard Split Tunnel macOS dependency check"
echo ""

require_executable "/opt/homebrew/bin/wg-quick" "WireGuard wg-quick"
require_executable "/opt/homebrew/bin/bash" "Homebrew bash 4+"

if [ -d "/opt/homebrew/etc/wireguard" ]; then
  echo "OK: config folder (/opt/homebrew/etc/wireguard)"
else
  echo "MISSING: config folder (/opt/homebrew/etc/wireguard)"
  failures=$((failures + 1))
fi

conf_count=$(find /opt/homebrew/etc/wireguard -maxdepth 1 -type f -name "*.conf" 2>/dev/null | wc -l | tr -d " ")
if [ "$conf_count" = "0" ]; then
  echo "WARNING: no .conf files found in /opt/homebrew/etc/wireguard"
else
  echo "OK: found $conf_count WireGuard config file(s)"
fi

echo ""
if [ "$failures" -gt 0 ]; then
  echo "Install missing tools with:"
  echo "  brew install wireguard-tools bash"
  echo ""
  echo "Then place WireGuard configs at:"
  echo "  /opt/homebrew/etc/wireguard/*.conf"
  exit 1
fi

echo "All required macOS dependencies are available."
