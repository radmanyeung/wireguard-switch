WireGuard Split Tunnel for macOS (Apple Silicon)
================================================

This private-use package contains:

- WireguardSplitTunnel.app
- check-mac-deps.sh
- README-Mac.txt

It does not contain any .conf files. WireGuard configs often contain private keys, so keep them separate and share them only with trusted devices.

Requirements
------------

1. Apple Silicon Mac.
2. Homebrew installed.
3. WireGuard tools and Homebrew bash:

   brew install wireguard-tools bash

4. WireGuard config files placed at:

   /opt/homebrew/etc/wireguard/*.conf

5. Config permissions:

   chmod 600 /opt/homebrew/etc/wireguard/*.conf

Before Opening
--------------

From Terminal, you can check dependencies:

   cd <unzipped package folder>
   ./check-mac-deps.sh

Opening The App
---------------

Private builds are not Apple-notarized.

If macOS blocks the first launch:

1. Right-click WireguardSplitTunnel.app.
2. Choose Open.
3. Confirm Open again.

If the app is quarantined after downloading:

   xattr -dr com.apple.quarantine WireguardSplitTunnel.app

Using The App
-------------

1. Open WireguardSplitTunnel.app.
2. In Tunnel, click Pick...
3. Select a config from /opt/homebrew/etc/wireguard.
4. Click Enable Tunnel and approve the macOS administrator prompt.
5. Enabling a new config automatically disables previous active WireGuard tunnels.
6. In Domain Rules, add presets and click Apply Routes.
7. In Monitor, check VPN/Normal speed, latency, and route classification.

Mac Software Rules
------------------

This build includes Phase 1 Mac Software Rules:

1. Add one or more WireGuard profiles from /opt/homebrew/etc/wireguard/*.conf.
2. Pick a macOS .app bundle, such as ChatGPT.app, Claude.app, or Google Chrome.app.
3. Assign the app bundle identifier to a WireGuard profile.
4. Save and reopen the app to confirm the rules persist.

Important: true per-app routing on macOS requires a signed Apple Network Extension entitlement. Without an Apple Developer Network Extension build, Apply Mac Software Rules will show a clear blocked status and will not modify routes, pf rules, or system firewall state.

Notes
-----

- This package is osx-arm64 only.
- It is self-contained and does not require .NET SDK on the target Mac.
- Do not put .conf files into the app zip unless you fully trust every recipient.
