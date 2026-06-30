WireGuard Split Tunnel for macOS (Apple Silicon)
================================================

This private-use package contains:

- WireguardSplitTunnel.app
- Start WireGuard Split Tunnel.command
- check-mac-deps.sh
- README-Mac.txt

It does not contain any .conf files. WireGuard configs often contain private keys, so keep them separate and share them only with trusted devices.

Requirements
------------

1. Apple Silicon Mac.
2. Homebrew installed.
3. WireGuard tools and Homebrew Bash:

   brew install wireguard-tools bash

4. A real WireGuard config from your VPN provider or WireGuard server.

The release does not include a .conf file. WireGuard configs normally contain
private keys, so keep them private and share them only with trusted devices.

Configuration Setup
-------------------

Create the standard Homebrew WireGuard config directory, copy your config into
it, and protect the file permissions:

   sudo mkdir -p /opt/homebrew/etc/wireguard
   sudo cp "/path/to/your-vpn.conf" /opt/homebrew/etc/wireguard/
   sudo chmod 600 /opt/homebrew/etc/wireguard/*.conf

Replace /path/to/your-vpn.conf with the real path to your configuration.

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

Then open it from Terminal:

   open "Start WireGuard Split Tunnel.command"

You can also double-click Start WireGuard Split Tunnel.command in Finder. The
launcher removes the quarantine flag when possible, opens the app, and falls
back to the direct executable if Finder cannot open the app.

To open the app bundle directly:

   open WireguardSplitTunnel.app

If Finder still says that the application cannot be opened, launch the
executable directly from the extracted package folder:

   ./WireguardSplitTunnel.app/Contents/MacOS/WireguardSplitTunnel

Troubleshooting
---------------

App will not open:

1. Right-click the app and choose Open.
2. Remove the quarantine attribute with the xattr command above.
3. Use the direct executable command above to bypass Finder launching.

App opens but the tunnel will not enable:

1. Run ./check-mac-deps.sh again.
2. Confirm that a real .conf file exists in /opt/homebrew/etc/wireguard.
3. Check permissions with:

   ls -l /opt/homebrew/etc/wireguard/*.conf

4. The config file should be readable only by its owner (mode 600).

Using The App
-------------

1. Open the app with Start WireGuard Split Tunnel.command or WireguardSplitTunnel.app.
2. In Tunnel, choose a config from /opt/homebrew/etc/wireguard.
3. Click Start AI VPN and approve the macOS administrator prompt.
4. The app starts the tunnel, adds the AI Services Bundle, applies routes, and starts Monitor.
5. In Monitor, check VPN/Normal speed, latency, and route classification.

Manual controls are still available. You can click Enable Tunnel, add presets
in Domain Rules, and click Apply Routes yourself when you want to troubleshoot
one step at a time.

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
