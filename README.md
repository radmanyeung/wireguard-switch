# WireGuard Domain + Software Split Tunnel (Windows 11)

Windows GUI tool to manage split tunnel for domain rules + software rules with WireGuard.

An Apple Silicon macOS release is also available for tunnel control, domain
routes, and network monitoring.

## One-click install (new PC)
1. Copy this whole folder to the target Windows PC.
2. Double-click `install.cmd`.
3. Approve UAC when prompted.

`install.cmd` forwards parameters to `scripts\install.ps1`.

Installer bootstrap does:
- auto-elevate to Administrator
- check/install missing `WireGuard`
- if no local EXE and no SDK: auto-download latest prebuilt from GitHub Releases
- check/install missing `.NET 8 SDK` only when prebuilt is unavailable and publish is needed
- prefer `winget`; fallback to official direct installer download
- publish app to `.\WireguardSplitTunnel\` (unless skipped)
- create desktop shortcuts (unless skipped)
- launch post-install self test (unless skipped)

## New-machine install checklist (Windows)

Lessons from real fresh-machine installs:

1. Install **WireGuard for Windows** first (https://www.wireguard.com/install/).
   The installer refuses to continue without it.
2. Download `wireguard-split-tunnel-win-x64.zip` from GitHub **Releases**
   (not the source-code ZIP from the `Code` button).
3. Extract the ZIP into a **brand-new empty folder**. Never extract over an
   existing folder and never add files into it afterwards: the installer is
   fail-closed and rejects any file that is not declared in the release
   manifest (`Release package contains an undeclared payload: ...`).
4. Double-click `install.cmd` and approve the UAC prompt. Since v0.2.3 the
   window stays open on failure so you can read the error; details are also
   in `%LOCALAPPDATA%\WireguardSplitTunnel\logs\`.
5. After a successful install, start the app from the **desktop shortcut**
   (or `C:\Program Files\WireguardSplitTunnel\start.cmd`). The `start.cmd`
   in the extracted folder is not an entry point and always refuses.
6. Put your `.conf` files in
   `C:\Program Files\WireGuard\Data\Configurations\` (or pick any file with
   the app's **Browse** button), then click **Refresh Configs** in the app.
   Configs whose `AllowedIPs` would trigger the WireGuard kill switch are
   sanitized automatically; the original file is never modified.

## If someone downloads from GitHub
- If they download the repository source (`Code` -> `Download ZIP`), they should extract it first, then run `install.cmd`.
- After install finishes, start the app from the desktop shortcut (or `start.cmd` inside the installed copy at `C:\Program Files\WireguardSplitTunnel`). The `start.cmd` in the downloaded/extracted folder is not a launch entry point and will refuse to start by design.
- On first launch, select a WireGuard `.conf` or `.conf.dpapi` file, then click `Enable Now`.
- If the target PC already has a published `WireguardSplitTunnel\WireguardSplitTunnel.App.exe`, install will use it.
- If no local EXE is present, install/start will try to fetch the latest GitHub Release prebuilt automatically.
- If no Release prebuilt is available, the target PC may need internet access plus `.NET 8 SDK` so the installer can publish locally.

## If someone downloads from Releases
- Download the latest `wireguard-split-tunnel-win-x64.zip` from GitHub Releases.
- Extract the ZIP first.
- Run `install.cmd` from the extracted folder.
- After install finishes, start the app from the desktop shortcut (or `start.cmd` inside `C:\Program Files\WireguardSplitTunnel`), not from the extracted folder.
- The Release ZIP includes the published app, helper scripts, and installer/startup wrappers.
- Installer will automatically try to remove the Windows download block (`Unblock-File`) from the extracted release files.

## Windows automatic updates (v0.2.0 and later)

Version `0.2.0` is the first updater-capable Release. An existing `v0.1.9` or
older installation cannot bootstrap this feature by itself: download the
verified `v0.2.0` Windows Release, extract it to a fresh folder, and run
`install.cmd` once. Later stable Releases can then update automatically.

Automatic updates are enabled by default. The Windows app checks GitHub stable
Releases at most once every 24 hours, downloads and validates an available
update in the background, and shows its current status. Use the **Automatically
update from GitHub Releases** preference to control scheduled checks or **Check
now** to run one check immediately. A manual check still works while scheduled
checks are disabled. Typical statuses include checking, downloading, ready to
install, up to date, an error, or `RecoveryBlocked`.

A ready update is installed only after an eligible, elevated, normal app close.
A crash, forced termination, Windows session ending, reboot, or a non-elevated
run does not authorize installation. The app restores its routes and saves its
state first, then starts the protected updater. It deliberately does not reopen
itself after a close-time update; start it normally next time, when the new
version performs its health check and either commits or rolls back safely.

Updater diagnostics are written to:

```text
%LOCALAPPDATA%\WireguardSplitTunnel\logs\updater.log
```

If startup reports `RecoveryBlocked`, do not delete the protected transaction
or replace files by hand. Download a freshly extracted, verified Windows
Release and explicitly run:

```bat
install.cmd -RepairBlockedUpdate
```

The repair validates the bundled Release, clears only the active pointer, and
keeps the blocked transaction evidence for diagnosis. During an online update,
the current GitHub Release API response supplies the trusted asset digest; the
downloaded ZIP and fixed-name `.sha256` sidecar must both match it. This detects
corruption and mixed-up downloads, but is not independent publisher signing.
Authenticode signing remains a future hardening option.

The macOS package has no automatic updater. Download and install each macOS
Release manually.

## macOS Apple Silicon release

Download `wireguard-split-tunnel-mac-arm64.zip` from GitHub Releases and extract
it first. The package is for Apple Silicon Macs and is self-contained, so the
.NET SDK is not required.

The release does not include a WireGuard `.conf` file. Configurations normally
contain private keys, so download or export a real configuration from your VPN
provider or WireGuard server and keep it private.

Install the required command-line tools, create the configuration directory,
and copy your configuration into it:

```bash
brew install wireguard-tools bash
sudo mkdir -p /opt/homebrew/etc/wireguard
sudo cp "/path/to/your-vpn.conf" /opt/homebrew/etc/wireguard/
sudo chown "$USER" /opt/homebrew/etc/wireguard/*.conf
sudo chmod 600 /opt/homebrew/etc/wireguard/*.conf
```

The config must be owned by your user account (not root) so the app can read
it to build its split-tunnel variant; mode 600 keeps it private.

Replace `/path/to/your-vpn.conf` with the real path to your configuration. Then
check the dependencies from the extracted release folder:

```bash
cd "$HOME/Downloads/wireguard-split-tunnel-mac-arm64"
./check-mac-deps.sh
```

When the check reports that all dependencies are available, open the app:

```bash
open "Start WireGuard Split Tunnel.command"
```

You can also double-click `Start WireGuard Split Tunnel.command` in Finder. The
launcher removes the macOS quarantine flag when possible, opens
`WireguardSplitTunnel.app`, and falls back to the direct executable if Finder
cannot open the app.

On first launch, macOS may block this private, non-notarized build. Right-click
`WireguardSplitTunnel.app`, choose **Open**, and confirm **Open** again. If the
app is still quarantined, run:

```bash
xattr -dr com.apple.quarantine WireguardSplitTunnel.app
open WireguardSplitTunnel.app
```

If Finder still says the application cannot be opened, launch its executable
directly from Terminal:

```bash
"$HOME/Downloads/wireguard-split-tunnel-mac-arm64/WireguardSplitTunnel.app/Contents/MacOS/WireguardSplitTunnel"
```

Inside the app, the easiest path is now:

1. Disconnect the official WireGuard app if it is connected. Ordinary Tailscale
   and MagicDNS can stay connected, but Tailscale **Exit Node must be off**.
   Start AI VPN refuses to run while an Exit Node or another full-tunnel VPN
   owns the default route.
2. Choose a config from `/opt/homebrew/etc/wireguard`.
3. Click **Start AI VPN** and approve the macOS administrator prompt.

Start AI VPN creates a split tunnel: only the AI Services Bundle domains go
through WireGuard; all other traffic and system DNS stay on your normal
network. The tunnel runs under the name `wgst-split` (a derived copy of your
config with `Table = off`); your original config file is never modified.

When Tailscale is connected without an Exit Node, the app keeps Tailscale and
MagicDNS unchanged. Status, AI routes, Monitor, and cleanup are pinned to the
named `wgst-split` tunnel and never fall back to Tailscale's `utun` interface.

If the app opens but the tunnel will not enable, this is a tunnel-setup issue,
not an app-launch issue. Run `./check-mac-deps.sh` again, confirm that a real
`.conf` file exists in `/opt/homebrew/etc/wireguard`, and verify its permissions
with `ls -l /opt/homebrew/etc/wireguard/*.conf`.

## Optional installer switches
- `install.cmd -NoPostInstallSelfTest`
- `install.cmd -SkipPublish`
- `install.cmd -NoDesktopShortcut`

Examples:
```bat
install.cmd -NoPostInstallSelfTest
install.cmd -SkipPublish -NoDesktopShortcut
```

## Start / test
- Start app: double-click `start.cmd` (or `start-admin.cmd`)
- When UAC prompt appears, click **Yes**
- Run tests: double-click `test.cmd`
- If startup, install, testing, or diagnostics closes immediately, check
  `%LOCALAPPDATA%\WireguardSplitTunnel\logs\` for:
  - `install.cmd.log`
  - `install.ps1.log`
  - `start.cmd.log`
  - `start-admin.cmd.log`
  - `start-safe.cmd.log`
  - `start.ps1.log`
  - `test.cmd.log`
  - `diagnose.cmd.log`
- You can also run `diagnose.cmd` to capture current app / WireGuard / route status into a log file.

## Routing behavior (current)
- GUI uses one unified global mode for both Domain + Software.
- Mode `1 = Use WireGuard`:
  - traffic defaults to WireGuard.
- Mode `2 = Bypass WireGuard` (OR mode):
  - software in enabled software list (including subprocess) uses WireGuard.
  - non-software-list traffic: only domain-list traffic uses WireGuard.
  - other traffic uses normal network.
  - app maintains both `WG /1` and `Bypass /1` routes (dual `/1`) for stability.

## Self-test outputs
- `Software Self Test` includes:
  - enabled rule count
  - executable path status
  - firewall rule key match (`WGST-Software-*`)
  - effective Mode 2 profile
  - `WG /1 present` and `Bypass /1 present`
  - routing status `PASS/WARNING/FAIL`

## Developer run (optional)
```powershell
pwsh -File .\scripts\build.ps1
pwsh -File .\scripts\start.ps1
pwsh -File .\scripts\test.ps1
```

## GitHub Releases prebuilt
- Fixed source: stable Releases from `radmanyeung/wireguard-switch`.
- Bootstrap requires the exact Windows archive
  `wireguard-split-tunnel-win-x64.zip` and its exact `.sha256` sidecar.
- Repository and direct-asset environment overrides are intentionally not
  accepted by the secure bootstrap, updater, or blocked-recovery flow.

## Release automation (update prebuilt)
A maintainer may manually push a tag that exactly matches the
`VersionPrefix` in `Directory.Build.props`. GitHub Actions tests and validates
both platform packages, then one final job publishes the Release assets.
Creating or pushing a tag is never performed by the app's automatic updater and
remains an explicit maintainer action.

Recommended when sharing with other people:
- Create a new tag after user-facing fixes, so GitHub Releases contains the latest prebuilt.
- Tell users to download the latest Release asset when you want the simplest install path (`extract -> install.cmd`).

Example maintainer commands (replace the version deliberately):
```powershell
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

Links:
- Releases: https://github.com/radmanyeung/wireguard-switch/releases
- Actions: https://github.com/radmanyeung/wireguard-switch/actions
