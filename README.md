# WireGuard Domain + Software Split Tunnel (Windows 11)

Windows GUI tool to manage split tunnel for domain rules + software rules with WireGuard.

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

## If someone downloads from GitHub
- If they download the repository source (`Code` -> `Download ZIP`), they should extract it first, then run `install.cmd`.
- After install finishes, start the app with `start.cmd`.
- On first launch, select a WireGuard `.conf` or `.conf.dpapi` file, then click `Enable Now`.
- If the target PC already has a published `WireguardSplitTunnel\WireguardSplitTunnel.App.exe`, install will use it.
- If no local EXE is present, install/start will try to fetch the latest GitHub Release prebuilt automatically.
- If no Release prebuilt is available, the target PC may need internet access plus `.NET 8 SDK` so the installer can publish locally.

## If someone downloads from Releases
- Download the latest `wireguard-split-tunnel-win-x64.zip` from GitHub Releases.
- Extract the ZIP first.
- Run `install.cmd` from the extracted folder.
- After install finishes, run `start.cmd`.
- The Release ZIP includes the published app, helper scripts, and installer/startup wrappers.

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
- Default source: `radmanyeung/wireguard-switch` latest release.
- Installer/startup auto-downloads `.zip` or `.exe` prebuilt when local EXE is missing.
- Recommended asset name includes `wireguard` + (`split`/`tunnel`/`switch`).

Environment overrides:
- `WGST_RELEASE_REPO`: override GitHub repo (format `owner/repo`).
- `WGST_RELEASE_ASSET_URL`: direct URL to prebuilt `.zip` or `.exe` asset (takes priority).

## Release automation (update prebuilt)
Push a tag like `v0.1.1`; GitHub Actions will auto-build and publish release asset `wireguard-split-tunnel-win-x64.zip`.

Recommended when sharing with other people:
- Create a new tag after user-facing fixes, so GitHub Releases contains the latest prebuilt.
- Tell users to download the latest Release asset when you want the simplest install path (`extract -> install.cmd`).

Commands:
```powershell
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
```

Links:
- Releases: https://github.com/radmanyeung/wireguard-switch/releases
- Actions: https://github.com/radmanyeung/wireguard-switch/actions
