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

Commands:
```powershell
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1
```

Links:
- Releases: https://github.com/radmanyeung/wireguard-switch/releases
- Actions: https://github.com/radmanyeung/wireguard-switch/actions
