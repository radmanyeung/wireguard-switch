# LOGFILE

## 2026-04-02
- Added `Restore normal routing when app exits` option and exit-time route restore flow.
- Added `Software Self Test` button and checks (exe path, firewall rule match, routing compatibility).
- Added `Check Routing` button for quick default-route status check.
- Updated startup flow: `start.ps1` now prefers published `WireguardSplitTunnel.App.exe`, fallback to `dotnet run` only when needed.
- Updated installer: publish as `self-contained` single-file (`win-x64`) to avoid `.NET SDK command` errors on other PCs.
- Added software apply pre-check: when software default is `2 = Bypass WireGuard` but default route is not via WireGuard, app blocks apply and shows guidance (prevents app no-internet case like WhatsApp).

## 2026-04-01
- Initial project request captured: Build a Windows 11 tool to choose which traffic uses WireGuard.
- Scope decided: Website/domain-based routing (not app-based, not port-based for MVP).
- Product type decided: GUI desktop app.
- Default behavior decided: Unlisted websites bypass WireGuard.
- Design options evaluated; selected approach: DNS + Route Engine.
- Design spec created at `docs/superpowers/specs/2026-04-01-wireguard-domain-split-tunnel-design.md`.
- `README.md` and `LOGFILE.md` created.
- Implementation plan created at `docs/superpowers/plans/2026-04-01-wireguard-domain-split-tunnel-mvp-implementation-plan.md`.
- Task 1 completed: scaffolded solution/projects and added sandbox-safe build script.
- Task 2 completed: implemented `DomainValidator` + tests, including hyphen-label edge-case fix.
- Task 3 completed: implemented `RouteDiffEngine` and robust `StateStore` with reliability tests.
- Task 4 completed: added resolver/detector/route services, enabled-rule coordinator, and MVP UI shell wiring.
- Task 4 route quality fixes: interface-index routing, IPv4 resolver filtering, and scoped route deletes.
- Task evidence logs added under `docs/superpowers/logs/` for tasks 2-4.
- Task 5 completed: updated run instructions and implementation logs.
- Added global single-list policy model for both `domain` and `software`.
- Added mode support for both lists: mode 1 (Use WireGuard) / mode 2 (Bypass WireGuard).
- Added software subprocess option in policy list.
- Added temp save/load for both lists and global defaults (`temp-lists.json`).
- Added WireGuard config selector + auto-enable + enable button flow in GUI.
- Clarified behavior in docs: items not in list follow global default mode.
- Clarified MVP limitation: `Apply Now` currently processes domain mode 1 resolution/apply only; software list is currently policy storage/UI.
- Fixed test sandbox path issue in `StateStoreTests` by using workspace-local temp files.
- Verification: build success; unit tests passed (`33/33`).

## Log Template
Use this format for future entries:

### YYYY-MM-DD
- What changed
- Why it changed
- Any risks or follow-up items
