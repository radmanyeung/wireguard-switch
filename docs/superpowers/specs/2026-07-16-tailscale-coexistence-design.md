# Tailscale Coexistence for macOS AI Split Tunnel

Status: approved design scope (2026-07-16)

## Problem

The macOS app currently has generic `utun` fallback logic. When no readable
WireGuard mapping is available, it chooses the lowest-numbered active `utun`
interface that has IPv4. Tailscale creates exactly that kind of interface, so
startup, route application, status, or monitoring can mistake Tailscale for the
app-managed WireGuard tunnel.

This can send AI host routes to the wrong tunnel and can make the monitor switch
between interfaces. The user needs normal Tailscale connectivity and MagicDNS to
remain enabled while the AI domain split tunnel is running.

## Scope

### Goals

- Keep normal Tailscale connectivity and MagicDNS active while `Start AI VPN`
  runs the WireGuard split tunnel.
- Identify the app-owned WireGuard tunnel only through its configured tunnel
  name, `wgst-split`, and its `/var/run/wireguard` mapping.
- Use the same app-owned interface for route application, status, monitoring,
  disable, restore, and exit cleanup.
- Never stop, reconfigure, or clean up a Tailscale interface.
- Fail clearly instead of falling back to an unrelated `utun` interface.

### Non-goals

- Tailscale Exit Node coexistence. Exit Node must remain off because it owns the
  default route and creates a VPN-over-VPN path with additional MTU, endpoint
  route, and DNS concerns.
- Reusing an official WireGuard app Network Extension tunnel.
- True per-application macOS routing through a Network Extension entitlement.
- Changing the WireGuard `.conf` format.

## Considered Approaches

### 1. Pin to the named `wgst-split` mapping (selected)

Resolve the interface through `/var/run/wireguard/wgst-split.name` and confirm
that the mapped interface is active. The existing unambiguous-socket fallback
may still handle an unreadable name file. If ownership cannot be proven, wait
for the mapping or fail.

This is deterministic, matches how `wg-quick` records tunnel ownership, and
does not depend on interface numbering or IP ranges.

### 2. Compare `utun` interfaces before and after startup

Record all interfaces before starting WireGuard and choose the newly created
one. This is vulnerable to simultaneous interface changes and reconnects, and
it loses ownership information after an app restart.

### 3. Exclude Tailscale address ranges

Reject interfaces using Tailscale's current CGNAT range. This is a heuristic
that couples the app to another product's addressing behavior and does not
prove that the remaining interface belongs to `wgst-split`.

## Design

### Managed tunnel resolution

Add a small `MacManagedTunnelInterfaceResolver` in the Core services layer. It
will delegate named lookups to `MacTunnelNameResolver` and expose one consistent
decision:

1. Resolve `wgst-split` by name.
2. If no split tunnel exists and `ActiveRawTunnelName` is explicitly persisted,
   resolve that exact raw tunnel name.
3. Otherwise return no managed interface.

The resolver must not enumerate arbitrary `utun` devices and must not call the
generic fallback detector. An internal lookup-injection overload will keep the
selection policy independently testable without requiring live macOS tunnels.

### Start AI VPN flow

1. Keep the current default-route guard. Normal Tailscale with Exit Node off
   leaves the default route on Wi-Fi/Ethernet and is allowed. A default route on
   any `utun`, including a Tailscale Exit Node, remains blocked.
2. Generate and start the `wgst-split` configuration as today.
3. Poll specifically for the `wgst-split` mapping for the existing bounded wait
   period.
4. If the mapping appears, store that interface as the active managed interface,
   apply AI domain routes to it, and start monitoring.
5. If the mapping does not appear, report a named-tunnel detection error and do
   not apply routes to any other `utun`.

### Status, routes, and monitoring

All Mac UI paths that currently call the generic detector for managed behavior
will use the managed resolver instead:

- `WaitForWireGuardInterfaceAsync`
- manual Apply Routes
- tunnel status refresh
- each monitor refresh
- disable/restore target selection where applicable

The monitor may re-resolve the named mapping to detect a tunnel restart, but it
must never select Tailscale as a fallback. If the managed tunnel disappears, the
monitor reports WireGuard as unavailable and leaves Tailscale untouched.

The existing generic `SystemWireguardDetector` can remain for other platforms or
non-managed discovery, but the Mac app's managed route and monitor flows will no
longer depend on its arbitrary `utun` fallback.

### Cleanup

Cleanup continues to target only:

- the generated `wgst-split.conf`, when its named mapping is active;
- an explicitly persisted `ActiveRawTunnelName`; and
- host routes recorded in `ManagedRouteSnapshot`.

Tailscale's interface, service, routes, and MagicDNS settings are never cleanup
targets. Closing the app must leave Tailscale connected.

### User-visible behavior

- Status shows connected only when an app-managed named tunnel is active.
- Tailscale by itself no longer makes the app display `connected via utun...`.
- If only Tailscale is connected, Apply Routes reports that the app-managed
  WireGuard tunnel is not running.
- If Tailscale Exit Node owns the default route, `Start AI VPN` explains that
  Exit Node must be disabled before starting the split tunnel.
- No additional setup is required for ordinary Tailscale or MagicDNS.

## Error Handling

- Missing `wgst-split` mapping after startup: fail before route application and
  show the expected tunnel name in the message.
- Managed tunnel disappears while monitoring: show WireGuard unavailable; do
  not switch to another `utun`.
- Exit Node detected through a `utun` default route: block quick start without
  modifying Tailscale.
- Cleanup failure: keep the existing friendly error and recovery behavior, but
  never broaden cleanup to generic interfaces.

No diagnostic output may include WireGuard private keys or complete config
contents.

## Testing

### Unit tests

- A named split mapping to `utun5` resolves to `utun5` even when the generic
  detector could also offer a Tailscale-like `utun4`.
- Tailscale-like `utun4` without a `wgst-split` mapping resolves to no managed
  WireGuard interface.
- An explicitly persisted raw tunnel resolves only by its exact tunnel name.
- The split tunnel takes precedence over a persisted raw tunnel.
- Existing quick-start tests continue to allow a normal network default route
  and block a `utun` default route.
- Cleanup planning contains only named WireGuard tunnels and managed host routes.

### Verification

- Run `dotnet test WireguardSplitTunnel.sln --no-restore`.
- With Tailscale connected and Exit Node off, verify the system default route
  remains on Wi-Fi/Ethernet before and after `Start AI VPN`.
- Verify an AI destination route uses the `wgst-split` interface.
- Verify a non-AI destination continues to use Wi-Fi/Ethernet.
- Verify the Monitor displays the `wgst-split` interface rather than Tailscale.
- Close the app and verify Tailscale remains connected and MagicDNS still works.

## Documentation

Update both `README.md` and `docs/README-Mac.txt` with the same coexistence rule:
ordinary Tailscale and MagicDNS are supported, while Tailscale Exit Node must be
off when starting the AI split tunnel.

## Success Criteria

- Tailscale remains connected throughout app startup, route application,
  monitoring, and app shutdown.
- `Start AI VPN` never applies AI routes to the Tailscale interface.
- The monitor never reports Tailscale traffic as WireGuard traffic.
- Ordinary traffic continues through the normal network while configured AI
  domain IPs use `wgst-split`.
- Existing non-Tailscale macOS startup and cleanup behavior remains covered by
  the full test suite.
