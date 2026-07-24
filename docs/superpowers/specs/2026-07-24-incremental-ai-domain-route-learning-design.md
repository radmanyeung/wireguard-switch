# Incremental AI Domain Route Learning Design

Date: 2026-07-24
Status: Approved in chat

## Objective

Prevent newly observed Claude and ChatGPT wildcard subdomains from bypassing
WireGuard after the application's startup renew, including clients running in
WSL mirrored networking.

## Confirmed failure

The current full renew resolves wildcard rules by stripping `*.` and resolving
only the root domain. Actual subdomains are learned from the Windows DNS cache,
but that cache is read only during startup or a manually triggered full renew.

For example, Claude Code resolved `downloads.claude.ai` to `35.190.46.17` after
the startup renew. The address appeared in the Windows DNS cache but not in the
managed route snapshot, so Windows had no WireGuard `/32` route and WSL selected
its LAN interface.

## Considered approaches

### Selected: periodic incremental DNS-cache learning

Every 10 seconds, read the Windows DNS cache and match IPv4 A records against
enabled wildcard rules whose mode is `UseWireGuard`. Add only IPs that are not
already in the managed route snapshot.

This closes the timing gap without repeatedly rebuilding default routes or
removing last-known-good host routes.

### Rejected: run the complete renew every 10 seconds

A full renew performs direct DNS resolution, reapplies all managed routes,
reconciles default routing, and removes stale snapshot addresses. Repeating
those side effects every few seconds is unnecessarily disruptive.

### Rejected: refresh only after a network-change event

Network-change events do not fire when an already-running application first
uses a new hostname, so this does not cover the observed Claude Code failure.

## Architecture

### Incremental planner

Add a pure Core planner that receives the current `AppState` and learned
`ResolvedRule` values. It:

- accepts only domains that still correspond to enabled wildcard
  `UseWireGuard` rules;
- retains every existing managed snapshot entry;
- returns only newly observed IPv4 addresses in `ToAdd`;
- never produces a removal list;
- is idempotent when the same DNS cache values are processed again.

### Incremental state merge

Extend `ResolutionStateUpdater` with an incremental merge operation. It merges
new learned details into the touched domains without removing or overwriting
unrelated last-known data. Direct resolution provenance wins over learned
provenance for duplicate IPs. The operation reports whether persisted state
actually changed so repeated timer ticks do not rewrite files.

### Incremental reconciler

Add a Core reconciler around the DNS-cache reader, learner, planner, and state
merge. Its route callback accepts additions only, which makes route removal
impossible in this code path. State and snapshot mutation happens only after
the route callback succeeds. This boundary provides executable coverage of a
complete late-DNS learning cycle without depending on WPF.

### Windows timer integration

Add a 10-second `DispatcherTimer` to the Windows application. Start it after
startup initialization and stop/cancel it during window shutdown.

Each tick uses the existing domain-renew semaphore in non-blocking mode:

- skip when a full renew or another incremental pass is active;
- skip when WireGuard is unavailable;
- read and learn the current DNS cache;
- apply only `ToAdd`, with an empty removal set;
- update state and the applied-state snapshot only after route application
  succeeds;
- log background failures without displaying recurring message boxes.

The full renew remains the authoritative operation for stale-route removal and
complete reconciliation.

## Preset compatibility

Extend the Claude preset with:

- `claude.com`
- `*.claude.com`
- `downloads.claude.ai`

Existing installations receive those domains only when all six members of the
old Claude preset exist and every matching duplicate remains enabled in
`UseWireGuard` mode. Customized or partial rule sets are left untouched. This
matches the existing conservative OpenAI preset migration policy.

Shared third-party telemetry domains are not added automatically because doing
so could route unrelated applications through WireGuard.

## Error and lifecycle behavior

- A failed DNS-cache read leaves routes and state unchanged.
- A failed route add leaves the managed snapshot unchanged so the next tick can
  retry.
- Cancellation during window close stops the current incremental pass.
- No incremental pass deletes a route.
- Full renew retains its existing add/remove and route-healing behavior.

## Tests

Automated behavior coverage must prove:

- a late wildcard cache entry yields one new `/32` addition while retaining old
  snapshot entries;
- repeated processing is idempotent;
- disabled, bypass, exact-domain, root-domain, invalid, and IPv6 entries are
  ignored;
- incremental metadata merge preserves unrelated domains and does not downgrade
  direct provenance;
- the updated Claude preset contains the three new domains;
- legacy Claude migration runs only for a complete, unmodified old preset and
  is idempotent;
- primary state loading persists both OpenAI and Claude migrations.

Runtime acceptance verifies that `downloads.claude.ai` has a Windows `/32`
route through the active WireGuard interface and that `ip route get` inside the
Claude WSL distribution selects the mirrored WireGuard interface rather than
the LAN interface.
