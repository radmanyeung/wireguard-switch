# WireGuard Domain-Based Split Tunneling Tool (Windows 11) - Design Spec

Date: 2026-04-01
Status: Draft approved in chat; pending user review of written spec

## 1. Objective
Build a Windows 11 GUI tool that lets the user choose which websites (domains) use WireGuard while all other websites bypass WireGuard.

Primary goal:
- Domain-based routing policy with safe apply/rollback.

Out of scope for MVP:
- Per-app routing.
- Per-port routing.
- Kernel-level packet filtering.

## 2. Product Requirements

### 2.1 User-facing requirements
- User can add, edit, disable, and delete website rules.
- User can apply rule changes on demand.
- User can roll back to the previous stable routing snapshot with one click.
- App shows WireGuard tunnel/interface status.
- Unlisted websites bypass WireGuard by default.

### 2.2 Policy semantics
- Rule target is a domain (for example, `example.com`).
- Enabled rule means: traffic to currently resolved IPs for that domain should route via WireGuard.
- Disabled rule means: no forced WireGuard routes are managed for that domain.
- Default policy is fixed for MVP: domains not listed in rules are not forced through WireGuard.

## 3. Architecture

### 3.1 Components
1. Rule Manager (GUI)
- Manages domain rules and rule state.
- Triggers apply/rollback actions.

2. Resolver + Route Engine (background worker)
- Resolves domains to A/AAAA records.
- Computes route diffs (add/remove) from previous state.
- Applies routes via Windows route APIs/commands.
- Refreshes periodically.

3. WireGuard Interface Detector
- Detects active WireGuard interface and route path.
- Validates prerequisites before route apply.

4. State Store
- Persists rules, last known resolved sets, and route snapshots.

### 3.2 Data flow
1. User adds/updates rule.
2. Rule validated and persisted.
3. Resolver gets IP set.
4. Diff engine compares desired vs active managed routes.
5. Route engine applies adds/removes through WireGuard interface.
6. Snapshot updated on successful converge.

## 4. GUI Design

## 4.1 Main window sections
- Tunnel status: Connected/Disconnected, interface name.
- Policy banner: "Unlisted websites bypass WireGuard".
- Rules table:
  - Domain
  - Enabled/Disabled
  - Last resolved IP count
  - Last refresh timestamp
- Action buttons:
  - Add Rule
  - Edit
  - Disable/Enable
  - Delete
  - Apply Now
  - Rollback

### 4.2 UX safeguards
- Preview of pending route changes before apply.
- One-click rollback to last stable snapshot.
- Startup admin privilege check and clear message if missing.

## 5. Domain Resolution and Routing Logic

### 5.1 Resolution behavior
- Resolve each enabled domain periodically (configurable interval).
- For temporary DNS failures, keep last known good IP set and retry.
- Maintain TTL-aware or interval-based refresh strategy (interval for MVP, TTL-aware optional later).

### 5.2 Route behavior
- For each desired IP, ensure route points to WireGuard interface path.
- Remove stale managed routes that are no longer in desired IP sets.
- Never touch routes not tagged/owned by this app.

### 5.3 Managed-route ownership
- Managed routes must be identifiable by app state mapping (rule -> IP -> route record).
- Snapshot contains all currently managed route entries to support deterministic rollback.

## 6. Error Handling
- WireGuard interface unavailable:
  - Block apply operations.
  - Show red status in UI.
  - Keep last successful snapshot unchanged.
- DNS resolution errors:
  - Retry with backoff.
  - Keep last known routes unless explicitly removed by successful refresh.
- Route apply failure:
  - Stop batch.
  - Revert to prior stable snapshot.
  - Show detailed error with failed operation.
- Crash/startup recovery:
  - Reconcile existing managed routes and persisted snapshot.
  - Clean orphaned managed routes if safe to do so.

## 7. Security and Safety
- Require elevation (administrator) for route modification.
- Validate domain input strictly.
- Avoid shell command injection by using safe command invocation APIs.
- Keep an audit log of apply/rollback operations.

## 8. Testing Strategy

### 8.1 Unit tests
- Domain validator.
- Rule parser and normalization.
- Diff calculator for route add/remove sets.
- Snapshot serialization/deserialization.

### 8.2 Integration tests (Windows)
- Mock DNS with deterministic IP sets.
- Route wrapper apply/remove behavior.
- Rollback correctness after simulated partial failure.
- Interface up/down transition handling.

### 8.3 Manual acceptance tests
- Add domain and verify its traffic uses WireGuard.
- Confirm unlisted domains bypass WireGuard.
- Simulate DNS changes and verify route updates.
- Restart app and verify state recovery.

## 9. Implementation Phases

### Phase 1 (MVP)
- GUI for domain rule CRUD.
- WireGuard interface detection.
- Resolver + route apply engine.
- Apply preview and rollback snapshot.
- Periodic refresh.

### Phase 2 (V1.1)
- Wildcard/domain helper improvements.
- Import/export rules JSON.
- Enhanced diagnostics view.

### Phase 3 (V1.2)
- Optional per-app override layer (future, separate design extension).

## 10. Open Decisions (Resolved)
- Selector type: domain/website-based.
- Product type: GUI desktop app.
- Default policy: unlisted websites bypass WireGuard.

## 11. Suggested Tech Stack (for planning)
- UI: C# .NET (WPF or WinUI 3).
- Background service layer: C# hosted worker.
- Persistence: local JSON or SQLite.
- Routing integration: Windows IP Helper / `route` command wrapper.

Rationale: native Windows integration, robust privilege handling, and straightforward packaging for Windows 11.
