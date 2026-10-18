# Software process destination routing implementation plan

Reactivated 2026-10-18: the user explicitly selected the simpler observed-IP
approach after reviewing the strict-driver option. Mullvad/VM work is deferred.
Success authorizes the next unused version, commit and GitHub push. Keep the
running GB tunnel intact and do not reset ChatGPT/Codex connections.

User-approved semantics: observed public TCP IPv4 destinations, including recursive
descendants when enabled, for every Software Rule. Routes are system-wide per IP;
new connections may precede observation. No VPN restart or connection reset.

## 1. Read-only Windows snapshots

Implement `SoftwareConnectionSnapshot` in `SoftwareRouting.cs`: process identity is PID, parent PID, executable
path and creation time; connection identity is PID and remote IPv4. Implement
`ISoftwareConnectionSnapshotReader.ReadAsync()` with Toolhelp process enumeration plus
GetExtendedTcpTable OWNER_PID_ALL. Throw on a failed whole-table read (do not
interpret it as no traffic). Skip inaccessible/exited processes. The pure planner
uses exact paths and parent creation times to reject PID-reuse relationships.

## 2. Planner and ownership tests before implementation

Create `SoftwareRoutingTests.cs` and `SoftwareRouting.cs`. Verify
recursive descendants, disabled rules, IncludeSubprocesses=false, reused PIDs,
case-insensitive paths, exclusion of local/non-IPv4 addresses, retention of learned
IPs for active rule configurations, overlap with domain ownership, and removal of
inactive rule ownership. Rule keys include IncludeSubprocesses so toggling it
invalidates previously learned descendant routes. Persist learned routes separately
in AppState and deep-clone them in RuleStateMutations.

## 3. Reconcile safely

Create `SoftwareRouteReconciler` with an injectable route writer
and current-request predicate. Route additions/removals update the ownership ledger
only after success. Recheck the current predicate after snapshot acquisition and
before each route mutation. Preserve domain-owned routes when software rules are
removed; domain renewal must preserve software-owned routes. Prove failures and
stale-rule/close interleavings with executable async tests.

## 4. WPF integration

Create `MainWindow.SoftwareRouting.cs` with a 2-second timer independent of the
Monitor tab. Serialize all writes with renewSemaphore. Capture snapshots away from
the dispatcher, then derive the plan against current rules under the gate.
Run learning independently alongside software policy application, periodically for new TCP
destinations. Exclude WireGuard transport endpoints and local networks. Stop and
cancel on close, preserving ledger ownership until cleanup succeeds. Retain
software routes during domain renew; include both ledgers in restore-on-exit.
Show monitored process/destination counts and unsupported UDP/IPv6/new-connection
limitations instead of presenting firewall-rule existence as routing proof.

## 5. Monitor binding evidence

Preserve netstat local IP/port. Separate rows with the same PID/destination but
different source addresses. On Windows classify using recognized socket-source
interface addresses, not the current destination route; missing/unrecognized
bindings are Unknown. Label this as socket binding, not packet capture proof.
Test a physical-source socket after its destination route changes to WireGuard.

## 6. Validate and apply

Run targeted tests RED then GREEN, full Core tests, and Windows Release build.
Use a separate output path. Inspect route plans read-only against configured
programs. Validate exact learned IPv4 host-route additions with a controlled
child-process probe; do not restart WireGuard or reset existing app TCP sessions.
Verify the selected route and report existing sessions that retain a
physical-interface source address. The user's explicit success-conditional
commit/push request is already present; do not commit until validation succeeds.
Use exact owned /32 routes for the acceptance probe, retain evidence and remove
only test-created routes. Record limitations and untested cases in release notes.
