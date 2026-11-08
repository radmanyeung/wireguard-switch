# Windows User-Close WireGuard Disconnect Design

## Problem and evidence

The Windows application's ordinary close path currently removes application-managed routes but never stops or uninstalls WireGuard tunnel services. WireGuard therefore continues routing traffic after the window closes. This is longstanding documented behavior, not a regression from Test Config.

The requested new behavior is: when the user deliberately closes the application, restore ordinary non-WireGuard networking by stopping all WireGuard tunnel services.

## Approved product decisions

- A user-initiated close stops **all** installed WireGuard tunnel services, including services not created by this application.
- Automatic-update and installer-maintenance close operations preserve tunnels. They must not inherit the user-close disconnect behavior.
- Use the existing close orchestrator and existing elevated WireGuard control boundary. Do not add a resident watchdog or a post-exit cleanup executable.
- Restore application-managed routes before stopping tunnel services. Save application state only after route cleanup and requested tunnel shutdown have completed.
- Never report that ordinary networking was restored when any requested tunnel remains running.

## Close flow

1. On the first user-close request, mark the close intent and prevent duplicate close operations.
2. Stop new Enable Now, renewal, DNS learning, software-policy, and Test Config mutations using the existing operation gates and close guards.
3. If Enable Now has already launched its elevated process, wait for that process and its follow-on operation to settle. Do not abandon an uncancellable process and allow it to install a tunnel after the application exits.
4. Acquire the existing software-policy and routing gates in their established order.
5. Run the existing application-route restoration and cleanup callback.
6. Enumerate installed WireGuard tunnel services through the Windows service boundary. Validate exact `WireGuardTunnel$…` names and reject malformed names rather than passing arbitrary input to a shell.
7. Record the exact target service identities and pending Enable Now tunnel identity in a durable close-intent journal before the first tunnel mutation.
8. Use the existing elevated WireGuard control mechanism to stop and uninstall every recorded tunnel service. One elevated batch may stop multiple exact service names; it must not enumerate or stop unrelated Windows services.
9. Re-enumerate and verify that every targeted service is absent or stopped according to the existing tunnel-control contract. A service that appears from the recorded pending Enable Now operation is also stopped.
10. Save primary application state, release gates, finish the existing updater-close draining, and resume the existing normal window close exactly once. A staged update may be authorized only after successful disconnect and state save, preserving the existing update handoff; it must not restart a tunnel.

The close operation joins the existing orchestrator; it does not introduce a second route-restoration algorithm or an independent application-exit path.

## Enable Now and durable reconciliation

Enable Now is already tracked through process exit. User close must remain excluded from starting a new enable operation once close intent exists.

Before waiting for an in-flight elevated enable, persist enough information to identify its selected tunnel and the close request. If the application is forcibly terminated while that process cannot be cancelled, the next startup must reconcile only the recorded close targets and the recorded pending-enable tunnel. It must not stop unrelated tunnels first observed after that interrupted close.

A late process result must never change a successful close into a claimed success while a recorded tunnel is still running. Ordinary close cannot complete until the pending enable has settled and its tunnel has been removed.

External Task Manager termination, power loss, or a crash before a close request cannot be handled by a close handler and is outside this feature's guarantee.

## Failure behavior

- Route cleanup, service enumeration, elevated helper launch, service stop, and verification errors are preserved as typed failures without secret-bearing command output.
- Attempt all recorded tunnel stops so one failure does not leave other targets untried.
- If any target cannot be stopped or verified, normal close is aborted and the window remains open. Show the exact unresolved service names and warn that networking may still use WireGuard.
- Offer a retry. An explicit **Close anyway** action may close after a separate warning, but it must state that normal networking was not restored. This action must not authorize an update or record successful cleanup.
- Repeated close requests join the same in-flight operation and do not repeat service mutations.
- Automatic-update and installer-maintenance close paths bypass tunnel enumeration, stop operations, and the close-intent journal. Existing update authorization rules remain unchanged.

## Components

Add a testable Core close-disconnect coordinator with injected service enumeration, elevated stop, verification, journal, and clock/process boundaries. Keep WPF responsible for messages and window lifecycle only.

Extend the existing application-close orchestration with an optional user-close disconnect participant. Maintenance close does not supply this participant. The participant runs after the existing route-restoration callback and before primary-state save and update authorization.

Use a small durable journal in the existing protected application-data area. It contains only the close operation identifier, phase, exact WireGuard service identities, and pending-enable tunnel identity. It contains no configuration contents, private keys, or command-line secrets. Completed journals are idempotently finalized; incomplete journals are reconciled at startup before automatic enable or renewal.

## Testing

Use deterministic behavioral tests with fake service/process boundaries and temporary journal directories:

- User close with multiple tunnels cleans routes first, stops every exact tunnel once, verifies them, then saves state and closes.
- An externally installed tunnel is included, as explicitly requested.
- No tunnels still performs route cleanup and closes without elevation.
- Maintenance/update close preserves all tunnels and does not create a close-intent journal.
- Enumeration, helper-start, partial-stop, and verification failures attempt remaining stops, preserve failures, block normal close/update authorization, and never report successful restoration.
- Retry after failure is idempotent; repeated close does not duplicate mutations.
- Close during in-flight Enable Now waits, stops the late selected tunnel, and only then closes.
- Interrupted close with a pending enable reconciles only recorded targets on the next startup before automatic enable/renewal.
- Close during Test Config or startup recovery retains existing deferral and gate ordering; no lock-order inversion or second close occurs.
- Existing route cleanup, update authorization, installer maintenance, and Windows wiring tests remain intact.

Run focused tests, all non-Mac Core tests, and the Windows App build. Do not launch the app or perform real service, route, network, update, or elevated operations during offline verification.

## Documentation and verification limits

Update README close semantics, maintenance exception, failure behavior, and crash limitations. Remove or revise statements that say WireGuard always outlives user close.

Real elevated enumeration/stop, actual route restoration, updater close, and late-process behavior remain unverified until separately authorized live tests. Offline tests must not be described as proof of live network restoration.
