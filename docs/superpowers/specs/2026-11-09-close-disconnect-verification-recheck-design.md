# Close-disconnect bounded verification re-check design

## Goal

Prevent a transient service-name observation immediately after a successful elevated uninstall from producing a false cleanup warning, while preserving every genuine failure and never repeating the privileged uninstall automatically.

## Evidence

At the 2026-11-08 23:39 close:

- The elevated uninstall process was awaited and returned success.
- Route restoration removed the managed routes.
- The new close log recorded `disconnectFailures=None, disconnectUnresolved=GB-netsh-diagnostic-tested`.
- A later read-only check found neither that Registry service key nor any `WireGuardTunnel$*` service.
- The explicit retry recorded `disconnectFailures=None, disconnectUnresolved=None` and restored no additional routes because none remained.

This establishes an unresolved-only first verification followed by confirmed absence. It does not establish an exact Service Control Manager deletion latency, so the fix must be bounded and condition-based rather than an unbounded wait or another uninstall.

## Approaches considered

1. **Bounded read-only re-check (selected).** Re-enumerate every 200 ms, with at most ten delayed re-checks (2 seconds of added delay), only for an unresolved-only result. Stop as soon as all owned targets are absent.
2. **One fixed 250 ms delay and one re-check.** Smaller, but there is no latency measurement proving that 250 ms is sufficient.
3. **Diagnostics only.** Preserves behavior but also preserves the reproduced false warning.

## Minimal design

Change only `CloseDisconnectCoordinator.DisconnectAsync` after its existing first verification:

1. Compute `unresolved` exactly as today by intersecting the operation's owned targets with the enumerator result.
2. If there are no accumulated failures and `unresolved` is non-empty, wait 200 ms and call `IWindowsTunnelServiceEnumerator.ListInstalledAsync` again.
3. Repeat until `unresolved` becomes empty or ten delayed re-checks have run. The nominal additional delay is therefore capped at 2 seconds, excluding time spent inside Registry enumeration itself.
4. Recompute the same owned-target intersection after every enumeration. Never adopt or remove unrelated services.
5. When all owned targets are absent and there are no failures, use the existing `CompleteWithoutFailures` path and journal completion.
6. If targets remain after the bound, return the existing failed result with the exact remaining targets. The existing warning and Yes / No / Cancel behavior stay unchanged.
7. If a re-check enumeration fails, add the existing sanitized `Verification` failure and return the last known unresolved targets. Do not turn an unavailable verification into success.
8. Cancellation follows the existing failure/cancellation handling; it must not cause journal completion or an automatic uninstall retry.

The 200 ms delay will be injected as an optional asynchronous delay delegate defaulting to `Task.Delay`. Production construction remains unchanged, while tests can advance the delay instantly and verify its duration and count.

## Explicitly unchanged

- Exactly one elevated stop/uninstall batch per disconnect attempt.
- Elevated process creation, command construction, and process exit handling.
- Initial enumeration, target ownership, and journal phases.
- The existing first verification and all stop/helper failure preservation.
- Route restoration, close timeouts, cancellation contracts, and retry dialogs.
- `ReconcileAsync`; startup reconciliation does not gain a new delay in this change.
- The sanitized diagnostic fields added previously.
- No changes to Config Test, `netsh`, server selection, country checks, DNS, or the separately observed certificate-validation error.

## Tests

Use test-first development with the existing fake enumerator, stop adapter, journal, and an immediate fake delay:

1. **Transient unresolved target:** first verification returns `SG`, next returns empty. Prove success, one 200 ms delay, one extra enumeration, one stop batch, and journal completion.
2. **Disappearance during the bound:** first verification returns `SG`, then `SG`, then empty. Prove success and exactly two delayed re-checks without another stop.
3. **Persistent target:** every enumeration returns `SG`. Prove failure with unresolved `SG`, exactly ten 200 ms delays, eleven total verifications including the existing first verification, no second stop, and no journal completion.
4. **Stop failure is not hidden:** a stop exception with first verification still returning `SG` performs no delayed re-check and preserves the original stop failure.
5. **Re-check enumeration failure:** a transient unresolved result followed by an enumeration exception returns `Verification`, preserves the last unresolved target, does not complete the journal, and does not stop again.
6. Existing close-disconnect, application-close, wiring-contract, and diagnostic-formatter tests remain green; App build has zero warnings and errors.

## Live validation

Run the App as administrator with the preserved GB test copy. Because Config Test currently has a separate `netsh.exe` failure, close cleanup can be validated with the startup-enabled tunnel without treating Config Test as passed.

Close normally and inspect the application-close log. Success for this change means the first close does not show the prior unresolved-only warning when the target disappears within the bounded re-check, no second elevated uninstall occurs, and a read-only final check confirms zero tunnel services/processes/adapters/`/1` routes plus the ordinary default route.

If the target remains after 2 seconds, the warning is correct behavior and requires new evidence rather than an automatic uninstall retry. Do not describe the separate Config Test or certificate-validation issues as fixed by this change.
