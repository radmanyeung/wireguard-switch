# Close-disconnect failure diagnostics design

## Goal

Explain why the first application close can report `WireGuardTunnel$GB` as unresolved while an explicit retry succeeds, without changing cleanup timing or retry behavior during evidence collection.

## Observed evidence

- The 2026-11-08 21:47 close restored normal routes but ended with `UserCloseDisconnect` and an unresolved `WireGuardTunnel$GB` warning.
- The explicit retry completed with `NoProtectedTransaction` and no failures.
- A subsequent read-only check found no WireGuard tunnel services, WireGuard adapters, or WireGuard `/1` routes, and the ordinary default route was restored.
- The current close log records only the aggregate `UserCloseDisconnect` flag. It does not reveal whether `CloseDisconnectResult.Failures` contains `Stop`, `Verification`, another sanitized kind, or no adapter failure.

## Approaches considered

1. **Add sanitized result diagnostics first (selected).** Preserve all cleanup behavior and identify the failing boundary before changing it.
2. Add a bounded registry verification delay immediately. This may hide a transient uninstall race but would not address a genuine stop failure and is not yet evidence-led.
3. Retry the complete elevated uninstall automatically. This repeats privileged mutations without evidence that a second uninstall is necessary.

## Minimal design

Extend `MainWindow.LogApplicationCloseResult` so the existing application-close log also records:

- `disconnectFailures`: the ordered `CloseDisconnectFailure.Kind` values already present in `CloseDisconnectResult.Failures`, or `None` when there is no disconnect result or no failure.
- `disconnectUnresolved`: the tunnel names already present in `CloseDisconnectResult.UnresolvedTargets`, or `None` when empty.

Example shape:

```text
disconnectFailures=Stop, disconnectUnresolved=GB
```

Only enum names and validated tunnel names are logged. Do not log exception messages, native command output, command arguments, IP addresses, configuration contents, or key material. The existing service-name formatting remains the single tunnel-name formatting boundary.

No changes are permitted to:

- elevated process creation or uninstall commands;
- close timeouts, cancellation, or retries;
- journal phases or target ownership;
- route restoration;
- `Yes`, `No`, or `Cancel` behavior.

## Tests

Use test-first development:

1. Add a UI contract test proving the close-result log includes the ordered sanitized failure kinds and unresolved targets from `DisconnectResult`, with `None` for absent values.
2. Run it and confirm it fails because the diagnostic fields are absent.
3. Implement the smallest formatting change and run the close-disconnect, application-close, and UI contract suites.
4. Build the App with zero warnings and errors.

## Live validation

Run the App as administrator, select the preserved plaintext GB test copy, and perform `Test Config` again. Close the App normally. If cleanup warning appears, retain the result long enough to collect the new log, then use **Yes** to retry rather than **No**.

Validation succeeds when the log identifies the failure kinds and unresolved targets and a subsequent read-only check establishes the final service, process, route, adapter, and DNS state. A later fix requires separate evidence and approval; this diagnostic change alone must not be described as fixing cleanup.
