# Close-disconnect diagnostics implementation plan

> Execute test-first. Keep every product change uncommitted. Do not pull, push, run a real update, change cleanup timing, or retry privileged uninstalls.

**Goal:** Add only sanitized failure-kind and unresolved-tunnel diagnostics to the existing application-close log so the next live close can distinguish a stop/verification failure from an unresolved-only result.

**Architecture:** Put deterministic, secret-free formatting in a small Core formatter. `MainWindow.LogApplicationCloseResult` appends that formatter's output to its existing log entry. The coordinator, elevated adapter, journal, route restoration, close dialogs, and retry behavior remain unchanged.

**Tech stack:** C# / .NET 8, xUnit, FluentAssertions, WPF App build.

---

## Task 1: Specify formatter behavior with failing tests

**Files:**
- Create: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectDiagnosticFormatterTests.cs`
- Reference: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs`
- Reference: `src/WireguardSplitTunnel.Core/Services/WindowsTunnelServiceIdentity.cs`

- [ ] **Step 1: Write formatter tests before the production type exists**

Create tests covering this public contract:

```csharp
CloseDisconnectDiagnosticFormatter.Format(CloseDisconnectResult? result)
```

Test cases:

1. `Format(null)` returns exactly:
   ```text
   disconnectFailures=None, disconnectUnresolved=None
   ```
2. A successful result with empty lists returns the same `None` fields.
3. A result with `Stop` then `Verification` failures preserves that order, while unresolved targets are distinct case-insensitively, sorted case-insensitively, and joined with `+`. For targets `external.tunnel-1`, `gb`, and `GB`, output is:
   ```text
   disconnectFailures=Stop+Verification, disconnectUnresolved=external.tunnel-1+gb
   ```
   The first spelling of a case-insensitive duplicate is retained.
4. A failure whose `Message` contains the synthetic secret `PRIVATE-KEY-MUST-NOT-LOG` still produces only the enum and tunnel fields. Assert that the output does not contain the secret, `Message`, `WireGuardTunnel$`, an IP address, or command text.

Use `WindowsTunnelServiceIdentity.FromTunnelName` to construct valid targets. Do not read or embed a real `.conf` or real key material.

- [ ] **Step 2: Run the new tests and confirm RED for the missing formatter**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectDiagnosticFormatterTests"
```

Expected: compilation fails because `CloseDisconnectDiagnosticFormatter` does not exist. Do not proceed until this failure is observed.

## Task 2: Implement the smallest safe formatter

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectDiagnosticFormatter.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectDiagnosticFormatterTests.cs`

- [ ] **Step 1: Implement enum-only failures and validated-name targets**

Add a public static formatter in `WireguardSplitTunnel.Core.Updates` with behavior equivalent to:

```csharp
public static string Format(CloseDisconnectResult? result)
{
    var failures = result?.Failures is { Count: > 0 } items
        ? string.Join("+", items.Select(item => item.Kind))
        : "None";
    var unresolved = result?.UnresolvedTargets is { Count: > 0 } targets
        ? string.Join("+", targets
            .Select(target => target.TunnelName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        : "None";

    return $"disconnectFailures={failures}, disconnectUnresolved={unresolved}";
}
```

Do not read failure messages, exceptions, native output, service names, configuration data, or network values. Do not alter `CloseDisconnectResult` or the coordinator.

- [ ] **Step 2: Run formatter tests and confirm GREEN**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectDiagnosticFormatterTests"
```

Expected: all formatter tests pass.

## Task 3: Prove and add the App logging wiring

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/WindowsCloseDisconnectWiringContractTests.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs` (`LogApplicationCloseResult`)

- [ ] **Step 1: Add a failing source-contract test**

Add a test that extracts `LogApplicationCloseResult` through `CreateApplicationCloseOrchestrator` and asserts that it contains:

```csharp
CloseDisconnectDiagnosticFormatter.Format(result.DisconnectResult)
```

Also assert that the existing authorization fields remain present. Do not weaken any existing close-behavior contract assertions.

- [ ] **Step 2: Run the wiring test and confirm RED**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~WindowsCloseDisconnectWiringContractTests"
```

Expected: only the new diagnostic-wiring assertion fails because the App does not call the formatter yet.

- [ ] **Step 3: Append diagnostics to the existing log entry**

In `LogApplicationCloseResult`, retain every existing field and append the formatter result before the final period:

```csharp
+ $"authorizationError={authorization?.ErrorCode ?? "none"}, "
+ $"{CloseDisconnectDiagnosticFormatter.Format(result.DisconnectResult)}.");
```

Expected successful-close shape:

```text
Application close completed. outcome=..., failures=None, authorizationPresent=..., authorizationOutcome=..., authorizationError=none, disconnectFailures=None, disconnectUnresolved=None.
```

Do not change any other close or update method.

- [ ] **Step 4: Run focused regression tests and confirm GREEN**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectDiagnosticFormatterTests|FullyQualifiedName~WindowsCloseDisconnectWiringContractTests|FullyQualifiedName~CloseDisconnectCoordinatorTests|FullyQualifiedName~ApplicationCloseOrchestratorTests"
```

Expected: all selected tests pass with zero failures.

- [ ] **Step 5: Build the App**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" build "src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj"
```

Expected: build succeeds with zero warnings and zero errors.

## Task 4: Review the evidence-only diff and prepare live validation

**Files:**
- Review only the five implementation/test files above.
- Preserve all earlier uncommitted country and `netsh` diagnostics.

- [ ] **Step 1: Inspect the scoped diff**

Confirm the diff contains only the formatter, its tests, one log-field append, and its wiring test. Confirm there are no changes to elevated uninstall commands, timeouts, cancellation, journals, route restoration, dialog choices, or automatic retries. Do not commit.

- [ ] **Step 2: Perform a separate approved live run**

With the App running as administrator, select only the preserved test copy:

```text
D:\wireguard switch\.worktrees\app-config-test\live-validation\GB-netsh-diagnostic-tested.conf
```

Run `Test Config`, then close normally. If the cleanup warning appears, collect the new log before choosing **Yes** to retry; do not choose **No**. Afterwards perform read-only checks of WireGuard services, processes, adapters, `/1` routes, default route, and DNS.

Report the observed `disconnectFailures` and `disconnectUnresolved` values and final network state. This diagnostic change is evidence collection, not a cleanup fix. Propose any bounded verification re-check only after the new evidence supports it, as a separate approved change.
