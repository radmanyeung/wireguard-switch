# Close-disconnect Bounded Verification Re-check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-check unresolved-owned tunnel service names for at most 2 seconds after an otherwise successful uninstall, without repeating privileged mutations or hiding genuine failures.

**Architecture:** Keep the change inside `CloseDisconnectCoordinator.DisconnectAsync`. Inject only an optional asynchronous delay delegate for deterministic tests; production construction and the enumerator contract remain unchanged. The existing first verification remains, and only an unresolved-only result enters a ten-attempt read-only loop.

**Tech Stack:** C# / .NET 8, xUnit, FluentAssertions, WPF App build.

**Repository constraint:** Keep all changes uncommitted. Do not commit, pull, push, run a real update, change elevated commands, or modify Config Test / DNS / country checks.

---

## File map

- Modify `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs`: optional delay injection and bounded unresolved-only verification loop.
- Modify `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`: transient, bounded, persistent, failure, cancellation, and retry-enumeration tests using existing fakes.
- Review `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`: confirm production constructor call is unchanged; do not edit it.
- Review `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectDiagnosticFormatter.cs`: confirm diagnostics are unchanged; do not edit it.

## Task 1: Add all failing coordinator tests

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`

- [ ] **Step 1: Extend the test coordinator factory with an optional delay**

Replace the existing `CreateCoordinator` helper with:

```csharp
private static CloseDisconnectCoordinator CreateCoordinator(
    FakeJournal? journal = null,
    FakeEnumerator? enumerator = null,
    FakeStop? stop = null,
    FakeActivitySource? activitySource = null,
    Func<Guid>? operationIdFactory = null,
    FakeSettlementProbe? settlementProbe = null,
    Func<TimeSpan, CancellationToken, Task>? delayAsync = null) =>
    new(
        enumerator ?? new FakeEnumerator(),
        stop ?? new FakeStop(),
        journal ?? new FakeJournal(),
        activitySource ?? new FakeActivitySource(),
        operationIdFactory ?? (() => Guid.NewGuid()),
        settlementProbe ?? new FakeSettlementProbe(),
        delayAsync);
```

- [ ] **Step 2: Add transient and mid-bound success tests before the factory**

```csharp
[Fact]
public async Task Disconnect_TransientUnresolvedTarget_RechecksOnceWithoutStoppingAgain()
{
    var original = Entry(targets: [Sg]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator()
        .Returns(Sg)
        .Returns(Sg)
        .Returns();
    var stop = new FakeStop();
    var delays = new List<TimeSpan>();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

    result.Success.Should().BeTrue();
    result.Failures.Should().BeEmpty();
    result.UnresolvedTargets.Should().BeEmpty();
    delays.Should().Equal(TimeSpan.FromMilliseconds(200));
    enumerator.Calls.Should().Be(3, "initial enumeration, first verification, and one re-check");
    stop.Batches.Should().ContainSingle();
    journal.CompleteCalls.Should().Be(1);
    journal.Entry.Should().BeNull();
}

[Fact]
public async Task Disconnect_TargetDisappearsDuringBound_StopsRecheckingImmediately()
{
    var original = Entry(targets: [Sg]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator()
        .Returns(Sg)
        .Returns(Sg)
        .Returns(Sg)
        .Returns();
    var stop = new FakeStop();
    var delays = new List<TimeSpan>();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

    result.Success.Should().BeTrue();
    delays.Should().Equal(
        TimeSpan.FromMilliseconds(200),
        TimeSpan.FromMilliseconds(200));
    enumerator.Calls.Should().Be(4);
    stop.Batches.Should().ContainSingle();
    journal.CompleteCalls.Should().Be(1);
}
```

- [ ] **Step 3: Replace the existing persistent-target test with the bounded version**

Replace `Disconnect_TargetStillInstalled_IsUnresolvedButUnrelatedNewTargetIsIgnored` with:

```csharp
[Fact]
public async Task Disconnect_TargetStillInstalled_StopsAfterTenRechecksAndIgnoresUnrelatedTarget()
{
    var original = Entry(targets: [External]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator().Returns(External);
    for (var verification = 0; verification < 11; verification++)
    {
        enumerator.Returns(External, NewAfterCrash);
    }

    var stop = new FakeStop();
    var delays = new List<TimeSpan>();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

    result.Success.Should().BeFalse();
    result.Failures.Should().BeEmpty();
    result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(External);
    result.UnresolvedTargets.Should().NotContain(NewAfterCrash);
    delays.Should().HaveCount(10);
    delays.Should().AllSatisfy(delay => delay.Should().Be(TimeSpan.FromMilliseconds(200)));
    enumerator.Calls.Should().Be(12, "initial enumeration plus eleven total verifications");
    stop.Batches.Should().ContainSingle();
    stop.Batches[0].Should().ContainSingle().Which.Should().Be(External);
    journal.Entry.Should().NotBeNull();
    journal.CompleteCalls.Should().Be(0);
}
```

- [ ] **Step 4: Add stop-failure, re-check-failure, and cancellation tests**

```csharp
[Fact]
public async Task Disconnect_StopFailureWithUnresolvedTarget_DoesNotRecheckOrHideFailure()
{
    var original = Entry(targets: [Sg]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator()
        .Returns(Sg)
        .Returns(Sg);
    var stop = new FakeStop
    {
        Failure = new AdapterStopException(
            CloseDisconnectFailureKind.Stop,
            SecretFailure("stop").Message)
    };
    var delays = new List<TimeSpan>();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

    result.Success.Should().BeFalse();
    result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
    result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
    delays.Should().BeEmpty();
    enumerator.Calls.Should().Be(2);
    stop.Batches.Should().ContainSingle();
    journal.CompleteCalls.Should().Be(0);
    AssertSafeMessages(result);
}

[Fact]
public async Task Disconnect_RecheckEnumerationFailure_PreservesVerificationAndLastUnresolvedTarget()
{
    var original = Entry(targets: [Sg]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator()
        .Returns(Sg)
        .Returns(Sg)
        .Throws(SecretFailure("re-check verification"));
    var stop = new FakeStop();
    var delays = new List<TimeSpan>();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        });

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

    result.Success.Should().BeFalse();
    result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Verification);
    result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
    delays.Should().Equal(TimeSpan.FromMilliseconds(200));
    enumerator.Calls.Should().Be(3);
    stop.Batches.Should().ContainSingle();
    journal.Entry.Should().NotBeNull();
    journal.CompleteCalls.Should().Be(0);
    AssertSafeMessages(result);
}

[Fact]
public async Task Disconnect_RecheckCancellation_ReturnsVerificationWithoutCompletingJournal()
{
    var original = Entry(targets: [Sg]);
    var journal = new FakeJournal { Entry = original };
    var enumerator = new FakeEnumerator()
        .Returns(Sg)
        .Returns(Sg);
    var stop = new FakeStop();
    using var cancellation = new CancellationTokenSource();
    cancellation.Cancel();
    var coordinator = CreateCoordinator(
        journal,
        enumerator,
        stop,
        delayAsync: (delay, token) => Task.Delay(delay, token));

    var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), cancellation.Token);

    result.Success.Should().BeFalse();
    result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Verification);
    result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
    enumerator.Calls.Should().Be(2);
    stop.Batches.Should().ContainSingle();
    journal.Entry.Should().NotBeNull();
    journal.CompleteCalls.Should().Be(0);
    AssertSafeMessages(result);
}
```

- [ ] **Step 5: Run the tests and confirm RED for the missing constructor parameter**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectCoordinatorTests"
```

Expected: compilation fails because `CloseDisconnectCoordinator` has no overload accepting the final `delayAsync` argument. Do not write the loop yet.

## Task 2: Add delay injection without behavior, then verify behavioral RED

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs:61-87`
- Test: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`

- [ ] **Step 1: Add only the optional delay field and constructor parameter**

Add the field beside the existing coordinator dependencies:

```csharp
private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
```

Use this constructor signature and assignment, retaining all existing parameters and null checks:

```csharp
public CloseDisconnectCoordinator(
    IWindowsTunnelServiceEnumerator enumerator,
    IWindowsTunnelServiceStop tunnelStop,
    ICloseDisconnectJournal journal,
    IEnableTunnelActivitySource enableActivitySource,
    Func<Guid> operationIdFactory,
    IEnableTunnelProcessSettlementProbe enableSettlementProbe,
    Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
{
    this.enumerator = enumerator ?? throw new ArgumentNullException(nameof(enumerator));
    this.tunnelStop = tunnelStop ?? throw new ArgumentNullException(nameof(tunnelStop));
    this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
    this.enableActivitySource = enableActivitySource
        ?? throw new ArgumentNullException(nameof(enableActivitySource));
    this.operationIdFactory = operationIdFactory
        ?? throw new ArgumentNullException(nameof(operationIdFactory));
    this.enableSettlementProbe = enableSettlementProbe
        ?? throw new ArgumentNullException(nameof(enableSettlementProbe));
    this.delayAsync = delayAsync ?? Task.Delay;
}
```

Do not change `DisconnectAsync` in this step. The App constructor call remains valid without an added argument.

- [ ] **Step 2: Run coordinator tests and confirm behavior is still missing**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectCoordinatorTests"
```

Expected: transient, mid-bound, persistent-bound, re-check-failure, and cancellation tests fail because no delayed re-check exists. The stop-failure protection test may pass because it requires unchanged behavior. Confirm the failing reasons are missing re-check behavior, not test setup errors.

## Task 3: Implement the bounded read-only re-check

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs:286-305`
- Test: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`

- [ ] **Step 1: Add explicit bounds beside the coordinator fields**

```csharp
private static readonly TimeSpan VerificationRecheckDelay = TimeSpan.FromMilliseconds(200);
private const int MaximumVerificationRechecks = 10;
```

- [ ] **Step 2: Insert the loop immediately after the existing first `unresolved` intersection**

Keep the existing first verification and its catch unchanged. Replace only the tail from `var unresolved = IntersectTargets(targets, remaining);` through the success/failure returns with:

```csharp
var unresolved = IntersectTargets(targets, remaining);
for (var attempt = 0;
    failures.Count == 0
    && unresolved.Count > 0
    && attempt < MaximumVerificationRechecks;
    attempt++)
{
    try
    {
        await delayAsync(VerificationRecheckDelay, cancellationToken).ConfigureAwait(false);
        remaining = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
        unresolved = IntersectTargets(targets, remaining);
    }
    catch (Exception exception) when (IsOperationalFailure(exception))
    {
        failures.Add(CreateFailure(CloseDisconnectFailureKind.Verification));
        return CloseDisconnectResult.Failed(failures, unresolved);
    }
}

if (failures.Count == 0 && unresolved.Count == 0)
{
    return CompleteWithoutFailures(operationId);
}

return CloseDisconnectResult.Failed(failures, unresolved);
```

This loop contains no stop call, journal save, or target expansion. Do not modify `ReconcileAsync` or the first verification catch.

- [ ] **Step 3: Run coordinator tests and confirm GREEN**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectCoordinatorTests"
```

Expected: all coordinator tests pass with zero failures, including exactly ten persistent-target delays and no delay after stop failure.

## Task 4: Run focused regressions and review scope

**Files:**
- Review: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs`
- Review: `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`
- Review only, unchanged: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Review only, unchanged: `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectDiagnosticFormatter.cs`

- [ ] **Step 1: Run close, application, wiring, and diagnostic tests**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~CloseDisconnectDiagnosticFormatterTests|FullyQualifiedName~WindowsCloseDisconnectWiringContractTests|FullyQualifiedName~CloseDisconnectCoordinatorTests|FullyQualifiedName~ApplicationCloseOrchestratorTests"
```

Expected: all selected tests pass with zero failures.

- [ ] **Step 2: Build the App**

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" build "src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj"
```

Expected: build succeeds with zero warnings and zero errors.

- [ ] **Step 3: Inspect the final scoped source diff**

Read the modified coordinator and tests. Verify all of the following:

- Only the optional delay constructor parameter was added; the App call is unchanged.
- Only `DisconnectAsync` gained re-check behavior; `ReconcileAsync` is unchanged.
- At most ten 200 ms delays occur, only when failures are empty and unresolved targets remain.
- Every re-check calls only `ListInstalledAsync` and `IntersectTargets`.
- The stop adapter is still called at most once per disconnect attempt.
- Re-check failure preserves `Verification` and the last known unresolved targets.
- No Config Test, network restoration, updater, or dialog code changed.
- No commit, pull, push, or real update is performed.

## Task 5: Live-validate the first close

**Files:**
- Read: `runtime.log`
- Create evidence under: `live-validation/`

- [ ] **Step 1: Launch the Debug App as administrator**

Launch:

```text
D:\wireguard switch\.worktrees\app-config-test\src\WireguardSplitTunnel.App\bin\Debug\net8.0-windows\WireguardSplitTunnel.App.exe
```

Use working directory:

```text
D:\wireguard switch\.worktrees\app-config-test
```

Allow the startup-enabled GB tunnel to settle. Do not treat Config Test as passed: its separate `netsh.exe` failure remains outside this fix.

- [ ] **Step 2: Close normally and collect the result**

Close the App on the first attempt. If the cleanup warning appears, leave it open and read `runtime.log` before choosing **Yes** to retry. Do not choose **No**.

Record `disconnectFailures` and `disconnectUnresolved`. Expected for a target disappearing inside the bound: no warning, `failures=None`, `disconnectFailures=None`, and `disconnectUnresolved=None`. A still-present target after ten re-checks must retain the warning rather than trigger another uninstall.

- [ ] **Step 3: Verify final state read-only**

Run:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "live-validation\capture-state.ps1" -Label "post-bounded-recheck-state" -OutputDirectory "live-validation"
```

Confirm zero tunnel services, App/WireGuard processes, WireGuard adapters, and WireGuard `/1` routes, and confirm the ordinary default route returns. DNS should match the earlier physical-adapter values. Report any HTTPS certificate-validation error separately; do not claim it is fixed by this cleanup change.

- [ ] **Step 4: Report evidence without committing**

State the automated test count, App build result, first-close log fields, final route/service state, and any remaining separate Config Test or certificate issue. Keep all source and evidence files uncommitted.
