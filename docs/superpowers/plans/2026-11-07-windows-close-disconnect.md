# Windows User-Close WireGuard Disconnect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make deliberate Windows user close restore application-managed routes, durably stop and uninstall every recorded `WireGuardTunnel$…` service, verify the result, and only then save final state, authorize a staged update, and close.

**Architecture:** Extend `ApplicationCloseOrchestrator` with an optional user-close participant. A Core coordinator owns an atomic close-intent journal, existing Enable Now process lifetime, exact service targets, and startup reconciliation. Windows adapters use existing registry discovery and elevated WireGuard control; installer maintenance never invokes the participant.

**Tech Stack:** .NET 8, C#, WPF, xUnit, FluentAssertions, Windows registry service discovery, elevated WireGuard process control.

---

## Global constraints

- Work only in `D:\wireguard switch\.worktrees\app-config-test`; preserve all existing uncommitted Test Config work and unrelated files.
- No commits, pull, push, app launch, live service/route/network/update/installer/elevated operations.
- User close stops all installed WireGuard tunnels, including external tunnels. Installer-maintenance, session-ending, and elevation-handoff close do not disconnect.
- Keep software-gate → renew-gate ordering and the existing route-restoration callback. Do not add another close path or route algorithm.
- Verification is **absent-only**: a recorded service still installed after `/uninstalltunnelservice` is unresolved.
- Route cleanup failure still attempts tunnel disconnect, but blocks final state save, update authorization, and normal close. Disconnect/verification failure does the same.
- Tests use fake process/service boundaries and temporary journal directories only.
- Use the configured dotnet command with `ProgramFiles` environment variables; every task ends with focused tests, not a commit.

## Task 1: Exact service identities and close command construction

**Files:**
- Create `src/WireguardSplitTunnel.Core/Services/WindowsTunnelServiceIdentity.cs`
- Create `src/WireguardSplitTunnel.Core/Services/WindowsCloseDisconnectCommandBuilder.cs`
- Modify `src/WireguardSplitTunnel.Core/Services/WindowsEnableTunnelCommandBuilder.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/WindowsCloseDisconnectCommandBuilderTests.cs`
- Modify existing Enable command-builder tests

- [ ] Write failing tests proving `WireGuardTunnel$SG` and an external tunnel are included, malformed suffixes are rejected before process creation, identities deduplicate case-insensitively, and every exact target is attempted even after another fails.
- [ ] Run the focused tests and confirm compilation fails because the new identity/builder types are absent.
- [ ] Add immutable `WindowsTunnelServiceIdentity` with `ServiceName`, `TunnelName`, `FromServiceName`, `FromTunnelName`, and `IsValidTunnelName`. Require exact case-insensitive prefix and a conservative nonempty ASCII suffix containing letters, digits, `_`, `=`, `+`, `.`, or `-`; reject whitespace, quotes, shell metacharacters, slashes, controls, and traversal. Preserve casing and sort deterministically.
- [ ] Add `IWindowsTunnelServiceEnumerator.ListInstalledAsync` and a registry-backed implementation. Adapt `WindowsTunnelServiceDiscovery` with typed parsing while retaining existing bare-name wrappers for Enable Now.
- [ ] Add `WindowsCloseDisconnectCommandBuilder.BuildArguments(wireguardExePath, targets)`. Return empty for no targets; otherwise join exact `/uninstalltunnelservice` commands with `&`, never shell enumeration, `sc`, PowerShell, or `&&`.

```csharp
var identity = WindowsTunnelServiceIdentity.FromServiceName("WireGuardTunnel$SG");
identity.ServiceName.Should().Be("WireGuardTunnel$SG");
identity.TunnelName.Should().Be("SG");
var parse = () => WindowsTunnelServiceIdentity.FromTunnelName("bad\" & calc");
parse.Should().Throw<ArgumentException>();
```

- [ ] Run identity/builder and existing Enable command tests; expect all pass.

## Task 2: Atomic durable close-intent journal

**Files:**
- Create `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectJournal.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectJournalTests.cs`

- [ ] Write failing round-trip, malformed-data, atomic-save, and idempotent-completion tests.
- [ ] Run journal tests and confirm the journal types are absent.
- [ ] Implement `CloseDisconnectJournalPhase { WaitingForEnable, TargetsRecorded }`, `CloseDisconnectJournalEntry`, `ICloseDisconnectJournal`, and `FileCloseDisconnectJournal`.

```csharp
public sealed record CloseDisconnectJournalEntry(
    Guid OperationId,
    CloseDisconnectJournalPhase Phase,
    IReadOnlyList<WindowsTunnelServiceIdentity> Targets,
    WindowsTunnelServiceIdentity? PendingEnable);

public interface ICloseDisconnectJournal
{
    CloseDisconnectJournalEntry? Load();
    void Save(CloseDisconnectJournalEntry entry);
    void Complete(Guid operationId);
}
```

- [ ] Serialize only operation ID, phase, full target service names, and optional pending-enable service name. Reject default IDs, undefined phases, malformed identities, and malformed JSON with `InvalidDataException`.
- [ ] Save through a unique sibling temporary file and `File.Replace`/`File.Move`, following `StateStore`. Completion is idempotent when absent and requires matching operation ID before deletion.
- [ ] Production path is `%LOCALAPPDATA%\WireguardSplitTunnel\close-disconnect.json`; never store config contents, private keys, paths, commands, stdout, or stderr.
- [ ] Run journal tests; expect all pass and no files outside temporary test directories.

## Task 3: Expose Enable Now process lifetime and exit code

**Files:**
- Modify `src/WireguardSplitTunnel.Core/Services/EnableTunnelCoordinator.cs`
- Modify `src/WireguardSplitTunnel.App/Services/WindowsEnableTunnelProcessFactory.cs`
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/EnableTunnelCoordinatorCloseTests.cs`
- Modify existing coordinator fakes/tests

- [ ] Write a failing controlled-task test proving captured activity remains pending through process exit, follow-on renewal, exception propagation, disposal, and gate release.
- [ ] Run the test and confirm the activity API and process exit code are absent.
- [ ] Add `IEnableTunnelProcess.ExitCode`, `EnableTunnelActivity`, and `IEnableTunnelActivitySource.CaptureActivity()`.

```csharp
public sealed record EnableTunnelActivity(
    WindowsTunnelServiceIdentity? PendingTunnel,
    Task Completion);

public Task RunAsync(
    Func<ProcessStartInfo> startInfoFactory,
    Func<bool> mayStart,
    Action processStarted,
    Func<CancellationToken, Task> followOnAsync,
    CancellationToken cancellationToken = default,
    WindowsTunnelServiceIdentity? selectedTunnel = null);
```

- [ ] Register only an operation that passed both `mayStart` checks, immediately before process start. Clear current state in `finally`, release the routing gate, then complete exposed activity. Idle capture returns `(null, Task.CompletedTask)`.
- [ ] Pass the selected identity from MainWindow using `WireguardConfigCatalog.GetTunnelName(selectedPath)`. Keep process waiting non-cancelable.
- [ ] Run Enable close tests plus ConfigCheck coordinator/startup tests; expect all existing queued-enable and cancellation behavior preserved.

## Task 4: Core close-disconnect coordinator and startup reconciliation

**Files:**
- Create `src/WireguardSplitTunnel.Core/Updates/CloseDisconnectCoordinator.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/CloseDisconnectCoordinatorTests.cs`

- [ ] Write failing deterministic tests for multiple/external targets, no targets, journal failure, enumeration failure, helper/start/stop failure, partial failure, verification failure, idempotent retry, pending Enable, and startup reconciliation limited to recorded targets.
- [ ] Run coordinator tests and confirm the coordinator/result contracts are absent.
- [ ] Add typed `CloseDisconnectFailureKind`, safe failure/result records, `IUserCloseDisconnectParticipant`, `IWindowsTunnelServiceStop`, and `CloseDisconnectCoordinator`.

```csharp
public interface IUserCloseDisconnectParticipant
{
    Task<CloseDisconnectPreparation> PrepareAsync(CancellationToken cancellationToken);
    Task<CloseDisconnectResult> DisconnectAsync(
        CloseDisconnectPreparation preparation,
        CancellationToken cancellationToken);
}

public Task<CloseDisconnectResult> ReconcileAsync(CancellationToken cancellationToken);
```

- [ ] `PrepareAsync`: load existing journal; capture current Enable once; reuse operation ID; preserve/replace pending identity only from current Enable; persist `WaitingForEnable` before awaiting; await captured completion without starting Enable.
- [ ] `DisconnectAsync`: reload journal and enumerate after route cleanup; union recorded/current/pending targets; no targets means no elevation/journal mutation; persist complete `TargetsRecorded` before stopping; stop only recorded targets still installed; re-enumerate even after stop exception; unresolved means recorded target still installed; complete only with no failures/unresolved.
- [ ] `ReconcileAsync`: use only journal targets/pending identity; never enumerate-and-stop unrelated new services and never capture new Enable. Preserve journal and typed safe errors on failure.
- [ ] Add a test where recorded `external` and unrelated `new-after-crash` coexist: only `external` is stopped. Add pending Enable test proving journal write precedes wait and late selected tunnel is stopped.
- [ ] Run coordinator and journal tests; expect all pass.

## Task 5: Integrate the existing application-close orchestrator

**Files:**
- Modify `src/WireguardSplitTunnel.Core/Updates/ApplicationCloseOrchestrator.cs`
- Modify `tests/WireguardSplitTunnel.Core.Tests/ApplicationCloseOrchestratorTests.cs`

- [ ] Add failing exact-order, failure, maintenance-bypass, and repeated-close tests.
- [ ] Run orchestrator tests and confirm new constructor/result behavior fails.
- [ ] Add optional `IUserCloseDisconnectParticipant? userCloseDisconnect`, `ApplicationCloseFailureFlags.UserCloseDisconnect`, `DisconnectResult`, and result-driven `CanClose`.

```csharp
var order = new List<string>();
// Expected user-close order:
order.Should().Equal(
    "StopUpdateWork", "PrepareDisconnect", "AcquireSoftware", "AcquireRenew",
    "RestoreRoutes", "DisconnectTunnels", "SavePrimaryState",
    "ReleaseRenew", "ReleaseSoftware", "AuthorizeAndLaunch");
```

- [ ] Invoke only for `ApplicationCloseIntent.UserOrApplicationClose` with participant supplied. Call `PrepareAsync` after `StopForCloseAsync` and before acquiring routing gates, so pending Enable is journaled before waiting.
- [ ] Inside the existing routing callback: existing route restoration → disconnect → save only if both succeeded. Route failure still attempts disconnect but blocks save/authorization/normal close.
- [ ] On preparation/disconnect/verification/cancellation failure set `UserCloseDisconnect`, skip final save and update authorization, and return `CanClose == false`.
- [ ] InstallerMaintenance, SessionEnding, ElevationHandoff, and UnknownOrAbnormal never call the participant. Existing update eligibility remains after successful disconnect/save.
- [ ] Run close-intent, close-orchestrator, and ConfigCheck close/recovery tests; expect all pass.

## Task 6: Elevated stop adapter, WPF close/retry, and startup reconciliation

**Files:**
- Create `src/WireguardSplitTunnel.Core/Services/WindowsElevatedTunnelStopAdapter.cs`
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/WindowsElevatedTunnelStopAdapterTests.cs`
- Create `tests/WireguardSplitTunnel.Core.Tests/WindowsCloseDisconnectWiringContractTests.cs`

- [ ] Write failing adapter tests for one exact elevated batch, no-target no-process, nonzero exit, `Win32Exception`, non-cancelable wait, and sanitized errors.
- [ ] Implement `WindowsTunnelStopException` and `WindowsElevatedTunnelStopAdapter` through `IEnableTunnelProcessFactory`, `WindowsCloseDisconnectCommandBuilder`, and the existing WireGuard executable resolver. No registry/service enumeration or shell output in the adapter.
- [ ] Compose `EnableTunnelCoordinator` before close orchestration. Create one `FileCloseDisconnectJournal`, `CloseDisconnectCoordinator`, enumerator, and elevated stop adapter; retain them as fields and create a fresh close orchestrator for explicit retry while repeated close joins the active attempt.
- [ ] Immediately after successful Test Config startup recovery and before interface detection, automatic Enable, renewal, DNS/software work, or update startup, reconcile close journals through existing routing gates. Failure leaves journal intact, blocks those stages, displays exact unresolved service names, and returns.
- [ ] Replace unconditional user-close `finally { Close(); }` with result-driven close. Keep mutation guards active during failure/retry. Do not use forced timeout to outrun an uncancellable Enable or active disconnect.
- [ ] On failure show unresolved full service names and `MessageBoxButton.YesNoCancel`: Yes = Retry, No = Close anyway, Cancel = keep open. Close anyway requires a second warning that normal networking was not restored, no staged update will install, and cleanup is not marked successful.
- [ ] Only successful close disposes update state and resumes existing close. Close anyway directly closes without journal completion, save, disconnect, or update authorization. Maintenance retains its existing close behavior and never creates close journal entries.
- [ ] Add meaningful behavioral tests for close retry/reentry plus limited source wiring checks for startup order, maintenance bypass, selected identity, and absence of unconditional close.
- [ ] Run adapter, close wiring, update wiring, DNS integration, and coordinator tests; expect all pass.

## Task 7: Documentation and full offline verification

**Files:**
- Modify `README.md`
- Modify the stale startup comment in `MainWindow.xaml.cs`
- Modify `tests/WireguardSplitTunnel.Core.Tests/WindowsCloseDisconnectWiringContractTests.cs`

- [ ] Add a documentation contract test requiring all-service disconnect, external-service inclusion, maintenance preservation, Retry/Close anyway, recorded-only reconciliation, and update-after-success semantics.
- [ ] Update README close sections: route cleanup first; stop/uninstall all installed WireGuard tunnels including external; no-target no elevation; verified disconnect before save/update; failure choices; interrupted-close journal scope; maintenance exception; crash/Task Manager/power-loss limits; offline tests do not prove live restoration.
- [ ] Run every focused close-disconnect test using the configured dotnet environment and `--no-restore`; expect zero failures.
- [ ] Run all non-Mac Core tests with `--filter "FullyQualifiedName!~Mac"`; expect zero failures.
- [ ] Run safe ordinary WindowsUpdate tests without privileged native filters/environment; report environment skips/failures exactly and do not run real updates.
- [ ] Build `src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj --no-restore`; expect zero errors and inspect warnings.
- [ ] Run `git diff --check`, `git status --short`, and `git rev-parse HEAD`; preserve Test Config and unrelated files, confirm HEAD unchanged and no commits.
- [ ] Dispatch a fresh final whole-change reviewer. Fix all Critical/Important findings and re-review before reporting completion.

## Verification limits

Offline green tests prove deterministic ordering, exact target selection, journaling, failure propagation, retry, update gating, and compilation only. Real elevated service removal, route restoration, updater handoff, actual networking, and late real-process behavior require separately authorized live tests.
