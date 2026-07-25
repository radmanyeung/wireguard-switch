# Incremental AI Domain Route Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Learn Claude and ChatGPT wildcard subdomain IPv4 addresses after startup and add their WireGuard `/32` routes without background route removal.

**Architecture:** A testable Core reconciler reads the Windows DNS cache, delegates filtering to the existing learner, builds an additive-only plan, applies route additions through a callback, and mutates state only after the callback succeeds. A 10-second WPF timer runs the reconciler under the existing renew semaphore. A conservative legacy Claude migration adds new preset members only to complete, unmodified old presets.

**Tech Stack:** C# 12, .NET 8, WPF `DispatcherTimer`, xUnit, FluentAssertions

**Repository rule:** Do not stage, commit, or push until the user separately approves those actions. Keep `logs/*.log` untouched and unstaged.

---

### Task 1: Additive planner and incremental state merge

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/IncrementalDomainRouteApplyPlanner.cs`
- Modify: `src/WireguardSplitTunnel.Core/Services/ResolutionStateUpdater.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/IncrementalDomainRouteApplyPlannerTests.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/ResolutionStateUpdaterTests.cs`

- [ ] **Step 1: Write failing planner tests**

Cover a late learned wildcard IP, preservation of existing/stale snapshot entries,
idempotence after the snapshot contains the learned IP, and rejection of learned
results whose current state rule is disabled, bypass, or exact-domain.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~IncrementalDomainRouteApplyPlannerTests|FullyQualifiedName~ResolutionStateUpdaterTests"
```

Expected: compilation or assertion failure because the additive planner and
incremental merge API do not exist.

- [ ] **Step 3: Implement the minimal planner**

Create:

```csharp
public sealed record IncrementalDomainRouteApplyPlan(
    IReadOnlyList<ManagedRouteEntry> Snapshot,
    IReadOnlyList<string> ToAdd,
    IReadOnlyCollection<ResolvedRule> LearnedRules);

public static class IncrementalDomainRouteApplyPlanner
{
    public static IncrementalDomainRouteApplyPlan Build(
        AppState state,
        IEnumerable<ResolvedRule> learnedRules);
}
```

`Build` must retain the old snapshot, add only IPs absent from that snapshot,
return no removal API, and include only active wildcard `UseWireGuard` domains.

- [ ] **Step 4: Implement incremental metadata merge**

Add:

```csharp
public static bool MergeIncremental(
    AppState state,
    IEnumerable<ResolvedRule> resolvedRules);
```

Merge only touched domains, preserve unrelated state, prefer direct provenance
over learned provenance, and return `false` when processing the same values
again causes no state change.

- [ ] **Step 5: Run the focused tests and confirm GREEN**

Use the Step 2 command. Expected: all selected tests pass.

### Task 2: Executable late-DNS reconciliation

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/IncrementalDnsRouteReconciler.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/IncrementalDnsRouteReconcilerTests.cs`

- [ ] **Step 1: Write failing reconciler tests**

Use a deterministic `IDnsCacheReader` and a capturing route callback to prove:

- a cache entry appearing after the initial state yields exactly one route add;
- a second reconciliation is idempotent and does not invoke the callback;
- callback failure leaves snapshot and last-known metadata unchanged;
- root-domain, invalid, IPv6, disabled, bypass, and exact-domain entries do not
  produce additions.

- [ ] **Step 2: Run the focused reconciler tests and confirm RED**

Run:

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter FullyQualifiedName~IncrementalDnsRouteReconcilerTests
```

Expected: compilation failure because the reconciler does not exist.

- [ ] **Step 3: Implement the minimal reconciler**

Create:

```csharp
public sealed record IncrementalDnsRouteReconcileResult(
    int LearnedIpCount,
    int AddedRouteCount,
    bool StateChanged);

public sealed class IncrementalDnsRouteReconciler
{
    public IncrementalDnsRouteReconciler(IDnsCacheReader dnsCacheReader);

    public Task<IncrementalDnsRouteReconcileResult> ReconcileAsync(
        AppState state,
        Func<IReadOnlyCollection<string>, CancellationToken, Task> addRoutesAsync,
        CancellationToken cancellationToken);
}
```

Call the route callback before mutating state. The callback accepts additions
only, so this path cannot delete routes.

- [ ] **Step 4: Run the focused tests and confirm GREEN**

Use the Step 2 command. Expected: all selected tests pass.

### Task 3: Claude preset and conservative migration

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Services/DomainPresetService.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/LegacyClaudePresetMigrationService.cs`
- Modify: `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/DomainPresetServiceTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/LegacyClaudePresetMigrationServiceTests.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`

- [ ] **Step 1: Write failing preset and migration tests**

Require `claude.com`, `*.claude.com`, and `downloads.claude.ai`. Require automatic
migration only when all six old Claude preset rules exist and every matching
duplicate is enabled in `UseWireGuard`; prove partial/customized states remain
untouched and repeated migration creates no duplicates.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~DomainPresetServiceTests|FullyQualifiedName~LegacyClaudePresetMigrationServiceTests|FullyQualifiedName~PrimaryAppStateLoaderTests"
```

Expected: missing-domain assertions and missing migration type fail.

- [ ] **Step 3: Implement preset and migration changes**

Append the three approved domains to `ClaudeAnthropicDomains`. Add a migration
service matching the existing OpenAI eligibility rules. Run both migrations in
`PrimaryAppStateLoader.Load` and save once when either adds a rule.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command. Expected: all selected tests pass.

### Task 4: Windows periodic timer integration

**Files:**
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`

- [ ] **Step 1: Add lifecycle fields**

Add a 10-second `DispatcherTimer`, a close cancellation source, and an
`IncrementalDnsRouteReconciler` built from the existing DNS-cache reader.

- [ ] **Step 2: Integrate startup and shutdown**

Subscribe the timer in the constructor, start it after startup initialization,
and stop/cancel it in `OnWindowClosing`.

- [ ] **Step 3: Add a non-blocking timer tick**

Skip when closing, WireGuard is absent, or `renewSemaphore.WaitAsync(0)` fails.
While holding the semaphore, call the reconciler with an add-only callback that
uses `ApplyRoutesViaCurrentWireGuardAsync(toAdd, [], token)` and route healing.
Save both state stores and refresh the grid only when `StateChanged` is true.
Log exceptions without recurring UI dialogs.

- [ ] **Step 4: Compile the Windows application**

Run:

```powershell
dotnet build .\src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj -c Release
```

Expected: build succeeds with zero errors.

### Task 5: Regression, release, and runtime verification

**Files:**
- Verify: `Directory.Build.props`
- Verify: `tests/WireguardSplitTunnel.Core.Tests/ReleaseVersionMetadataTests.cs`
- Verify only: `scripts/start.ps1`

- [ ] **Step 1: Run the full Release suite**

Run:

```powershell
dotnet test .\WireguardSplitTunnel.sln -c Release
```

Expected: every test passes, including v0.1.9 metadata checks.

- [ ] **Step 2: Close only the running Wireguard Split Tunnel process**

Identify the executable path and stop only that process so Release outputs are
not locked. Do not stop WireGuard or unrelated applications.

- [ ] **Step 3: Build Release and verify launcher resolution**

Run the repository build script, then:

```powershell
.\scripts\start.ps1 -DryRun
```

Expected: the launcher resolves the newly built v0.1.9 executable.

- [ ] **Step 4: Restart the GUI**

Start through the repository launcher and confirm the process remains running.

- [ ] **Step 5: Verify live Windows and WSL routing**

Resolve `downloads.claude.ai`, confirm a Windows `/32` route uses the active
WireGuard interface, and run `ip -4 route get <resolved-ip>` in `Ubuntu-vllm`.
Expected: WSL selects the mirrored WireGuard interface (`eth7` in the diagnosed
environment), not the LAN interface.

- [ ] **Step 6: Review the final diff**

Confirm only source, tests, version metadata, and the two new design/plan
documents are intended changes. Leave all `logs/*.log` unstaged. Report results
and ask separately before any commit or push.
