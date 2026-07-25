# OpenAI Preset State Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically and safely add the three OpenAI login helper-domain rules when the primary saved state exactly matches the enabled legacy OpenAI preset signature.

**Architecture:** A pure `LegacyOpenAiPresetMigrationService` identifies the immutable 11-domain legacy signature and adds only missing helper rules. A separate `PrimaryAppStateLoader` applies that migration and saves only changed primary state, while ordinary `StateStore.Load()` remains migration-free for rollback and temporary files. Windows and macOS primary-state initialization both use the new loader.

**Tech Stack:** .NET 8, C#, xUnit, FluentAssertions, WPF, Avalonia

**Workspace constraint:** Execute directly in `D:\wireguard switch`, preserve the existing `logs/*` changes, and do not create a commit until the user explicitly approves one.

---

## File Structure

- Create `src/WireguardSplitTunnel.Core/Services/LegacyOpenAiPresetMigrationService.cs`: pure legacy-signature detection and idempotent rule addition.
- Create `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`: primary-state load, migrate, and save-if-changed orchestration.
- Create `tests/WireguardSplitTunnel.Core.Tests/LegacyOpenAiPresetMigrationServiceTests.cs`: conservative matching and idempotence regression tests.
- Create `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`: persistence, ordinary-load isolation, and Windows/macOS wiring tests.
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`: load the Windows primary state through `PrimaryAppStateLoader`.
- Modify `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs`: load the macOS primary state through `PrimaryAppStateLoader`.

### Task 1: Implement the pure legacy OpenAI preset migration

**Files:**

- Create: `tests/WireguardSplitTunnel.Core.Tests/LegacyOpenAiPresetMigrationServiceTests.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/LegacyOpenAiPresetMigrationService.cs`

- [ ] **Step 1: Write the failing migration tests**

Create `tests/WireguardSplitTunnel.Core.Tests/LegacyOpenAiPresetMigrationServiceTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class LegacyOpenAiPresetMigrationServiceTests
{
    private static readonly string[] LegacyDomains =
    [
        "chatgpt.com",
        "*.chatgpt.com",
        "openai.com",
        "*.openai.com",
        "auth.openai.com",
        "api.openai.com",
        "platform.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
        "oaiusercontent.com",
        "*.oaiusercontent.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "files.oaiusercontent.com",
        "challenges.cloudflare.com",
        "cdn.auth0.com"
    ];

    [Fact]
    public void Migrate_AddsThreeHelpers_WhenCompleteLegacyPresetIsEnabledForWireGuard()
    {
        var state = CreateLegacyState();
        state.DomainRules.Add(new DomainRule("one.google.com", true, DomainRouteMode.UseWireGuard));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(3);
        state.DomainRules.Select(rule => rule.Domain).Should().Contain(HelperDomains);
        state.DomainRules
            .Where(rule => HelperDomains.Contains(rule.Domain, StringComparer.OrdinalIgnoreCase))
            .Should().OnlyContain(rule => rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
    }

    [Fact]
    public void Migrate_IsIdempotent()
    {
        var state = CreateLegacyState();

        LegacyOpenAiPresetMigrationService.Migrate(state).Added.Should().Be(3);
        LegacyOpenAiPresetMigrationService.Migrate(state).Added.Should().Be(0);

        state.DomainRules.Select(rule => rule.Domain).Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void Migrate_DoesNothing_WhenLegacyPresetIsPartial()
    {
        var state = CreateLegacyState();
        state.DomainRules.RemoveAll(rule =>
            string.Equals(rule.Domain, "platform.openai.com", StringComparison.OrdinalIgnoreCase));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        state.DomainRules.Select(rule => rule.Domain).Should().NotContain(HelperDomains);
    }

    [Theory]
    [InlineData(false, DomainRouteMode.UseWireGuard)]
    [InlineData(true, DomainRouteMode.BypassWireGuard)]
    public void Migrate_DoesNothing_WhenLegacyRuleWasCustomized(bool enabled, DomainRouteMode mode)
    {
        var state = CreateLegacyState();
        var index = state.DomainRules.FindIndex(rule =>
            string.Equals(rule.Domain, "auth.openai.com", StringComparison.OrdinalIgnoreCase));
        state.DomainRules[index] = state.DomainRules[index] with { Enabled = enabled, Mode = mode };

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        state.DomainRules.Select(rule => rule.Domain).Should().NotContain(HelperDomains);
    }

    [Fact]
    public void Migrate_PreservesExistingCustomizedHelperRule()
    {
        var state = CreateLegacyState();
        state.DomainRules.Add(new DomainRule(
            "files.oaiusercontent.com",
            false,
            DomainRouteMode.BypassWireGuard));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(2);
        state.DomainRules.Single(rule => rule.Domain == "files.oaiusercontent.com")
            .Should().Be(new DomainRule(
                "files.oaiusercontent.com",
                false,
                DomainRouteMode.BypassWireGuard));
    }

    private static AppState CreateLegacyState() =>
        new(
            LegacyDomains
                .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
                .ToList(),
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
            []);
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
dotnet test tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~LegacyOpenAiPresetMigrationServiceTests
```

Expected: FAIL because `LegacyOpenAiPresetMigrationService` does not exist. Confirm the failure names that missing type rather than a test syntax or setup problem.

- [ ] **Step 3: Implement the minimal pure migration service**

Create `src/WireguardSplitTunnel.Core/Services/LegacyOpenAiPresetMigrationService.cs`:

```csharp
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record LegacyOpenAiPresetMigrationResult(int Added);

public static class LegacyOpenAiPresetMigrationService
{
    private static readonly string[] LegacyDomains =
    [
        "chatgpt.com",
        "*.chatgpt.com",
        "openai.com",
        "*.openai.com",
        "auth.openai.com",
        "api.openai.com",
        "platform.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
        "oaiusercontent.com",
        "*.oaiusercontent.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "files.oaiusercontent.com",
        "challenges.cloudflare.com",
        "cdn.auth0.com"
    ];

    public static LegacyOpenAiPresetMigrationResult Migrate(AppState state)
    {
        var matchesLegacyPreset = LegacyDomains.All(domain =>
            state.DomainRules.Any(rule =>
                string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase)
                && rule.Enabled
                && rule.Mode == DomainRouteMode.UseWireGuard));

        if (!matchesLegacyPreset)
        {
            return new LegacyOpenAiPresetMigrationResult(0);
        }

        var added = 0;
        foreach (var domain in HelperDomains)
        {
            if (RuleStateMutations.TryAddDomainRule(state, domain, DomainRouteMode.UseWireGuard))
            {
                added++;
            }
        }

        return new LegacyOpenAiPresetMigrationResult(added);
    }
}
```

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```powershell
dotnet test tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~LegacyOpenAiPresetMigrationServiceTests
```

Expected: PASS, six test cases successful with no failures; the theory contributes two cases.

- [ ] **Step 5: Review Task 1 scope without committing**

Run:

```powershell
git diff --check -- src\WireguardSplitTunnel.Core\Services\LegacyOpenAiPresetMigrationService.cs tests\WireguardSplitTunnel.Core.Tests\LegacyOpenAiPresetMigrationServiceTests.cs
git status --short
```

Expected: no diff-check errors; the two intended files are untracked or modified, and the pre-existing `logs/*` changes remain untouched. Do not stage or commit.

### Task 2: Persist migration only for primary state and wire both apps

**Files:**

- Create: `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs:90-93`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:45-48`

- [ ] **Step 1: Write the failing primary-state loader tests**

Create `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class PrimaryAppStateLoaderTests
{
    private static readonly string[] LegacyDomains =
    [
        "chatgpt.com",
        "*.chatgpt.com",
        "openai.com",
        "*.openai.com",
        "auth.openai.com",
        "api.openai.com",
        "platform.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
        "oaiusercontent.com",
        "*.oaiusercontent.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "files.oaiusercontent.com",
        "challenges.cloudflare.com",
        "cdn.auth0.com"
    ];

    [Fact]
    public void Load_MigratesAndPersistsCompleteLegacyPrimaryState()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyState());

            var loaded = PrimaryAppStateLoader.Load(store);
            var persisted = store.Load();

            loaded.DomainRules.Select(rule => rule.Domain).Should().Contain(HelperDomains);
            persisted.DomainRules.Select(rule => rule.Domain).Should().Contain(HelperDomains);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void StateStoreLoad_RemainsMigrationFree()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyState());

            var loaded = store.Load();

            loaded.DomainRules.Select(rule => rule.Domain).Should().NotContain(HelperDomains);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void ApplicationEntrypoints_UsePrimaryStateLoader()
    {
        var windowsSource = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");
        var macSource = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");

        windowsSource.Should().Contain("state = PrimaryAppStateLoader.Load(stateStore);");
        macSource.Should().Contain("appState = PrimaryAppStateLoader.Load(stateStore);");
    }

    private static AppState CreateLegacyState() =>
        new(
            LegacyDomains
                .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
                .ToList(),
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
            []);

    private static string CreateTestPath()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "test-temp");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"{Guid.NewGuid():N}.json");
    }

    private static void DeleteIfPresent(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(
            root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md"))
                && Directory.Exists(Path.Combine(directory, "src"))
                && Directory.Exists(Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
dotnet test tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~PrimaryAppStateLoaderTests
```

Expected: FAIL because `PrimaryAppStateLoader` does not exist and both app entrypoints still call `stateStore.Load()`.

- [ ] **Step 3: Implement primary-state load and save-if-changed**

Create `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`:

```csharp
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class PrimaryAppStateLoader
{
    public static AppState Load(StateStore store)
    {
        var state = store.Load();
        var migration = LegacyOpenAiPresetMigrationService.Migrate(state);
        if (migration.Added > 0)
        {
            store.Save(state);
        }

        return state;
    }
}
```

- [ ] **Step 4: Wire Windows primary-state initialization**

In `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`, replace:

```csharp
state = stateStore.Load();
```

with:

```csharp
state = PrimaryAppStateLoader.Load(stateStore);
```

- [ ] **Step 5: Wire macOS primary-state initialization**

In `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs`, replace:

```csharp
appState = stateStore.Load();
```

with:

```csharp
appState = PrimaryAppStateLoader.Load(stateStore);
```

- [ ] **Step 6: Run focused loader and migration tests and verify GREEN**

Run:

```powershell
dotnet test tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~PrimaryAppStateLoaderTests|FullyQualifiedName~LegacyOpenAiPresetMigrationServiceTests"
```

Expected: PASS, nine test cases successful with no failures.

- [ ] **Step 7: Review Task 2 scope without committing**

Run:

```powershell
git diff --check -- src tests
git diff -- src\WireguardSplitTunnel.App\MainWindow.xaml.cs src\WireguardSplitTunnel.MacApp\Views\MainWindow.axaml.cs src\WireguardSplitTunnel.Core\Services tests\WireguardSplitTunnel.Core.Tests
```

Expected: only the migration service, primary loader, their tests, and the two one-line app wiring changes appear. Do not stage or commit.

### Task 3: Verify the complete change and migrate the real state on restart

**Files:**

- Verify: `src/WireguardSplitTunnel.Core/Services/LegacyOpenAiPresetMigrationService.cs`
- Verify: `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`
- Verify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Verify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs`
- Verify: `tests/WireguardSplitTunnel.Core.Tests/LegacyOpenAiPresetMigrationServiceTests.cs`
- Verify: `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`
- Verify runtime: `%LOCALAPPDATA%\WireguardSplitTunnel\state.json`

- [ ] **Step 1: Run the full automated test suite**

Run:

```powershell
dotnet test tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release
```

Expected: PASS with zero failed tests and no build errors.

- [ ] **Step 2: Verify intended diffs and preserve runtime logs**

Run:

```powershell
git diff --check -- src tests docs\superpowers\specs\2026-07-14-openai-preset-state-migration-design.md docs\superpowers\plans\2026-07-14-openai-preset-state-migration.md
git status --short
```

Expected: no file-scoped diff errors. Existing modified/untracked `logs/*` entries remain separate and must not be staged.

- [ ] **Step 3: Check whether the running app blocks the Release build**

Run:

```powershell
Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue | Select-Object Id,StartTime,Path
```

Expected: if the app is running, stop here and ask the user for approval to close and restart it. Do not terminate it without approval.

- [ ] **Step 4: After approval, build the Release application**

Run:

```powershell
$runningApp = Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue
if ($runningApp) {
    $runningApp | Stop-Process
    $runningApp | Wait-Process
}
.\scripts\build.ps1 -c Release
```

Expected: the approved app shutdown completes, then the build completes successfully with exit code `0`.

- [ ] **Step 5: Verify what `start.cmd` will launch**

Run:

```powershell
.\scripts\start.ps1 -DryRun
```

Expected output includes:

```text
exe D:\wireguard switch\src\WireguardSplitTunnel.App\bin\Release\net8.0-windows\WireguardSplitTunnel.App.exe
```

- [ ] **Step 6: Restart through the normal launcher and verify real-state migration**

Run:

```powershell
.\start.cmd
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if (Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
}
if (-not (Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue)) {
    throw 'WireguardSplitTunnel.App did not start through start.cmd.'
}

$state = Get-Content -Raw "$env:LOCALAPPDATA\WireguardSplitTunnel\state.json" | ConvertFrom-Json
$helpers = @(
    'files.oaiusercontent.com',
    'challenges.cloudflare.com',
    'cdn.auth0.com'
)
$migrated = $state.DomainRules | Where-Object { $helpers -contains $_.Domain }
$migrated | Select-Object Domain,Enabled,Mode | Sort-Object Domain | Format-Table -AutoSize
if (@($migrated).Count -ne 3) { throw 'Expected exactly three migrated helper-domain rules.' }
if (@($migrated | Where-Object { -not $_.Enabled -or $_.Mode -ne 1 }).Count -ne 0) {
    throw 'Migrated helper-domain rules must be enabled and use WireGuard.'
}
```

Expected: exactly three helper rules, all `Enabled=True` and `Mode=1` (`UseWireGuard`). No credentials or unrelated state fields are printed.

- [ ] **Step 7: Confirm migration is idempotent at runtime**

After obtaining the required second close/restart approval, run:

```powershell
$runningApp = Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue
if ($runningApp) {
    $runningApp | Stop-Process
    $runningApp | Wait-Process
}
.\start.cmd
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    if (Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue) { break }
    Start-Sleep -Milliseconds 500
}
if (-not (Get-Process WireguardSplitTunnel.App -ErrorAction SilentlyContinue)) {
    throw 'WireguardSplitTunnel.App did not restart through start.cmd.'
}

$state = Get-Content -Raw "$env:LOCALAPPDATA\WireguardSplitTunnel\state.json" | ConvertFrom-Json
$helpers = @(
    'files.oaiusercontent.com',
    'challenges.cloudflare.com',
    'cdn.auth0.com'
)
$migrated = $state.DomainRules | Where-Object { $helpers -contains $_.Domain }
if (@($migrated).Count -ne 3) { throw 'Expected exactly three helper-domain rules after the second startup.' }
if (@($migrated | Where-Object { -not $_.Enabled -or $_.Mode -ne 1 }).Count -ne 0) {
    throw 'Helper-domain rules changed after the second startup.'
}
```

Expected: still exactly three helper-domain rules with no duplicates.

- [ ] **Step 8: Request review before claiming completion**

Run:

```powershell
git diff --stat
git status --short
```

Then request a focused code review of the migration contract, conservative match, persistence boundary, and tests. Address only verified actionable findings and rerun Steps 1, 2, 5, and 6 after any change.

- [ ] **Step 9: Ask whether to commit**

Present the verified file list and test/build/runtime evidence to the user. Ask whether they want the intended source, tests, design, and plan staged and committed. Keep every `logs/*` file unstaged unless the user explicitly requests otherwise.
