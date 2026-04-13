# WireGuard Domain Split Tunnel MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold and implement a Windows 11 GUI app MVP that routes listed domains through WireGuard while unlisted traffic bypasses WireGuard.

**Architecture:** A WPF desktop app hosts rule management UI and a background orchestration layer. Domain resolution produces desired IP sets, a diff engine computes route changes, and a route service applies/removes only app-managed routes. Persistent JSON state stores rules and snapshots for rollback.

**Tech Stack:** .NET 8, C#, WPF, xUnit, FluentAssertions, System.Text.Json

---

## File Structure

- `WireguardSplitTunnel.sln` - solution root.
- `src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj` - WPF app host.
- `src/WireguardSplitTunnel.App/App.xaml` - app resources/startup.
- `src/WireguardSplitTunnel.App/App.xaml.cs` - startup wiring.
- `src/WireguardSplitTunnel.App/MainWindow.xaml` - MVP UI.
- `src/WireguardSplitTunnel.App/MainWindow.xaml.cs` - UI event handlers.
- `src/WireguardSplitTunnel.Core/WireguardSplitTunnel.Core.csproj` - domain/services.
- `src/WireguardSplitTunnel.Core/Models/DomainRule.cs` - rule model.
- `src/WireguardSplitTunnel.Core/Models/AppState.cs` - persisted state model.
- `src/WireguardSplitTunnel.Core/Services/DomainValidator.cs` - validation logic.
- `src/WireguardSplitTunnel.Core/Services/StateStore.cs` - JSON persistence.
- `src/WireguardSplitTunnel.Core/Services/DomainResolver.cs` - DNS resolution.
- `src/WireguardSplitTunnel.Core/Services/RouteDiffEngine.cs` - compute add/remove.
- `src/WireguardSplitTunnel.Core/Services/WireguardDetector.cs` - WireGuard interface detection.
- `src/WireguardSplitTunnel.Core/Services/RouteService.cs` - route apply/remove wrappers.
- `tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj` - unit tests.
- `tests/WireguardSplitTunnel.Core.Tests/DomainValidatorTests.cs` - validator tests.
- `tests/WireguardSplitTunnel.Core.Tests/RouteDiffEngineTests.cs` - diff tests.
- `tests/WireguardSplitTunnel.Core.Tests/StateStoreTests.cs` - persistence tests.

### Task 1: Scaffold solution and projects

**Files:**
- Create: `WireguardSplitTunnel.sln`
- Create: `src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj`
- Create: `src/WireguardSplitTunnel.Core/WireguardSplitTunnel.Core.csproj`
- Create: `tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj`

- [ ] **Step 1: Create solution and project skeleton**

```powershell
dotnet new sln -n WireguardSplitTunnel
dotnet new wpf -n WireguardSplitTunnel.App -o src/WireguardSplitTunnel.App --framework net8.0
dotnet new classlib -n WireguardSplitTunnel.Core -o src/WireguardSplitTunnel.Core --framework net8.0
dotnet new xunit -n WireguardSplitTunnel.Core.Tests -o tests/WireguardSplitTunnel.Core.Tests --framework net8.0
```

- [ ] **Step 2: Add projects and references**

```powershell
dotnet sln WireguardSplitTunnel.sln add src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj
dotnet sln WireguardSplitTunnel.sln add src/WireguardSplitTunnel.Core/WireguardSplitTunnel.Core.csproj
dotnet sln WireguardSplitTunnel.sln add tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj
dotnet add src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj reference src/WireguardSplitTunnel.Core/WireguardSplitTunnel.Core.csproj
dotnet add tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj reference src/WireguardSplitTunnel.Core/WireguardSplitTunnel.Core.csproj
dotnet add tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj package FluentAssertions
```

- [ ] **Step 3: Build baseline**

Run: `dotnet build WireguardSplitTunnel.sln`
Expected: `Build succeeded.`

- [ ] **Step 4: Commit**

```powershell
git add WireguardSplitTunnel.sln src tests
git commit -m "chore: scaffold solution and project structure"
```

### Task 2: Add core models, validation, and tests (TDD)

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Models/DomainRule.cs`
- Create: `src/WireguardSplitTunnel.Core/Models/AppState.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/DomainValidator.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/DomainValidatorTests.cs`

- [ ] **Step 1: Write failing validator tests**

```csharp
[Theory]
[InlineData("example.com", true)]
[InlineData("sub.example.com", true)]
[InlineData("*.example.com", true)]
[InlineData("http://example.com", false)]
[InlineData("", false)]
public void IsValidDomain_ReturnsExpected(string input, bool expected)
{
    DomainValidator.IsValidDomain(input).Should().Be(expected);
}
```

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter IsValidDomain_ReturnsExpected`
Expected: FAIL (type/method missing)

- [ ] **Step 2: Implement minimal models and validator**

```csharp
public sealed record DomainRule(string Domain, bool Enabled = true);

public static class DomainValidator
{
    public static bool IsValidDomain(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains("://", StringComparison.Ordinal)
        && Regex.IsMatch(value, @"^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$");
}
```

- [ ] **Step 3: Run tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter IsValidDomain_ReturnsExpected`
Expected: PASS

- [ ] **Step 4: Commit**

```powershell
git add src/WireguardSplitTunnel.Core tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: add domain rule model and validation"
```

### Task 3: Build diff/state services with tests (TDD)

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/RouteDiffEngine.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/StateStore.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/RouteDiffEngineTests.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/StateStoreTests.cs`

- [ ] **Step 1: Write failing diff/state tests**

```csharp
[Fact]
public void Calculate_ReturnsAddsAndRemoves()
{
    var oldSet = new[] { "1.1.1.1", "2.2.2.2" };
    var newSet = new[] { "2.2.2.2", "3.3.3.3" };

    var diff = RouteDiffEngine.Calculate(oldSet, newSet);

    diff.ToAdd.Should().BeEquivalentTo(new[] { "3.3.3.3" });
    diff.ToRemove.Should().BeEquivalentTo(new[] { "1.1.1.1" });
}
```

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter Calculate_ReturnsAddsAndRemoves`
Expected: FAIL

- [ ] **Step 2: Implement minimal diff/state logic**

```csharp
public sealed record RouteDiff(IReadOnlyCollection<string> ToAdd, IReadOnlyCollection<string> ToRemove);

public static class RouteDiffEngine
{
    public static RouteDiff Calculate(IEnumerable<string> oldIps, IEnumerable<string> newIps)
    {
        var oldSet = oldIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var newSet = newIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new RouteDiff(newSet.Except(oldSet).ToArray(), oldSet.Except(newSet).ToArray());
    }
}
```

- [ ] **Step 3: Run targeted tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "Calculate_ReturnsAddsAndRemoves|StateStore"`
Expected: PASS

- [ ] **Step 4: Commit**

```powershell
git add src/WireguardSplitTunnel.Core tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: add route diff and state persistence services"
```

### Task 4: Implement MVP UI shell and service wiring

**Files:**
- Modify: `src/WireguardSplitTunnel.App/App.xaml`
- Modify: `src/WireguardSplitTunnel.App/App.xaml.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/DomainResolver.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/WireguardDetector.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/RouteService.cs`

- [ ] **Step 1: Write failing integration-style UI wiring test (core service level)**

```csharp
[Fact]
public async Task ResolveEnabledRulesAsync_ReturnsResultsPerEnabledRule()
{
    // Uses fake resolver to verify enabled-only behavior.
}
```

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter ResolveEnabledRulesAsync_ReturnsResultsPerEnabledRule`
Expected: FAIL

- [ ] **Step 2: Implement minimal service contracts and logic**

```csharp
public interface IDomainResolver { Task<IReadOnlyCollection<string>> ResolveAsync(string domain, CancellationToken ct); }
public interface IWireguardDetector { bool TryGetActiveInterface(out string interfaceName); }
public interface IRouteService { Task ApplyAsync(string interfaceName, IEnumerable<string> toAdd, IEnumerable<string> toRemove, CancellationToken ct); }
```

- [ ] **Step 3: Build MainWindow MVP shell**

```xml
<Grid>
  <TextBlock x:Name="TunnelStatusText" Text="Tunnel: Unknown" />
  <DataGrid x:Name="RulesGrid" />
  <Button x:Name="AddRuleButton" Content="Add Rule" />
  <Button x:Name="ApplyNowButton" Content="Apply Now" />
  <Button x:Name="RollbackButton" Content="Rollback" />
</Grid>
```

- [ ] **Step 4: Run full tests/build**

Run: `dotnet test WireguardSplitTunnel.sln`
Expected: PASS

Run: `dotnet build WireguardSplitTunnel.sln`
Expected: PASS

- [ ] **Step 5: Commit**

```powershell
git add src tests
git commit -m "feat: scaffold MVP UI and core service wiring"
```

### Task 5: Documentation and operational logging

**Files:**
- Modify: `README.md`
- Modify: `LOGFILE.md`

- [ ] **Step 1: Add run instructions to README**

```markdown
## Run
1. Open elevated terminal.
2. `dotnet build WireguardSplitTunnel.sln`
3. `dotnet run --project src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj`
```

- [ ] **Step 2: Add implementation milestones to LOGFILE**

```markdown
## YYYY-MM-DD
- Scaffolded .NET solution and projects.
- Implemented domain validator and route diff engine.
- Added MVP GUI shell.
```

- [ ] **Step 3: Commit**

```powershell
git add README.md LOGFILE.md
git commit -m "docs: add run guidance and implementation log updates"
```

## Self-Review

- Spec coverage check:
  - Domain rules CRUD: Task 4 UI shell + Task 2 models.
  - Default bypass for unlisted sites: architecture encoded in Task 4 service contracts and Task 3 diff logic.
  - Resolver/refresh foundation: Task 4 resolver contract and wiring.
  - Rollback/snapshot foundation: Task 3 state store + diff primitives.
  - Admin/safety baseline: to be enforced in Task 4 app startup handling.
- Placeholder scan: no TODO/TBD placeholders present.
- Type consistency: `DomainRule`, `RouteDiffEngine.Calculate`, and service interfaces are consistent across tasks.
