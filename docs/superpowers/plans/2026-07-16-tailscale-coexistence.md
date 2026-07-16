# Tailscale Coexistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the macOS AI split tunnel run alongside ordinary Tailscale and MagicDNS without ever selecting, routing through, monitoring, or stopping Tailscale's `utun` interface.

**Architecture:** Add a Core resolver that identifies only explicitly named app-managed WireGuard tunnels and a Core planner that builds disable targets only from named configs. Rewire the Mac UI to use those components for startup, route application, status, monitoring, disable, and exit cleanup while retaining the existing default-route guard for Tailscale Exit Node.

**Tech Stack:** .NET 8, C#, Avalonia macOS app, xUnit, FluentAssertions, macOS `wg-quick` `/var/run/wireguard` mappings.

## Global Constraints

- Support ordinary Tailscale connectivity and MagicDNS with Tailscale Exit Node off.
- Continue blocking startup when any `utun` owns the IPv4 default route.
- Resolve the split tunnel only by the exact name `wgst-split`; never infer ownership from a generic `utun`, interface number, or IP range.
- Do not stop, reconfigure, route through, or clean up a Tailscale interface.
- Do not change the WireGuard `.conf` format or add package dependencies.
- Do not log WireGuard private keys or complete configuration contents.
- Keep `README.md` and `docs/README-Mac.txt` aligned.
- Every production behavior change starts with a failing test or an explicit failing integration contract check.

---

## File Structure

- Create `src/WireguardSplitTunnel.Core/Services/MacManagedTunnelInterfaceResolver.cs`: resolve the exact `wgst-split` interface first and an explicitly persisted raw tunnel second.
- Create `tests/WireguardSplitTunnel.Core.Tests/MacManagedTunnelInterfaceResolverTests.cs`: test named ownership, split precedence, raw-tunnel lookup, and refusal to use unrelated `utun` interfaces.
- Create `src/WireguardSplitTunnel.Core/Services/MacTunnelDisablePlanner.cs`: build disable targets only from the generated split config, persisted raw tunnel, and selected config.
- Create `tests/WireguardSplitTunnel.Core.Tests/MacTunnelDisablePlannerTests.cs`: test target deduplication and the absence of an interface fallback.
- Modify `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs`: remove generic detector use from all app-managed Mac flows and consume both new Core components.
- Modify `src/WireguardSplitTunnel.Core/Services/MacQuickStartService.cs`: make the blocked-default-route message explain Tailscale Exit Node.
- Modify `tests/WireguardSplitTunnel.Core.Tests/MacQuickStartServiceTests.cs`: drive and verify the new message.
- Modify `README.md`: document ordinary Tailscale/MagicDNS support and the Exit Node restriction.
- Modify `docs/README-Mac.txt`: mirror the same Mac usage guidance.

---

### Task 1: Resolve Only App-Managed Named Tunnels

**Files:**
- Create: `tests/WireguardSplitTunnel.Core.Tests/MacManagedTunnelInterfaceResolverTests.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/MacManagedTunnelInterfaceResolver.cs`

**Interfaces:**
- Consumes: `MacTunnelNameResolver.TryGetInterfaceForTunnel(string tunnelName)` and `MacSplitTunnelConfigService.SplitTunnelName`.
- Produces: `MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface() -> string?` and `MacManagedTunnelInterfaceResolver.TryGetManagedInterface(string? activeRawTunnelName) -> string?`.
- Test seam: `MacManagedTunnelInterfaceResolver.ResolveManagedInterface(string? activeRawTunnelName, Func<string, string?> resolveByTunnelName) -> string?`.

- [ ] **Step 1: Write the failing resolver tests**

Create `tests/WireguardSplitTunnel.Core.Tests/MacManagedTunnelInterfaceResolverTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacManagedTunnelInterfaceResolverTests
{
    [Fact]
    public void ResolveManagedInterface_SplitMappingWinsOverRawTunnel()
    {
        var calls = new List<string>();
        string? Resolve(string name)
        {
            calls.Add(name);
            return name switch
            {
                MacSplitTunnelConfigService.SplitTunnelName => "utun5",
                "SG" => "utun6",
                _ => null
            };
        }

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface("SG", Resolve);

        result.Should().Be("utun5");
        calls.Should().Equal(MacSplitTunnelConfigService.SplitTunnelName);
    }

    [Fact]
    public void ResolveManagedInterface_OnlyUnrelatedTailscaleUtunExists_ReturnsNull()
    {
        const string tailscaleInterface = "utun4";

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface(
            activeRawTunnelName: null,
            resolveByTunnelName: _ => null);

        result.Should().BeNull();
        result.Should().NotBe(tailscaleInterface);
    }

    [Fact]
    public void ResolveManagedInterface_ExplicitRawTunnel_ResolvesExactName()
    {
        var requestedNames = new List<string>();
        string? Resolve(string name)
        {
            requestedNames.Add(name);
            return name == "SG" ? "utun6" : null;
        }

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface("  SG  ", Resolve);

        result.Should().Be("utun6");
        requestedNames.Should().Equal(MacSplitTunnelConfigService.SplitTunnelName, "SG");
    }

    [Fact]
    public void ResolveManagedInterface_NoNamedMappings_ReturnsNull()
    {
        MacManagedTunnelInterfaceResolver.ResolveManagedInterface("SG", _ => null)
            .Should().BeNull();
    }
}
```

- [ ] **Step 2: Run the resolver tests and verify RED**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacManagedTunnelInterfaceResolverTests
```

Expected: FAIL to compile because `MacManagedTunnelInterfaceResolver` does not exist.

- [ ] **Step 3: Add the minimal named resolver**

Create `src/WireguardSplitTunnel.Core/Services/MacManagedTunnelInterfaceResolver.cs`:

```csharp
using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

public static class MacManagedTunnelInterfaceResolver
{
    [SupportedOSPlatform("macos")]
    public static string? TryGetSplitTunnelInterface() =>
        MacTunnelNameResolver.TryGetInterfaceForTunnel(
            MacSplitTunnelConfigService.SplitTunnelName);

    [SupportedOSPlatform("macos")]
    public static string? TryGetManagedInterface(string? activeRawTunnelName) =>
        ResolveManagedInterface(
            activeRawTunnelName,
            MacTunnelNameResolver.TryGetInterfaceForTunnel);

    internal static string? ResolveManagedInterface(
        string? activeRawTunnelName,
        Func<string, string?> resolveByTunnelName)
    {
        ArgumentNullException.ThrowIfNull(resolveByTunnelName);

        var splitInterface = resolveByTunnelName(
            MacSplitTunnelConfigService.SplitTunnelName);
        if (!string.IsNullOrWhiteSpace(splitInterface))
        {
            return splitInterface;
        }

        if (string.IsNullOrWhiteSpace(activeRawTunnelName))
        {
            return null;
        }

        return resolveByTunnelName(activeRawTunnelName.Trim());
    }
}
```

- [ ] **Step 4: Run the resolver tests and verify GREEN**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacManagedTunnelInterfaceResolverTests
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit the resolver**

```bash
git add src/WireguardSplitTunnel.Core/Services/MacManagedTunnelInterfaceResolver.cs tests/WireguardSplitTunnel.Core.Tests/MacManagedTunnelInterfaceResolverTests.cs
git commit -m "feat: resolve only app-managed Mac tunnels"
```

---

### Task 2: Plan Disable Targets Without an Interface Fallback

**Files:**
- Create: `tests/WireguardSplitTunnel.Core.Tests/MacTunnelDisablePlannerTests.cs`
- Create: `src/WireguardSplitTunnel.Core/Services/MacTunnelDisablePlanner.cs`

**Interfaces:**
- Consumes: `WireguardConfigCatalog.GetTunnelName(string configPath)`.
- Produces: `MacTunnelDisablePlanner.BuildTargets(string? splitConfigPath, string? activeRawTunnelName, string? selectedConfigPath) -> IReadOnlyList<string>`.
- Later UI code supplies `null` for `splitConfigPath` when the generated file does not exist; no active `utun` interface is accepted by this API.

- [ ] **Step 1: Write the failing disable-planner tests**

Create `tests/WireguardSplitTunnel.Core.Tests/MacTunnelDisablePlannerTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacTunnelDisablePlannerTests
{
    [Fact]
    public void BuildTargets_NamedInputs_DeduplicatesTunnelNames()
    {
        var result = MacTunnelDisablePlanner.BuildTargets(
            "/data/wgst-split.conf",
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf");

        result.Should().Equal("/data/wgst-split.conf", "SG");
        result.Should().NotContain("utun4");
    }

    [Fact]
    public void BuildTargets_NoNamedInputs_ReturnsEmptyInsteadOfUsingActiveInterface()
    {
        MacTunnelDisablePlanner.BuildTargets(null, null, null)
            .Should().BeEmpty();
    }

    [Fact]
    public void BuildTargets_SelectedConfig_UsesTunnelNameNotConfigPath()
    {
        MacTunnelDisablePlanner.BuildTargets(
                null,
                null,
                "/opt/homebrew/etc/wireguard/nordusa1.conf")
            .Should().Equal("nordusa1");
    }
}
```

- [ ] **Step 2: Run the planner tests and verify RED**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacTunnelDisablePlannerTests
```

Expected: FAIL to compile because `MacTunnelDisablePlanner` does not exist.

- [ ] **Step 3: Add the minimal disable planner**

Create `src/WireguardSplitTunnel.Core/Services/MacTunnelDisablePlanner.cs`:

```csharp
namespace WireguardSplitTunnel.Core.Services;

public static class MacTunnelDisablePlanner
{
    public static IReadOnlyList<string> BuildTargets(
        string? splitConfigPath,
        string? activeRawTunnelName,
        string? selectedConfigPath)
    {
        var targets = new List<string>();

        if (!string.IsNullOrWhiteSpace(splitConfigPath))
        {
            targets.Add(splitConfigPath);
        }

        if (!string.IsNullOrWhiteSpace(activeRawTunnelName))
        {
            targets.Add(activeRawTunnelName.Trim());
        }

        if (!string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            targets.Add(WireguardConfigCatalog.GetTunnelName(selectedConfigPath));
        }

        return targets
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
```

- [ ] **Step 4: Run the planner tests and verify GREEN**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacTunnelDisablePlannerTests
```

Expected: PASS, 3 tests.

- [ ] **Step 5: Commit the disable planner**

```bash
git add src/WireguardSplitTunnel.Core/Services/MacTunnelDisablePlanner.cs tests/WireguardSplitTunnel.Core.Tests/MacTunnelDisablePlannerTests.cs
git commit -m "feat: restrict Mac tunnel disable targets"
```

---

### Task 3: Wire Every Mac Managed Flow to the Named Resolver

**Files:**
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:16-28`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:232-290`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:367-379`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:646-667`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:824-839`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:978-1007`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:1056-1080`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:1113-1119`

**Interfaces:**
- Consumes: `MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface()`, `MacManagedTunnelInterfaceResolver.TryGetManagedInterface(string?)`, and `MacTunnelDisablePlanner.BuildTargets(string?, string?, string?)` from Tasks 1-2.
- Produces: one Mac UI ownership rule: only the named split tunnel or explicit raw tunnel can drive routes, status, monitoring, disable, or cleanup.

- [ ] **Step 1: Verify the existing wiring violates the integration contract**

Run:

```bash
rg -n "detector|SystemWireguardDetector|TryGetActiveInterface" src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs
```

Expected: matches for the detector field and generic calls in Apply Routes,
Monitor refresh, startup wait, and status refresh. These matches are the failing
integration contract because any one can select Tailscale.

- [ ] **Step 2: Remove the generic detector field**

Delete this field from `MainWindow`:

```csharp
private readonly IWireguardDetector detector = new SystemWireguardDetector();
```

- [ ] **Step 3: Replace disable-target collection with the named planner**

Replace the target-building block at the start of `OnDisableTunnelClick` with:

```csharp
var splitConfigPath = Path.Combine(
    GetDataDirectory(),
    MacSplitTunnelConfigService.SplitTunnelConfigFileName);
var targets = MacTunnelDisablePlanner.BuildTargets(
    File.Exists(splitConfigPath) ? splitConfigPath : null,
    appState.ActiveRawTunnelName,
    selectedConfigPath);
```

Keep the existing `targets.Count == 0`, loop, state reset, and button-guard code.
Delete the `activeTunnelName` fallback entirely.

- [ ] **Step 4: Pin manual Apply Routes to a managed named tunnel**

Replace `OnApplyRoutesClick` with:

```csharp
private async void OnApplyRoutesClick(object? sender, RoutedEventArgs e)
{
    var iface = MacManagedTunnelInterfaceResolver.TryGetManagedInterface(
        appState.ActiveRawTunnelName);
    if (iface is null)
    {
        Log("no app-managed WireGuard tunnel detected. Start AI VPN or enable the selected tunnel first.");
        return;
    }

    await RunGuardedAsync("apply routes", async ct =>
    {
        await ApplyDomainRoutesAsync(iface, ct);
    });
}
```

- [ ] **Step 5: Pin every Monitor sample to the managed named tunnel**

Replace the detector call in `RefreshNetworkMonitorAsync` with:

```csharp
var wireGuardInterfaceName =
    MacManagedTunnelInterfaceResolver.TryGetManagedInterface(
        appState.ActiveRawTunnelName);
var snapshot = await networkMonitorService.CaptureAsync(
    appState,
    wireGuardInterfaceName,
    cts.Token);
```

- [ ] **Step 6: Wait specifically for `wgst-split` during Start AI VPN**

Replace `WaitForWireGuardInterfaceAsync` with:

```csharp
private async Task<string> WaitForWireGuardInterfaceAsync(
    CancellationToken cancellationToken)
{
    for (var attempt = 0; attempt < 12; attempt++)
    {
        var iface =
            MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface();
        if (iface is not null)
        {
            activeTunnelName = iface;
            return iface;
        }

        await Task.Delay(500, cancellationToken);
    }

    throw new InvalidOperationException(
        "The wgst-split tunnel started, but its WireGuard interface mapping was not detected. Routes were not applied; Tailscale was left unchanged.");
}
```

- [ ] **Step 7: Use the managed resolver for adoption and status**

In `AdoptLeftoverTunnel`, replace the split lookup with:

```csharp
var adopted =
    MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface();
```

Replace `RefreshTunnelStatus` with:

```csharp
private void RefreshTunnelStatus()
{
    var iface = MacManagedTunnelInterfaceResolver.TryGetManagedInterface(
        appState.ActiveRawTunnelName);
    if (iface is not null)
    {
        activeTunnelName = iface;
        TunnelStatusText.Text = $"connected via {iface}";
        TunnelStatusText.Foreground = Brushes.SeaGreen;
        return;
    }

    activeTunnelName = null;
    TunnelStatusText.Text = "not connected";
    TunnelStatusText.Foreground = Brushes.Gray;
}
```

Keep `ReconcileRawTunnel` using `MacTunnelNameResolver.TryGetInterfaceForTunnel(rawTunnelName)` because it intentionally resolves the exact persisted raw name.

- [ ] **Step 8: Use the split resolver in exit cleanup**

Replace the `splitTunnelUp` assignment in `CleanupThenCloseAsync` with:

```csharp
var splitTunnelUp =
    MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface() is not null;
```

Keep the exact raw-tunnel lookup and `MacExitCleanupService.RunAsync` call unchanged.

- [ ] **Step 9: Verify the generic-detector contract is now GREEN**

Run:

```bash
rg -n "detector|SystemWireguardDetector|TryGetActiveInterface" src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs
```

Expected: no output and exit code 1 because the Mac UI has no generic detector references.

- [ ] **Step 10: Build and run the focused Core tests**

Run:

```bash
dotnet build src/WireguardSplitTunnel.MacApp/WireguardSplitTunnel.MacApp.csproj --no-restore
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter "FullyQualifiedName~MacManagedTunnelInterfaceResolverTests|FullyQualifiedName~MacTunnelDisablePlannerTests"
```

Expected: build succeeds; 7 focused tests pass.

- [ ] **Step 11: Commit the Mac UI integration**

```bash
git add src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs
git commit -m "fix: keep Tailscale separate from Mac WireGuard"
```

---

### Task 4: Explain Exit Node and Document Supported Coexistence

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/MacQuickStartServiceTests.cs:8-21`
- Modify: `src/WireguardSplitTunnel.Core/Services/MacQuickStartService.cs:24-40`
- Modify: `README.md:100-111`
- Modify: `docs/README-Mac.txt:101-115`

**Interfaces:**
- Consumes: `MacQuickStartService.PlanStart(...)` and the existing `BlockedByOtherVpn` status.
- Produces: user-facing guidance that ordinary Tailscale/MagicDNS is supported while Tailscale Exit Node or another full-tunnel VPN must be disabled.

- [ ] **Step 1: Strengthen the blocked-route test and verify RED**

Change the final assertion in `PlanStart_BlocksWhenAnotherVpnOwnsDefaultRoute` to:

```csharp
result.Message.Should().Contain("Tailscale Exit Node")
    .And.Contain("full-tunnel VPN");
```

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacQuickStartServiceTests.PlanStart_BlocksWhenAnotherVpnOwnsDefaultRoute
```

Expected: FAIL because the current message contains neither phrase.

- [ ] **Step 2: Implement the minimal blocked-route message**

In `MacQuickStartService.PlanStart`, replace the blocked message with:

```csharp
$"A VPN or Tailscale Exit Node currently routes all traffic ({iface}). Turn off Tailscale Exit Node or disconnect the full-tunnel VPN, then click Start AI VPN again."
```

- [ ] **Step 3: Run the quick-start tests and verify GREEN**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --no-restore --filter FullyQualifiedName~MacQuickStartServiceTests
```

Expected: PASS, all `MacQuickStartServiceTests` tests.

- [ ] **Step 4: Update the top-level Mac instructions**

Replace the first item under `Inside the app, the easiest path is now:` in
`README.md` with:

```markdown
1. Disconnect the official WireGuard app if it is connected. Ordinary Tailscale
   and MagicDNS can stay connected, but Tailscale **Exit Node must be off**.
   Start AI VPN refuses to run while an Exit Node or another full-tunnel VPN
   owns the default route.
```

After the paragraph describing `wgst-split`, add:

```markdown
When Tailscale is connected without an Exit Node, the app keeps Tailscale and
MagicDNS unchanged. Status, AI routes, Monitor, and cleanup are pinned to the
named `wgst-split` tunnel and never fall back to Tailscale's `utun` interface.
```

- [ ] **Step 5: Mirror the packaged Mac instructions**

Replace item 2 under `Using The App` in `docs/README-Mac.txt` with:

```text
2. Disconnect the official WireGuard app if it is connected. Ordinary Tailscale
   and MagicDNS can stay connected, but Tailscale Exit Node must be off. Start AI
   VPN refuses to run while an Exit Node or another full-tunnel VPN owns the
   default route.
```

After item 5, add:

```text
   With Tailscale connected and Exit Node off, the app leaves Tailscale and
   MagicDNS unchanged. Status, AI routes, Monitor, and cleanup stay pinned to
   the named wgst-split tunnel and never fall back to Tailscale's utun interface.
```

- [ ] **Step 6: Verify documentation parity and formatting**

Run:

```bash
rg -n "Tailscale|Exit Node|MagicDNS|wgst-split" README.md docs/README-Mac.txt
git diff --check
```

Expected: both files state that ordinary Tailscale/MagicDNS is supported, Exit
Node must be off, and `wgst-split` is the only managed interface; `git diff
--check` prints nothing.

- [ ] **Step 7: Commit the message and documentation**

```bash
git add src/WireguardSplitTunnel.Core/Services/MacQuickStartService.cs tests/WireguardSplitTunnel.Core.Tests/MacQuickStartServiceTests.cs README.md docs/README-Mac.txt
git commit -m "fix: explain Tailscale coexistence on macOS"
```

---

### Task 5: Full Automated and Live macOS Verification

**Files:**
- Verify only; no planned file changes.

**Interfaces:**
- Consumes: all behavior and documentation from Tasks 1-4.
- Produces: fresh evidence that automated tests pass and the live route ownership matches the approved design.

- [ ] **Step 1: Run the full test suite**

Run:

```bash
dotnet test WireguardSplitTunnel.sln --no-restore
```

Expected: exit code 0 and zero failed tests.

- [ ] **Step 2: Build the Mac app from source**

Run:

```bash
dotnet build src/WireguardSplitTunnel.MacApp/WireguardSplitTunnel.MacApp.csproj --no-restore
```

Expected: exit code 0 with zero build errors.

- [ ] **Step 3: Run static ownership and formatting checks**

Run:

```bash
rg -n "detector|SystemWireguardDetector|TryGetActiveInterface" src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs
git diff --check
git status --short
```

Expected: the first two commands print nothing; status lists only intentional
implementation changes if the task commits have not yet been created.

- [ ] **Step 4: Establish the live Tailscale baseline**

With Tailscale connected and Exit Node off, run:

```bash
/sbin/route -n get default
/usr/sbin/scutil --nc list
```

Expected: default route uses Wi-Fi/Ethernet rather than `utun`; Tailscale shows
Connected.

- [ ] **Step 5: Start the source app and apply the AI split tunnel**

Run:

```bash
dotnet run --project src/WireguardSplitTunnel.MacApp/WireguardSplitTunnel.MacApp.csproj
```

In the app, select the saved config and click `Start AI VPN` once. Approve the
administrator prompt. Expected: status reports the `wgst-split` interface and
Monitor starts without showing Tailscale as WireGuard.

- [ ] **Step 6: Verify normal and AI route ownership**

In another Terminal, run:

```bash
/sbin/route -n get 1.1.1.1
AI_IP="$(jq -r '.ManagedRouteSnapshot[0].IpAddress' '/Users/user/Library/Application Support/WireguardSplitTunnel/state.json')"
/sbin/route -n get "$AI_IP"
```

Expected: `1.1.1.1` uses Wi-Fi/Ethernet; the AI IP uses the app-owned
`wgst-split` `utun`; Tailscale remains connected.

- [ ] **Step 7: Verify shutdown does not affect Tailscale**

Close the app with `Restore normal routing and DNS when quitting` enabled, then
run:

```bash
/sbin/route -n get default
/usr/sbin/scutil --nc list
```

Expected: the default route still uses Wi-Fi/Ethernet and Tailscale still shows
Connected with MagicDNS working.

- [ ] **Step 8: Review the final branch**

Run:

```bash
git log --oneline --decorate -8
git status --short --branch
```

Expected: the design/plan and implementation commits are present, and the
working tree is clean before push or release work begins.
