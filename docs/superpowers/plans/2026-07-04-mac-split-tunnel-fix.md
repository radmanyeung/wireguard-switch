# macOS Real Split Tunnel Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make *Start AI VPN* on macOS route only AI domains through WireGuard while all other traffic stays on the normal network, and stop the app from breaking the network when another VPN is already connected.

**Architecture:** Start the user's WireGuard config through a derived copy with `Table = off` (wg-quick then creates the tunnel but installs no catch-all routes and no DNS override); the app adds per-IP host routes for AI domains only. Before any tunnel start, a default-route guard blocks when another VPN (any `utun` owning the default route, e.g. the official WireGuard app) is connected. The interface detector no longer mistakes IPv6-only system `utun0–3` for WireGuard tunnels.

**Tech Stack:** .NET 8, Avalonia (Mac app), xUnit + FluentAssertions, wg-quick (Homebrew), macOS `route`/`osascript`.

**Background (diagnosed 2026-07-04):**
- User config `/opt/homebrew/etc/wireguard/SG.conf` is NordVPN full-tunnel (`AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1`, `DNS = 103.86.96.100, 103.86.99.100`). Plain `wg-quick up` hijacks all traffic and replaces system DNS.
- Enabling the tunnel while the official WireGuard app is connected starts a second full tunnel whose handshake cannot escape the first one → total network blackout.
- `SystemWireguardDetector` fallback returns system `utun0` (IPv6-only, not WireGuard) when no tunnel is active, so commit `0cfa1e0`'s reuse logic skipped starting the tunnel entirely.
- wg-quick Darwin supports `Table = off` (verified in `/opt/homebrew/bin/wg-quick` line 350) and accepts an absolute `.conf` path for both `up` and `down`.

**Key decisions:**
- Strip `DNS =` from the derived config (keep system DNS). Rationale: wg-quick would otherwise point *all* system DNS at NordVPN resolvers reachable only inside the tunnel; if the tunnel drops, every lookup dies — the exact "no network" symptom being fixed. AI domains are routed by resolved IP, so VPN DNS is not required.
- The derived config is written to the app data dir (`~/Library/Application Support/WireguardSplitTunnel/wgst-split.conf`, mode 600) so the tunnel gets a recognizable fixed name `wgst-split` and the source config is never modified.
- When another VPN owns the default route, **block with a clear message** instead of reusing it: a full-tunnel VPN already routes everything, so "reuse" cannot deliver split tunneling and double-tunnel starts blackhole the network.

---

### Task 1: Detector must not report IPv6-only system utun interfaces

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Services/WireguardDetector.cs:98-108`
- Test: `tests/WireguardSplitTunnel.Core.Tests/WireguardDetectorTests.cs`

- [ ] **Step 1: Write the failing test**

Add to `WireguardDetectorTests`:

```csharp
[Fact]
public void ChoosePreferredMacFallbackInterface_ReturnsNullWhenOnlyIpv6SystemUtunsExist()
{
    // A Mac with no WireGuard running still has up, IPv6-only utun0-3
    // (iCloud Private Relay etc.). They must never be reported as tunnels.
    var selected = SystemWireguardDetector.ChoosePreferredMacFallbackInterface(
        [
            new MacWireguardInterfaceCandidate("utun0", IsUp: true, HasIpv4: false),
            new MacWireguardInterfaceCandidate("utun1", IsUp: true, HasIpv4: false),
            new MacWireguardInterfaceCandidate("utun2", IsUp: true, HasIpv4: false),
            new MacWireguardInterfaceCandidate("utun3", IsUp: true, HasIpv4: false)
        ]);

    selected.Should().BeNull();
}
```

Also update the existing `ChoosePreferredMacFallbackInterface_IgnoresDownInterfaces` test — its up candidate must now have IPv4 to remain selectable:

```csharp
[Fact]
public void ChoosePreferredMacFallbackInterface_IgnoresDownInterfaces()
{
    var selected = SystemWireguardDetector.ChoosePreferredMacFallbackInterface(
        [
            new MacWireguardInterfaceCandidate("utun2", IsUp: false, HasIpv4: true),
            new MacWireguardInterfaceCandidate("utun3", IsUp: true, HasIpv4: true)
        ]);

    selected.Should().Be("utun3");
}
```

- [ ] **Step 2: Run tests to verify the new one fails**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter WireguardDetectorTests -v minimal`
Expected: `ChoosePreferredMacFallbackInterface_ReturnsNullWhenOnlyIpv6SystemUtunsExist` FAILS (returns `"utun0"` instead of null).

- [ ] **Step 3: Fix the fallback filter**

In `WireguardDetector.cs`, replace `ChoosePreferredMacFallbackInterface` (currently sorts IPv6-only candidates last instead of excluding them):

```csharp
internal static string? ChoosePreferredMacFallbackInterface(IEnumerable<MacWireguardInterfaceCandidate> candidates)
{
    // System utun interfaces (iCloud Private Relay etc.) are always up but
    // IPv6-only. A WireGuard tunnel from a .conf always has an IPv4 address,
    // so anything without IPv4 is not ours — exclude it, don't just rank it last.
    return candidates
        .Where(candidate => candidate.IsUp)
        .Where(candidate => candidate.HasIpv4)
        .Where(candidate => candidate.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase))
        .OrderBy(candidate => ParseUtunIndex(candidate.Name))
        .ThenBy(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase)
        .Select(candidate => candidate.Name)
        .FirstOrDefault();
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter WireguardDetectorTests -v minimal`
Expected: all WireguardDetectorTests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/WireguardSplitTunnel.Core/Services/WireguardDetector.cs tests/WireguardSplitTunnel.Core.Tests/WireguardDetectorTests.cs
git commit -m "fix: never detect IPv6-only system utun as WireGuard tunnel"
```

---

### Task 2: MacSplitTunnelConfigService — derive a Table=off config

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/MacSplitTunnelConfigService.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/MacSplitTunnelConfigServiceTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/WireguardSplitTunnel.Core.Tests/MacSplitTunnelConfigServiceTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacSplitTunnelConfigServiceTests
{
    private const string NordConfig = """
        [Interface]
        PrivateKey = SECRETKEY=
        Address = 10.5.0.2/32
        DNS = 103.86.96.100, 103.86.99.100

        [Peer]
        PublicKey = U3dKnkOJY5P9p6kEbEDGR7+K2+4HmkKK1hTMugq2HQA=
        AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
        Endpoint = sg476.nordvpn.com:51820
        PersistentKeepalive = 25
        """;

    [Fact]
    public void BuildSplitTunnelConfig_AddsTableOffInsideInterfaceSection()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        var lines = result.Split('\n').Select(line => line.Trim()).ToList();
        var interfaceIndex = lines.IndexOf("[Interface]");
        interfaceIndex.Should().BeGreaterThanOrEqualTo(0);
        lines[interfaceIndex + 1].Should().Be("Table = off");
    }

    [Fact]
    public void BuildSplitTunnelConfig_RemovesDnsOverride()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        result.Should().NotContain("DNS");
        result.Should().NotContain("103.86.96.100");
    }

    [Fact]
    public void BuildSplitTunnelConfig_KeepsKeysAddressAndPeerSection()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        result.Should().Contain("PrivateKey = SECRETKEY=");
        result.Should().Contain("Address = 10.5.0.2/32");
        result.Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1");
        result.Should().Contain("Endpoint = sg476.nordvpn.com:51820");
    }

    [Fact]
    public void BuildSplitTunnelConfig_ReplacesExistingTableSetting()
    {
        const string configWithTable = """
            [Interface]
            PrivateKey = SECRETKEY=
            Table = auto

            [Peer]
            PublicKey = U3dKnkOJY5P9p6kEbEDGR7+K2+4HmkKK1hTMugq2HQA=
            AllowedIPs = 0.0.0.0/0
            Endpoint = sg476.nordvpn.com:51820
            """;

        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(configWithTable);

        result.Should().Contain("Table = off");
        result.Should().NotContain("Table = auto");
    }

    [Fact]
    public void WriteSplitTunnelConfig_WritesDerivedFileNamedWgstSplit()
    {
        var workDir = Path.Combine(Path.GetTempPath(), $"wgst-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try
        {
            var source = Path.Combine(workDir, "SG.conf");
            File.WriteAllText(source, NordConfig);

            var derivedPath = MacSplitTunnelConfigService.WriteSplitTunnelConfig(source, workDir);

            derivedPath.Should().Be(Path.Combine(workDir, "wgst-split.conf"));
            var written = File.ReadAllText(derivedPath);
            written.Should().Contain("Table = off");
            written.Should().NotContain("DNS");
            if (!OperatingSystem.IsWindows())
            {
                File.GetUnixFileMode(derivedPath)
                    .Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            Directory.Delete(workDir, recursive: true);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter MacSplitTunnelConfigServiceTests -v minimal`
Expected: FAIL to compile — `MacSplitTunnelConfigService` does not exist.

- [ ] **Step 3: Implement the service**

Create `src/WireguardSplitTunnel.Core/Services/MacSplitTunnelConfigService.cs`:

```csharp
namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Derives a split-tunnel variant of a WireGuard config: Table=off so wg-quick
/// adds no catch-all routes, and no DNS override so system DNS keeps working
/// when most traffic bypasses the tunnel. The app then routes only the AI
/// domain IPs through the tunnel interface.
/// </summary>
public static class MacSplitTunnelConfigService
{
    public const string SplitTunnelName = "wgst-split";

    public static string SplitTunnelConfigFileName => SplitTunnelName + ".conf";

    public static string BuildSplitTunnelConfig(string originalConfigText)
    {
        var lines = originalConfigText.Replace("\r\n", "\n").Split('\n');
        var output = new List<string>();
        var inInterfaceSection = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();

            if (trimmed.StartsWith('['))
            {
                inInterfaceSection = trimmed.Equals("[Interface]", StringComparison.OrdinalIgnoreCase);
                output.Add(line);
                if (inInterfaceSection)
                {
                    output.Add("Table = off");
                }

                continue;
            }

            if (inInterfaceSection && (IsKey(trimmed, "DNS") || IsKey(trimmed, "Table")))
            {
                continue;
            }

            output.Add(line);
        }

        return string.Join('\n', output);

        static bool IsKey(string line, string key) =>
            line.StartsWith(key, StringComparison.OrdinalIgnoreCase)
            && line[key.Length..].TrimStart().StartsWith('=');
    }

    public static string WriteSplitTunnelConfig(string originalConfigPath, string dataDirectory)
    {
        string originalText;
        try
        {
            originalText = File.ReadAllText(originalConfigPath);
        }
        catch (UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Cannot read the WireGuard config. Make it readable for this app: sudo chown $USER \"{originalConfigPath}\"");
        }

        Directory.CreateDirectory(dataDirectory);
        var derivedPath = Path.Combine(dataDirectory, SplitTunnelConfigFileName);
        File.WriteAllText(derivedPath, BuildSplitTunnelConfig(originalText));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(derivedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return derivedPath;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter MacSplitTunnelConfigServiceTests -v minimal`
Expected: 5/5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/WireguardSplitTunnel.Core/Services/MacSplitTunnelConfigService.cs tests/WireguardSplitTunnel.Core.Tests/MacSplitTunnelConfigServiceTests.cs
git commit -m "feat: derive Table=off split-tunnel config for macOS"
```

---

### Task 3: DefaultRouteInspector — detect when another VPN owns the default route

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/DefaultRouteInspector.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/DefaultRouteInspectorTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/WireguardSplitTunnel.Core.Tests/DefaultRouteInspectorTests.cs`:

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DefaultRouteInspectorTests
{
    // Real `route -n get default` output shapes on macOS.
    private const string VpnDefaultRouteOutput = """
           route to: default
        destination: default
               mask: default
          interface: utun4
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """;

    private const string NormalDefaultRouteOutput = """
           route to: default
        destination: default
               mask: default
            gateway: 192.168.1.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """;

    [Fact]
    public void TryParseDefaultRouteInterface_ReadsInterfaceLine()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface(VpnDefaultRouteOutput, out var interfaceName)
            .Should().BeTrue();
        interfaceName.Should().Be("utun4");
    }

    [Fact]
    public void TryParseDefaultRouteInterface_ReadsPhysicalInterface()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface(NormalDefaultRouteOutput, out var interfaceName)
            .Should().BeTrue();
        interfaceName.Should().Be("en0");
    }

    [Fact]
    public void TryParseDefaultRouteInterface_FailsWhenNoInterfaceLine()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface("route: writing to routing socket", out var interfaceName)
            .Should().BeFalse();
        interfaceName.Should().BeEmpty();
    }

    [Theory]
    [InlineData("utun4", true)]
    [InlineData(" utun12 ", true)]
    [InlineData("en0", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsVpnInterface_MatchesUtunOnly(string? interfaceName, bool expected)
    {
        DefaultRouteInspector.IsVpnInterface(interfaceName).Should().Be(expected);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter DefaultRouteInspectorTests -v minimal`
Expected: FAIL to compile — `DefaultRouteInspector` does not exist.

- [ ] **Step 3: Implement the inspector**

Create `src/WireguardSplitTunnel.Core/Services/DefaultRouteInspector.cs`:

```csharp
using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public static class DefaultRouteInspector
{
    public static bool TryParseDefaultRouteInterface(string routeGetOutput, out string interfaceName)
    {
        foreach (var line in routeGetOutput.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("interface:", StringComparison.OrdinalIgnoreCase))
            {
                interfaceName = trimmed["interface:".Length..].Trim();
                return interfaceName.Length > 0;
            }
        }

        interfaceName = string.Empty;
        return false;
    }

    public static bool IsVpnInterface(string? interfaceName) =>
        !string.IsNullOrWhiteSpace(interfaceName)
        && interfaceName.Trim().StartsWith("utun", StringComparison.OrdinalIgnoreCase);

    /// <summary>Returns the IPv4 default-route interface, or null when it cannot be determined.</summary>
    [SupportedOSPlatform("macos")]
    public static async Task<string?> GetDefaultRouteInterfaceAsync(CancellationToken cancellationToken)
    {
        // `route -n get default` needs no root and prints an "interface:" line.
        var result = await MacAdminShell.RunAsync("/sbin/route", "-n get default", cancellationToken);
        if (result.ExitCode != 0)
        {
            return null;
        }

        return TryParseDefaultRouteInterface(result.StandardOutput, out var interfaceName)
            ? interfaceName
            : null;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter DefaultRouteInspectorTests -v minimal`
Expected: all PASS (8 test cases).

- [ ] **Step 5: Commit**

```bash
git add src/WireguardSplitTunnel.Core/Services/DefaultRouteInspector.cs tests/WireguardSplitTunnel.Core.Tests/DefaultRouteInspectorTests.cs
git commit -m "feat: detect VPN-owned default route on macOS"
```

---

### Task 4: Rework PlanStart — block on foreign VPN, always start own tunnel

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Services/MacQuickStartService.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/MacQuickStartServiceTests.cs`

The reuse-existing-tunnel branch from commit `0cfa1e0` is removed: a full-tunnel VPN already routes everything, so reuse cannot deliver split tunneling, and misdetection of system utuns made it skip the tunnel start entirely.

- [ ] **Step 1: Rewrite the PlanStart tests**

In `MacQuickStartServiceTests.cs`, **delete** `PlanStart_UsesExistingWireGuardTunnelWithoutRequiringConfig` and **replace** the two `PlanStart` tests with:

```csharp
[Fact]
public void PlanStart_BlocksWhenAnotherVpnOwnsDefaultRoute()
{
    var result = MacQuickStartService.PlanStart(
        defaultRouteInterfaceName: "utun4",
        savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
        discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

    result.Status.Should().Be(MacQuickStartStatus.BlockedByOtherVpn);
    result.ShouldStartTunnel.Should().BeFalse();
    result.SelectedConfigPath.Should().BeNull();
    result.Message.Should().Contain("Disconnect");
}

[Fact]
public void PlanStart_SelectsConfigAndStartsTunnelOnNormalNetwork()
{
    var result = MacQuickStartService.PlanStart(
        defaultRouteInterfaceName: "en0",
        savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
        discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

    result.Status.Should().Be(MacQuickStartStatus.Success);
    result.ShouldStartTunnel.Should().BeTrue();
    result.SelectedConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
    result.Message.Should().Contain("SG.conf");
}

[Fact]
public void PlanStart_StartsTunnelWhenDefaultRouteUnknown()
{
    var result = MacQuickStartService.PlanStart(
        defaultRouteInterfaceName: null,
        savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
        discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

    result.Status.Should().Be(MacQuickStartStatus.Success);
    result.ShouldStartTunnel.Should().BeTrue();
}
```

Leave the `SelectConfig` tests unchanged.

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests --filter MacQuickStartServiceTests -v minimal`
Expected: FAIL to compile — `BlockedByOtherVpn` and the new parameter name don't exist yet.

- [ ] **Step 3: Rework MacQuickStartService**

In `MacQuickStartService.cs`:

Add enum member:

```csharp
public enum MacQuickStartStatus
{
    Success = 1,
    MissingConfig = 2,
    MissingDependency = 3,
    TunnelFailed = 4,
    RoutesFailed = 5,
    BlockedByOtherVpn = 6
}
```

Replace the plan-result record (drop `InterfaceName` — the caller always waits for the interface after starting):

```csharp
public sealed record MacQuickStartPlanResult(
    MacQuickStartStatus Status,
    string? SelectedConfigPath,
    bool ShouldStartTunnel,
    string Message);
```

Replace `PlanStart`:

```csharp
public static MacQuickStartPlanResult PlanStart(
    string? defaultRouteInterfaceName,
    string? savedConfigPath,
    IEnumerable<string> discoveredConfigPaths)
{
    if (DefaultRouteInspector.IsVpnInterface(defaultRouteInterfaceName))
    {
        var iface = defaultRouteInterfaceName!.Trim();
        return new MacQuickStartPlanResult(
            MacQuickStartStatus.BlockedByOtherVpn,
            null,
            ShouldStartTunnel: false,
            $"Another VPN currently routes all traffic ({iface}). Disconnect the WireGuard app (or other VPN) first, then click Start AI VPN again.");
    }

    var selection = SelectConfig(savedConfigPath, discoveredConfigPaths);
    return new MacQuickStartPlanResult(
        selection.Status,
        selection.SelectedConfigPath,
        ShouldStartTunnel: selection.Status == MacQuickStartStatus.Success,
        selection.Message);
}
```

- [ ] **Step 4: Run Core tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests -v minimal`
Expected: all PASS. (The MacApp project will not compile until Task 5 — that is expected; only Core tests must pass here.)

- [ ] **Step 5: Commit**

```bash
git add src/WireguardSplitTunnel.Core/Services/MacQuickStartService.cs tests/WireguardSplitTunnel.Core.Tests/MacQuickStartServiceTests.cs
git commit -m "feat: block quick start when another VPN owns the default route"
```

---

### Task 5: Wire the Mac app — split start, guarded enable, dual disable

**Files:**
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs:121-181` (`OnStartAiVpnClick`), `:205-239` (`OnEnableTunnelClick` / `OnDisableTunnelClick`)

No unit tests for this task (Avalonia code-behind); verification is manual in Step 4.

- [ ] **Step 1: Rewrite OnStartAiVpnClick**

Replace the whole method with:

```csharp
private async void OnStartAiVpnClick(object? sender, RoutedEventArgs e)
{
    var discoveredConfigs = WireguardConfigCatalog.DiscoverConfigPaths();
    var currentSelection = (ConfigCombo.SelectedItem as TunnelConfigRow)?.Path
                           ?? selectedConfigPath
                           ?? appState.SelectedTunnelConfigPath;
    var defaultRouteInterface = await DefaultRouteInspector.GetDefaultRouteInterfaceAsync(CancellationToken.None);
    var startPlan = MacQuickStartService.PlanStart(defaultRouteInterface, currentSelection, discoveredConfigs);
    RefreshTunnelConfigRows(startPlan.SelectedConfigPath ?? currentSelection);

    if (startPlan.Status != MacQuickStartStatus.Success || string.IsNullOrWhiteSpace(startPlan.SelectedConfigPath))
    {
        MainTabs.SelectedIndex = 0;
        Log(startPlan.Message);
        return;
    }

    selectedConfigPath = startPlan.SelectedConfigPath;
    appState = appState with { SelectedTunnelConfigPath = selectedConfigPath };
    SaveState();
    RefreshTunnelConfigRows(selectedConfigPath);

    StartAiVpnButton.IsEnabled = false;
    try
    {
        await RunGuardedAsync("start AI VPN", async ct =>
        {
            Log(startPlan.Message);
            var splitConfigPath = MacSplitTunnelConfigService.WriteSplitTunnelConfig(
                selectedConfigPath!, GetDataDirectory());
            Log($"split tunnel config ready: {splitConfigPath} (Table=off, system DNS kept)");
            await tunnelControl.InstallAndStartAsync(splitConfigPath, ct);
            var iface = await WaitForWireGuardInterfaceAsync(ct);
            activeTunnelName = iface;
            RefreshTunnelStatus();
            EnsureAiServicesPreset();
            await ApplyDomainRoutesAsync(iface, ct);
            await StartNetworkMonitorAsync();
            MainTabs.SelectedItem = MonitorTabItem;
        });
    }
    finally
    {
        StartAiVpnButton.IsEnabled = true;
    }
}
```

- [ ] **Step 2: Guard OnEnableTunnelClick and widen OnDisableTunnelClick**

Replace both handlers with:

```csharp
private async void OnEnableTunnelClick(object? sender, RoutedEventArgs e)
{
    if (string.IsNullOrWhiteSpace(selectedConfigPath))
    {
        Log("pick a config first.");
        return;
    }

    await RunGuardedAsync("enable tunnel", async ct =>
    {
        var defaultRouteInterface = await DefaultRouteInspector.GetDefaultRouteInterfaceAsync(ct);
        if (DefaultRouteInspector.IsVpnInterface(defaultRouteInterface))
        {
            throw new InvalidOperationException(
                $"Another VPN currently routes all traffic ({defaultRouteInterface}). Disconnect it first, then try again.");
        }

        await tunnelControl.InstallAndStartAsync(selectedConfigPath!, ct);
        await Task.Delay(500, ct);
        RefreshTunnelStatus();
    });
}

private async void OnDisableTunnelClick(object? sender, RoutedEventArgs e)
{
    var splitConfigPath = Path.Combine(GetDataDirectory(), MacSplitTunnelConfigService.SplitTunnelConfigFileName);
    var targets = new List<string>();
    if (File.Exists(splitConfigPath))
    {
        targets.Add(splitConfigPath);
    }

    if (!string.IsNullOrWhiteSpace(selectedConfigPath))
    {
        targets.Add(WireguardConfigCatalog.GetTunnelName(selectedConfigPath!));
    }
    else if (!string.IsNullOrWhiteSpace(activeTunnelName))
    {
        targets.Add(activeTunnelName!);
    }

    if (targets.Count == 0)
    {
        Log("nothing to disable.");
        return;
    }

    await RunGuardedAsync("disable tunnel", async ct =>
    {
        foreach (var target in targets)
        {
            try
            {
                await tunnelControl.StopAndUninstallAsync(target, ct);
                Log($"stopped: {Path.GetFileName(target)}");
            }
            catch (Exception ex)
            {
                // Not every target is necessarily up; keep going.
                Log($"stop {Path.GetFileName(target)}: {ToFriendlyMacError(ex.Message)}");
            }
        }

        await Task.Delay(300, ct);
        RefreshTunnelStatus();
    });
}
```

- [ ] **Step 3: Build everything**

Run: `dotnet build src/WireguardSplitTunnel.MacApp/WireguardSplitTunnel.MacApp.csproj -v q && dotnet test tests/WireguardSplitTunnel.Core.Tests -v minimal`
Expected: build success, all tests PASS.

- [ ] **Step 4: Manual verification on the Mac**

Run: `dotnet run --project src/WireguardSplitTunnel.MacApp`

1. **Guard test:** connect the official WireGuard app, click *Start AI VPN*. Expected log: "Another VPN currently routes all traffic (utunX). Disconnect…" and no admin prompt.
2. **Split test:** disconnect the official WireGuard app (menu bar → disconnect). Click *Start AI VPN*, approve the admin prompt. Then verify in Terminal:
   - `ls /var/run/wireguard/` → contains `wgst-split.name`
   - `netstat -rn -f inet | head -5` → default route still via `en0`/Wi-Fi (NOT utun)
   - `netstat -rn -f inet | grep -c "US"`-style check: `netstat -rn -f inet | awk '$4 ~ /utun/ && $3 ~ /S/' | head` → AI host routes pinned to the tunnel utun
   - `curl -s https://ifconfig.me` → your normal (non-VPN) public IP
   - `curl -s https://chatgpt.com -o /dev/null -w "%{http_code}\n"` → 200/3xx (reached through tunnel)
3. **Disable test:** click *Disable Tunnel*, approve prompt. `ls /var/run/wireguard/` → empty/removed; network still works.

- [ ] **Step 5: Commit**

```bash
git add src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs
git commit -m "feat: real macOS split tunnel start with foreign-VPN guard"
```

---

### Task 6: Documentation, LOGFILE, release package

**Files:**
- Modify: `README.md:96-111` (macOS "Inside the app" section), `docs/README-Mac.txt` (same guidance), `LOGFILE.md`

- [ ] **Step 1: Update README macOS usage section**

Replace the "Inside the app, the easiest path is now:" block (README.md lines 96–107) with:

```markdown
Inside the app, the easiest path is now:

1. Disconnect the official WireGuard app if it is connected. Start AI VPN
   needs to own the tunnel; it will refuse to run while another VPN routes
   all traffic.
2. Choose a config from `/opt/homebrew/etc/wireguard`.
3. Click **Start AI VPN** and approve the macOS administrator prompt.

Start AI VPN creates a split tunnel: only the AI Services Bundle domains go
through WireGuard; all other traffic and system DNS stay on your normal
network. The tunnel runs under the name `wgst-split` (a derived copy of your
config with `Table = off`); your original config file is never modified.
```

Apply the same wording change to the matching section in `docs/README-Mac.txt`.

- [ ] **Step 2: Add LOGFILE entry**

Append under a `## 2026-07-04` heading in `LOGFILE.md`:

```markdown
## 2026-07-04
- Diagnosed macOS "Start AI VPN" failures: system utun0 misdetected as WireGuard tunnel; full-tunnel NordVPN config hijacked all traffic; double tunnel with the official WireGuard app blacked out the network.
- Detector fallback now requires IPv4 on utun candidates (system utun0-3 are IPv6-only and are never WireGuard).
- Start AI VPN now starts a derived `wgst-split` config with `Table = off` and no DNS override: only AI domain routes go through the tunnel, system DNS and default route stay on the normal network.
- Added default-route guard: Start AI VPN / Enable Tunnel refuse to run while another VPN (utun default route) is connected, instead of silently double-tunneling.
- Disable Tunnel now also brings down the `wgst-split` tunnel.
- Risk/follow-up: IPv6 AI traffic is not routed through the tunnel (host routes are IPv4-only today); revisit if AI endpoints go IPv6-first.
```

- [ ] **Step 3: Rebuild the mac release package**

Run: `bash scripts/package-mac.sh`
Expected: new `wireguard-split-tunnel-mac-arm64.zip` produced (check script output for the artifact path).

- [ ] **Step 4: Commit**

```bash
git add README.md docs/README-Mac.txt LOGFILE.md
git commit -m "docs: describe macOS split tunnel behavior and VPN guard"
```

---

## Out of scope (deliberate)

- **IPv6 AI-domain routes** — resolver/route plumbing is IPv4-only today; the derived config still carries IPv6 AllowedIPs but no catch-alls are installed. Note captured in LOGFILE.
- **Reusing the official WireGuard app's tunnel** — impossible to combine with "everything else direct" while that app owns the `0.0.0.0/1` routes; the guard + message is the correct behavior.
- **Windows behavior** — untouched; all changed mac paths are behind `OperatingSystem.IsMacOS()` / separate services.

## Self-review notes

- Spec coverage: Table=off start (Task 2+5), DNS survival (Task 2 strips DNS; documented), double-tunnel guard (Tasks 3–5), utun detector fix (Task 1), docs (Task 6). DNS "route Nord resolvers through tunnel" alternative was rejected in favor of stripping DNS — recorded in Key decisions.
- Type consistency: `MacQuickStartPlanResult` loses `InterfaceName`; the only consumer (`OnStartAiVpnClick`) is rewritten in Task 5 and no longer reads it. `SplitTunnelConfigFileName` used in Tasks 2 and 5 matches. `DefaultRouteInspector.IsVpnInterface` used in Tasks 3–5 matches.
- Task 4 leaves the MacApp temporarily uncompilable (record signature change) until Task 5; Core tests still pass in isolation, and Task 5 restores full build. Execute Tasks 4 and 5 back-to-back.
