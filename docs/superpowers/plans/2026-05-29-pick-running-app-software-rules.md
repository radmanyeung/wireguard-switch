# Pick Running App Software Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `Pick Running App` flow that lets users add software rules from currently running Windows processes with readable `.exe` paths.

**Architecture:** Add a focused core discovery service that enumerates running processes and normalizes usable executable candidates. Add a WPF modal picker for search and multi-select, then wire the Software Rules tab to add selected candidates through the existing `SoftwareRuleMutations.TryAddSoftwareRule` path.

**Tech Stack:** C#/.NET 8, WPF, xUnit, FluentAssertions, existing `WireguardSplitTunnel.Core` and `WireguardSplitTunnel.App` projects.

---

## File Map

- Create `src/WireguardSplitTunnel.Core/Services/RunningSoftwareDiscovery.cs`: process discovery interface, candidate record, system implementation, and pure normalization helper.
- Create `tests/WireguardSplitTunnel.Core.Tests/RunningSoftwareDiscoveryTests.cs`: tests for filtering, de-duplication, and ordering.
- Create `src/WireguardSplitTunnel.App/RunningSoftwarePickerWindow.xaml`: modal picker UI.
- Create `src/WireguardSplitTunnel.App/RunningSoftwarePickerWindow.xaml.cs`: filtering, multi-select rows, selected candidate output.
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml`: add `Pick Running App` button beside `Add Software`.
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`: instantiate discovery service, open picker, add selected candidates, save state, refresh grid.

## Task 1: Core Discovery Service

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Services/RunningSoftwareDiscovery.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/RunningSoftwareDiscoveryTests.cs`

- [ ] **Step 1: Write failing tests**

```csharp
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RunningSoftwareDiscoveryTests
{
    [Fact]
    public void NormalizeCandidates_ReturnsOnlyExistingExePaths()
    {
        var chromePath = Path.Combine(AppContext.BaseDirectory, "chrome.exe");
        File.WriteAllText(chromePath, "");

        var rows = RunningSoftwareDiscovery.NormalizeCandidates([
            new RunningSoftwareRawCandidate("chrome", chromePath),
            new RunningSoftwareRawCandidate("missing", Path.Combine(AppContext.BaseDirectory, "missing.exe")),
            new RunningSoftwareRawCandidate("text", Path.Combine(AppContext.BaseDirectory, "note.txt")),
            new RunningSoftwareRawCandidate("", chromePath),
            new RunningSoftwareRawCandidate("blank", "")
        ]);

        rows.Should().Equal(new RunningSoftwareCandidate("chrome.exe", chromePath));
    }

    [Fact]
    public void NormalizeCandidates_DeduplicatesByExecutablePathAndOrdersByProcessName()
    {
        var alphaPath = Path.Combine(AppContext.BaseDirectory, "Alpha.exe");
        var betaPath = Path.Combine(AppContext.BaseDirectory, "beta.exe");
        File.WriteAllText(alphaPath, "");
        File.WriteAllText(betaPath, "");

        var rows = RunningSoftwareDiscovery.NormalizeCandidates([
            new RunningSoftwareRawCandidate("beta", betaPath),
            new RunningSoftwareRawCandidate("alpha", alphaPath),
            new RunningSoftwareRawCandidate("ALPHA", alphaPath.ToUpperInvariant())
        ]);

        rows.Select(row => row.ProcessName).Should().Equal("alpha.exe", "beta.exe");
        rows.Select(row => row.ExecutablePath).Should().Equal(alphaPath, betaPath);
    }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1 --filter RunningSoftwareDiscoveryTests
```

Expected: fail because `RunningSoftwareDiscovery`, `RunningSoftwareRawCandidate`, and `RunningSoftwareCandidate` do not exist.

- [ ] **Step 3: Implement discovery service**

```csharp
using System.Diagnostics;
using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

public sealed record RunningSoftwareCandidate(string ProcessName, string ExecutablePath);

public sealed record RunningSoftwareRawCandidate(string ProcessName, string? ExecutablePath);

public interface IRunningSoftwareDiscovery
{
    IReadOnlyList<RunningSoftwareCandidate> DiscoverRunningSoftware();
}

public sealed class SystemRunningSoftwareDiscovery : IRunningSoftwareDiscovery
{
    public IReadOnlyList<RunningSoftwareCandidate> DiscoverRunningSoftware()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var raw = Process.GetProcesses()
            .Select(TryReadProcess)
            .Where(row => row is not null)
            .Select(row => row!)
            .ToArray();

        return RunningSoftwareDiscovery.NormalizeCandidates(raw);
    }

    [SupportedOSPlatform("windows")]
    private static RunningSoftwareRawCandidate? TryReadProcess(Process process)
    {
        using (process)
        {
            try
            {
                return new RunningSoftwareRawCandidate(process.ProcessName, process.MainModule?.FileName);
            }
            catch
            {
                return null;
            }
        }
    }
}

public static class RunningSoftwareDiscovery
{
    public static IReadOnlyList<RunningSoftwareCandidate> NormalizeCandidates(
        IEnumerable<RunningSoftwareRawCandidate> rawCandidates)
    {
        return rawCandidates
            .Select(NormalizeCandidate)
            .Where(candidate => candidate is not null)
            .Select(candidate => candidate!)
            .GroupBy(candidate => candidate.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(candidate => candidate.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(candidate => candidate.ExecutablePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static RunningSoftwareCandidate? NormalizeCandidate(RunningSoftwareRawCandidate raw)
    {
        if (string.IsNullOrWhiteSpace(raw.ProcessName) || string.IsNullOrWhiteSpace(raw.ExecutablePath))
        {
            return null;
        }

        var executablePath = raw.ExecutablePath.Trim();
        if (!executablePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(executablePath))
        {
            return null;
        }

        var processName = Path.GetFileName(executablePath);
        if (string.IsNullOrWhiteSpace(processName))
        {
            return null;
        }

        return new RunningSoftwareCandidate(processName.ToLowerInvariant(), executablePath);
    }
}
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1 --filter RunningSoftwareDiscoveryTests
```

Expected: `RunningSoftwareDiscoveryTests` pass.

## Task 2: WPF Picker Dialog

**Files:**
- Create: `src/WireguardSplitTunnel.App/RunningSoftwarePickerWindow.xaml`
- Create: `src/WireguardSplitTunnel.App/RunningSoftwarePickerWindow.xaml.cs`

- [ ] **Step 1: Add dialog XAML**

```xml
<Window x:Class="WireguardSplitTunnel.App.RunningSoftwarePickerWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Pick Running App"
        Height="520"
        Width="840"
        MinHeight="420"
        MinWidth="700"
        WindowStartupLocation="CenterOwner"
        Background="#F6F8FC">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <TextBlock Text="Pick Running App" FontSize="20" FontWeight="SemiBold" Foreground="#1F2937" />

        <TextBox x:Name="SearchBox"
                 Grid.Row="1"
                 Margin="0,12,0,10"
                 Padding="8"
                 MinHeight="34"
                 VerticalContentAlignment="Center"
                 TextChanged="OnSearchTextChanged" />

        <DataGrid x:Name="CandidatesGrid"
                  Grid.Row="2"
                  AutoGenerateColumns="False"
                  IsReadOnly="False"
                  HeadersVisibility="Column"
                  CanUserAddRows="False"
                  RowHeaderWidth="0"
                  SelectionMode="Extended">
            <DataGrid.Columns>
                <DataGridCheckBoxColumn Header="Add" Binding="{Binding Selected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}" Width="70" />
                <DataGridTextColumn Header="Process" Binding="{Binding ProcessName}" IsReadOnly="True" Width="180" />
                <DataGridTextColumn Header="Path" Binding="{Binding ShortPath}" IsReadOnly="True" Width="*" />
            </DataGrid.Columns>
        </DataGrid>

        <Grid Grid.Row="3" Margin="0,12,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="Auto" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>

            <TextBlock x:Name="StatusText" VerticalAlignment="Center" Foreground="#46607A" />
            <Button Grid.Column="1" Content="Add Selected" MinWidth="120" Padding="10,6" Margin="0,0,8,0" Click="OnAddSelectedClicked" />
            <Button Grid.Column="2" Content="Cancel" MinWidth="90" Padding="10,6" Click="OnCancelClicked" />
        </Grid>
    </Grid>
</Window>
```

- [ ] **Step 2: Add dialog code-behind**

```csharp
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.App;

public partial class RunningSoftwarePickerWindow : Window
{
    private readonly List<RunningSoftwarePickerRow> allRows;
    private readonly ObservableCollection<RunningSoftwarePickerRow> visibleRows = [];

    public IReadOnlyList<RunningSoftwareCandidate> SelectedCandidates { get; private set; } = [];

    public RunningSoftwarePickerWindow(IReadOnlyList<RunningSoftwareCandidate> candidates)
    {
        InitializeComponent();
        allRows = candidates
            .Select(candidate => new RunningSoftwarePickerRow(candidate))
            .ToList();
        CandidatesGrid.ItemsSource = visibleRows;
        ApplyFilter();
    }

    private void OnSearchTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        var needle = SearchBox.Text.Trim();
        visibleRows.Clear();
        foreach (var row in allRows.Where(row => row.Matches(needle)))
        {
            visibleRows.Add(row);
        }

        StatusText.Text = visibleRows.Count == 0
            ? "No running apps with readable executable paths found."
            : $"{visibleRows.Count} app{(visibleRows.Count == 1 ? "" : "s")} found";
    }

    private void OnAddSelectedClicked(object sender, RoutedEventArgs e)
    {
        SelectedCandidates = allRows
            .Where(row => row.Selected)
            .Select(row => row.Candidate)
            .ToArray();

        if (SelectedCandidates.Count == 0)
        {
            MessageBox.Show(this, "Select at least one running app.", "Wireguard Split Tunnel");
            return;
        }

        DialogResult = true;
    }

    private void OnCancelClicked(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private sealed class RunningSoftwarePickerRow : INotifyPropertyChanged
    {
        private bool selected;

        public RunningSoftwarePickerRow(RunningSoftwareCandidate candidate)
        {
            Candidate = candidate;
            ShortPath = ShortenPath(candidate.ExecutablePath);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public RunningSoftwareCandidate Candidate { get; }
        public string ProcessName => Candidate.ProcessName;
        public string ShortPath { get; }

        public bool Selected
        {
            get => selected;
            set
            {
                if (selected == value)
                {
                    return;
                }

                selected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Selected)));
            }
        }

        public bool Matches(string needle)
        {
            if (string.IsNullOrWhiteSpace(needle))
            {
                return true;
            }

            return ProcessName.Contains(needle, StringComparison.OrdinalIgnoreCase)
                || Candidate.ExecutablePath.Contains(needle, StringComparison.OrdinalIgnoreCase);
        }

        private static string ShortenPath(string path)
        {
            var directory = Path.GetDirectoryName(path);
            var fileName = Path.GetFileName(path);
            if (string.IsNullOrWhiteSpace(directory))
            {
                return fileName;
            }

            return directory.Length <= 52 ? path : $"{directory[..24]}...{directory[^24..]}\\{fileName}";
        }
    }
}
```

- [ ] **Step 3: Build to verify XAML/code-behind compiles**

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Expected: build passes.

## Task 3: Main Window Integration

**Files:**
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`

- [ ] **Step 1: Add Software Rules button**

Add the button beside `Add Software`:

```xml
<Button x:Name="PickRunningAppButton" Content="Pick Running App" MinWidth="140" Margin="0,0,8,0" Padding="10,6" />
```

- [ ] **Step 2: Wire the click handler and discovery service**

Add field:

```csharp
private readonly IRunningSoftwareDiscovery runningSoftwareDiscovery = new SystemRunningSoftwareDiscovery();
```

Wire constructor:

```csharp
PickRunningAppButton.Click += OnPickRunningAppClicked;
```

Add handler:

```csharp
private void OnPickRunningAppClicked(object sender, RoutedEventArgs e)
{
    IReadOnlyList<RunningSoftwareCandidate> candidates;
    try
    {
        candidates = runningSoftwareDiscovery.DiscoverRunningSoftware();
    }
    catch (Exception ex)
    {
        logger.Error("Running app discovery failed.", ex);
        MessageBox.Show(this, $"Could not list running apps: {ex.Message}", "Wireguard Split Tunnel");
        return;
    }

    var dialog = new RunningSoftwarePickerWindow(candidates)
    {
        Owner = this
    };

    if (dialog.ShowDialog() != true)
    {
        return;
    }

    var added = 0;
    var skipped = 0;
    var invalid = 0;
    foreach (var candidate in dialog.SelectedCandidates)
    {
        if (string.IsNullOrWhiteSpace(candidate.ExecutablePath) || !File.Exists(candidate.ExecutablePath))
        {
            invalid++;
            continue;
        }

        if (SoftwareRuleMutations.TryAddSoftwareRule(
            state,
            candidate.ProcessName,
            DomainRouteMode.UseWireGuard,
            includeSubprocesses: true,
            candidate.ExecutablePath))
        {
            added++;
        }
        else
        {
            skipped++;
        }
    }

    stateStore.Save(state);
    RefreshSoftwareGrid();
    MessageBox.Show(
        this,
        $"Running app add completed. Added: {added}, skipped existing: {skipped}, skipped invalid: {invalid}.",
        "Wireguard Split Tunnel");
}
```

- [ ] **Step 3: Verify manually through build/tests**

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Expected: tests and build pass.

## Task 4: Manual Check

**Files:**
- No source edits.

- [ ] **Step 1: Launch app**

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\start.ps1 -DryRun
```

Expected: start script resolves an app executable without failing.

- [ ] **Step 2: Manual UI check**

Open the app normally, go to Software Rules, click `Pick Running App`, search for `codex` or another running `.exe`, select it, click `Add Selected`, and confirm the Software Rules grid updates with the process name.

## Self-Review Checklist

- The plan covers process discovery, filtering, multi-select UI, duplicate skipping, invalid-path skipping, state save, grid refresh, and fallback preservation.
- No route or firewall behavior changes are included.
- The existing `Add Software` browse flow remains untouched.
- The plan uses TDD for the core behavior where automated tests are practical.
