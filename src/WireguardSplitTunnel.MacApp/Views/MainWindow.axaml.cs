using System.Diagnostics;
using Avalonia;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.MacApp.Views;

public partial class MainWindow : Window
{
    private readonly MainWindowState viewState = new();
    private readonly IWireguardDetector detector = new SystemWireguardDetector();
    private readonly IDomainResolver resolver = new SystemDomainResolver();
    private readonly ITunnelControlService tunnelControl = new TunnelControlService();
    private readonly IRouteService routeService = new RouteService();
    private readonly INetworkMonitorService networkMonitorService = new SystemNetworkMonitorService();
    private readonly DispatcherTimer monitorTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly NetworkGraphHistory monitorGraphHistory = new(TimeSpan.FromSeconds(60));
    private readonly StateStore stateStore;
    private readonly StateStore appliedStateStore;
    private AppState appState;
    private string? selectedConfigPath;
    private string? activeTunnelName;
    private CancellationTokenSource? monitorRefreshCts;
    private int monitorRefreshInProgress;
    private int monitorRunGeneration;
    private bool suppressConfigSelectionChanged;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = viewState;
        ConfigCombo.ItemsSource = viewState.TunnelConfigs;
        DomainList.ItemsSource = viewState.Domains;
        MacProfileCombo.ItemsSource = viewState.MacProfiles;
        MacProfileList.ItemsSource = viewState.MacProfiles;
        MacSoftwareRuleList.ItemsSource = viewState.MacSoftwareRules;
        MonitorActivityList.ItemsSource = viewState.MonitorActivities;

        var dataDirectory = GetDataDirectory();
        stateStore = new StateStore(Path.Combine(dataDirectory, "state.json"));
        appliedStateStore = new StateStore(Path.Combine(dataDirectory, "applied-state.json"));
        appState = stateStore.Load();

        LoadStateToUi();
        RefreshTunnelStatus();
        monitorTimer.Tick += OnMonitorTimerTick;
        MonitorGraphCanvas.SizeChanged += OnMonitorGraphCanvasSizeChanged;
    }

    private static string GetDataDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library",
            "Application Support",
            "WireguardSplitTunnel");
    }

    private async void OnPickConfigClick(object? sender, RoutedEventArgs e)
    {
        var initialFolder = await ResolveInitialFolderAsync();
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select WireGuard config",
            AllowMultiple = false,
            SuggestedStartLocation = initialFolder,
            FileTypeFilter =
            [
                new FilePickerFileType("WireGuard config") { Patterns = ["*.conf"] },
                new FilePickerFileType("All files") { Patterns = ["*"] }
            ]
        });

        if (files.Count == 0)
        {
            return;
        }

        selectedConfigPath = files[0].Path.LocalPath;
        appState = appState with { SelectedTunnelConfigPath = selectedConfigPath };
        SaveState();
        RefreshTunnelConfigRows(selectedConfigPath);
        if (!IsDiscoveredConfigPath(selectedConfigPath))
        {
            Log("For reliable startup, copy this config to /opt/homebrew/etc/wireguard and select it there.");
        }

        Log($"selected config: {selectedConfigPath}");
    }

    private void OnRefreshConfigsClick(object? sender, RoutedEventArgs e)
    {
        RefreshTunnelConfigRows(selectedConfigPath);
        Log("config list refreshed.");
    }

    private void OnConfigSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (suppressConfigSelectionChanged)
        {
            return;
        }

        if (ConfigCombo.SelectedItem is not TunnelConfigRow row)
        {
            return;
        }

        selectedConfigPath = row.Path;
        appState = appState with { SelectedTunnelConfigPath = selectedConfigPath };
        SaveState();
        Log($"selected config: {selectedConfigPath}");
    }

    private async void OnStartAiVpnClick(object? sender, RoutedEventArgs e)
    {
        var discoveredConfigs = WireguardConfigCatalog.DiscoverConfigPaths();
        var currentSelection = (ConfigCombo.SelectedItem as TunnelConfigRow)?.Path
                               ?? selectedConfigPath
                               ?? appState.SelectedTunnelConfigPath;
        detector.TryGetActiveInterface(out var existingInterfaceName);
        var startPlan = MacQuickStartService.PlanStart(existingInterfaceName, currentSelection, discoveredConfigs);
        RefreshTunnelConfigRows(startPlan.SelectedConfigPath ?? currentSelection);

        if (startPlan.Status != MacQuickStartStatus.Success)
        {
            MainTabs.SelectedIndex = 0;
            Log(startPlan.Message);
            return;
        }

        if (!string.IsNullOrWhiteSpace(startPlan.SelectedConfigPath))
        {
            selectedConfigPath = startPlan.SelectedConfigPath;
            appState = appState with { SelectedTunnelConfigPath = selectedConfigPath };
            SaveState();
            RefreshTunnelConfigRows(selectedConfigPath);
        }

        StartAiVpnButton.IsEnabled = false;
        try
        {
            await RunGuardedAsync("start AI VPN", async ct =>
            {
                Log(startPlan.Message);
                var iface = startPlan.InterfaceName;
                if (startPlan.ShouldStartTunnel)
                {
                    if (string.IsNullOrWhiteSpace(startPlan.SelectedConfigPath))
                    {
                        throw new InvalidOperationException(
                            "Choose a WireGuard config, then click Start AI VPN again.");
                    }

                    await tunnelControl.InstallAndStartAsync(startPlan.SelectedConfigPath, ct);
                    iface = await WaitForWireGuardInterfaceAsync(ct);
                }
                else if (string.IsNullOrWhiteSpace(iface))
                {
                    iface = await WaitForWireGuardInterfaceAsync(ct);
                }

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

    private async Task<IStorageFolder?> ResolveInitialFolderAsync()
    {
        foreach (var dir in WireguardConfigCatalog.DefaultConfigDirectories)
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            try
            {
                return await StorageProvider.TryGetFolderFromPathAsync(new Uri(dir));
            }
            catch
            {
                // Best-effort only.
            }
        }

        return null;
    }

    private async void OnEnableTunnelClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            Log("pick a config first.");
            return;
        }

        await RunGuardedAsync("enable tunnel", async ct =>
        {
            await tunnelControl.InstallAndStartAsync(selectedConfigPath!, ct);
            await Task.Delay(500, ct);
            RefreshTunnelStatus();
        });
    }

    private async void OnDisableTunnelClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(selectedConfigPath) && string.IsNullOrWhiteSpace(activeTunnelName))
        {
            Log("nothing to disable.");
            return;
        }

        var name = !string.IsNullOrWhiteSpace(selectedConfigPath)
            ? WireguardConfigCatalog.GetTunnelName(selectedConfigPath!)
            : activeTunnelName!;

        await RunGuardedAsync("disable tunnel", async ct =>
        {
            await tunnelControl.StopAndUninstallAsync(name, ct);
            await Task.Delay(300, ct);
            RefreshTunnelStatus();
        });
    }

    private void OnRefreshStatusClick(object? sender, RoutedEventArgs e)
    {
        RefreshTunnelStatus();
    }

    private void OnAddDomainClick(object? sender, RoutedEventArgs e)
    {
        var input = NewDomainBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(input))
        {
            return;
        }

        if (!RuleStateMutations.TryAddDomainRule(appState, input, DomainRouteMode.UseWireGuard))
        {
            Log($"invalid or existing domain: {input}");
            return;
        }

        SaveState();
        RefreshDomainRows();
        NewDomainBox.Text = string.Empty;
        Log($"added domain: {input}");
    }

    private void OnAddPresetClick(object? sender, RoutedEventArgs e)
    {
        var preset = PresetCombo.SelectedIndex switch
        {
            0 => DomainPreset.OpenAiChatGpt,
            1 => DomainPreset.ClaudeAnthropic,
            2 => DomainPreset.GoogleAiGemini,
            _ => DomainPreset.AiServicesBundle
        };

        var result = DomainPresetService.ApplyPreset(appState, preset);
        SaveState();
        RefreshDomainRows();
        Log($"preset added: {result.Added}, skipped existing: {result.SkippedExisting.Count}");
    }

    private void OnDomainEnabledChanged(object? sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: string domain } checkbox)
        {
            return;
        }

        if (RuleStateMutations.TrySetRuleEnabled(appState, domain, checkbox.IsChecked == true))
        {
            SaveState();
        }
    }

    private void OnRemoveDomainClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string domain })
        {
            return;
        }

        if (RuleStateMutations.RemoveRule(appState, domain))
        {
            SaveState();
            RefreshDomainRows();
            Log($"removed domain: {domain}");
        }
    }

    private async void OnApplyRoutesClick(object? sender, RoutedEventArgs e)
    {
        if (!detector.TryGetActiveInterface(out var iface))
        {
            Log("no active WireGuard interface detected. Enable the tunnel first.");
            return;
        }

        await RunGuardedAsync("apply routes", async ct =>
        {
            await ApplyDomainRoutesAsync(iface, ct);
        });
    }

    private async void OnRestoreNormalRoutesClick(object? sender, RoutedEventArgs e)
    {
        var managedIps = appState.ManagedRouteSnapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (managedIps.Count == 0)
        {
            Log("no managed routes to restore.");
            return;
        }

        detector.TryGetActiveInterface(out var iface);
        iface = string.IsNullOrWhiteSpace(iface) ? activeTunnelName ?? "utun0" : iface;
        await RunGuardedAsync("restore normal routes", async ct =>
        {
            await routeService.ApplyAsync(iface, [], managedIps, ct);
            appState = appState with { ManagedRouteSnapshot = [] };
            SaveState();
            RefreshDomainRows();
            Log($"removed {managedIps.Count} managed route(s).");
        });
    }

    private void OnRollbackClick(object? sender, RoutedEventArgs e)
    {
        var appliedPath = Path.Combine(GetDataDirectory(), "applied-state.json");
        if (!File.Exists(appliedPath))
        {
            Log("no applied snapshot found.");
            return;
        }

        appState = RuleStateMutations.Clone(appliedStateStore.Load());
        SaveState();
        LoadStateToUi();
        Log("rolled back to last applied snapshot.");
    }

    private async void OnAddMacProfileClick(object? sender, RoutedEventArgs e)
    {
        var initialFolder = await ResolveInitialFolderAsync();
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Select WireGuard config for Mac software profile",
            AllowMultiple = false,
            SuggestedStartLocation = initialFolder,
            FileTypeFilter =
            [
                new FilePickerFileType("WireGuard config") { Patterns = ["*.conf"] },
                new FilePickerFileType("All files") { Patterns = ["*"] }
            ]
        });

        if (files.Count == 0)
        {
            return;
        }

        var profile = MacTunnelProfileService.CreateProfile(files[0].Path.LocalPath);
        if (!MacSoftwareRuleMutations.TryAddProfile(appState, profile))
        {
            Log($"mac profile already exists or is invalid: {profile.DisplayName}");
            return;
        }

        SaveState();
        RefreshMacSoftwareRows(profile.Id);
        Log($"added Mac profile: {profile.DisplayName}");
    }

    private async void OnPickMacAppBundleClick(object? sender, RoutedEventArgs e)
    {
        if (MacProfileCombo.SelectedItem is not MacTunnelProfileRow profile)
        {
            Log("add or select a Mac WireGuard profile first.");
            return;
        }

        var initialFolder = await ResolveApplicationsFolderAsync();
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select macOS .app bundle",
            AllowMultiple = false,
            SuggestedStartLocation = initialFolder
        });

        if (folders.Count == 0)
        {
            return;
        }

        var bundlePath = folders[0].Path.LocalPath;
        var bundleInfo = MacAppBundleInfoParser.TryReadBundle(bundlePath);
        if (bundleInfo is null)
        {
            Log($"unable to read CFBundleIdentifier from: {bundlePath}");
            return;
        }

        if (!MacSoftwareRuleMutations.TryAddSoftwareRule(
                appState,
                bundleInfo.BundleIdentifier,
                bundleInfo.DisplayName,
                bundlePath,
                profile.Id))
        {
            Log($"mac software rule already exists: {bundleInfo.DisplayName} -> {profile.DisplayName}");
            return;
        }

        SaveState();
        RefreshMacSoftwareRows(profile.Id);
        Log($"added Mac software rule: {bundleInfo.DisplayName} -> {profile.DisplayName}");
    }

    private void OnMacProfileEnabledChanged(object? sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: string profileId } checkbox)
        {
            return;
        }

        if (MacSoftwareRuleMutations.TrySetProfileEnabled(appState, profileId, checkbox.IsChecked == true))
        {
            SaveState();
            RefreshMacSoftwareRows(profileId);
        }
    }

    private void OnRemoveMacProfileClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string profileId })
        {
            return;
        }

        if (MacSoftwareRuleMutations.RemoveProfile(appState, profileId))
        {
            SaveState();
            RefreshMacSoftwareRows();
            Log("removed Mac profile and its software rules.");
        }
    }

    private void OnMacSoftwareRuleEnabledChanged(object? sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: MacSoftwareRuleRow row } checkbox)
        {
            return;
        }

        if (MacSoftwareRuleMutations.TrySetSoftwareRuleEnabled(
                appState,
                row.BundleIdentifier,
                row.ProfileId,
                checkbox.IsChecked == true))
        {
            SaveState();
        }
    }

    private void OnRemoveMacSoftwareRuleClick(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: MacSoftwareRuleRow row })
        {
            return;
        }

        if (MacSoftwareRuleMutations.RemoveSoftwareRule(appState, row.BundleIdentifier, row.ProfileId))
        {
            SaveState();
            RefreshMacSoftwareRows(row.ProfileId);
            Log($"removed Mac software rule: {row.DisplayName} -> {row.ProfileDisplayName}");
        }
    }

    private void OnApplyMacSoftwareRulesClick(object? sender, RoutedEventArgs e)
    {
        var enabledProfiles = appState.MacTunnelProfiles.Count(profile => profile.Enabled);
        var enabledRules = appState.MacSoftwareRules.Count(rule => rule.Enabled);
        var capability = MacSoftwareRuleApplyGuard.CheckCapability();
        var status = $"{capability.Message} Profiles: {enabledProfiles}; enabled app rules: {enabledRules}.";
        MacSoftwareApplyStatusText.Text = status;
        Log($"mac software rules apply blocked: {status}");
    }

    private async void OnStartMonitorClick(object? sender, RoutedEventArgs e)
    {
        await StartNetworkMonitorAsync();
    }

    private void OnStopMonitorClick(object? sender, RoutedEventArgs e)
    {
        StopNetworkMonitor();
    }

    private async void OnMainTabsSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.Source, MainTabs))
        {
            return;
        }

        var action = MonitorTabAutoRunPolicy.GetAction(
            wasMonitorTabSelected: e.RemovedItems.Contains(MonitorTabItem),
            isMonitorTabSelected: ReferenceEquals(MainTabs.SelectedItem, MonitorTabItem));

        if (action == MonitorTabAutoRunAction.Start)
        {
            await StartNetworkMonitorAsync();
        }
        else if (action == MonitorTabAutoRunAction.Stop)
        {
            StopNetworkMonitor();
        }
    }

    private async Task StartNetworkMonitorAsync()
    {
        if (monitorTimer.IsEnabled)
        {
            return;
        }

        var generation = Interlocked.Increment(ref monitorRunGeneration);
        StartMonitorButton.IsEnabled = false;
        StopMonitorButton.IsEnabled = true;
        MonitorStatusText.Text = "Monitor: Starting...";
        monitorTimer.Start();
        await RefreshNetworkMonitorAsync(generation);
    }

    private void StopNetworkMonitor()
    {
        Interlocked.Increment(ref monitorRunGeneration);
        monitorTimer.Stop();
        monitorRefreshCts?.Cancel();
        StartMonitorButton.IsEnabled = true;
        StopMonitorButton.IsEnabled = false;
        MonitorStatusText.Text = "Monitor: Stopped";
    }

    private async void OnMonitorTimerTick(object? sender, EventArgs e)
    {
        await RefreshNetworkMonitorAsync(Volatile.Read(ref monitorRunGeneration));
    }

    private void OnMonitorGraphCanvasSizeChanged(object? sender, SizeChangedEventArgs e)
    {
        RenderNetworkMonitorGraph();
    }

    private async Task RefreshNetworkMonitorAsync(int generation)
    {
        if (Interlocked.CompareExchange(ref monitorRefreshInProgress, 1, 0) != 0)
        {
            return;
        }

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var previous = Interlocked.Exchange(ref monitorRefreshCts, cts);
        previous?.Dispose();

        try
        {
            detector.TryGetActiveInterface(out var wireGuardInterfaceName);
            var snapshot = await networkMonitorService.CaptureAsync(appState, wireGuardInterfaceName, cts.Token);
            if (generation != Volatile.Read(ref monitorRunGeneration) || !monitorTimer.IsEnabled)
            {
                return;
            }

            RenderNetworkMonitorSnapshot(snapshot);
        }
        catch (OperationCanceledException)
        {
            MonitorWarningsText.Text = "Monitor refresh canceled.";
        }
        catch (Exception ex)
        {
            MonitorWarningsText.Text = $"Monitor refresh failed: {ex.Message}";
            Log($"monitor failed: {ex.Message}");
            Debug.WriteLine(ex);
        }
        finally
        {
            if (ReferenceEquals(monitorRefreshCts, cts))
            {
                monitorRefreshCts = null;
            }

            cts.Dispose();
            Interlocked.Exchange(ref monitorRefreshInProgress, 0);
        }
    }

    private void RenderNetworkMonitorSnapshot(NetworkMonitorSnapshot snapshot)
    {
        MonitorStatusText.Text = snapshot.WireGuardFound
            ? $"Monitor: Running | WireGuard: {snapshot.WireGuardInterfaceName} | {snapshot.CapturedAt:HH:mm:ss}"
            : $"Monitor: Running | WireGuard: not detected | {snapshot.CapturedAt:HH:mm:ss}";

        VpnSpeedText.Text = FormatTrafficRate(snapshot.VpnTraffic);
        NormalSpeedText.Text = FormatTrafficRate(snapshot.NormalTraffic);
        var vpnTotalMbps = GetTotalMbps(snapshot.VpnTraffic);
        var normalTotalMbps = GetTotalMbps(snapshot.NormalTraffic);
        monitorGraphHistory.Add(new NetworkGraphSample(snapshot.CapturedAt, vpnTotalMbps, normalTotalMbps));
        VpnTotalText.Text = FormatTrafficStats(snapshot.VpnTraffic, useVpn: true);
        NormalTotalText.Text = FormatTrafficStats(snapshot.NormalTraffic, useVpn: false);
        VpnLatencyText.Text = FormatLatency("VPN", snapshot.Quality.VpnLatency);
        NormalLatencyText.Text = FormatLatency("Normal", snapshot.Quality.NormalLatency);
        GraphStatsText.Text = $"Mini graph: VPN peak {monitorGraphHistory.GetPeakMbps(useVpn: true):0.0} Mbps / avg30 {monitorGraphHistory.GetAverageMbps(TimeSpan.FromSeconds(30), useVpn: true):0.0} Mbps | Normal peak {monitorGraphHistory.GetPeakMbps(useVpn: false):0.0} Mbps / avg30 {monitorGraphHistory.GetAverageMbps(TimeSpan.FromSeconds(30), useVpn: false):0.0} Mbps";
        RenderNetworkMonitorGraph();

        viewState.MonitorActivities.Clear();
        foreach (var row in snapshot.Activities.Take(200))
        {
            viewState.MonitorActivities.Add(new MonitorActivityRowView(
                row.ProcessName,
                row.DomainOrAddress,
                row.RemoteEndpoint,
                row.Route.ToString(),
                row.Connections,
                ShortenPath(row.ExecutablePath),
                row.LastSeen.ToString("HH:mm:ss")));
        }

        MonitorWarningsText.Text = snapshot.Warnings.Count == 0
            ? ""
            : "Warnings: " + string.Join(" | ", snapshot.Warnings.Take(4));
    }

    private void RenderNetworkMonitorGraph()
    {
        var width = MonitorGraphCanvas.Bounds.Width;
        var height = MonitorGraphCanvas.Bounds.Height;
        if (width <= 0 || height <= 0)
        {
            return;
        }

        VpnGraphLine.Points = ToPointCollection(NetworkGraphNormalizer.Normalize(
            monitorGraphHistory.Samples,
            width,
            height,
            useVpn: true));
        NormalGraphLine.Points = ToPointCollection(NetworkGraphNormalizer.Normalize(
            monitorGraphHistory.Samples,
            width,
            height,
            useVpn: false));
    }

    private static AvaloniaList<Point> ToPointCollection(IReadOnlyList<NetworkGraphPoint> points)
    {
        var collection = new AvaloniaList<Point>();
        foreach (var point in points)
        {
            collection.Add(new Point(point.X, point.Y));
        }

        return collection;
    }

    private void LoadStateToUi()
    {
        selectedConfigPath = appState.SelectedTunnelConfigPath;
        RefreshTunnelConfigRows(selectedConfigPath);
        RefreshDomainRows();
        RefreshMacSoftwareRows();
    }

    private void RefreshTunnelConfigRows(string? preferredPath = null)
    {
        var discovered = WireguardConfigCatalog.DiscoverConfigPaths();
        if (!string.IsNullOrWhiteSpace(selectedConfigPath)
            && File.Exists(selectedConfigPath)
            && !discovered.Contains(selectedConfigPath, StringComparer.OrdinalIgnoreCase))
        {
            discovered.Add(selectedConfigPath);
        }

        var rows = discovered
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(path => new TunnelConfigRow(path, WireguardConfigCatalog.GetTunnelName(path)))
            .OrderBy(row => row.Display, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        suppressConfigSelectionChanged = true;
        try
        {
            viewState.TunnelConfigs.Clear();
            foreach (var row in rows)
            {
                viewState.TunnelConfigs.Add(row);
            }

            var preferred = preferredPath ?? selectedConfigPath ?? appState.SelectedTunnelConfigPath;
            ConfigCombo.SelectedItem = viewState.TunnelConfigs.FirstOrDefault(row =>
                !string.IsNullOrWhiteSpace(preferred)
                && string.Equals(row.Path, preferred, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            suppressConfigSelectionChanged = false;
        }
    }

    private async Task<string> WaitForWireGuardInterfaceAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 12; attempt++)
        {
            if (detector.TryGetActiveInterface(out var iface))
            {
                activeTunnelName = iface;
                return iface;
            }

            await Task.Delay(500, cancellationToken);
        }

        throw new InvalidOperationException(
            "Tunnel started, but no WireGuard interface was detected. Check the selected config and try Refresh Status.");
    }

    private void EnsureAiServicesPreset()
    {
        var result = DomainPresetService.ApplyPreset(appState, DomainPreset.AiServicesBundle);
        if (result.Added > 0)
        {
            SaveState();
            RefreshDomainRows();
            Log($"AI Services Bundle added {result.Added} domain rule(s).");
        }
        else
        {
            Log("AI Services Bundle already selected.");
        }
    }

    private async Task ApplyDomainRoutesAsync(string iface, CancellationToken ct)
    {
        SyncDomainRowsToState();
        var enabledRules = appState.DomainRules
            .Where(rule => rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard)
            .ToList();
        var coordinator = new RuleResolutionCoordinator(resolver);
        var resolvedRules = await coordinator.ResolveEnabledRulesAsync(enabledRules, ct);
        var plan = DomainRouteApplyPlanner.Build(appState.ManagedRouteSnapshot, resolvedRules);

        await routeService.ApplyAsync(iface, plan.ToAdd, plan.ToRemove, ct);
        ResolutionStateUpdater.Apply(appState, resolvedRules);
        appState = appState with { ManagedRouteSnapshot = plan.Snapshot.ToList() };
        SaveState();
        appliedStateStore.Save(RuleStateMutations.Clone(appState));
        RefreshDomainRows();
        Log($"applied {plan.ToAdd.Count} route(s) on {iface}; removed {plan.ToRemove.Count}; resolved {resolvedRules.Count} rule(s).");
    }

    private static bool IsDiscoveredConfigPath(string path) =>
        WireguardConfigCatalog.DiscoverConfigPaths()
            .Contains(path, StringComparer.OrdinalIgnoreCase);

    private void RefreshDomainRows()
    {
        viewState.Domains.Clear();
        foreach (var rule in appState.DomainRules.OrderBy(rule => rule.Domain, StringComparer.OrdinalIgnoreCase))
        {
            var row = new DomainRuleRow(rule.Domain)
            {
                Enabled = rule.Enabled
            };
            if (appState.LastKnownResolvedIps.TryGetValue(rule.Domain, out var ips) && ips.Count > 0)
            {
                row.ResolvedIps = ips.ToList();
                row.ResolvedSummary = string.Join(", ", ips);
            }

            viewState.Domains.Add(row);
        }
    }

    private void SyncDomainRowsToState()
    {
        foreach (var row in viewState.Domains)
        {
            RuleStateMutations.TrySetRuleEnabled(appState, row.Domain, row.Enabled);
        }

        SaveState();
    }

    private void RefreshMacSoftwareRows(string? preferredProfileId = null)
    {
        var selectedProfileId = preferredProfileId
            ?? (MacProfileCombo.SelectedItem as MacTunnelProfileRow)?.Id;

        viewState.MacProfiles.Clear();
        foreach (var profile in appState.MacTunnelProfiles
                     .OrderBy(profile => profile.DisplayName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(profile => profile.ConfigPath, StringComparer.OrdinalIgnoreCase))
        {
            viewState.MacProfiles.Add(new MacTunnelProfileRow(
                profile.Id,
                profile.DisplayName,
                profile.ConfigPath,
                profile.TunnelName,
                profile.Enabled));
        }

        MacProfileCombo.SelectedItem = viewState.MacProfiles.FirstOrDefault(profile =>
                                           string.Equals(profile.Id, selectedProfileId, StringComparison.OrdinalIgnoreCase))
                                       ?? viewState.MacProfiles.FirstOrDefault();

        var profileNames = appState.MacTunnelProfiles.ToDictionary(
            profile => profile.Id,
            profile => profile.DisplayName,
            StringComparer.OrdinalIgnoreCase);

        viewState.MacSoftwareRules.Clear();
        foreach (var rule in appState.MacSoftwareRules
                     .OrderBy(rule => rule.DisplayName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(rule => rule.BundleIdentifier, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(rule => rule.ProfileId, StringComparer.OrdinalIgnoreCase))
        {
            viewState.MacSoftwareRules.Add(new MacSoftwareRuleRow(
                rule.BundleIdentifier,
                rule.DisplayName,
                rule.BundlePath,
                rule.ProfileId,
                profileNames.TryGetValue(rule.ProfileId, out var profileName) ? profileName : "(missing profile)",
                rule.Enabled));
        }
    }

    private async Task<IStorageFolder?> ResolveApplicationsFolderAsync()
    {
        foreach (var path in new[] { "/Applications", "/System/Applications" })
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            try
            {
                return await StorageProvider.TryGetFolderFromPathAsync(new Uri(path));
            }
            catch
            {
                // Best-effort only.
            }
        }

        return null;
    }

    private void SaveState()
    {
        stateStore.Save(appState);
    }

    private void RefreshTunnelStatus()
    {
        if (detector.TryGetActiveInterface(out var iface))
        {
            activeTunnelName = iface;
            TunnelStatusText.Text = $"connected via {iface}";
            TunnelStatusText.Foreground = Brushes.SeaGreen;
        }
        else
        {
            activeTunnelName = null;
            TunnelStatusText.Text = "not connected";
            TunnelStatusText.Foreground = Brushes.Gray;
        }
    }

    private async Task RunGuardedAsync(string label, Func<CancellationToken, Task> body)
    {
        try
        {
            Log($"{label}: running...");
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await body(cts.Token);
            Log($"{label}: done");
        }
        catch (Exception ex)
        {
            Log($"{label}: FAILED - {ToFriendlyMacError(ex.Message)}");
            Debug.WriteLine(ex);
        }
    }

    private static string ToFriendlyMacError(string message)
    {
        if (message.Contains("/opt/homebrew/bin/bash: No such file or directory", StringComparison.OrdinalIgnoreCase))
        {
            return "Homebrew Bash is missing. Run: brew install bash";
        }

        if (message.Contains("wg-quick not found", StringComparison.OrdinalIgnoreCase))
        {
            return "WireGuard tools are missing. Run: brew install wireguard-tools bash";
        }

        if (message.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            && message.Contains(".conf", StringComparison.OrdinalIgnoreCase))
        {
            return "macOS blocked that config path. Copy the .conf file to /opt/homebrew/etc/wireguard, refresh configs, and choose it there.";
        }

        return message;
    }

    private void Log(string message)
    {
        var stamp = DateTime.Now.ToString("HH:mm:ss");
        var line = $"[{stamp}] {message}";
        Dispatcher.UIThread.Post(() =>
        {
            LogText.Text = LogText.Text is { Length: > 0 } current
                ? current + "\n" + line
                : line;
        });
    }

    private static string FormatTrafficRate(NetworkTrafficSummary summary)
    {
        if (!summary.IsAvailable)
        {
            return "Unavailable";
        }

        return $"Down {FormatBytesPerSecond(summary.DownloadBytesPerSecond)} ({FormatMegabitsPerSecond(summary.DownloadBytesPerSecond)}) | Up {FormatBytesPerSecond(summary.UploadBytesPerSecond)} ({FormatMegabitsPerSecond(summary.UploadBytesPerSecond)})";
    }

    private string FormatTrafficStats(NetworkTrafficSummary summary, bool useVpn)
    {
        if (!summary.IsAvailable)
        {
            return "Total: unavailable";
        }

        var totalMbps = GetTotalMbps(summary);
        var peak = monitorGraphHistory.GetPeakMbps(useVpn);
        var average = monitorGraphHistory.GetAverageMbps(TimeSpan.FromSeconds(30), useVpn);
        return $"Total {totalMbps:0.0} Mbps | Peak {peak:0.0} Mbps | Avg 30s {average:0.0} Mbps";
    }

    private static string FormatBytesPerSecond(double bytesPerSecond) => $"{FormatBytes(bytesPerSecond)}/s";

    private static string FormatMegabitsPerSecond(double bytesPerSecond) => $"{BytesPerSecondToMbps(bytesPerSecond):0.0} Mbps";

    private static double GetTotalMbps(NetworkTrafficSummary summary)
    {
        if (!summary.IsAvailable)
        {
            return 0;
        }

        return BytesPerSecondToMbps(summary.DownloadBytesPerSecond + summary.UploadBytesPerSecond);
    }

    private static double BytesPerSecondToMbps(double bytesPerSecond) => Math.Max(0, bytesPerSecond) * 8 / 1_000_000;

    private static string FormatLatency(string label, NetworkLatencySummary summary)
    {
        if (!summary.IsAvailable)
        {
            return $"{label}: Unavailable";
        }

        var ping = summary.PingMs.HasValue ? $"{summary.PingMs.Value:0} ms" : "Timeout";
        var jitter = summary.JitterMs.HasValue ? $"{summary.JitterMs.Value:0.0} ms" : "-";
        return $"{label}: {ping} | Jitter {jitter} | Loss {summary.PacketLossPercent:0}%";
    }

    private static string FormatBytes(double bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = Math.Max(0, bytes);
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{value:0} {units[unitIndex]}"
            : $"{value:0.0} {units[unitIndex]}";
    }

    private static string ShortenPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "";
        }

        var directory = Path.GetDirectoryName(path);
        var fileName = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(fileName))
        {
            return path;
        }

        return $"{directory}/.../{fileName}";
    }
}
