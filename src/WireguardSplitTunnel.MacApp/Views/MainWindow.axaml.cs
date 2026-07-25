using System.Diagnostics;
using System.Runtime.Versioning;
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

[SupportedOSPlatform("macos")]
public partial class MainWindow : Window
{
    private readonly MainWindowState viewState = new();
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
    private bool suppressRestoreOnExitChanged;
    private bool allowCloseWithoutRestore;
    private bool exitCleanupInProgress;

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
        AdoptLeftoverTunnel();
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
        // Disable before the first await so a double-click cannot race two starts.
        StartAiVpnButton.IsEnabled = false;
        try
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

            await RunGuardedAsync("start AI VPN", async ct =>
            {
                Log(startPlan.Message);
                var splitConfigPath = MacSplitTunnelConfigService.WriteSplitTunnelConfig(
                    selectedConfigPath!, GetDataDirectory());
                Log($"split tunnel config ready: {splitConfigPath} (Table=off, system DNS kept)");
                await tunnelControl.InstallAndStartAsync(splitConfigPath, ct);
                appState = appState with { ActiveSplitTunnelConfigPath = splitConfigPath };
                SaveState();
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

        // Disable before the first await so a double-click cannot stack admin prompts.
        EnableTunnelButton.IsEnabled = false;
        try
        {
            await RunGuardedAsync("enable tunnel", async ct =>
            {
                var defaultRouteInterface = await DefaultRouteInspector.GetDefaultRouteInterfaceAsync(ct);
                if (DefaultRouteInspector.IsVpnInterface(defaultRouteInterface))
                {
                    throw new InvalidOperationException(
                        $"Another VPN currently routes all traffic ({defaultRouteInterface}). Disconnect it first, then try again.");
                }

                if (appState.RawTunnelDnsCleanupDebt is not null)
                {
                    throw new InvalidOperationException(
                        "DNS cleanup from a previous full tunnel is still pending. Restore normal routes and DNS before enabling another full tunnel.");
                }

                var rawConfigPath = selectedConfigPath!;
                var rawTunnelName = WireguardConfigCatalog.GetTunnelName(rawConfigPath);
                var configText = await File.ReadAllTextAsync(rawConfigPath, ct);
                MacRawTunnelDnsCleanupDebt? dnsDebt = null;
                string? dnsJournalPath = null;
                if (MacSplitTunnelConfigService.ExtractDnsServers(configText).Count > 0)
                {
                    dnsJournalPath = MacDnsJournalService.CreateJournalPath(GetDataDirectory());
                    dnsDebt = MacDnsRepairService.CreatePendingCleanupDebt(
                        rawTunnelName,
                        rawConfigPath,
                        configText,
                        dnsJournalPath);
                }

                // Persist cleanup provenance before elevation so a crash after
                // wg-quick changes the system cannot erase the debt.
                appState = appState with
                {
                    ActiveRawTunnelName = rawTunnelName,
                    RawTunnelDnsCleanupDebt = dnsDebt
                };
                SaveState();
                await tunnelControl.InstallAndStartAsync(rawConfigPath, dnsJournalPath, ct);

                if (dnsDebt is not null && dnsJournalPath is not null)
                {
                    try
                    {
                        var journalContent = await File.ReadAllTextAsync(dnsJournalPath, ct);
                        appState = appState with
                        {
                            RawTunnelDnsCleanupDebt = MacDnsJournalService.RecoverDebt(
                                dnsDebt,
                                journalContent,
                                MacTunnelNameResolver.GetExactMappingPresence(rawTunnelName))
                        };
                        SaveState();
                    }
                    catch (Exception ex)
                    {
                        // The elevated transaction made the journal durable
                        // before wg-quick up. Keep its path for startup recovery.
                        Log($"DNS cleanup journal kept for recovery: {ToFriendlyMacError(ex.Message)}");
                    }
                }

                Log("full tunnel enabled: ALL traffic and DNS now go through the VPN until you disable it.");
                await Task.Delay(500, ct);
                RefreshTunnelStatus();
            });
        }
        finally
        {
            EnableTunnelButton.IsEnabled = true;
        }
    }

    private async void OnDisableTunnelClick(object? sender, RoutedEventArgs e)
    {
        var splitConfigPath = Path.Combine(
            GetDataDirectory(),
            MacSplitTunnelConfigService.SplitTunnelConfigFileName);
        var targets = MacTunnelDisablePlanner.BuildTargets(
            File.Exists(splitConfigPath) ? splitConfigPath : null,
            appState.ActiveRawTunnelName,
            selectedConfigPath);
        var managedRoutes = appState.ManagedRouteSnapshot.ToList();
        if (targets.Count == 0
            && managedRoutes.Count == 0
            && appState.RawTunnelDnsCleanupDebt is null)
        {
            Log("nothing to disable.");
            return;
        }

        // Disable before the first await so a double-click cannot stack admin prompts.
        DisableTunnelButton.IsEnabled = false;
        try
        {
            await RunGuardedAsync("disable tunnel", async ct =>
            {
                var rawTunnelName = appState.ActiveRawTunnelName;
                var splitTarget = targets.FirstOrDefault(target =>
                    string.Equals(target, splitConfigPath, StringComparison.OrdinalIgnoreCase));
                var rawTarget = targets.FirstOrDefault(target =>
                    !string.IsNullOrWhiteSpace(rawTunnelName)
                    && string.Equals(target, rawTunnelName, StringComparison.OrdinalIgnoreCase));
                var additionalTargets = targets
                    .Where(target =>
                        !string.Equals(target, splitTarget, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals(target, rawTarget, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                var request = new MacCleanupRequest
                {
                    SplitConfigPath = splitTarget,
                    RawTunnelName = rawTarget,
                    AdditionalTunnelTargets = additionalTargets,
                    ManagedRoutesToRemove = managedRoutes,
                    DnsRestorePlan = await BuildDnsRestorePlanAsync(ct)
                };
                var result = await MacExitCleanupService.RunAsync(
                    request,
                    "WireGuard split tunnel needs to stop the selected tunnels",
                    ct);

                ApplyCleanupResult(request, result);
                LogCleanupOutcome(request, result);

                await Task.Delay(300, ct);
                RefreshTunnelStatus();
            });
        }
        finally
        {
            DisableTunnelButton.IsEnabled = true;
        }
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

    private async void OnRestoreNormalRoutesClick(object? sender, RoutedEventArgs e)
    {
        var managedRoutes = appState.ManagedRouteSnapshot.ToList();

        await RunGuardedAsync("restore normal routes", async ct =>
        {
            var dnsRestorePlan = await BuildDnsRestorePlanAsync(ct);
            if (managedRoutes.Count == 0
                && dnsRestorePlan.ServicesToRestore.Count == 0
                && dnsRestorePlan.ServicesResolvedWithoutRestore.Count == 0)
            {
                Log(appState.RawTunnelDnsCleanupDebt is null
                    ? "no managed routes or DNS overrides to restore."
                    : "DNS cleanup debt is still pending because its exact service state could not be confirmed.");
                return;
            }

            var request = new MacCleanupRequest
            {
                ManagedRoutesToRemove = managedRoutes,
                DnsRestorePlan = dnsRestorePlan
            };
            var result = await MacExitCleanupService.RunAsync(
                request,
                "WireGuard split tunnel needs to restore routes and DNS",
                ct);

            ApplyCleanupResult(request, result);
            RefreshDomainRows();
            LogCleanupOutcome(request, result);
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
            var wireGuardInterfaceName =
                MacManagedTunnelInterfaceResolver.TryGetManagedInterface(
                    appState.ActiveRawTunnelName);
            var snapshot = await networkMonitorService.CaptureAsync(
                appState,
                wireGuardInterfaceName,
                cts.Token);
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

        suppressRestoreOnExitChanged = true;
        try
        {
            RestoreOnExitCheckBox.IsChecked = appState.RestoreNormalRoutingOnExit;
        }
        finally
        {
            suppressRestoreOnExitChanged = false;
        }
    }

    private void OnRestoreOnExitChanged(object? sender, RoutedEventArgs e)
    {
        if (suppressRestoreOnExitChanged)
        {
            return;
        }

        appState = appState with { RestoreNormalRoutingOnExit = RestoreOnExitCheckBox.IsChecked == true };
        SaveState();
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
        var plan = DomainRouteApplyPlanner.Build(
            appState.ManagedRouteSnapshot,
            resolvedRules,
            iface);

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

    private void AdoptLeftoverTunnel()
    {
        // A previous session may have left the split tunnel running (the app
        // used to forget it on restart). Re-adopt it so status, route restore,
        // and Disable Tunnel keep working against the right utun.
        var adopted =
            MacManagedTunnelInterfaceResolver.TryGetSplitTunnelInterface();
        if (adopted is not null)
        {
            activeTunnelName = adopted;
            var splitConfigPath = Path.Combine(
                GetDataDirectory(),
                MacSplitTunnelConfigService.SplitTunnelConfigFileName);
            if (File.Exists(splitConfigPath)
                && !string.Equals(
                    appState.ActiveSplitTunnelConfigPath,
                    splitConfigPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                appState = appState with { ActiveSplitTunnelConfigPath = splitConfigPath };
                SaveState();
            }

            Log($"adopted running split tunnel {MacSplitTunnelConfigService.SplitTunnelName} on {adopted} from a previous session");
        }
        else if (!string.IsNullOrWhiteSpace(appState.ActiveSplitTunnelConfigPath)
                 && MacTunnelNameResolver.GetExactMappingPresence(
                     MacSplitTunnelConfigService.SplitTunnelName) == MacTunnelMappingPresence.Absent)
        {
            appState = appState with { ActiveSplitTunnelConfigPath = null };
            SaveState();
        }

        HydrateDnsCleanupDebtFromJournal();
        ReconcileRawTunnel();
        ReconcileDnsCleanupDebt();
    }

    private void HydrateDnsCleanupDebtFromJournal()
    {
        var debt = appState.RawTunnelDnsCleanupDebt;
        if (debt is null || string.IsNullOrWhiteSpace(debt.JournalPath))
        {
            return;
        }

        try
        {
            var journalContent = File.Exists(debt.JournalPath)
                ? File.ReadAllText(debt.JournalPath)
                : null;
            var recovered = MacDnsJournalService.RecoverDebt(
                debt,
                journalContent,
                MacTunnelNameResolver.GetExactMappingPresence(debt.TunnelName));
            if (!Equals(recovered, debt))
            {
                appState = appState with { RawTunnelDnsCleanupDebt = recovered };
                SaveState();
            }
        }
        catch (Exception ex)
        {
            // Malformed or unreadable journals remain conservative debt; no
            // resolver values are guessed or restored from a partial record.
            Log($"saved DNS cleanup journal could not be read; keeping it for retry: {ToFriendlyMacError(ex.Message)}");
        }
    }

    private void ReconcileDnsCleanupDebt()
    {
        var debt = appState.RawTunnelDnsCleanupDebt;
        if (debt is null || !string.IsNullOrWhiteSpace(appState.ActiveRawTunnelName))
        {
            return;
        }

        var mappingPresence = MacTunnelNameResolver.GetExactMappingPresence(debt.TunnelName);
        if (mappingPresence != MacTunnelMappingPresence.Absent)
        {
            Log($"saved DNS cleanup belongs to full tunnel {debt.TunnelName}, whose exact mapping is {mappingPresence}; keeping it for retry.");
            return;
        }

        _ = RepairDnsAfterStaleRawTunnelAsync();
    }

    private void ReconcileRawTunnel()
    {
        var rawTunnelName = appState.ActiveRawTunnelName;
        if (string.IsNullOrWhiteSpace(rawTunnelName))
        {
            return;
        }

        var rawInterface =
            MacTunnelNameResolver.TryGetExactInterfaceForTunnel(rawTunnelName);
        if (rawInterface is not null)
        {
            activeTunnelName = rawInterface;
            Log($"adopted running full tunnel {rawTunnelName} on {rawInterface} from a previous session");
            return;
        }

        var mappingPresence =
            MacTunnelNameResolver.GetExactMappingPresence(rawTunnelName);
        if (MacTunnelLifecyclePlanner.ShouldPreserveUnresolvedRawTunnel(
                mappingPresence))
        {
            Log($"full tunnel {rawTunnelName} ownership could not be confirmed ({mappingPresence}); keeping saved tunnel state and skipping DNS repair.");
            return;
        }

        // The exact raw mapping is confirmed gone. Its tunnel ownership is no
        // longer debt, but its separately persisted DNS snapshot remains until
        // each service is confirmed or restored.
        appState = appState with { ActiveRawTunnelName = null };
        SaveState();
        if (appState.RawTunnelDnsCleanupDebt is not null)
        {
            Log($"full tunnel {rawTunnelName} from a previous session is gone; restoring its saved DNS state...");
        }
    }

    private async Task RepairDnsAfterStaleRawTunnelAsync()
    {
        await RunGuardedAsync("repair DNS", async ct =>
        {
            var dnsRestorePlan = await BuildDnsRestorePlanAsync(ct);
            if (dnsRestorePlan.ServicesToRestore.Count == 0
                && dnsRestorePlan.ServicesResolvedWithoutRestore.Count == 0)
            {
                Log(appState.RawTunnelDnsCleanupDebt is null
                    ? "system DNS is clean; nothing to repair."
                    : "saved DNS cleanup is still pending because its exact service state could not be confirmed.");
                return;
            }

            var request = new MacCleanupRequest { DnsRestorePlan = dnsRestorePlan };
            var result = await MacExitCleanupService.RunAsync(
                request,
                "WireGuard split tunnel needs to restore saved system DNS",
                ct);
            ApplyCleanupResult(request, result);
            LogCleanupOutcome(request, result);
        });
    }

    private async Task<MacDnsRestorePlan> BuildDnsRestorePlanAsync(CancellationToken ct)
    {
        var debt = appState.RawTunnelDnsCleanupDebt;
        if (debt is null)
        {
            // Split-only operation never creates DNS debt, so it never even
            // enumerates network services during cleanup.
            return new MacDnsRestorePlan();
        }

        try
        {
            var current = await MacDnsRepairService.CaptureSnapshotAsync(ct);
            return MacDnsRepairService.PlanSnapshotRestore(
                debt,
                MacDnsRepairService.ToSnapshotMap(current));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log($"could not verify saved DNS cleanup state: {ToFriendlyMacError(ex.Message)}");
            return new MacDnsRestorePlan
            {
                TunnelName = debt.TunnelName,
                ConfigPath = debt.ConfigPath
            };
        }
    }

    private void ApplyCleanupResult(MacCleanupRequest request, MacCleanupResult result)
    {
        var journalPath = appState.RawTunnelDnsCleanupDebt?.JournalPath;
        appState = MacCleanupStateReducer.Apply(appState, request, result);
        SaveState();
        if (appState.RawTunnelDnsCleanupDebt is null)
        {
            MacDnsJournalService.TryDeleteJournal(journalPath);
        }
    }

    private void LogCleanupOutcome(MacCleanupRequest request, MacCleanupResult result)
    {
        if (result.Cancelled)
        {
            Log("cleanup was cancelled; all unresolved ownership was saved for retry.");
            return;
        }

        var requestedTunnelStops =
            (request.SplitConfigPath is null ? 0 : 1)
            + (request.RawTunnelName is null ? 0 : 1)
            + request.AdditionalTunnelTargets.Count;
        var successfulTunnelStops =
            (result.SplitTunnelStopped ? 1 : 0)
            + (result.RawTunnelStopped ? 1 : 0)
            + result.AdditionalTunnelTargetsStopped.Count;
        var requestedDnsRestores = request.DnsRestorePlan.DnsServersToRestore.Count
            + request.DnsRestorePlan.SearchDomainsToRestore.Count;
        var successfulDnsRestores = result.RestoredDnsServerServices.Count
            + result.RestoredSearchDomainServices.Count;
        var resolvedRoutes = result.DeletedManagedRoutes.Count
            + result.AlreadyAbsentManagedRoutes.Count
            + result.ReplacedManagedRoutes.Count;
        var unresolved = successfulTunnelStops < requestedTunnelStops
            || resolvedRoutes < request.ManagedRoutesToRemove.Count
            || successfulDnsRestores < requestedDnsRestores
            || !result.BatchCompleted;

        Log($"cleanup: stopped {successfulTunnelStops}/{requestedTunnelStops} tunnel target(s), reconciled {resolvedRoutes}/{request.ManagedRoutesToRemove.Count} route(s), restored {successfulDnsRestores}/{requestedDnsRestores} DNS component(s).");
        if (unresolved)
        {
            Log("cleanup incomplete; remaining app-owned state was saved for retry.");
        }
    }

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

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        monitorTimer.Stop();
        monitorRefreshCts?.Cancel();

        if (allowCloseWithoutRestore || !appState.RestoreNormalRoutingOnExit)
        {
            base.OnClosing(e);
            return;
        }

        // Cancel this close (also cancels a Cmd+Q shutdown), run the cleanup
        // once, then re-close for real. Mirrors the Windows app's OnWindowClosing.
        e.Cancel = true;
        base.OnClosing(e);
        _ = CleanupThenCloseAsync();
    }

    private async Task CleanupThenCloseAsync()
    {
        if (exitCleanupInProgress)
        {
            return;
        }

        exitCleanupInProgress = true;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));

            // Only include work that is actually pending so a clean system
            // quits without any admin prompt.
            var generatedSplitConfigPath = Path.Combine(
                GetDataDirectory(),
                MacSplitTunnelConfigService.SplitTunnelConfigFileName);
            var splitMappingPresence = MacTunnelNameResolver.GetExactMappingPresence(
                MacSplitTunnelConfigService.SplitTunnelName);
            var splitTunnelPossiblyUp =
                MacTunnelLifecyclePlanner.ShouldAttemptCleanup(splitMappingPresence);
            var splitConfigPath = appState.ActiveSplitTunnelConfigPath
                                  ?? (File.Exists(generatedSplitConfigPath)
                                      ? generatedSplitConfigPath
                                      : null);
            var rawTunnelName = appState.ActiveRawTunnelName;
            var rawTunnelPossiblyUp = !string.IsNullOrWhiteSpace(rawTunnelName)
                && MacTunnelLifecyclePlanner.ShouldAttemptCleanup(
                    MacTunnelNameResolver.GetExactMappingPresence(rawTunnelName!));
            var managedRoutes = appState.ManagedRouteSnapshot.ToList();
            var dnsRestorePlan = await BuildDnsRestorePlanAsync(cts.Token);

            Log("restoring normal routing before quitting...");
            var request = new MacCleanupRequest
            {
                SplitConfigPath = splitTunnelPossiblyUp
                                  && splitConfigPath is not null
                                  && File.Exists(splitConfigPath)
                    ? splitConfigPath
                    : null,
                RawTunnelName = rawTunnelPossiblyUp ? rawTunnelName : null,
                ManagedRoutesToRemove = managedRoutes,
                DnsRestorePlan = dnsRestorePlan
            };
            var result = await MacExitCleanupService.RunAsync(
                request,
                "WireGuard split tunnel is restoring normal routing before quitting",
                cts.Token);

            ApplyCleanupResult(request, result);
            LogCleanupOutcome(request, result);
        }
        catch (Exception ex)
        {
            // Never trap the user in the app because cleanup (or the admin
            // prompt) failed — log and close anyway.
            Log($"restore on exit failed: {MacErrorPresenter.ToFriendly(ex.Message)}");
            Debug.WriteLine(ex);
        }
        finally
        {
            allowCloseWithoutRestore = true;
            Dispatcher.UIThread.Post(Close);
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

    private static string ToFriendlyMacError(string message) => MacErrorPresenter.ToFriendly(message);

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
