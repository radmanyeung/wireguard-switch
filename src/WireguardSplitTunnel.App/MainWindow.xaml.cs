using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.VisualBasic;
using Microsoft.Win32;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.App.Services;

namespace WireguardSplitTunnel.App;

public partial class MainWindow : Window
{
    private readonly IWireguardDetector detector = new SystemWireguardDetector();
    private readonly IDomainResolver domainResolver = new SystemDomainResolver();
    private readonly IRouteService routeService = new RouteService();
    private readonly ISoftwarePolicyService softwarePolicyService = new SoftwareFirewallPolicyService();
    private readonly ISoftwareExecutableLocator softwareExecutableLocator = new SystemSoftwareExecutableLocator();
    private readonly IAppLogger logger;
    private readonly StateStore stateStore;
    private readonly StateStore appliedStateStore;
    private readonly StateStore tempListStore;
    private AppState state;
    private bool suppressSettingsEvents;
    private bool allowCloseWithoutRestore;
    private bool isWindowClosing;
    private readonly bool runPostInstallSelfTestOnLoad;
    private readonly SemaphoreSlim renewSemaphore = new(1, 1);
    private readonly SemaphoreSlim softwareApplySemaphore = new(1, 1);
    private CancellationTokenSource? softwareReapplyDebounceCts;
    private int softwareApplyInProgress;
    private int renewInProgress;
    private volatile bool suppressAutoSoftwareReapply;
    private bool mode2RoutingWarningShownThisSession;
    private const int BypassHalfDefaultMetric = 5;
    private const int WireGuardHalfDefaultMetric = 35;
    private static readonly string[] SafeDnsFallbackServers = ["8.8.8.8", "1.1.1.1"];


    public MainWindow(bool runPostInstallSelfTestOnLoad = false)
    {
        this.runPostInstallSelfTestOnLoad = runPostInstallSelfTestOnLoad;
        InitializeComponent();

        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WireguardSplitTunnel");

        var runtimeLogCandidates = new List<string>
        {
            Path.Combine(Environment.CurrentDirectory, "runtime.log"),
            Path.Combine(AppContext.BaseDirectory, "runtime.log"),
            Path.Combine(dataDirectory, "runtime.log")
        };

        var baseDirParent = Directory.GetParent(AppContext.BaseDirectory)?.FullName;
        if (!string.IsNullOrWhiteSpace(baseDirParent))
        {
            runtimeLogCandidates.Add(Path.Combine(baseDirParent, "runtime.log"));
        }

        logger = new FileAppLogger(
            (new[] { Path.Combine(dataDirectory, "app.log") })
                .Concat(runtimeLogCandidates)
                .ToArray());
        logger.Info("MainWindow initializing.");

        stateStore = new StateStore(Path.Combine(dataDirectory, "state.json"));
        appliedStateStore = new StateStore(Path.Combine(dataDirectory, "applied-state.json"));
        tempListStore = new StateStore(Path.Combine(dataDirectory, "temp-lists.json"));
        state = stateStore.Load();

        Loaded += OnLoaded;
        Closing += OnWindowClosing;

        AddDomainRuleButton.Click += OnAddDomainRuleClicked;
        ToggleDomainEnabledButton.Click += OnToggleDomainEnabledClicked;
        DeleteDomainRuleButton.Click += OnDeleteDomainRuleClicked;
        ViewDomainIpsButton.Click += OnViewDomainIpsClicked;
        RollbackButton.Click += OnRollbackClicked;
        SelfTestButton.Click += OnSelfTestClicked;

        AddSoftwareRuleButton.Click += OnAddSoftwareRuleClicked;
        ToggleSoftwareEnabledButton.Click += OnToggleSoftwareEnabledClicked;
        ToggleSubprocessButton.Click += OnToggleSubprocessClicked;
        DeleteSoftwareRuleButton.Click += OnDeleteSoftwareRuleClicked;
        ApplySoftwareButton.Click += OnApplySoftwareClicked;
        SoftwareSelfTestButton.Click += OnSoftwareSelfTestClicked;

        RefreshConfigsButton.Click += OnRefreshConfigsClicked;
        BrowseConfigButton.Click += OnBrowseConfigClicked;
        EnableTunnelButton.Click += OnEnableTunnelClicked;
        SaveTempButton.Click += OnSaveTempClicked;
        LoadTempButton.Click += OnLoadTempClicked;

        TunnelConfigCombo.SelectionChanged += OnTunnelConfigSelectionChanged;
        AutoEnableCheckBox.Checked += OnAutoEnableChanged;
        AutoEnableCheckBox.Unchecked += OnAutoEnableChanged;
        RestoreOnExitCheckBox.Checked += OnRestoreOnExitChanged;
        RestoreOnExitCheckBox.Unchecked += OnRestoreOnExitChanged;
        UnifiedGlobalModeCombo.SelectionChanged += OnUnifiedGlobalModeChanged;

        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
    }
    private async void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        isWindowClosing = true;
        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
        softwareReapplyDebounceCts?.Cancel();

        if (allowCloseWithoutRestore || !state.RestoreNormalRoutingOnExit)
        {
            return;
        }

        e.Cancel = true;

        try
        {
            await RestoreNormalRoutingOnExitAsync();
        }
        catch (Exception ex)
        {
            logger.Error("Restore on exit failed.", ex);
            MessageBox.Show(this, $"Restore on exit failed: {ex.Message}", "Wireguard Split Tunnel");
        }
        finally
        {
            allowCloseWithoutRestore = true;
            Close();
        }
    }
    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        suppressAutoSoftwareReapply = true;
        try
        {
            logger.Info("Window loaded. Starting initialization.");

            NormalizeUnifiedGlobalModeOnLoad();
            LoadSettingsToUi();

            var isConnected = detector.TryGetActiveInterface(out var interfaceName);
            TunnelStatusText.Text = isConnected
                ? $"Tunnel: Connected ({interfaceName})"
                : "Tunnel: Disconnected";

            if (!isConnected && state.AutoEnableTunnel)
            {
                logger.Info("Auto enable tunnel triggered on startup.");
                TryEnableSelectedTunnel(autoTriggered: true);
            }

            RefreshDomainGrid();
            RefreshSoftwareGrid();

            await AutoRenewDomainRoutesOnStartAsync();

            if (runPostInstallSelfTestOnLoad)
            {
                await RunPostInstallSelfTestsAsync();
            }
        }
        catch (Exception ex)
        {
            logger.Error("Unhandled startup exception.", ex);
            TunnelStatusText.Text = "Tunnel: Startup renew failed";
            MessageBox.Show(this, $"Startup renew failed: {ex.Message}", "Wireguard Split Tunnel");
        }
        finally
        {
            suppressAutoSoftwareReapply = false;
        }
    }
    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        ScheduleSoftwareReapply("network address changed");
    }

    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
    {
        if (!e.IsAvailable)
        {
            return;
        }

        ScheduleSoftwareReapply("network availability changed");
    }

    private void ScheduleSoftwareReapply(string reason)
    {
        if (isWindowClosing)
        {
            return;
        }

        if (suppressAutoSoftwareReapply)
        {
            logger.Info($"Skip auto software rules re-apply ({reason}): startup routing is still initializing.");
            return;
        }

        if (!(state.SoftwareRules ?? []).Any(rule => rule.Enabled))
        {
            return;
        }

        if (!detector.TryGetActiveInterface(out _))
        {
            return;
        }

        if (!IsRunningAsAdministrator())
        {
            logger.Info($"Skip auto software rules re-apply ({reason}): app is not running as Administrator.");
            return;
        }

        logger.Info($"Scheduling software rules re-apply: {reason}");

        var nextCts = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref softwareReapplyDebounceCts, nextCts);
        previous?.Cancel();
        previous?.Dispose();

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(3), nextCts.Token);
                if (nextCts.IsCancellationRequested || isWindowClosing)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref renewInProgress, 0, 0) == 1)
                {
                    logger.Info($"Auto software rules re-apply delayed ({reason}): domain renew is in progress.");
                    await WaitForDomainRenewIdleAsync(nextCts.Token);
                    if (nextCts.IsCancellationRequested || isWindowClosing)
                    {
                        return;
                    }
                }

                var op = Dispatcher.InvokeAsync(() =>
                    ApplySoftwarePoliciesAsync(showMessage: false, triggerReason: $"auto re-apply ({reason})", CancellationToken.None));
                await op.Task.Unwrap();
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                logger.Error($"Auto software rules re-apply failed ({reason}).", ex);
            }
        });
    }
    private void NormalizeUnifiedGlobalModeOnLoad()
    {
        if (state.DomainGlobalDefaultMode != state.SoftwareGlobalDefaultMode)
        {
            logger.Info($"Global mode mismatch detected on load. Domain={state.DomainGlobalDefaultMode}, Software={state.SoftwareGlobalDefaultMode}. Syncing to Domain mode.");
            state = state with { SoftwareGlobalDefaultMode = state.DomainGlobalDefaultMode };
            stateStore.Save(state);
        }

        if (GetUnifiedGlobalMode() == DomainRouteMode.BypassWireGuard)
        {
            logger.Info("OR mode active: listed domains/software use WireGuard; other traffic prefers non-WireGuard.");
        }
    }
    private void LoadSettingsToUi()
    {
        suppressSettingsEvents = true;

        var mode = GetUnifiedGlobalMode();
        AutoEnableCheckBox.IsChecked = state.AutoEnableTunnel;
        RestoreOnExitCheckBox.IsChecked = state.RestoreNormalRoutingOnExit;
        UnifiedGlobalModeCombo.SelectedIndex = mode == DomainRouteMode.UseWireGuard ? 0 : 1;

        RefreshTunnelConfigOptions();
        if (!string.IsNullOrWhiteSpace(state.SelectedTunnelConfigPath))
        {
            TunnelConfigCombo.SelectedValue = state.SelectedTunnelConfigPath;
        }

        suppressSettingsEvents = false;
    }

    private void RefreshTunnelConfigOptions()
    {
        var discovered = WireguardConfigCatalog.DiscoverConfigPaths();

        if (!string.IsNullOrWhiteSpace(state.SelectedTunnelConfigPath)
            && File.Exists(state.SelectedTunnelConfigPath)
            && !discovered.Contains(state.SelectedTunnelConfigPath, StringComparer.OrdinalIgnoreCase))
        {
            discovered.Add(state.SelectedTunnelConfigPath);
        }

        var options = discovered
            .Select(path => new TunnelConfigOption(path, WireguardConfigCatalog.GetTunnelName(path)))
            .OrderBy(option => option.Display, StringComparer.OrdinalIgnoreCase)
            .ToList();

        TunnelConfigCombo.ItemsSource = options;
    }

    private void OnRefreshConfigsClicked(object sender, RoutedEventArgs e)
    {
        var previous = TunnelConfigCombo.SelectedValue as string;
        RefreshTunnelConfigOptions();
        TunnelConfigCombo.SelectedValue = previous;
    }

    private void OnBrowseConfigClicked(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select WireGuard config",
            Filter = "WireGuard Config (*.conf;*.conf.dpapi)|*.conf;*.conf.dpapi|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        state = state with { SelectedTunnelConfigPath = dialog.FileName };
        SaveStateAndRefreshConfigSelection(dialog.FileName);
    }

    private void OnTunnelConfigSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (suppressSettingsEvents)
        {
            return;
        }

        state = state with { SelectedTunnelConfigPath = TunnelConfigCombo.SelectedValue as string };
        stateStore.Save(state);
    }

    private void OnAutoEnableChanged(object sender, RoutedEventArgs e)
    {
        if (suppressSettingsEvents)
        {
            return;
        }

        state = state with { AutoEnableTunnel = AutoEnableCheckBox.IsChecked == true };
        stateStore.Save(state);
    }

    private void OnRestoreOnExitChanged(object sender, RoutedEventArgs e)
    {
        if (suppressSettingsEvents)
        {
            return;
        }

        state = state with { RestoreNormalRoutingOnExit = RestoreOnExitCheckBox.IsChecked == true };
        stateStore.Save(state);
    }
    private void OnUnifiedGlobalModeChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (suppressSettingsEvents)
        {
            return;
        }

        var selectedMode = UnifiedGlobalModeCombo.SelectedIndex == 0
            ? DomainRouteMode.UseWireGuard
            : DomainRouteMode.BypassWireGuard;
        ApplyUnifiedGlobalMode(selectedMode, showBypassInfo: true);
    }

    private DomainRouteMode GetUnifiedGlobalMode() => state.DomainGlobalDefaultMode;

    private void ApplyUnifiedGlobalMode(DomainRouteMode mode, bool showBypassInfo)
    {
        state = state with
        {
            DomainGlobalDefaultMode = mode,
            SoftwareGlobalDefaultMode = mode
        };
        stateStore.Save(state);

        suppressSettingsEvents = true;
        UnifiedGlobalModeCombo.SelectedIndex = mode == DomainRouteMode.UseWireGuard ? 0 : 1;
        suppressSettingsEvents = false;

        if (showBypassInfo && mode == DomainRouteMode.BypassWireGuard)
        {
            MessageBox.Show(this, "Unified mode is 2. OR mode active: listed domains or listed software use WireGuard; other traffic prefers non-WireGuard.", "Wireguard Split Tunnel");
        }
    }

    private void OnEnableTunnelClicked(object sender, RoutedEventArgs e)
    {
        TryEnableSelectedTunnel(autoTriggered: false);
    }

    private void TryEnableSelectedTunnel(bool autoTriggered)
    {
        var selectedPath = (TunnelConfigCombo.SelectedValue as string) ?? state.SelectedTunnelConfigPath;
        if (string.IsNullOrWhiteSpace(selectedPath))
        {
            if (!autoTriggered)
            {
                MessageBox.Show(this, "Select a WireGuard config first.", "Wireguard Split Tunnel");
            }

            return;
        }

        if (!File.Exists(selectedPath))
        {
            MessageBox.Show(this, "Selected config file was not found.", "Wireguard Split Tunnel");
            return;
        }

        var wireguardExePath = ResolveWireguardExecutablePath();
        if (string.IsNullOrWhiteSpace(wireguardExePath))
        {
            MessageBox.Show(this, "wireguard.exe not found. Please install WireGuard first.", "Wireguard Split Tunnel");
            return;
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = wireguardExePath,
                Arguments = WireguardConfigCatalog.BuildInstallTunnelArgs(selectedPath),
                UseShellExecute = true,
                Verb = "runas"
            };

            Process.Start(startInfo);
            TunnelStatusText.Text = $"Tunnel: Enabling ({WireguardConfigCatalog.GetTunnelName(selectedPath)})";
            _ = AutoRenewAfterEnableTunnelAsync();
        }
        catch (Win32Exception)
        {
            if (!autoTriggered)
            {
                MessageBox.Show(this, "WireGuard enable was canceled.", "Wireguard Split Tunnel");
            }
        }
        catch (Exception ex)
        {
            logger.Error("Failed to enable selected tunnel.", ex);
            MessageBox.Show(this, $"Failed to enable tunnel: {ex.Message}", "Wireguard Split Tunnel");
        }
    }

    private static string? ResolveWireguardExecutablePath()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WireGuard", "wireguard.exe")
        };

        return candidates.FirstOrDefault(File.Exists);
    }
    private async Task AutoRenewAfterEnableTunnelAsync()
    {
        try
        {
            await Task.Delay(3000);
            var renewed = await RenewDomainRoutesLockedAsync(showMessage: false, fromStartup: false);
            if (renewed)
            {
                TunnelStatusText.Text = "Tunnel: Connected (Domain IP auto-renewed after enable)";
                logger.Info("Auto renew after enable tunnel completed successfully.");
            }
            else
            {
                logger.Info("Auto renew after enable tunnel skipped.");
            }
        }
        catch (Exception ex)
        {
            logger.Error("Auto renew after enable tunnel failed.", ex);
            TunnelStatusText.Text = "Tunnel: Auto-renew after enable failed";
        }
    }

    private void SaveStateAndRefreshConfigSelection(string selectedPath)
    {
        stateStore.Save(state);

        suppressSettingsEvents = true;
        RefreshTunnelConfigOptions();
        TunnelConfigCombo.SelectedValue = selectedPath;
        suppressSettingsEvents = false;
    }

    private void OnSaveTempClicked(object sender, RoutedEventArgs e)
    {
        tempListStore.Save(RuleStateMutations.Clone(state));
        MessageBox.Show(this, "Current domain/software lists saved to temp.", "Wireguard Split Tunnel");
    }

    private void OnLoadTempClicked(object sender, RoutedEventArgs e)
    {
        var temp = tempListStore.Load();
        var unifiedMode = temp.DomainGlobalDefaultMode;

        state = state with
        {
            DomainRules = temp.DomainRules.Select(rule => rule with { }).ToList(),
            SoftwareRules = (temp.SoftwareRules ?? []).Select(rule => rule with { }).ToList(),
            DomainGlobalDefaultMode = unifiedMode,
            SoftwareGlobalDefaultMode = unifiedMode
        };

        stateStore.Save(state);
        LoadSettingsToUi();
        RefreshDomainGrid();
        RefreshSoftwareGrid();
        MessageBox.Show(this, "Temp lists loaded.", "Wireguard Split Tunnel");
    }

    private async void OnAddDomainRuleClicked(object sender, RoutedEventArgs e)
    {
        var domainInput = Interaction.InputBox("Enter domain (example.com or *.example.com)", "Add Domain Rule", "");
        if (string.IsNullOrWhiteSpace(domainInput))
        {
            return;
        }

        if (!RuleStateMutations.TryAddDomainRule(state, domainInput, DomainRouteMode.UseWireGuard))
        {
            MessageBox.Show(this, "Domain is invalid or already exists.", "Wireguard Split Tunnel");
            return;
        }

        var extraCandidates = BuildRelatedDomainCandidates(domainInput)
            .Where(candidate => !string.Equals(candidate, domainInput.Trim(), StringComparison.OrdinalIgnoreCase))
            .Where(candidate => !state.DomainRules.Any(rule => string.Equals(rule.Domain, candidate, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var selectedExtras = PromptSelectRelatedDomains(extraCandidates);
        foreach (var extra in selectedExtras)
        {
            RuleStateMutations.TryAddDomainRule(state, extra, DomainRouteMode.UseWireGuard);
        }

        stateStore.Save(state);
        RefreshDomainGrid();

        TunnelStatusText.Text = "Tunnel: Domain added (auto-renewing IP routes...)";

        try
        {
            var renewed = await RenewDomainRoutesLockedAsync(showMessage: false, fromStartup: false);
            TunnelStatusText.Text = renewed
                ? "Tunnel: Domain added (IP auto-renewed)"
                : "Tunnel: Domain added (auto-renew skipped)";
        }
        catch (Exception ex)
        {
            logger.Error("Auto renew after adding domain failed.", ex);
            TunnelStatusText.Text = "Tunnel: Domain added (auto-renew error)";
            MessageBox.Show(this, $"Domain added but auto-renew failed: {ex.Message}", "Wireguard Split Tunnel");
        }
    }

    private void OnToggleDomainEnabledClicked(object sender, RoutedEventArgs e)
    {
        if (DomainRulesGrid.SelectedItem is not DomainRow selected)
        {
            MessageBox.Show(this, "Select a domain rule first.", "Wireguard Split Tunnel");
            return;
        }

        RuleStateMutations.TrySetRuleEnabled(state, selected.Domain, !selected.Enabled);
        stateStore.Save(state);
        RefreshDomainGrid();
    }

    private void OnDeleteDomainRuleClicked(object sender, RoutedEventArgs e)
    {
        if (DomainRulesGrid.SelectedItem is not DomainRow selected)
        {
            MessageBox.Show(this, "Select a domain rule first.", "Wireguard Split Tunnel");
            return;
        }

        if (!RuleStateMutations.RemoveRule(state, selected.Domain))
        {
            return;
        }

        stateStore.Save(state);
        RefreshDomainGrid();
    }

    private void OnViewDomainIpsClicked(object sender, RoutedEventArgs e)
    {
        if (DomainRulesGrid.SelectedItem is not DomainRow selected)
        {
            MessageBox.Show(this, "Select a domain rule first.", "Wireguard Split Tunnel");
            return;
        }

        var ips = ResolutionStateQueries.GetResolvedIps(state, selected.Domain);
        if (ips.Count == 0)
        {
            MessageBox.Show(this, "No resolved IPs yet. Please restart app to auto-renew domain IPs.", "Wireguard Split Tunnel");
            return;
        }

        MessageBox.Show(this, string.Join(Environment.NewLine, ips), $"Resolved IPs - {selected.Domain}");
    }
    private async Task<bool> RenewDomainRoutesLockedAsync(bool showMessage, bool fromStartup)
    {
        await renewSemaphore.WaitAsync();
        Interlocked.Exchange(ref renewInProgress, 1);
        try
        {
            return await RenewDomainRoutesAsync(showMessage, fromStartup);
        }
        finally
        {
            Interlocked.Exchange(ref renewInProgress, 0);
            renewSemaphore.Release();
        }
    }

    private async Task WaitForDomainRenewIdleAsync(CancellationToken cancellationToken)
    {
        while (Interlocked.CompareExchange(ref renewInProgress, 0, 0) == 1)
        {
            await Task.Delay(500, cancellationToken);
        }
    }
    private async Task AutoRenewDomainRoutesOnStartAsync()
    {
        try
        {
            logger.Info("Auto renew on startup started.");
            var renewed = await RenewDomainRoutesLockedAsync(showMessage: false, fromStartup: true);
            if (renewed)
            {
                TunnelStatusText.Text = "Tunnel: Connected (Domain IP auto-renewed)";
                logger.Info("Auto renew on startup completed successfully.");
            }
            else
            {
                logger.Info("Auto renew on startup skipped.");
            }
        }
        catch (Exception ex)
        {
            logger.Error("Auto renew on startup failed.", ex);
            TunnelStatusText.Text = "Tunnel: Auto-renew error";
            MessageBox.Show(this, $"Auto-renew failed: {ex.Message}", "Wireguard Split Tunnel");
        }
    }
    private async Task RunPostInstallSelfTestsAsync()
    {
        try
        {
            logger.Info("Post-install self test started.");
            TunnelStatusText.Text = "Tunnel: Running post-install self test...";

            await RenewDomainRoutesLockedAsync(showMessage: false, fromStartup: false);
            await Task.Delay(3000);

            await RunSelfTestAsync();
            await RunSoftwareSelfTestAsync();

            TunnelStatusText.Text = "Tunnel: Post-install self test completed";
            logger.Info("Post-install self test completed.");
            MessageBox.Show(this, "Post-install self test completed.", "Wireguard Split Tunnel");
        }
        catch (Exception ex)
        {
            logger.Error("Post-install self test failed.", ex);
            TunnelStatusText.Text = "Tunnel: Post-install self test failed";
            MessageBox.Show(this, $"Post-install self test failed: {ex.Message}", "Wireguard Split Tunnel");
        }
    }

    private async Task<bool> RenewDomainRoutesAsync(bool showMessage, bool fromStartup)
    {
        if (!await WaitForWireguardInterfaceAsync(TimeSpan.FromSeconds(20)))
        {
            if (showMessage)
            {
                MessageBox.Show(this, "WireGuard interface not detected. Enable tunnel first.", "Wireguard Split Tunnel");
            }

            return false;
        }

        detector.TryGetActiveInterface(out var wireguardInterfaceName);

        var forceBypassDefault = state.DomainGlobalDefaultMode == DomainRouteMode.BypassWireGuard;
        if (forceBypassDefault)
        {
            if (!IsRunningAsAdministrator())
            {
                var permissionMessage = "Bypass mode needs Administrator rights to change default route. Please run this app as Administrator.";
                logger.Info(permissionMessage);
                if (showMessage || fromStartup)
                {
                    MessageBox.Show(this, permissionMessage, "Wireguard Split Tunnel");
                }

                return false;
            }

            if (!TryGetBypassDefaultGateway(wireguardInterfaceName, out var bypassTarget))
            {
                if (showMessage)
                {
                    MessageBox.Show(this, "Cannot find non-WireGuard default gateway. Check your normal network connection.", "Wireguard Split Tunnel");
                }

                return false;
            }

            await EnsureDefaultRouteToBypassGatewayAsync(bypassTarget, CancellationToken.None);
            await EnsureMode2DualHalfDefaultRoutesAsync(wireguardInterfaceName, bypassTarget, CancellationToken.None);
            await EnsureWireGuardDnsReachableAsync(wireguardInterfaceName, CancellationToken.None);
            await VerifyBypassNotBlockedAsync(bypassTarget, cancellationToken: CancellationToken.None);

            var domainRoutingCompatibility = EvaluateRoutingCompatibility(wireguardInterfaceName, enabledSoftwareRuleCount: 0);
            if (domainRoutingCompatibility.Status != RoutingStatus.Pass)
            {
                logger.Info($"Domain renew routing status: {domainRoutingCompatibility.Status}. reason={domainRoutingCompatibility.Reason}");
                if (showMessage || fromStartup)
                {
                    var statusText = domainRoutingCompatibility.Status.ToString().ToUpperInvariant();
                    var shouldPrompt = domainRoutingCompatibility.Status == RoutingStatus.Fail
                        || !mode2RoutingWarningShownThisSession;
                    if (shouldPrompt)
                    {
                        if (domainRoutingCompatibility.Status == RoutingStatus.Warning)
                        {
                            mode2RoutingWarningShownThisSession = true;
                        }

                        MessageBox.Show(
                            this,
                            $"Mode 2 routing {statusText}: {domainRoutingCompatibility.Reason}",
                            "Wireguard Split Tunnel");
                    }
                }
            }
        }

        var coordinator = new RuleResolutionCoordinator(domainResolver);
        var enabledRules = state.DomainRules
            .Where(rule => rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard)
            .ToList();

        var resolvedRules = await coordinator.ResolveEnabledRulesAsync(enabledRules, CancellationToken.None);

        var previousManagedIps = state.ManagedRouteSnapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var newSnapshot = resolvedRules
            .SelectMany(result => result.ResolvedIps.Select(ip => new ManagedRouteEntry(result.Rule.Domain, ip)))
            .GroupBy(entry => entry.IpAddress, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        var newIps = newSnapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Always re-add current domain IP routes, because external route updates (WireGuard reapply)
        // may remove them without updating our local state snapshot.
        var toAdd = newIps;
        var toRemove = previousManagedIps
            .Except(newIps, StringComparer.OrdinalIgnoreCase)
            .ToList();

        await routeService.ApplyAsync(wireguardInterfaceName, toAdd, toRemove, CancellationToken.None);
        await HealMissingDomainRoutesAsync(wireguardInterfaceName, newIps, CancellationToken.None);

        ResolutionStateUpdater.Apply(state, resolvedRules);
        state = state with { ManagedRouteSnapshot = newSnapshot };

        stateStore.Save(state);
        appliedStateStore.Save(RuleStateMutations.Clone(state));

        RefreshDomainGrid();

        if (showMessage)
        {
            MessageBox.Show(this,
                $"Domain renew completed. Resolved: {resolvedRules.Count}, route add: {toAdd.Count}, route remove: {toRemove.Count}, force-split: {(forceBypassDefault ? "on" : "off")}.",
                "Wireguard Split Tunnel");
        }

        logger.Info($"RenewDomainRoutes finished: resolved={resolvedRules.Count}, add={toAdd.Count}, remove={toRemove.Count}.");
        return true;
    }

    private async Task HealMissingDomainRoutesAsync(string wireguardInterfaceName, List<string> expectedIps, CancellationToken cancellationToken)
    {
        if (expectedIps.Count == 0)
        {
            return;
        }

        var wireguardIps = GetInterfaceIpv4Addresses(wireguardInterfaceName);
        if (wireguardIps.Count == 0)
        {
            return;
        }

        for (var attempt = 1; attempt <= 3; attempt++)
        {
            var allRoutes = GetAllIpv4Routes();
            var missing = expectedIps
                .Where(ip => !allRoutes.Any(route =>
                    string.Equals(route.Destination, ip, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(route.Netmask, "255.255.255.255", StringComparison.Ordinal)
                    && wireguardIps.Contains(route.InterfaceIp)))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (missing.Count == 0)
            {
                if (attempt > 1)
                {
                    logger.Info($"Domain route heal succeeded on retry {attempt}.");
                }

                return;
            }

            logger.Info($"Domain route heal attempt {attempt}: missing={missing.Count}. Re-applying.");
            await routeService.ApplyAsync(wireguardInterfaceName, missing, [], cancellationToken);
            await Task.Delay(2000, cancellationToken);
        }
    }
    private async Task<bool> WaitForWireguardInterfaceAsync(TimeSpan timeout)
    {
        var started = DateTime.UtcNow;
        while (DateTime.UtcNow - started < timeout)
        {
            if (detector.TryGetActiveInterface(out _))
            {
                return true;
            }

            await Task.Delay(1000);
        }

        return false;
    }
    private async Task RestoreNormalRoutingOnExitAsync()
    {
        logger.Info("Restore on exit started.");

        if (!detector.TryGetActiveInterface(out var wireguardInterfaceName))
        {
            logger.Info("Restore on exit skipped: WireGuard interface not detected.");
            return;
        }

        var managedIps = state.ManagedRouteSnapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (managedIps.Count > 0)
        {
            await routeService.ApplyAsync(
                wireguardInterfaceName,
                Array.Empty<string>(),
                managedIps,
                CancellationToken.None);
        }

        await RemoveWireGuardDnsHostRoutesAsync(wireguardInterfaceName, CancellationToken.None);
        logger.Info("Restore on exit: skipping forced WireGuard full-tunnel /1 routes.");

        state = state with { ManagedRouteSnapshot = [] };
        stateStore.Save(state);

        logger.Info($"Restore on exit completed. Removed managed routes: {managedIps.Count}");
    }

    private async Task RemoveWireGuardDnsHostRoutesAsync(string wireguardInterfaceName, CancellationToken cancellationToken)
    {
        var nic = FindNetworkInterface(wireguardInterfaceName);
        if (nic is null)
        {
            return;
        }

        var ipv4 = nic.GetIPProperties().GetIPv4Properties();
        if (ipv4 is null)
        {
            return;
        }

        var dnsServers = nic.GetIPProperties().DnsAddresses
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var dnsIp in dnsServers)
        {
            var result = await RunRouteCommandAsync($"delete {dnsIp} mask 255.255.255.255 0.0.0.0 if {ipv4.Index}", cancellationToken);
            logger.Info($"route delete DNS host {dnsIp} via if {ipv4.Index} => exit={result.ExitCode}, stderr={result.Stderr}, stdout={result.Stdout}");
        }
    }

    private async Task EnsureWireGuardFullTunnelRoutesAsync(string wireguardInterfaceName, CancellationToken cancellationToken)
    {
        var nic = FindNetworkInterface(wireguardInterfaceName);
        if (nic is null)
        {
            return;
        }

        var ipv4 = nic.GetIPProperties().GetIPv4Properties();
        if (ipv4 is null)
        {
            return;
        }

        var commands = new[]
        {
            $"add 0.0.0.0 mask 128.0.0.0 0.0.0.0 if {ipv4.Index} metric 5",
            $"add 128.0.0.0 mask 128.0.0.0 0.0.0.0 if {ipv4.Index} metric 5"
        };

        foreach (var command in commands)
        {
            var result = await RunRouteCommandAsync(command, cancellationToken);
            logger.Info($"route {command} => exit={result.ExitCode}, stderr={result.Stderr}, stdout={result.Stdout}");
        }
    }
    private async void OnSelfTestClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            SelfTestButton.IsEnabled = false;
            await RunSelfTestAsync();
        }
        catch (Exception ex)
        {
            logger.Error("Self test failed.", ex);
            MessageBox.Show(this, $"Self test failed: {ex.Message}", "Wireguard Split Tunnel");
        }
        finally
        {
            SelfTestButton.IsEnabled = true;
        }
    }

    private async Task RunSelfTestAsync()
    {
        if (!detector.TryGetActiveInterface(out var wireguardInterfaceName))
        {
            MessageBox.Show(this, "Self Test: WireGuard interface not detected.", "Wireguard Split Tunnel");
            return;
        }

        var defaults = GetDefaultRoutes();
        if (defaults.Count == 0)
        {
            MessageBox.Show(this, "Self Test: No default-like IPv4 route found.", "Wireguard Split Tunnel");
            return;
        }

        var best = defaults
            .OrderByDescending(route => PrefixLengthFromMask(route.Netmask))
            .ThenBy(route => route.Metric)
            .First();

        var wireguardIps = GetInterfaceIpv4Addresses(wireguardInterfaceName);
        var defaultViaWireguard = wireguardIps.Contains(best.InterfaceIp);

        var allRoutes = GetAllIpv4Routes();
        var enabledDomains = state.DomainRules
            .Where(rule => rule.Enabled)
            .Select(rule => rule.Domain)
            .ToList();

        var details = new List<string>();
        var expectedHostRoutes = 0;
        var missingHostRoutes = 0;

        foreach (var domain in enabledDomains)
        {
            if (!state.LastKnownResolvedIps.TryGetValue(domain, out var ips) || ips.Count == 0)
            {
                details.Add($"{domain}: no resolved IPs in state");
                continue;
            }

            foreach (var ip in ips.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                expectedHostRoutes++;
                var hasWgHostRoute = allRoutes.Any(route =>
                    string.Equals(route.Destination, ip, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(route.Netmask, "255.255.255.255", StringComparison.Ordinal)
                    && wireguardIps.Contains(route.InterfaceIp));

                if (hasWgHostRoute)
                {
                    details.Add($"{domain} {ip}: OK via WG");
                }
                else
                {
                    details.Add($"{domain} {ip}: MISSING WG host route");
                    missingHostRoutes++;
                }
            }
        }

        var dnsProbeDomain = enabledDomains.FirstOrDefault() ?? "chatgpt.com";
        var dnsOk = false;
        var dnsMessage = string.Empty;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            var resolved = await domainResolver.ResolveAsync(dnsProbeDomain, cts.Token);
            dnsOk = resolved.Count > 0;
            dnsMessage = dnsOk
                ? $"DNS OK ({dnsProbeDomain} -> {string.Join(", ", resolved.Take(3))})"
                : $"DNS failed ({dnsProbeDomain}, no A record)";
        }
        catch (Exception ex)
        {
            dnsOk = false;
            dnsMessage = $"DNS failed ({dnsProbeDomain}): {ex.Message}";
        }

        var domainRouteStatus = expectedHostRoutes == 0
            ? "No enabled domain IPs to verify"
            : (missingHostRoutes == 0
                ? $"Domain route check: PASS ({expectedHostRoutes}/{expectedHostRoutes})"
                : $"Domain route check: FAIL ({expectedHostRoutes - missingHostRoutes}/{expectedHostRoutes}, missing={missingHostRoutes})");

        var summary = new StringBuilder();
        summary.AppendLine("Self Test Result");
        summary.AppendLine($"Default effective route: {best.Destination}/{best.Netmask} via {best.InterfaceIp} (metric {best.Metric})");
        summary.AppendLine($"Default via WireGuard: {(defaultViaWireguard ? "YES" : "NO")}");
        summary.AppendLine(domainRouteStatus);
        summary.AppendLine(dnsMessage);

        if (details.Count > 0)
        {
            summary.AppendLine();
            summary.AppendLine("Domain details:");
            foreach (var line in details.Take(20))
            {
                summary.AppendLine($"- {line}");
            }

            if (details.Count > 20)
            {
                summary.AppendLine($"- ... ({details.Count - 20} more)");
            }
        }

        logger.Info($"Self test completed. defaultViaWg={defaultViaWireguard}, expectedHostRoutes={expectedHostRoutes}, missingHostRoutes={missingHostRoutes}, dnsOk={dnsOk}");
        MessageBox.Show(this, summary.ToString(), "Self Test");
    }
    private void OnRollbackClicked(object sender, RoutedEventArgs e)
    {
        var appliedStatePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WireguardSplitTunnel",
            "applied-state.json");

        if (!File.Exists(appliedStatePath))
        {
            MessageBox.Show(this, "No applied snapshot found.", "Wireguard Split Tunnel");
            return;
        }

        state = RuleStateMutations.Clone(appliedStateStore.Load());
        stateStore.Save(state);
        LoadSettingsToUi();
        RefreshDomainGrid();
        RefreshSoftwareGrid();
        MessageBox.Show(this, "Rolled back to last applied snapshot.", "Wireguard Split Tunnel");
    }

    private void OnAddSoftwareRuleClicked(object sender, RoutedEventArgs e)
    {
        var includeInput = Interaction.InputBox("Include subprocesses? y/n", "Subprocess", "y").Trim();
        var includeSubprocesses = !string.Equals(includeInput, "n", StringComparison.OrdinalIgnoreCase);

        var picker = new OpenFileDialog
        {
            Title = "Select software executable(s)",
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            Multiselect = true,
            CheckFileExists = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
        };

        if (picker.ShowDialog(this) != true)
        {
            return;
        }

        var added = 0;
        var skipped = 0;
        foreach (var file in picker.FileNames)
        {
            var processName = Path.GetFileName(file);
            if (SoftwareRuleMutations.TryAddSoftwareRule(state, processName, DomainRouteMode.UseWireGuard, includeSubprocesses, file))
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
        MessageBox.Show(this, $"Software add completed. Added: {added}, skipped: {skipped}.", "Wireguard Split Tunnel");
    }

    private void OnToggleSoftwareEnabledClicked(object sender, RoutedEventArgs e)
    {
        if (SoftwareRulesGrid.SelectedItem is not SoftwareRow selected)
        {
            MessageBox.Show(this, "Select a software rule first.", "Wireguard Split Tunnel");
            return;
        }

        SoftwareRuleMutations.TrySetEnabled(state, selected.ProcessName, !selected.Enabled);
        stateStore.Save(state);
        RefreshSoftwareGrid();
    }

    private void OnToggleSubprocessClicked(object sender, RoutedEventArgs e)
    {
        if (SoftwareRulesGrid.SelectedItem is not SoftwareRow selected)
        {
            MessageBox.Show(this, "Select a software rule first.", "Wireguard Split Tunnel");
            return;
        }

        var list = state.SoftwareRules ?? [];
        var index = list.FindIndex(rule => string.Equals(rule.ProcessName, selected.ProcessName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return;
        }

        list[index] = list[index] with { IncludeSubprocesses = !list[index].IncludeSubprocesses };
        stateStore.Save(state);
        RefreshSoftwareGrid();
    }

    private void OnDeleteSoftwareRuleClicked(object sender, RoutedEventArgs e)
    {
        if (SoftwareRulesGrid.SelectedItem is not SoftwareRow selected)
        {
            MessageBox.Show(this, "Select a software rule first.", "Wireguard Split Tunnel");
            return;
        }

        if (!SoftwareRuleMutations.Remove(state, selected.ProcessName))
        {
            return;
        }

        stateStore.Save(state);
        RefreshSoftwareGrid();
    }
    private async void OnSoftwareSelfTestClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            if (Volatile.Read(ref softwareApplyInProgress) == 1)
            {
                MessageBox.Show(this, "Software apply is still running. Please wait a few seconds and run Software Self Test again.", "Wireguard Split Tunnel");
                return;
            }

            SoftwareSelfTestButton.IsEnabled = false;
            await RunSoftwareSelfTestAsync();
        }
        catch (Exception ex)
        {
            logger.Error("Software self test failed.", ex);
            MessageBox.Show(this, $"Software self test failed: {ex.Message}", "Wireguard Split Tunnel");
        }
        finally
        {
            SoftwareSelfTestButton.IsEnabled = true;
        }
    }

    private async Task RunSoftwareSelfTestAsync()
    {
        var enabledRules = (state.SoftwareRules ?? [])
            .Where(rule => rule.Enabled)
            .ToList();

        if (enabledRules.Count == 0)
        {
            MessageBox.Show(this, "Software Self Test: no enabled software rules.", "Wireguard Split Tunnel");
            return;
        }

        if (!detector.TryGetActiveInterface(out var wireguardInterfaceName))
        {
            MessageBox.Show(this, "Software Self Test: WireGuard interface not detected.", "Wireguard Split Tunnel");
            return;
        }

        var (firewallRuleNames, firewallQueryError) = await GetSoftwareFirewallRuleDisplayNamesAsync();

        var defaultViaWireGuard = IsDefaultRouteViaWireGuard(wireguardInterfaceName);
        var hasWireGuardHalfDefaults = HasWireGuardHalfDefaultRoute(wireguardInterfaceName);
        var hasBypassHalfDefaults = TryGetBypassDefaultGateway(wireguardInterfaceName, out var bypassTarget)
            && HasBypassHalfDefaultPreference(bypassTarget);
        var unifiedMode = GetUnifiedGlobalMode();
        var routingCompatibility = Mode2RoutingEvaluator.Evaluate(
            unifiedMode,
            enabledRules.Count,
            hasWireGuardHalfDefaults,
            hasBypassHalfDefaults,
            defaultViaWireGuard);

        var details = new List<string>();
        var resolvedPathCount = 0;
        var missingPathCount = 0;
        var firewallMatchedCount = 0;

        foreach (var rule in enabledRules)
        {
            var path = rule.ExecutablePath;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                if (softwareExecutableLocator.TryResolvePath(rule.ProcessName, out var resolvedPath))
                {
                    path = resolvedPath;
                    resolvedPathCount++;
                }
            }

            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                details.Add($"{rule.ProcessName}: MISSING exe path");
                missingPathCount++;
                continue;
            }

            var key = ComputeSoftwareRuleKey(path);
            var matched = firewallRuleNames.Any(name => name.Contains(key, StringComparison.OrdinalIgnoreCase));
            if (matched)
            {
                firewallMatchedCount++;
                details.Add($"{rule.ProcessName}: OK (path + firewall)");
            }
            else
            {
                details.Add($"{rule.ProcessName}: path OK, firewall rule NOT FOUND (key={key})");
            }
        }

        var expectedMatchCount = Math.Max(0, enabledRules.Count - missingPathCount);
        var selfTestStatus = RoutingStatus.Pass;
        if (firewallQueryError is not null || missingPathCount > 0 || firewallMatchedCount < expectedMatchCount)
        {
            selfTestStatus = RoutingStatus.Fail;
        }
        else if (routingCompatibility.Status == RoutingStatus.Fail)
        {
            selfTestStatus = RoutingStatus.Fail;
        }
        else if (routingCompatibility.Status == RoutingStatus.Warning)
        {
            selfTestStatus = RoutingStatus.Warning;
        }

        var sb = new StringBuilder();
        sb.AppendLine("Software Self Test Result");
        sb.AppendLine($"Enabled software rules: {enabledRules.Count}");
        sb.AppendLine($"Resolved exe path now: {resolvedPathCount}");
        sb.AppendLine($"Missing exe path: {missingPathCount}");
        sb.AppendLine($"Firewall rules found (WGST-Software-*): {(firewallQueryError is null ? firewallRuleNames.Count.ToString() : "N/A")}");
        sb.AppendLine($"Rules matched by key: {firewallMatchedCount}/{expectedMatchCount}");
        sb.AppendLine($"Unified global mode: {(unifiedMode == DomainRouteMode.BypassWireGuard ? "2 = Bypass WireGuard" : "1 = Use WireGuard")}");
        sb.AppendLine($"Effective mode2 profile: {routingCompatibility.Profile}");
        sb.AppendLine($"Default via WireGuard now: {(defaultViaWireGuard ? "YES" : "NO")}");
        sb.AppendLine($"WG /1 present: {(hasWireGuardHalfDefaults ? "YES" : "NO")}");
        sb.AppendLine($"Bypass /1 present: {(hasBypassHalfDefaults ? "YES" : "NO")}");
        sb.AppendLine($"Routing status: {selfTestStatus.ToString().ToUpperInvariant()}");
        if (routingCompatibility.Status != RoutingStatus.Pass)
        {
            sb.AppendLine($"Routing note: {routingCompatibility.Reason}");
        }
        if (firewallQueryError is not null)
        {
            sb.AppendLine($"Firewall query: FAIL ({firewallQueryError})");
        }

        sb.AppendLine();
        sb.AppendLine("Details:");
        foreach (var line in details.Take(20))
        {
            sb.AppendLine($"- {line}");
        }

        if (details.Count > 20)
        {
            sb.AppendLine($"- ... ({details.Count - 20} more)");
        }

        logger.Info($"Software self test completed. enabled={enabledRules.Count}, resolvedPathNow={resolvedPathCount}, missingPath={missingPathCount}, fwCount={firewallRuleNames.Count}, matched={firewallMatchedCount}, profile={routingCompatibility.Profile}, routingStatus={selfTestStatus}, defaultViaWg={defaultViaWireGuard}, wgHalf={hasWireGuardHalfDefaults}, bypassHalf={hasBypassHalfDefaults}, firewallQueryError={(firewallQueryError is null ? "none" : firewallQueryError)}.");
        MessageBox.Show(this, sb.ToString(), "Software Self Test");
    }

    private async Task<(List<string> RuleNames, string? QueryError)> GetSoftwareFirewallRuleDisplayNamesAsync()
    {
        const string errorMarker = "__WGST_FWERR__";
        var cmd = "$ErrorActionPreference='Stop'; try { Get-NetFirewallRule -DisplayName 'WGST-Software-*' | Select-Object -ExpandProperty DisplayName } catch { Write-Output '__WGST_FWERR__ ' + $_.Exception.Message; exit 9 }";
        var result = await RunProcessCaptureAsync("powershell", $"-NoProfile -Command \"{cmd}\"", CancellationToken.None);

        string? queryError = null;
        if (!result.Success && !string.IsNullOrWhiteSpace(result.Stderr))
        {
            logger.Info($"Software self test firewall query stderr: {result.Stderr}");
            queryError = result.Stderr;
        }

        var rawLines = result.Stdout
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        var markerLine = rawLines.FirstOrDefault(line => line.StartsWith(errorMarker, StringComparison.Ordinal));
        if (markerLine is not null)
        {
            queryError = markerLine[errorMarker.Length..].Trim();
            rawLines.Remove(markerLine);
        }

        var names = rawLines
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (queryError is null && names.Count == 0 && !IsRunningAsAdministrator())
        {
            queryError = "Firewall query ran without Administrator rights; empty result may be incomplete.";
        }

        return (names, queryError);
    }

    private static string ComputeSoftwareRuleKey(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..10];
    }

    private RoutingCompatibility EvaluateRoutingCompatibility(string wireguardInterfaceName, int enabledSoftwareRuleCount)
    {
        var hasWireGuardHalfDefaults = HasWireGuardHalfDefaultRoute(wireguardInterfaceName);
        var defaultViaWireGuard = IsDefaultRouteViaWireGuard(wireguardInterfaceName);
        var hasBypassHalfDefaults = TryGetBypassDefaultGateway(wireguardInterfaceName, out var bypassTarget)
            && HasBypassHalfDefaultPreference(bypassTarget);

        return Mode2RoutingEvaluator.Evaluate(
            GetUnifiedGlobalMode(),
            enabledSoftwareRuleCount,
            hasWireGuardHalfDefaults,
            hasBypassHalfDefaults,
            defaultViaWireGuard);
    }

    private void NotifyRoutingCompatibilityIfNeeded(RoutingCompatibility compatibility, bool showMessage)
    {
        if (compatibility.Status == RoutingStatus.Pass)
        {
            return;
        }

        var statusText = compatibility.Status.ToString().ToUpperInvariant();
        TunnelStatusText.Text = $"Tunnel: Mode2 routing {statusText} ({compatibility.Profile})";

        if (!showMessage)
        {
            return;
        }

        var shouldPrompt = compatibility.Status == RoutingStatus.Fail
            || !mode2RoutingWarningShownThisSession;
        if (!shouldPrompt)
        {
            return;
        }

        if (compatibility.Status == RoutingStatus.Warning)
        {
            mode2RoutingWarningShownThisSession = true;
        }

        MessageBox.Show(
            this,
            $"{compatibility.Reason}\n\nSoftware rules will still be applied.",
            "Wireguard Split Tunnel");
    }

    private async Task EnsureSoftwareRoutingPreparedAsync(string wireguardInterfaceName, int enabledRuleCount, CancellationToken cancellationToken)
    {
        if (GetUnifiedGlobalMode() != DomainRouteMode.BypassWireGuard)
        {
            return;
        }

        if (!IsRunningAsAdministrator())
        {
            logger.Info("Software apply: skip mode2 /1 route self-heal (app not running as Administrator).");
            return;
        }

        if (!TryGetBypassDefaultGateway(wireguardInterfaceName, out var bypassTarget))
        {
            return;
        }

        var compatibility = EvaluateRoutingCompatibility(wireguardInterfaceName, enabledRuleCount);
        if (compatibility.Status == RoutingStatus.Pass)
        {
            return;
        }

        logger.Info($"Software apply: mode2 routing is {compatibility.Status}. Healing dual /1 routes. reason={compatibility.Reason}");
        await EnsureMode2DualHalfDefaultRoutesAsync(wireguardInterfaceName, bypassTarget, cancellationToken);

        var afterSelfHeal = EvaluateRoutingCompatibility(wireguardInterfaceName, enabledRuleCount);
        if (afterSelfHeal.Status != RoutingStatus.Fail)
        {
            return;
        }

        logger.Info("Software apply: mode2 routing still FAIL after local /1 heal; attempting domain renew heal.");
        try
        {
            await RenewDomainRoutesLockedAsync(showMessage: false, fromStartup: false);
        }
        catch (Exception ex)
        {
            logger.Error("Software apply: routing pre-heal via domain renew failed.", ex);
        }
    }

    private async Task<(bool Verified, bool Unknown, string Detail)> VerifySoftwareRulesAppliedAsync(List<SoftwareRule> effectiveRules)
    {
        var expectedKeys = effectiveRules
            .Where(rule => !string.IsNullOrWhiteSpace(rule.ExecutablePath) && File.Exists(rule.ExecutablePath))
            .Select(rule => ComputeSoftwareRuleKey(rule.ExecutablePath!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (expectedKeys.Count == 0)
        {
            return (true, false, "No resolvable software executable paths to verify.");
        }

        var (firewallRuleNames, firewallQueryError) = await GetSoftwareFirewallRuleDisplayNamesAsync();
        if (!string.IsNullOrWhiteSpace(firewallQueryError))
        {
            return (false, true, $"Firewall query unavailable: {firewallQueryError}");
        }

        var missingKeys = expectedKeys
            .Where(key => !firewallRuleNames.Any(name => name.Contains(key, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (missingKeys.Count == 0)
        {
            return (true, false, $"Verified firewall rules for {expectedKeys.Count} software key(s).");
        }

        return (false, false, $"Missing firewall rule key(s): {string.Join(", ", missingKeys)}");
    }

    private async Task ApplySoftwarePoliciesAsync(bool showMessage, string triggerReason, CancellationToken cancellationToken)
    {
        await softwareApplySemaphore.WaitAsync(cancellationToken);
        Interlocked.Exchange(ref softwareApplyInProgress, 1);
        try
        {
            if (showMessage)
            {
                ApplySoftwareButton.IsEnabled = false;
            }

            SoftwareSelfTestButton.IsEnabled = false;

            if (!detector.TryGetActiveInterface(out var wireguardInterfaceName))
            {
                if (showMessage)
                {
                    MessageBox.Show(this, "WireGuard interface not detected. Enable tunnel first.", "Wireguard Split Tunnel");
                }

                logger.Info($"Software apply skipped ({triggerReason}): WireGuard interface not detected.");
                return;
            }

            var enabledRules = (state.SoftwareRules ?? [])
                .Where(rule => rule.Enabled)
                .ToList();

            var autoFixed = 0;
            var unresolved = new List<string>();
            foreach (var rule in enabledRules)
            {
                if (!string.IsNullOrWhiteSpace(rule.ExecutablePath) && File.Exists(rule.ExecutablePath))
                {
                    continue;
                }

                if (softwareExecutableLocator.TryResolvePath(rule.ProcessName, out var resolvedPath))
                {
                    if (SoftwareRuleMutations.TrySetExecutablePath(state, rule.ProcessName, resolvedPath))
                    {
                        autoFixed++;
                    }
                }
                else
                {
                    unresolved.Add(rule.ProcessName);
                }
            }

            stateStore.Save(state);

            var effectiveRules = (state.SoftwareRules ?? [])
                .Where(rule => rule.Enabled)
                .ToList();

            await EnsureSoftwareRoutingPreparedAsync(wireguardInterfaceName, effectiveRules.Count, cancellationToken);
            var routingCompatibility = EvaluateRoutingCompatibility(wireguardInterfaceName, effectiveRules.Count);
            if (routingCompatibility.Status != RoutingStatus.Pass)
            {
                logger.Info($"Software apply routing status ({triggerReason}): {routingCompatibility.Status}. reason={routingCompatibility.Reason}");
                NotifyRoutingCompatibilityIfNeeded(routingCompatibility, showMessage);
            }

            await softwarePolicyService.ApplyAsync(
                wireguardInterfaceName,
                effectiveRules,
                GetUnifiedGlobalMode(),
                cancellationToken);

            var verification = await VerifySoftwareRulesAppliedAsync(effectiveRules);
            if (!verification.Verified && !verification.Unknown)
            {
                logger.Info($"Software apply verification mismatch ({triggerReason}). Retrying once. detail={verification.Detail}");
                await Task.Delay(500, cancellationToken);
                await softwarePolicyService.ApplyAsync(
                    wireguardInterfaceName,
                    effectiveRules,
                    GetUnifiedGlobalMode(),
                    cancellationToken);
                verification = await VerifySoftwareRulesAppliedAsync(effectiveRules);
            }

            var unresolvedText = unresolved.Count == 0
                ? ""
                : $"\nUnresolved path skipped: {string.Join(", ", unresolved.Distinct(StringComparer.OrdinalIgnoreCase))}";
            var verificationText = $"\nVerification: {verification.Detail}";
            var routingText = routingCompatibility.Status == RoutingStatus.Pass
                ? "\nRouting: PASS"
                : $"\nRouting: WARNING ({routingCompatibility.Reason})";

            if (showMessage)
            {
                MessageBox.Show(this,
                    $"Software apply completed ({triggerReason}). Enabled: {effectiveRules.Count}, auto-fixed paths: {autoFixed}.{unresolvedText}{verificationText}{routingText}\n(Requires Administrator approval)",
                    "Wireguard Split Tunnel");
            }

            if (!verification.Verified && !verification.Unknown)
            {
                logger.Error($"Software apply finished but verification failed ({triggerReason}). {verification.Detail}");
            }
            else
            {
                logger.Info($"Software apply completed ({triggerReason}). enabled={effectiveRules.Count}, autoFixed={autoFixed}, unresolved={unresolved.Count}, verify={(verification.Verified ? "ok" : "unknown")}.");
            }
        }
        finally
        {
            Interlocked.Exchange(ref softwareApplyInProgress, 0);
            ApplySoftwareButton.IsEnabled = true;
            SoftwareSelfTestButton.IsEnabled = true;
            softwareApplySemaphore.Release();
        }
    }

    private async void OnApplySoftwareClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            await ApplySoftwarePoliciesAsync(showMessage: true, triggerReason: "manual apply", CancellationToken.None);
        }
        catch (Win32Exception)
        {
            logger.Info("Software apply canceled by user (UAC).");
            MessageBox.Show(this, "Software apply was canceled (UAC).", "Wireguard Split Tunnel");
        }
        catch (Exception ex)
        {
            logger.Error("Software apply failed.", ex);
            MessageBox.Show(this, $"Software apply failed: {ex.Message}", "Wireguard Split Tunnel");
        }
    }

    private void RefreshDomainGrid()
    {
        var rows = state.DomainRules
            .Select(rule => new DomainRow(
                rule.Domain,
                rule.Enabled,
                state.LastKnownResolvedIps.TryGetValue(rule.Domain, out var ips) ? ips.Count : 0))
            .OrderBy(row => row.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();

        DomainRulesGrid.ItemsSource = rows;
    }

    private void RefreshSoftwareGrid()
    {
        var rows = (state.SoftwareRules ?? [])
            .Select(rule => new SoftwareRow(
                rule.ProcessName,
                rule.Enabled,
                rule.IncludeSubprocesses))
            .OrderBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        SoftwareRulesGrid.ItemsSource = rows;
    }

    private List<string> BuildRelatedDomainCandidates(string domainInput)
    {
        var normalized = domainInput.Trim().ToLowerInvariant();
        var host = normalized.StartsWith("*.", StringComparison.Ordinal) ? normalized[2..] : normalized;
        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (labels.Length < 2)
        {
            return [];
        }

        var root = $"{labels[^2]}.{labels[^1]}";
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            root,
            $"www.{root}",
            $"*.{root}"
        };

        if (!string.Equals(host, root, StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(host);
        }

        if (host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(root);
        }

        foreach (var existing in state.DomainRules.Select(rule => rule.Domain))
        {
            var existingHost = existing.StartsWith("*.", StringComparison.Ordinal) ? existing[2..] : existing;
            if (existingHost.EndsWith("." + root, StringComparison.OrdinalIgnoreCase)
                || string.Equals(existingHost, root, StringComparison.OrdinalIgnoreCase))
            {
                candidates.Add(existing);
            }
        }

        candidates.RemoveWhere(candidate => !DomainValidator.IsValidDomain(candidate));
        candidates.RemoveWhere(candidate => string.Equals(candidate, normalized, StringComparison.OrdinalIgnoreCase));
        return candidates.OrderBy(candidate => candidate, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private List<string> PromptSelectRelatedDomains(List<string> candidates)
    {
        if (candidates.Count == 0)
        {
            return [];
        }

        var sb = new StringBuilder();
        sb.AppendLine("Related domains found:");
        for (var i = 0; i < candidates.Count; i++)
        {
            sb.AppendLine($"{i + 1}. {candidates[i]}");
        }

        sb.AppendLine();
        sb.AppendLine("Enter numbers to add (example: 1,3,4). Leave blank to skip.");
        var input = Interaction.InputBox(sb.ToString(), "Related Domain Suggestions", "");
        if (string.IsNullOrWhiteSpace(input))
        {
            return [];
        }

        var indexes = input
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(token => int.TryParse(token, out var index) ? index : -1)
            .Where(index => index >= 1 && index <= candidates.Count)
            .Distinct()
            .ToList();

        return indexes.Select(index => candidates[index - 1]).ToList();
    }


    private static List<Ipv4RouteEntry> GetAllIpv4Routes()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "route",
            Arguments = "print -4",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Unable to start route print process.");

        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        var routes = new List<Ipv4RouteEntry>();
        foreach (var line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5)
            {
                continue;
            }

            if (!IPAddress.TryParse(parts[0], out _)
                || !IPAddress.TryParse(parts[1], out _)
                || !IPAddress.TryParse(parts[3], out _))
            {
                continue;
            }

            if (!int.TryParse(parts[4], out var metric))
            {
                metric = int.MaxValue;
            }

            routes.Add(new Ipv4RouteEntry(parts[0], parts[1], parts[2], parts[3], metric));
        }

        return routes;
    }
    private static List<DefaultRouteEntry> GetDefaultRoutes()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "route",
            Arguments = "print -4",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Unable to start route print process.");

        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        var routes = new List<DefaultRouteEntry>();
        foreach (var line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5)
            {
                continue;
            }

            var destination = parts[0];
            var netmask = parts[1];
            var isDefaultLike =
                (string.Equals(destination, "0.0.0.0", StringComparison.Ordinal) && string.Equals(netmask, "0.0.0.0", StringComparison.Ordinal))
                || (string.Equals(destination, "0.0.0.0", StringComparison.Ordinal) && string.Equals(netmask, "128.0.0.0", StringComparison.Ordinal))
                || (string.Equals(destination, "128.0.0.0", StringComparison.Ordinal) && string.Equals(netmask, "128.0.0.0", StringComparison.Ordinal));

            if (!isDefaultLike)
            {
                continue;
            }

            if (!int.TryParse(parts[4], out var metric))
            {
                metric = int.MaxValue;
            }

            routes.Add(new DefaultRouteEntry(destination, netmask, parts[2], parts[3], metric));
        }

        return routes;
    }

    private static int PrefixLengthFromMask(string netmask)
    {
        return netmask switch
        {
            "255.255.255.255" => 32,
            "255.255.255.254" => 31,
            "255.255.255.252" => 30,
            "255.255.255.248" => 29,
            "255.255.255.240" => 28,
            "255.255.255.224" => 27,
            "255.255.255.192" => 26,
            "255.255.255.128" => 25,
            "255.255.255.0" => 24,
            "255.255.254.0" => 23,
            "255.255.252.0" => 22,
            "255.255.248.0" => 21,
            "255.255.240.0" => 20,
            "255.255.224.0" => 19,
            "255.255.192.0" => 18,
            "255.255.128.0" => 17,
            "255.255.0.0" => 16,
            "255.254.0.0" => 15,
            "255.252.0.0" => 14,
            "255.248.0.0" => 13,
            "255.240.0.0" => 12,
            "255.224.0.0" => 11,
            "255.192.0.0" => 10,
            "255.128.0.0" => 9,
            "255.0.0.0" => 8,
            "254.0.0.0" => 7,
            "252.0.0.0" => 6,
            "248.0.0.0" => 5,
            "240.0.0.0" => 4,
            "224.0.0.0" => 3,
            "192.0.0.0" => 2,
            "128.0.0.0" => 1,
            "0.0.0.0" => 0,
            _ => 0
        };
    }
    private static HashSet<string> GetInterfaceIpv4Addresses(string interfaceName)
    {
        var nic = FindNetworkInterface(interfaceName);

        if (nic is null)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        return nic.GetIPProperties().UnicastAddresses
            .Where(item => item.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(item => item.Address.ToString())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
    private static bool TryGetBypassDefaultGateway(string wireguardInterfaceName, out DefaultGatewayTarget target)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            if (string.Equals(nic.Name, wireguardInterfaceName, StringComparison.OrdinalIgnoreCase)
                || nic.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                || nic.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var ipv4 = nic.GetIPProperties().GetIPv4Properties();
            if (ipv4 is null)
            {
                continue;
            }

            var gateway = nic.GetIPProperties().GatewayAddresses
                .Select(item => item?.Address)
                .FirstOrDefault(address =>
                    address is not null
                    && address.AddressFamily == AddressFamily.InterNetwork
                    && !IPAddress.Any.Equals(address)
                    && !IPAddress.None.Equals(address));

            if (gateway is null)
            {
                continue;
            }

            target = new DefaultGatewayTarget(nic.Name, ipv4.Index, gateway.ToString());
            return true;
        }

        target = new DefaultGatewayTarget(string.Empty, -1, string.Empty);
        return false;
    }
    private async Task EnsureDefaultRouteToBypassGatewayAsync(DefaultGatewayTarget target, CancellationToken cancellationToken)
    {
        var args = $"0.0.0.0 mask 0.0.0.0 {target.Gateway} if {target.InterfaceIndex} metric 1";
        logger.Info($"Forcing default route to bypass gateway: iface={target.InterfaceName}, index={target.InterfaceIndex}, gateway={target.Gateway}");
        await EnsureRouteChangeOrAddAsync(args, "default bypass route", cancellationToken);
    }

    private async Task EnsureMode2DualHalfDefaultRoutesAsync(string wireguardInterfaceName, DefaultGatewayTarget bypassTarget, CancellationToken cancellationToken)
    {
        logger.Info($"Ensuring mode2 dual /1 routes. bypassIface={bypassTarget.InterfaceName}, bypassIndex={bypassTarget.InterfaceIndex}, wgIface={wireguardInterfaceName}");
        await EnsureBypassHalfDefaultRoutesAsync(bypassTarget, cancellationToken);
        await EnsureWireGuardHalfDefaultRoutesAsync(wireguardInterfaceName, cancellationToken);
        await Task.Delay(300, cancellationToken);
    }

    private async Task EnsureBypassHalfDefaultRoutesAsync(DefaultGatewayTarget target, CancellationToken cancellationToken)
    {
        logger.Info($"Ensuring bypass /1 routes: iface={target.InterfaceName}, index={target.InterfaceIndex}, gateway={target.Gateway}, metric={BypassHalfDefaultMetric}");
        await EnsureRouteChangeOrAddAsync(
            $"0.0.0.0 mask 128.0.0.0 {target.Gateway} if {target.InterfaceIndex} metric {BypassHalfDefaultMetric}",
            "bypass half-default route 0.0.0.0/1",
            cancellationToken);
        await EnsureRouteChangeOrAddAsync(
            $"128.0.0.0 mask 128.0.0.0 {target.Gateway} if {target.InterfaceIndex} metric {BypassHalfDefaultMetric}",
            "bypass half-default route 128.0.0.0/1",
            cancellationToken);
    }

    private async Task EnsureWireGuardHalfDefaultRoutesAsync(string wireguardInterfaceName, CancellationToken cancellationToken)
    {
        var nic = FindNetworkInterface(wireguardInterfaceName);
        var interfaceIndex = nic?.GetIPProperties().GetIPv4Properties()?.Index;
        if (interfaceIndex is not int index || index <= 0)
        {
            logger.Info($"Skipping WireGuard /1 ensure: unable to resolve IPv4 index for {wireguardInterfaceName}.");
            return;
        }

        logger.Info($"Ensuring WireGuard /1 routes: iface={wireguardInterfaceName}, index={index}, metric={WireGuardHalfDefaultMetric}");
        await EnsureRouteChangeOrAddAsync(
            $"0.0.0.0 mask 128.0.0.0 0.0.0.0 if {index} metric {WireGuardHalfDefaultMetric}",
            "wireguard half-default route 0.0.0.0/1",
            cancellationToken);
        await EnsureRouteChangeOrAddAsync(
            $"128.0.0.0 mask 128.0.0.0 0.0.0.0 if {index} metric {WireGuardHalfDefaultMetric}",
            "wireguard half-default route 128.0.0.0/1",
            cancellationToken);
    }

    private bool IsDefaultRouteViaWireGuard(string wireguardInterfaceName)
    {
        var defaults = GetDefaultRoutes();
        if (defaults.Count == 0)
        {
            return false;
        }

        var wireguardIps = GetInterfaceIpv4Addresses(wireguardInterfaceName);
        var best = defaults
            .OrderByDescending(route => PrefixLengthFromMask(route.Netmask))
            .ThenBy(route => route.Metric)
            .First();

        return wireguardIps.Contains(best.InterfaceIp);
    }

    private bool HasWireGuardHalfDefaultRoute(string wireguardInterfaceName)
    {
        var defaults = GetDefaultRoutes();
        if (defaults.Count == 0)
        {
            return false;
        }

        var wireguardIps = GetInterfaceIpv4Addresses(wireguardInterfaceName);
        return defaults.Any(route =>
            PrefixLengthFromMask(route.Netmask) == 1
            && wireguardIps.Contains(route.InterfaceIp));
    }

    private bool HasBypassHalfDefaultPreference(DefaultGatewayTarget target)
    {
        var defaults = GetDefaultRoutes();
        if (defaults.Count == 0)
        {
            return false;
        }

        var bypassIps = GetInterfaceIpv4Addresses(target.InterfaceName);
        if (bypassIps.Count == 0)
        {
            return false;
        }

        var bestLowerHalf = defaults
            .Where(route => string.Equals(route.Destination, "0.0.0.0", StringComparison.Ordinal)
                && string.Equals(route.Netmask, "128.0.0.0", StringComparison.Ordinal))
            .OrderBy(route => route.Metric)
            .FirstOrDefault();

        var bestUpperHalf = defaults
            .Where(route => string.Equals(route.Destination, "128.0.0.0", StringComparison.Ordinal)
                && string.Equals(route.Netmask, "128.0.0.0", StringComparison.Ordinal))
            .OrderBy(route => route.Metric)
            .FirstOrDefault();

        return bestLowerHalf is not null
            && bestUpperHalf is not null
            && bypassIps.Contains(bestLowerHalf.InterfaceIp)
            && bypassIps.Contains(bestUpperHalf.InterfaceIp);
    }

    private async Task EnsureRouteChangeOrAddAsync(string args, string routeLabel, CancellationToken cancellationToken)
    {
        var change = await RunRouteCommandAsync($"change {args}", cancellationToken);
        if (!change.Success)
        {
            logger.Info($"route change failed for {routeLabel} (exit={change.ExitCode}). stderr={change.Stderr}; stdout={change.Stdout}");
            var add = await RunRouteCommandAsync($"add {args}", cancellationToken);
            if (!add.Success)
            {
                var addCombined = (add.Stdout + Environment.NewLine + add.Stderr).Trim();
                if (ContainsRouteAlreadyExists(addCombined))
                {
                    logger.Info($"route add reported already exists for {routeLabel}; treating as success.");
                    return;
                }

                logger.Error($"route add failed for {routeLabel} (exit={add.ExitCode}). stderr={add.Stderr}; stdout={add.Stdout}");
                throw new InvalidOperationException(
                    $"Failed to configure {routeLabel}. route change stderr: {change.Stderr}; route add stderr: {add.Stderr}");
            }

            logger.Info($"route add succeeded for {routeLabel}.");
            return;
        }

        logger.Info($"route change succeeded for {routeLabel}.");
    }
    private async Task VerifyBypassNotBlockedAsync(DefaultGatewayTarget bypassTarget, CancellationToken cancellationToken)
    {
        var result = await RunProcessCaptureAsync("ping", $"{bypassTarget.Gateway} -n 1", cancellationToken);
        var output = (result.Stdout + Environment.NewLine + result.Stderr).Trim();

        if (output.Contains("General failure", StringComparison.OrdinalIgnoreCase))
        {
            const string message = "Bypass route was set, but local traffic is blocked by WireGuard policy (likely Block untunneled traffic / Kill Switch). Disable that option in WireGuard tunnel settings.";
            logger.Error($"{message} pingOutput={output}");
            throw new InvalidOperationException(message);
        }
    }

    private async Task EnsureWireGuardDnsReachableAsync(string wireguardInterfaceName, CancellationToken cancellationToken)
    {
        var nic = FindNetworkInterface(wireguardInterfaceName);
        if (nic is null)
        {
            logger.Info($"WireGuard DNS enforce skipped: interface not found ({wireguardInterfaceName}).");
            return;
        }

        if (!IsRunningAsAdministrator())
        {
            logger.Info("WireGuard DNS enforce skipped: administrator rights are required.");
            return;
        }

        var dnsServers = nic.GetIPProperties().DnsAddresses
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var alreadySafe = dnsServers.Count == SafeDnsFallbackServers.Length
            && !SafeDnsFallbackServers.Except(dnsServers, StringComparer.OrdinalIgnoreCase).Any();

        if (alreadySafe)
        {
            logger.Info($"WireGuard DNS already safe on {nic.Name}: {string.Join(", ", dnsServers)}");
            return;
        }

        logger.Info($"WireGuard DNS enforce: current={string.Join(", ", dnsServers)} => target={string.Join(", ", SafeDnsFallbackServers)}");
        await ApplyDnsServersAsync(nic.Name, SafeDnsFallbackServers, cancellationToken);

        var flush = await RunProcessCaptureAsync("ipconfig", "/flushdns", cancellationToken);
        logger.Info($"ipconfig /flushdns => exit={flush.ExitCode}, stderr={flush.Stderr}, stdout={flush.Stdout}");
    }

    private async Task ApplyDnsServersAsync(string adapterName, IReadOnlyList<string> dnsServers, CancellationToken cancellationToken)
    {
        if (dnsServers.Count == 0)
        {
            return;
        }

        var escapedAdapter = adapterName.Replace("\"", "\"\"", StringComparison.Ordinal);

        var setPrimary = await RunProcessCaptureAsync(
            "netsh",
            $"interface ip set dns name=\"{escapedAdapter}\" static {dnsServers[0]} primary",
            cancellationToken);

        if (!setPrimary.Success)
        {
            throw new InvalidOperationException($"Failed to set primary DNS on adapter {adapterName}: {setPrimary.Stderr}");
        }

        for (var i = 1; i < dnsServers.Count; i++)
        {
            var add = await RunProcessCaptureAsync(
                "netsh",
                $"interface ip add dns name=\"{escapedAdapter}\" {dnsServers[i]} index={i + 1}",
                cancellationToken);

            if (!add.Success)
            {
                throw new InvalidOperationException($"Failed to add DNS {dnsServers[i]} on adapter {adapterName}: {add.Stderr}");
            }
        }
    }

    private static NetworkInterface? FindNetworkInterface(string interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            return null;
        }

        var all = NetworkInterface.GetAllNetworkInterfaces();

        return all.FirstOrDefault(n => string.Equals(n.Name, interfaceName, StringComparison.OrdinalIgnoreCase))
            ?? all.FirstOrDefault(n => string.Equals(n.Description, interfaceName, StringComparison.OrdinalIgnoreCase))
            ?? all.FirstOrDefault(n => n.Name.Contains(interfaceName, StringComparison.OrdinalIgnoreCase))
            ?? all.FirstOrDefault(n => n.Description.Contains(interfaceName, StringComparison.OrdinalIgnoreCase));
    }
    private static async Task<RouteCommandResult> RunProcessCaptureAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Unable to start process: {fileName} {arguments}");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return new RouteCommandResult(process.ExitCode == 0, process.ExitCode, stdout.Trim(), stderr.Trim());
    }
    private static async Task<RouteCommandResult> RunRouteCommandAsync(string arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "route",
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Unable to start route command process.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var combined = (stdout + Environment.NewLine + stderr).Trim();
        var success = process.ExitCode == 0
            && string.IsNullOrWhiteSpace(stderr)
            && !ContainsRouteFailure(combined);
        return new RouteCommandResult(success, process.ExitCode, stdout.Trim(), stderr.Trim());
    }

    private static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool ContainsRouteAlreadyExists(string output) =>
        output.Contains("already exists", StringComparison.OrdinalIgnoreCase)
        || output.Contains("object already exists", StringComparison.OrdinalIgnoreCase)
        || output.Contains("\u7269\u4EF6\u5DF2\u7D93\u5B58\u5728", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsRouteFailure(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return false;
        }

        return output.Contains("failed", StringComparison.OrdinalIgnoreCase)
            || output.Contains("failure", StringComparison.OrdinalIgnoreCase)
            || output.Contains("not found", StringComparison.OrdinalIgnoreCase)
            || output.Contains("route deletion failed", StringComparison.OrdinalIgnoreCase)
            || output.Contains("route addition failed", StringComparison.OrdinalIgnoreCase)
            || output.Contains("\u5143\u7D20\u627E\u4E0D\u5230", StringComparison.OrdinalIgnoreCase)
            || output.Contains("\u8DEF\u7531\u522A\u9664\u5931\u6557", StringComparison.OrdinalIgnoreCase)
            || output.Contains("\u8DEF\u7531\u65B0\u589E\u5931\u6557", StringComparison.OrdinalIgnoreCase)
            || output.Contains("\u8DEF\u7531\u6DFB\u52A0\u5931\u6557", StringComparison.OrdinalIgnoreCase);
    }

    private sealed record RouteCommandResult(bool Success, int ExitCode, string Stdout, string Stderr);
    private sealed record DefaultGatewayTarget(string InterfaceName, int InterfaceIndex, string Gateway);
    private sealed record DefaultRouteEntry(string Destination, string Netmask, string Gateway, string InterfaceIp, int Metric);
    private sealed record Ipv4RouteEntry(string Destination, string Netmask, string Gateway, string InterfaceIp, int Metric);
    private sealed record DomainRow(string Domain, bool Enabled, int ResolvedIpCount);
    private sealed record SoftwareRow(string ProcessName, bool Enabled, bool IncludeSubprocesses);
    private sealed record TunnelConfigOption(string Path, string Display);
}





































































































