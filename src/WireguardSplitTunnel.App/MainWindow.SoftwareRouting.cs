using System.Net.NetworkInformation;
using System.Windows.Threading;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;
namespace WireguardSplitTunnel.App;

public partial class MainWindow
{
    private const string SoftwareSharedDomainDebt = SoftwareDomainRouteOwnership.SharedDebtDomain;
    private readonly DispatcherTimer softwareLearningTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly CancellationTokenSource softwareLearningCts = new();
    private readonly ISoftwareConnectionSnapshotReader softwareSnapshotReader = new WindowsSoftwareConnectionSnapshotReader();
    private readonly WindowsSoftwareRouteWriter softwareRouteWriter = new WindowsSoftwareRouteWriter();
    private readonly SoftwareRoutePlanner softwareRoutePlanner = new();
    private Dictionary<string, int> softwareChildCounts = [];
    private Task softwareLearningTask = Task.CompletedTask;
    private DateTime nextSoftwarePathRepairUtc;
    private string? lastSoftwareLearningError;

    private NetworkInterface? SelectedSoftwareInterface()
    {
        var candidates = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up
            && (n.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase))).ToArray();
        var selectedName = SoftwareTunnelSelector.Select(state.SelectedTunnelConfigPath, candidates.Select(n => n.Name));
        return candidates.FirstOrDefault(n => n.Name == selectedName);
    }
    private void StartSoftwareLearning()
    {
        softwareLearningTimer.Tick += OnSoftwareLearningTick;
        softwareLearningTimer.Start();
        OnSoftwareLearningTick(null, EventArgs.Empty);
    }
    private void OnSoftwareLearningTick(object? sender, EventArgs e)
    {
        if (isWindowClosing || !softwareLearningTask.IsCompleted) return;
        softwareLearningTask = LearnSoftwareRoutesAsync(softwareLearningCts.Token);
    }
    private string SoftwareConfigurationKey() => $"{state.SoftwareGlobalDefaultMode}|{state.SelectedTunnelConfigPath}|" +
        string.Join(";", (state.SoftwareRules ?? []).Select(r => $"{SoftwareRoutePlanner.Fingerprint(r)}:{r.Enabled}"));
    private HashSet<string> DesiredSoftwareIps()
    {
        if (state.SoftwareGlobalDefaultMode != DomainRouteMode.BypassWireGuard) return [];
        var active = (state.SoftwareRules ?? []).Where(r => r.Enabled && r.Mode == DomainRouteMode.UseWireGuard)
            .Select(SoftwareRoutePlanner.Fingerprint).ToHashSet();
        return state.SoftwareLearnedDestinations.Where(l => active.Contains(l.Fingerprint))
            .SelectMany(l => l.IpAddresses).Where(SoftwareRoutePlanner.IsPublicIpv4).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
    private HashSet<string> DomainProtectedIps() => state.ManagedRouteSnapshot.Where(r => r.Domain != SoftwareSharedDomainDebt).Select(r => r.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);

    private async Task LearnSoftwareRoutesAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!IsRunningAsAdministrator())
            {
                SoftwareLearningStatus.Text = "Software learning paused: run as Administrator to install destination routes.";
                return;
            }
            await softwareApplySemaphore.WaitAsync(cancellationToken);
            try
            {
                if (isWindowClosing) return;
                if (DateTime.UtcNow >= nextSoftwarePathRepairUtc)
                {
                    nextSoftwarePathRepairUtc = DateTime.UtcNow.AddSeconds(30);
                    var repaired = SoftwareRulePathRepair.RepairEnabledRulePaths(state, softwareExecutableLocator);
                    if (repaired.Added + repaired.Updated > 0) { stateStore.Save(state); ScheduleSoftwareReapply("executable path repaired"); }
                }
                var capturedState = state;
                var generation = SoftwareConfigurationKey();
                bool Current() => !isWindowClosing && !cancellationToken.IsCancellationRequested
                    && ReferenceEquals(state, capturedState) && SoftwareConfigurationKey() == generation;
                var supported = state.SoftwareGlobalDefaultMode == DomainRouteMode.BypassWireGuard;
                var enabled = supported ? (state.SoftwareRules ?? []).Where(r => r.Enabled && r.Mode == DomainRouteMode.UseWireGuard).ToArray() : [];
                var selectedInterface = SelectedSoftwareInterface();
                int? interfaceIndex = selectedInterface?.GetIPProperties().GetIPv4Properties()?.Index;
                SoftwareConnectionSnapshot snapshot = new([], []);
                IReadOnlyList<string> endpoints = [];
                if (enabled.Length > 0)
                {
                    if (interfaceIndex is not null)
                        endpoints = await WindowsSoftwareConnectionSnapshotReader.ReadTransportEndpointsAsync(cancellationToken);
                    snapshot = await softwareSnapshotReader.ReadAsync(cancellationToken);
                }
                if (!Current() || SelectedSoftwareInterface()?.GetIPProperties().GetIPv4Properties()?.Index != interfaceIndex) return;
                await renewSemaphore.WaitAsync(cancellationToken);
                try
                {
                    if (!Current()) return;
                    var exclusions = endpoints.Concat(NetworkInterface.GetAllNetworkInterfaces()
                        .Where(n => n.OperationalStatus == OperationalStatus.Up)
                        .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                        .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(a => $"{a.Address}/{a.PrefixLength}"));
                    var observation = softwareRoutePlanner.Observe(enabled, state.SoftwareLearnedDestinations, snapshot, exclusions);
                    state.SoftwareLearnedDestinations.Clear(); state.SoftwareLearnedDestinations.AddRange(observation.Learned);
                    softwareChildCounts = observation.ChildCounts;
                    stateStore.Save(state);
                    var desired = DesiredSoftwareIps();
                    await TransferSharedDomainDebtAsync(desired, interfaceIndex, cancellationToken);
                    await new SoftwareRouteReconciler(softwareRouteWriter).ReconcileAsync(desired, DomainProtectedIps(), supported ? interfaceIndex : null,
                        state.SoftwareOwnedRoutes, () => stateStore.Save(state), Current, cancellationToken);
                    if (!Current()) return;
                    SoftwareLearningStatus.Text = supported
                        ? $"TCP/IPv4 learning: {desired.Count} destinations, {softwareChildCounts.Values.Sum()} child processes, {state.SoftwareOwnedRoutes.Count} owned routes. " + (interfaceIndex is null ? "Waiting for selected WireGuard interface (or select one if multiple are active)." : "Active (2 s).")
                        : "Software destination routing is unsupported in VPN-default mode; software-only learned routes are being removed.";
                    var unresolvedDebt = state.ManagedRouteSnapshot.Count(r => r.Domain == SoftwareSharedDomainDebt);
                    if (unresolvedDebt > 0) SoftwareLearningStatus.Text += $" {unresolvedDebt} legacy shared route(s) retained: original ownership could not be verified.";
                    lastSoftwareLearningError = null;
                    RefreshSoftwareGrid();
                }
                finally { renewSemaphore.Release(); }
            }
            finally { softwareApplySemaphore.Release(); }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            SoftwareLearningStatus.Text = $"Software learning paused/retrying: {ex.Message}";
            if (lastSoftwareLearningError != ex.Message) logger.Error("Software destination learning failed; ownership retained for retry.", ex);
            lastSoftwareLearningError = ex.Message;
        }
    }
    private async Task TransferSharedDomainDebtAsync(HashSet<string> desired, int? interfaceIndex, CancellationToken token)
    {
        // Even if software was just disabled, transfer legacy app-owned debt before exact
        // cleanup. No-interface/lookup errors leave the original domain ledger intact.
        var debts = state.ManagedRouteSnapshot.Where(r => r.Domain == SoftwareSharedDomainDebt).ToArray();
        var transferred = await SoftwareDomainRouteOwnership.TransferAsync(debts, debts.Select(r => r.IpAddress), interfaceIndex,
            state.SoftwareOwnedRoutes, softwareRouteWriter.ReadExactAsync, softwareRouteWriter, () => stateStore.Save(state), token);
        if (transferred.Count > 0)
        {
            state.ManagedRouteSnapshot.RemoveAll(r => r.Domain == SoftwareSharedDomainDebt && transferred.Contains(r.IpAddress));
            stateStore.Save(state);
        }
    }
    private async Task StopSoftwareLearningAsync()
    {
        softwareLearningTimer.Stop(); softwareLearningCts.Cancel();
        await softwareLearningTask;
    }
    private async Task CleanupSoftwareRoutesOnExitAsync()
    {
        int? index = SelectedSoftwareInterface()?.GetIPProperties().GetIPv4Properties()?.Index;
        await TransferSharedDomainDebtAsync([], index, CancellationToken.None);
        await new SoftwareRouteReconciler(softwareRouteWriter).ReconcileAsync([], [], null,
            state.SoftwareOwnedRoutes, () => stateStore.Save(state), () => true, CancellationToken.None);
        stateStore.Save(state);
    }
}
