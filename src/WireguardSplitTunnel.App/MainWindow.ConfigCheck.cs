using System.IO;
using System.Windows;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.App;

public partial class MainWindow
{
    private async void OnTestConfigClicked(object sender, RoutedEventArgs e)
    {
        if (isWindowClosing) return;

        var selectedPath = (TunnelConfigCombo.SelectedValue as string) ?? state.SelectedTunnelConfigPath;
        string? selectedFullPath = null;
        CheckedConfig? config = null;
        WindowsConfigCheckAdapter? adapter = null;
        ConfigCheckResult? result = null;
        try
        {
            await configCheckCoordinator.RunAsync(
                _ => ConfirmInterruptionAsync(),
                RunWorkflowAsync,
                CompleteAsync,
                SetConfigCheckControlsEnabled,
                routingWorkCts.Token);
        }
        catch (Exception)
        {
            LogConfigCheck(
                "Fatal",
                config?.Path ?? selectedFullPath ?? selectedPath ?? string.Empty,
                config?.Endpoint ?? string.Empty,
                "CoordinatorFailed");
            ShowConfigCheckError(
                "Config test could not be completed safely. Review the selected file, saved selection, and network state before retrying.");
        }

        Task<bool> ConfirmInterruptionAsync()
        {
            if (string.IsNullOrWhiteSpace(selectedPath))
            {
                ShowConfigCheckError("Select a plaintext .conf config first.");
                return Task.FromResult(false);
            }

            try
            {
                selectedFullPath = Path.GetFullPath(selectedPath);
                config = CheckedConfig.Parse(selectedFullPath);
            }
            catch (Exception)
            {
                LogConfigCheck("ParseFailed", selectedPath, string.Empty, "InvalidConfig");
                ShowConfigCheckError(
                    "The selected config cannot be tested. Select a valid plaintext single-peer NordVPN .conf file.");
                return Task.FromResult(false);
            }

            var answer = MessageBox.Show(
                this,
                $"Testing the selected config means internet access may be interrupted while WireGuard tunnels are stopped and restored:\n{selectedFullPath}\n\nContinue?",
                "Wireguard Split Tunnel",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            return Task.FromResult(answer == MessageBoxResult.Yes && !isWindowClosing);
        }

        async Task RunWorkflowAsync(CancellationToken cancellationToken)
        {
            adapter = new WindowsConfigCheckAdapter(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WireguardSplitTunnel"));
            try
            {
                result = await ConfigCheckWorkflow.RunAsync(
                    config!,
                    adapter,
                    cancellationToken,
                    restoreRoutesAsync: RestoreRoutesAsync,
                    derivedConfigPath: global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer
                        .SanitizeText(config!.Text).Changed
                        ? Path.Combine(
                            global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.GetDefaultDerivedConfigDirectory(),
                            Path.GetFileName(config.Path))
                        : null,
                    reconcileDerivedConfigAsync: ReconcileDerivedConfigAsync);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                LogConfigCheck("Canceled", config!.Path, config.Endpoint, "WorkflowCanceled");
                ShowConfigCheckError("Config test was canceled. No Recycle Bin action was taken.");
            }
            catch (Exception ex)
            {
                logger.Error("Config check workflow failed.", ex);
                LogConfigCheck("Fatal", config!.Path, config.Endpoint, "WorkflowFailed");
                ShowConfigCheckError(
                    "Config test failed. No Recycle Bin action was taken. Review the selected config and network state before retrying.");
            }
        }

        async Task RestoreRoutesAsync(CancellationToken _)
        {
            // ConfigCheckCoordinator already holds renewSemaphore. Reuse the
            // core renewal path and finish restoration even if close was requested.
            var restored = await RenewDomainRoutesAsync(
                showMessage: false,
                fromStartup: false,
                CancellationToken.None);
            if (!restored)
                throw new InvalidOperationException("Application routes could not be restored after config testing.");
        }

        async Task CompleteAsync(CancellationToken cancellationToken)
        {
            if (result is not ConfigCheckResult completed
                || config is null
                || adapter is null
                || selectedFullPath is null
                || isWindowClosing)
            {
                return;
            }

            LogConfigCheck(completed.Status.ToString(), completed.ConfigPath, completed.Endpoint, completed.Reason, config.Country, completed.ObservedCountry);
            if (!ConfigCheckDeletePolicy.MayOffer(completed.Status))
            {
                MessageBox.Show(
                    this,
                    $"Config test completed: {completed.Status}\n{completed.ConfigPath}\nEndpoint: {completed.Endpoint}\nReason: {completed.Reason}",
                    "Wireguard Split Tunnel",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }

            if (!string.Equals(completed.ConfigPath, selectedFullPath, StringComparison.OrdinalIgnoreCase))
            {
                LogConfigCheck(completed.Status.ToString(), selectedFullPath, completed.Endpoint, "ResultPathMismatch");
                ShowConfigCheckError(
                    "Config test returned an unexpected file path. Nothing was recycled and the saved selection was kept.");
                return;
            }

            var answer = MessageBox.Show(
                this,
                $"Connection could not be repaired:\n{completed.ConfigPath}\n\nMove this file to the Recycle Bin?",
                "Wireguard Split Tunnel",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes || isWindowClosing) return;

            try
            {
                await adapter.RecycleUnrepairedAsync(config, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                LogConfigCheck("Canceled", completed.ConfigPath, completed.Endpoint, "RecycleCanceled");
                ShowConfigCheckError("Recycling was canceled. The saved selection was kept.");
                return;
            }
            catch (Exception)
            {
                LogConfigCheck(completed.Status.ToString(), completed.ConfigPath, completed.Endpoint, "RecycleFailed");
                ShowConfigCheckError(
                    "The config could not be moved to the Recycle Bin. The saved selection was kept. Review the file and recovery state before retrying.");
                return;
            }

            var clearedState = state with { SelectedTunnelConfigPath = null };
            try
            {
                stateStore.Save(clearedState);
            }
            catch (Exception)
            {
                LogConfigCheck(completed.Status.ToString(), completed.ConfigPath, completed.Endpoint, "SelectionSaveFailed");
                ShowConfigCheckError(
                    "The file was moved to the Recycle Bin, but saving the selection could not be confirmed. The current selection was kept; review the config selection before continuing.");
                return;
            }

            state = clearedState;
            if (!isWindowClosing) RefreshTunnelConfigOptions();
        }
    }

    private async Task RecoverConfigCheckTransactionsOnStartupAsync()
    {
        var adapter = new WindowsConfigCheckAdapter(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WireguardSplitTunnel"));
        await configCheckStartupRecoveryCoordinator.RunAsync(
            adapter,
            reconcileDerivedConfigAsync: ReconcileDerivedConfigAsync,
            shouldRestoreRoutes: ShouldRestoreRecoveredRoutes,
            restoreRoutesAsync: RestoreRecoveredRoutesAsync,
            cancellationToken: routingWorkCts.Token);
    }

    private bool ShouldRestoreRecoveredRoutes(ConfigCheckRecoveredService service)
    {
        var tunnelName = WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(service.SourcePath);
        return string.Equals(service.ServiceName, "WireGuardTunnel$" + tunnelName, StringComparison.OrdinalIgnoreCase) &&
            WireguardSplitTunnel.Core.Services.SoftwareTunnelSelector.Select(state.SelectedTunnelConfigPath,
                [tunnelName]) is not null;
    }

    private async Task RestoreRecoveredRoutesAsync(CancellationToken _)
    {
        // The startup recovery coordinator already owns renewSemaphore. Reuse
        // the normal renewal path without prompts or a second routing algorithm.
        var restored = await RenewDomainRoutesAsync(
            showMessage: false,
            fromStartup: false,
            CancellationToken.None);
        if (!restored)
            throw new IOException("Application routes could not be restored after config-check recovery.");
    }

    private static Task ReconcileDerivedConfigAsync(ConfigCheckRestoreContext context, CancellationToken _)
    {
        global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.ReconcileRepairedConfigFile(
            context.SourcePath,
            context.DerivedConfigPath,
            context.SourceFingerprint);
        return Task.CompletedTask;
    }

    private void SetConfigCheckControlsEnabled(bool enabled)
    {
        TunnelConfigCombo.IsEnabled = enabled;
        RefreshConfigsButton.IsEnabled = enabled;
        BrowseConfigButton.IsEnabled = enabled;
        EnableTunnelButton.IsEnabled = enabled;
        TestConfigButton.IsEnabled = enabled;
    }

    private void LogConfigCheck(
        string status,
        string path,
        string endpoint,
        string reason,
        string expectedCountry = "",
        string observedCountry = "")
    {
        var countries = expectedCountry.Length == 2 && observedCountry.Length == 2
            ? $", expected={expectedCountry}, observed={observedCountry}"
            : string.Empty;
        logger.Info($"Config check. status={status}, path={path}, endpoint={endpoint}, reason={reason}{countries}");
    }

    private void ShowConfigCheckError(string message)
    {
        if (isWindowClosing)
        {
            return;
        }

        MessageBox.Show(
            this,
            message,
            "Wireguard Split Tunnel",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }
}
