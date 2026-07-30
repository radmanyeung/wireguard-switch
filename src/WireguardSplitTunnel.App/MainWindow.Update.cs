using System.Windows;
using WireguardSplitTunnel.App.Services;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.App;

public partial class MainWindow
{
    private WindowsUpdateCompositionRoot? windowsUpdate;
    private readonly UpdateStartupHealthContext?
        updateStartupHealthContext;
    private ApplicationUpdateStartupOrchestrator?
        updateStartupOrchestrator;
    private bool updateStartupCompleted;
    private bool updateStatusIsBusy;
    private bool updateEventsDetached;

    private void InitializeWindowsUpdate()
    {
        AutoUpdateEnabledCheckBox.IsChecked =
            state.AutoUpdateEnabled;
        if (windowsUpdate is null)
        {
            AutoUpdateEnabledCheckBox.IsEnabled = false;
            CheckForUpdatesButton.IsEnabled = false;
            UpdateStatusTextBlock.Text =
                "Automatic updates are unavailable in this run";
            return;
        }

        windowsUpdate.ConfigureAutomaticEnabled(
            state.AutoUpdateEnabled);
        AutoUpdateEnabledCheckBox.IsEnabled = false;
        CheckForUpdatesButton.IsEnabled = false;
        if (runPostInstallSelfTestOnLoad
            || windowsUpdate.IsPostInstallSelfTest)
        {
            AutoUpdateEnabledCheckBox.IsEnabled = false;
            CheckForUpdatesButton.IsEnabled = false;
            UpdateStatusTextBlock.Text =
                "Update work is disabled during post-install self test";
            return;
        }

        windowsUpdate.StatusChanged +=
            OnWindowsUpdateStatusChanged;
        AutoUpdateEnabledCheckBox.Checked +=
            OnAutoUpdateEnabledChanged;
        AutoUpdateEnabledCheckBox.Unchecked +=
            OnAutoUpdateEnabledChanged;
        CheckForUpdatesButton.Click +=
            OnCheckForUpdatesClicked;
        UpdateStatusTextBlock.Text =
            state.AutoUpdateEnabled
                ? "Automatic update checks will start after routing is ready"
                : "Automatic update checks are disabled";
    }

    private void LoadWindowsUpdateSettingsToUi()
    {
        AutoUpdateEnabledCheckBox.IsChecked =
            state.AutoUpdateEnabled;
    }

    private async Task RunWindowsUpdateStartupAsync(
        ApplicationStartupRoutingOutcome routingOutcome)
    {
        if (windowsUpdate is null)
        {
            return;
        }

        windowsUpdate.ConfigureAutomaticEnabled(
            state.AutoUpdateEnabled);
        updateStartupOrchestrator ??=
            new ApplicationUpdateStartupOrchestrator(
                windowsUpdate,
                new ApplicationUpdateStartupRequest(
                    InteractiveWindowInitialized: true,
                    PrimaryStateLoaded: true,
                    routingOutcome,
                    runPostInstallSelfTestOnLoad,
                    updateStartupHealthContext),
                () => isWindowClosing);
        var result = await updateStartupOrchestrator
            .RunOnceAsync(CancellationToken.None);
        logger.Info(
            $"Update startup completed. "
            + $"outcome={result.Outcome}, "
            + $"health={result.HealthDisposition}, "
            + $"failure={result.Failure}, "
            + $"checksStarted={result.ChecksStarted}.");
        updateStartupCompleted =
            !isWindowClosing
            && (result.Outcome
                    == ApplicationUpdateStartupOutcome
                        .ChecksStarted
                || result.Outcome
                    == ApplicationUpdateStartupOutcome
                        .RecoverableFailure
                && result.Failure
                    == ApplicationUpdateStartupFailure
                        .StartChecks);
        ApplyWindowsUpdateControlAvailability();
        if (result.Outcome
                == ApplicationUpdateStartupOutcome
                    .RecoverableFailure
            && !isWindowClosing)
        {
            UpdateStatusTextBlock.Text =
                updateStartupCompleted
                    ? "Update startup failed; retry with Check now"
                    : "Update startup safety check failed; restart the application";
        }
    }

    private async void OnAutoUpdateEnabledChanged(
        object sender,
        RoutedEventArgs e)
    {
        if (suppressSettingsEvents
            || !updateStartupCompleted
            || isWindowClosing
            || windowsUpdate is null
            || runPostInstallSelfTestOnLoad)
        {
            return;
        }

        var enabled =
            AutoUpdateEnabledCheckBox.IsChecked == true;
        var prior = state;
        if (prior.AutoUpdateEnabled == enabled)
        {
            return;
        }

        var operation =
            windowsUpdate.BeginAutomaticEnabledChange();

        var updated = prior with
        {
            AutoUpdateEnabled = enabled
        };
        try
        {
            stateStore.Save(updated);
            state = updated;
        }
        catch (Exception ex)
        {
            logger.Error(
                "Saving automatic update preference failed.",
                ex);
            if (operation.IsLatest)
            {
                RestoreAutomaticUpdatePreference(prior);
                UpdateStatusTextBlock.Text =
                    "Could not save the update preference";
            }

            try
            {
                await windowsUpdate.SetAutomaticEnabledAsync(
                    prior.AutoUpdateEnabled,
                    operation,
                    CancellationToken.None);
            }
            catch (Exception reconcileException)
            {
                logger.Error(
                    "Reconciling the unsaved automatic update preference failed.",
                    reconcileException);
            }
            if (operation.IsLatest)
            {
                updateStatusIsBusy =
                    windowsUpdate.LatestRuntimeStatusIsBusy;
                ApplyWindowsUpdateControlAvailability();
                UpdateStatusTextBlock.Text =
                    "Could not save the update preference";
            }
            return;
        }

        try
        {
            await windowsUpdate.SetAutomaticEnabledAsync(
                enabled,
                operation,
                CancellationToken.None);
            if (operation.IsLatest)
            {
                updateStatusIsBusy =
                    windowsUpdate.LatestRuntimeStatusIsBusy;
                UpdateStatusTextBlock.Text = enabled
                    ? "Automatic update checks are enabled"
                    : "Automatic update checks are disabled";
                ApplyWindowsUpdateControlAvailability();
            }
        }
        catch (Exception ex)
        {
            logger.Error(
                "Applying automatic update preference failed.",
                ex);
            if (!operation.IsLatest)
            {
                return;
            }

            if (!enabled)
            {
                // Persisted false is authoritative. Never turn the UI or
                // coordinator authorization back on after cleanup failure.
                state = updated;
                SetAutomaticUpdateCheckBox(false);
                UpdateStatusTextBlock.Text =
                    "Automatic updates are disabled; cleanup will retry later";
                return;
            }

            try
            {
                stateStore.Save(prior);
                state = prior;
            }
            catch (Exception rollbackException)
            {
                logger.Error(
                    "Rolling back automatic update preference failed.",
                    rollbackException);
            }

            RestoreAutomaticUpdatePreference(prior);
            UpdateStatusTextBlock.Text =
                "Could not enable automatic updates";
        }
    }

    private async void OnCheckForUpdatesClicked(
        object sender,
        RoutedEventArgs e)
    {
        if (isWindowClosing
            || !updateStartupCompleted
            || windowsUpdate is null
            || runPostInstallSelfTestOnLoad)
        {
            return;
        }

        CheckForUpdatesButton.IsEnabled = false;
        try
        {
            await windowsUpdate.CheckNowAsync(
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.Error("Manual update check failed.", ex);
            UpdateStatusTextBlock.Text =
                "Update check failed; try again";
        }
        finally
        {
            ApplyWindowsUpdateControlAvailability();
        }
    }

    private void OnWindowsUpdateStatusChanged(
        object? sender,
        StampedWindowsUpdateStatus update)
    {
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(
                () => ApplyWindowsUpdateStatus(
                    update.Status,
                    update.GenerationStamp));
            return;
        }

        ApplyWindowsUpdateStatus(
            update.Status,
            update.GenerationStamp);
    }

    private void ApplyWindowsUpdateStatus(
        WindowsUpdateStatus status,
        LatestOperationStatusGate.Stamp generationStamp)
    {
        if (isWindowClosing
            || updateEventsDetached
            || !generationStamp.IsLatest)
        {
            return;
        }

        updateStatusIsBusy = status.IsBusy;
        UpdateStatusTextBlock.Text = status.Message;
        ApplyWindowsUpdateControlAvailability();
    }

    private void PrepareWindowsUpdateForClose()
    {
        updateStartupCompleted = false;
        AutoUpdateEnabledCheckBox.IsEnabled = false;
        CheckForUpdatesButton.IsEnabled = false;
        if (windowsUpdate is null || updateEventsDetached)
        {
            return;
        }

        updateEventsDetached = true;
        windowsUpdate.StatusChanged -=
            OnWindowsUpdateStatusChanged;
        AutoUpdateEnabledCheckBox.Checked -=
            OnAutoUpdateEnabledChanged;
        AutoUpdateEnabledCheckBox.Unchecked -=
            OnAutoUpdateEnabledChanged;
        CheckForUpdatesButton.Click -=
            OnCheckForUpdatesClicked;
    }

    private void ApplyWindowsUpdateControlAvailability()
    {
        var interactive =
            updateStartupCompleted
            && !isWindowClosing
            && !updateEventsDetached
            && windowsUpdate is not null
            && !runPostInstallSelfTestOnLoad
            && !windowsUpdate.IsPostInstallSelfTest;
        AutoUpdateEnabledCheckBox.IsEnabled = interactive;
        CheckForUpdatesButton.IsEnabled =
            interactive && !updateStatusIsBusy;
    }

    private void DisposeWindowsUpdate()
    {
        PrepareWindowsUpdateForClose();
        windowsUpdate?.Dispose();
        windowsUpdate = null;
    }

    private void RestoreAutomaticUpdatePreference(
        WireguardSplitTunnel.Core.Models.AppState prior)
    {
        state = prior;
        SetAutomaticUpdateCheckBox(
            prior.AutoUpdateEnabled);
    }

    private void SetAutomaticUpdateCheckBox(bool enabled)
    {
        suppressSettingsEvents = true;
        try
        {
            AutoUpdateEnabledCheckBox.IsChecked = enabled;
        }
        finally
        {
            suppressSettingsEvents = false;
        }
    }
}
