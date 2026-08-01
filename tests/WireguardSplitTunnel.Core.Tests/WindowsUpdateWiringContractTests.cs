using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsUpdateWiringContractTests
{
    [Fact]
    public void App_RecordsSpecialCloseIntentBeforeShutdownHandling()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/App.xaml.cs");

        var sessionEnding = ExtractBetween(
            source,
            "protected override void OnSessionEnding",
            "private static bool ShouldRequireAdministratorForCurrentMode");
        sessionEnding.IndexOf(
                "closeIntentTracker.RecordSessionEnding();",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                sessionEnding.IndexOf(
                    "base.OnSessionEnding(e);",
                    StringComparison.Ordinal));

        var relaunched = source.IndexOf(
            "if (relaunched)",
            StringComparison.Ordinal);
        var handoff = source.IndexOf(
            "closeIntentTracker.RecordElevationHandoff();",
            relaunched,
            StringComparison.Ordinal);
        var shutdown = source.IndexOf(
            "Shutdown();",
            relaunched,
            StringComparison.Ordinal);
        relaunched.Should().BeGreaterThanOrEqualTo(0);
        handoff.Should().BeGreaterThan(relaunched);
        shutdown.Should().BeGreaterThan(handoff);
    }

    [Fact]
    public void App_AutoElevatesOnlyAValidatedProtectedInstalledRelease()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/App.xaml.cs");
        var startup = ExtractBetween(
            source,
            "protected override void OnStartup",
            "protected override void OnSessionEnding");
        startup.IndexOf(
                "IsCurrentExecutableEligibleForAutoElevation();",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                startup.IndexOf(
                    "TryRelaunchAsAdministrator(",
                    StringComparison.Ordinal));
        startup.Should().Contain(
            "if (!autoElevationEligible)");
        startup.Should().Contain(
            "Auto-elevation refused for an unprotected executable.");
        startup.Should().Contain(
            "Install it with install.cmd");

        var eligibility = ExtractBetween(
            source,
            "private static InstalledReleaseLaunchLease?",
            "private static bool ShouldRequireAdministratorForCurrentMode");
        eligibility.Should().Contain(
            "new InstalledReleaseLocator()");
        eligibility.Should().Contain(
            ".Locate(Environment.ProcessPath)");
        eligibility.Should().Contain(
            "InstalledReleaseLocatorStatus.Available");
    }

    [Fact]
    public void App_LogsArgumentContextWithoutRawArguments()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/App.xaml.cs");

        source.Should().Contain(
            "hasArguments={e.Args.Length > 0}");
        source.Should().Contain(
            "selfTestArg={runPostInstallSelfTest}");
        source.Should().NotContain(
            "string.Join(\" \", e.Args)");
        source.Should().NotContain("args={");
    }

    [Fact]
    public void MainWindow_UsesTwoPassAsyncCloseForEveryNormalClose()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");
        var closing = ExtractBetween(
            source,
            "private async void OnWindowClosing",
            "private async void OnLoaded");

        closing.Should().Contain(
            "if (allowCloseWithoutRestore)");
        closing.IndexOf(
                "e.Cancel = true;",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                closing.IndexOf(
                    "isWindowClosing = true;",
                    StringComparison.Ordinal));
        closing.Should().Contain(
            "closeIntentTracker.ResolveNormalClose();");
        closing.Should().Contain(
            "applicationCloseOrchestrator");
        closing.Should().Contain(".RunOnceAsync(");
        // Close must never hang on a stuck restore: orchestration is
        // cancellable and the window force-closes after a hard timeout.
        closing.Should().Contain("Task.WhenAny(");
        closing.Should().Contain(
            "LogApplicationCloseResult(result);");
        closing.Should().NotContain(
            "!state.RestoreNormalRoutingOnExit");
        closing.IndexOf(
                "allowCloseWithoutRestore = true;",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                closing.LastIndexOf(
                    "Close();",
                    StringComparison.Ordinal));

        var restore = ExtractBetween(
            source,
            "private async Task RestoreNormalRoutingOnExitAsync",
            "private async Task RemoveWireGuardDnsHostRoutesAsync");
        restore.Should().Contain(
            "if (!state.RestoreNormalRoutingOnExit)");
        restore.Should().NotContain("stateStore.Save(state);");
        closing.Should().NotContain("stateStore.Save(state);");
        source.Should().Contain(
            "() => stateStore.Save(state)");
    }

    [Fact]
    public void MainWindow_ExposesTheApprovedUpdateControls()
    {
        var xaml = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml");

        xaml.Should().Contain(
            "x:Name=\"AutoUpdateEnabledCheckBox\"");
        xaml.Should().Contain(
            "Content=\"Automatically update from GitHub Releases\"");
        xaml.Should().Contain(
            "x:Name=\"CheckForUpdatesButton\"");
        xaml.Should().Contain("Content=\"Check now\"");
        xaml.Should().Contain(
            "x:Name=\"UpdateStatusTextBlock\"");
        xaml.Should().Contain("TextWrapping=\"Wrap\"");
    }

    [Fact]
    public void MainWindow_KeepsUpdateControlsGatedUntilStartupCompletes()
    {
        var update = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.Update.cs");
        var initialize = ExtractBetween(
            update,
            "private void InitializeWindowsUpdate",
            "private void LoadWindowsUpdateSettingsToUi");
        initialize.Should().Contain(
            "AutoUpdateEnabledCheckBox.IsEnabled = false;");
        initialize.Should().Contain(
            "CheckForUpdatesButton.IsEnabled = false;");

        var startup = ExtractBetween(
            update,
            "private async Task RunWindowsUpdateStartupAsync",
            "private async void OnAutoUpdateEnabledChanged");
        startup.IndexOf(
                "await updateStartupOrchestrator",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                startup.IndexOf(
                    "updateStartupCompleted =",
                    StringComparison.Ordinal));
        startup.IndexOf(
                "updateStartupCompleted =",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                startup.IndexOf(
                    "ApplyWindowsUpdateControlAvailability();",
                    StringComparison.Ordinal));

        var preference = ExtractBetween(
            update,
            "private async void OnAutoUpdateEnabledChanged",
            "private async void OnCheckForUpdatesClicked");
        preference.Should().Contain(
            "|| !updateStartupCompleted");
        var manual = ExtractBetween(
            update,
            "private async void OnCheckForUpdatesClicked",
            "private void OnWindowsUpdateStatusChanged");
        manual.Should().Contain(
            "|| !updateStartupCompleted");

        var availability = ExtractBetween(
            update,
            "private void ApplyWindowsUpdateControlAvailability",
            "private void DisposeWindowsUpdate");
        availability.Should().Contain(
            "updateStartupCompleted");
        availability.Should().Contain("!isWindowClosing");
        availability.Should().Contain("!updateEventsDetached");
        availability.Should().Contain(
            "AutoUpdateEnabledCheckBox.IsEnabled = interactive;");
        availability.Should().Contain(
            "interactive && !updateStatusIsBusy;");
    }

    [Fact]
    public void AutomaticPreferenceStatusBindingCarriesOneExactGenerationThroughDispatcher()
    {
        var window = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.Update.cs");
        var preference = ExtractBetween(
            window,
            "private async void OnAutoUpdateEnabledChanged",
            "private async void OnCheckForUpdatesClicked");
        preference.IndexOf(
                "BeginAutomaticEnabledChange()",
                StringComparison.Ordinal)
            .Should().BeLessThan(
                preference.IndexOf(
                    "stateStore.Save(updated)",
                    StringComparison.Ordinal));
        preference.Should().Contain(
            "operation,");
        (preference.Split(
                "windowsUpdate.LatestRuntimeStatusIsBusy",
                StringSplitOptions.None).Length - 1)
            .Should().Be(2);
        (preference.Split(
                "ApplyWindowsUpdateControlAvailability();",
                StringSplitOptions.None).Length - 1)
            .Should().Be(2);

        var statusHandler = ExtractBetween(
            window,
            "private void OnWindowsUpdateStatusChanged",
            "private void PrepareWindowsUpdateForClose");
        statusHandler.Should().Contain(
            "update.GenerationStamp");
        statusHandler.Should().Contain(
            "!generationStamp.IsLatest");

        var composition = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/Services/WindowsUpdateCompositionRoot.cs");
        composition.Should().Contain(
            "automaticStatusGate.SetSource(operation)");
        composition.Should().Contain(
            "automaticStatusGate.CaptureStatus(status.IsBusy)");
        composition.Should().Contain(
            "LatestRuntimeStatusIsBusy");
        composition.Should().Contain(
            "StampedWindowsUpdateStatus");
    }

    [Fact]
    public void MainWindow_HealthFailureKeepsUpdateInteractionsFailClosed()
    {
        var update = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.Update.cs");
        var startup = ExtractBetween(
            update,
            "private async Task RunWindowsUpdateStartupAsync",
            "private async void OnAutoUpdateEnabledChanged");

        startup.Should().Contain(
            "result.Failure");
        startup.Should().Contain(
            "ApplicationUpdateStartupFailure");
        startup.Should().Contain(
            ".StartChecks");
        startup.Should().Contain(
            "Update startup safety check failed; restart the application");
        startup.Should().NotContain(
            "ApplicationUpdateStartupFailure.Health");
    }

    [Fact]
    public void MainWindow_StartsUpdateWorkOnlyAfterStartupRoutingFinishes()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");
        var loaded = ExtractBetween(
            source,
            "private async void OnLoaded",
            "private async Task<ApplicationStartupRoutingOutcome>");

        loaded.IndexOf(
                "await AutoRenewDomainRoutesOnStartAsync();",
                StringComparison.Ordinal)
            .Should()
            .BeLessThan(
                loaded.IndexOf(
                    "await RunWindowsUpdateStartupAsync(",
                    StringComparison.Ordinal));
    }

    [Fact]
    public void MainWindow_BusyStatusDisablesOnlyManualCheckAfterStartup()
    {
        var update = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.Update.cs");
        var status = ExtractBetween(
            update,
            "private void ApplyWindowsUpdateStatus",
            "private void PrepareWindowsUpdateForClose");
        status.Should().Contain(
            "updateStatusIsBusy = status.IsBusy;");
        status.Should().Contain(
            "ApplyWindowsUpdateControlAvailability();");
        status.Should().NotContain(
            "AutoUpdateEnabledCheckBox.IsEnabled = false;");

        var close = ExtractBetween(
            update,
            "private void PrepareWindowsUpdateForClose",
            "private void ApplyWindowsUpdateControlAvailability");
        close.Should().Contain(
            "updateStartupCompleted = false;");
        close.Should().Contain(
            "windowsUpdate.StatusChanged -=");
        close.Should().Contain(
            "AutoUpdateEnabledCheckBox.Checked -=");
        close.Should().Contain(
            "AutoUpdateEnabledCheckBox.Unchecked -=");
        close.Should().Contain(
            "CheckForUpdatesButton.Click -=");
    }

    [Fact]
    public void WpfCloseActions_AcquireSoftwareThenRenewAndReleaseInReverse()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/Services/WpfApplicationCloseActions.cs");
        var run = ExtractBetween(
            source,
            "public async Task RunRoutingExclusiveAsync",
            "public void SavePrimaryState");

        var softwareAcquire = run.IndexOf(
            "await softwareApplySemaphore.WaitAsync(",
            StringComparison.Ordinal);
        var renewRun = run.IndexOf(
            "await DomainRouteOperationSerializer.RunAsync(",
            StringComparison.Ordinal);
        var renewGate = run.IndexOf(
            "renewSemaphore,",
            renewRun,
            StringComparison.Ordinal);
        var softwareRelease = run.IndexOf(
            "softwareApplySemaphore.Release();",
            StringComparison.Ordinal);

        softwareAcquire.Should().BeGreaterThanOrEqualTo(0);
        renewRun.Should().BeGreaterThan(softwareAcquire);
        renewGate.Should().BeGreaterThan(renewRun);
        softwareRelease.Should().BeGreaterThan(renewGate);
        source.Split(
                "_savePrimaryState();",
                StringSplitOptions.None)
            .Should()
            .HaveCount(2);
    }

    private static string ExtractBetween(
        string source,
        string startMarker,
        string endMarker)
    {
        var start = source.IndexOf(
            startMarker,
            StringComparison.Ordinal);
        var end = source.IndexOf(
            endMarker,
            start < 0 ? 0 : start,
            StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        end.Should().BeGreaterThan(start);
        return source[start..end];
    }

    private static string ReadRepositoryFile(
        string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(
            Path.Combine(
                root,
                relativePath.Replace(
                    '/',
                    Path.DirectorySeparatorChar)));
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(
                    Path.Combine(directory, "README.md"))
                && Directory.Exists(
                    Path.Combine(directory, "src"))
                && Directory.Exists(
                    Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory =
                Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException(
            "Repository root was not found.");
    }
}
