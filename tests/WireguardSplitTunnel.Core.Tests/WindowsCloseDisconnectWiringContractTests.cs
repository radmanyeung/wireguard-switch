using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsCloseDisconnectWiringContractTests
{
    [Fact]
    public void Composition_EnableActivityAndSingleJournalFeedUserCloseOnly()
    {
        var source = ReadAppSource();
        var constructor = ExtractBetween(
            source,
            "internal MainWindow(",
            "private void LogApplicationCloseResult");

        source.Should().Contain("private readonly WpfApplicationCloseActions closeActions;");
        source.Should().Contain("private readonly FileCloseDisconnectJournal closeDisconnectJournal;");
        source.Should().Contain("private readonly CloseDisconnectCoordinator closeDisconnectCoordinator;");
        constructor.IndexOf("enableTunnelCoordinator = new EnableTunnelCoordinator(", StringComparison.Ordinal)
            .Should().BeGreaterThanOrEqualTo(0);
        constructor.IndexOf("closeDisconnectCoordinator = new CloseDisconnectCoordinator(", StringComparison.Ordinal)
            .Should().BeGreaterThan(
                constructor.IndexOf("enableTunnelCoordinator = new EnableTunnelCoordinator(", StringComparison.Ordinal));
        constructor.Should().Contain("Path.Combine(dataDirectory, \"close-disconnect.json\")");
        constructor.Should().Contain("new RegistryWindowsTunnelServiceEnumerator()");
        constructor.Should().Contain("new WindowsElevatedTunnelStopAdapter(");
        constructor.Should().Contain("tunnelProcessFactory,");
        constructor.Should().Contain("ResolveWireguardExecutablePath");
        constructor.Should().Contain("enableTunnelCoordinator,");

        var factory = ExtractBetween(
            source,
            "private ApplicationCloseOrchestrator CreateApplicationCloseOrchestrator",
            "private async void OnWindowClosing");
        factory.Should().Contain("closeActions,");
        factory.Should().Contain(
            "closeIntentTracker.Current == ApplicationCloseIntent.UserOrApplicationClose");
        factory.Should().Contain("? closeDisconnectCoordinator");
        factory.Should().Contain(": null");
    }

    [Fact]
    public void CloseLog_IncludesSanitizedDisconnectDiagnosticsAndAuthorizationFields()
    {
        var source = ReadAppSource();
        var logging = ExtractBetween(
            source,
            "private void LogApplicationCloseResult",
            "private ApplicationCloseOrchestrator CreateApplicationCloseOrchestrator");

        logging.Should().Contain(
            "CloseDisconnectDiagnosticFormatter.Format(result.DisconnectResult)");
        logging.Should().Contain("authorizationPresent=");
        logging.Should().Contain("authorizationOutcome=");
        logging.Should().Contain("authorizationError=");
    }

    [Fact]
    public void Startup_ReconcilesThroughRoutingGatesBeforeEveryDependentStage()
    {
        var source = ReadAppSource();
        var loaded = ExtractBetween(
            source,
            "private async void OnLoaded",
            "private async Task WaitForInstallCommitAsync");
        var recovery = loaded.IndexOf(
            "await RecoverConfigCheckTransactionsOnStartupAsync();",
            StringComparison.Ordinal);
        var reconcile = loaded.IndexOf(
            "if (!await ReconcileCloseDisconnectOnStartupAsync()) return;",
            StringComparison.Ordinal);

        recovery.Should().BeGreaterThanOrEqualTo(0);
        reconcile.Should().BeGreaterThan(recovery);
        foreach (var dependentStage in new[]
        {
            "detector.TryGetActiveInterface(out var interfaceName)",
            "TryEnableSelectedTunnel(autoTriggered: true);",
            "await AutoRenewDomainRoutesOnStartAsync();",
            "await RunWindowsUpdateStartupAsync(",
            "dnsCacheLearningTimer.Start();",
            "StartSoftwareLearning();",
            "ScheduleSoftwareReapply(\"startup\");"
        })
        {
            loaded.IndexOf(dependentStage, StringComparison.Ordinal)
                .Should().BeGreaterThan(reconcile, dependentStage);
        }

        var reconciliation = ExtractBetween(
            source,
            "private async Task<bool> ReconcileCloseDisconnectOnStartupAsync",
            "private bool TryDeferCloseDisconnectStartup");
        reconciliation.Should().Contain("closeActions.RunRoutingExclusiveAsync(");
        reconciliation.Should().Contain("closeDisconnectCoordinator.ReconcileAsync(CancellationToken.None)");
        reconciliation.Should().Contain("CancellationToken.None);");
        reconciliation.Should().Contain("UnresolvedTargets");
        reconciliation.Should().Contain(".ServiceName");
        reconciliation.Should().Contain("normal networking may still use WireGuard");
        reconciliation.Should().Contain("return false;");
        loaded.Should().Contain("if (!await ReconcileCloseDisconnectOnStartupAsync()) return;");
        loaded.Should().Contain("closeDisconnectReconciliationCompleted");
        loaded.Should().Contain("!closeDisconnectReconciliationCompleted");
    }

    [Fact]
    public void StartupReconciliation_ParticipatesInCloseDeferralAndResumesOnce()
    {
        var source = ReadAppSource();
        var closing = ExtractBetween(
            source,
            "private async void OnWindowClosing",
            "private void ResumeWindowCloseAfterConfigCheck");

        closing.Should().Contain("TryDeferCloseDisconnectStartup()");
        closing.Should().Contain("closeDisconnectStartupCloseDeferred");
        source.Should().Contain("private bool closeDisconnectStartupReconciliationActive = true;");
        source.Should().Contain("private void CompleteCloseDisconnectStartupReconciliation()");
        var completion = ExtractBetween(
            source,
            "private void CompleteCloseDisconnectStartupReconciliation",
            "private static string FormatCloseDisconnectServiceNames");
        completion.Should().Contain("closeDisconnectStartupCloseDeferred = false;");
        completion.Should().Contain("ResumeWindowCloseAfterConfigCheck();");
    }

    [Fact]
    public void Close_TimeoutNeverOutrunsAttemptAndOnlyCanCloseResumesWindowClose()
    {
        var source = ReadAppSource();
        var closing = ExtractBetween(
            source,
            "private async void OnWindowClosing",
            "private void ResumeWindowCloseAfterConfigCheck");

        closing.Should().Contain("Task.WhenAny(");
        closing.Should().Contain("result = await runTask;");
        closing.Should().Contain("if (result.CanClose)");
        closing.Should().Contain("applicationCloseAttemptLifecycle.RunAsync(");
        closing.Should().Contain("() => applicationCloseOrchestrator = CreateApplicationCloseOrchestrator()");
        closing.Should().Contain("applicationCloseRunTask");
        closing.Should().Contain("applicationCloseAttemptLatched");
        closing.Should().Contain("applicationCloseRunTask is not { } activeAttempt");
        closing.Should().Contain("activeAttempt.IsCompleted");
        closing.Should().Contain("if (!ReferenceEquals(applicationCloseRunTask, runTask))");
        closing.Should().NotContain("applicationCloseRunTask is { IsCompleted: false }");
        closing.Should().Contain("ReleaseApplicationCloseAttempt(runTask);");
        closing.Should().NotContain("closing without waiting for route restore");
        closing.Should().NotContain("force the window closed");
        closing.Should().NotContain("finally\n        {\n            DisposeWindowsUpdate();");

        var finish = ExtractBetween(
            source,
            "private void FinishWindowClose()",
            "private async void OnLoaded");
        finish.Should().Contain("if (allowCloseWithoutRestore) return;");
        finish.IndexOf("DisposeWindowsUpdate();", StringComparison.Ordinal)
            .Should().BeLessThan(finish.IndexOf("allowCloseWithoutRestore = true;", StringComparison.Ordinal));
        finish.IndexOf("allowCloseWithoutRestore = true;", StringComparison.Ordinal)
            .Should().BeLessThan(finish.IndexOf("Close();", StringComparison.Ordinal));
    }

    [Fact]
    public void CloseFailure_RetryAndTwoStepCloseAnywayPreserveCleanupDebt()
    {
        var source = ReadAppSource();
        var closing = ExtractBetween(
            source,
            "private async void OnWindowClosing",
            "private void ResumeWindowCloseAfterConfigCheck");

        closing.Should().Contain("MessageBoxButton.YesNoCancel");
        closing.Should().Contain("MessageBoxResult.Cancel");
        closing.Should().Contain("normal networking was not restored");
        closing.Should().Contain("Unresolved WireGuard services:");
        closing.Should().Contain("MessageBoxResult.Yes");
        closing.Should().Contain("MessageBoxResult.No");
        closing.Should().Contain("Close anyway without restoring normal networking?");
        closing.Should().Contain("WireGuard may still route traffic");
        closing.Should().Contain("no staged update installs");
        closing.Should().Contain("cleanup is not marked successful");
        closing.Should().Contain("MessageBoxButton.YesNo");
        closing.Should().Contain("applicationCloseAttemptLifecycle.RunAsync(");
        closing.Should().Contain("() => applicationCloseOrchestrator = CreateApplicationCloseOrchestrator()");
        closing.Should().Contain("closeIntentTracker,");

        var nonUserTransition = ExtractBetween(
            source,
            "if (closeIntentTracker.Current != ApplicationCloseIntent.UserOrApplicationClose)",
            "var serviceNames = FormatCloseDisconnectServiceNames");
        nonUserTransition.Should().Contain("continue;");
        nonUserTransition.Should().NotContain("MessageBox.Show");

        var forceClose = ExtractBetween(
            source,
            "if (closeAnyway == MessageBoxResult.Yes)",
            "// Cancel and a declined second warning release only after every dialog");
        forceClose.Should().Contain("FinishWindowClose();");
        forceClose.Should().NotContain("DisconnectAsync(");
        forceClose.Should().NotContain("SavePrimaryState");
        forceClose.Should().NotContain("TryAuthorizeAndLaunchAsync");
        forceClose.Should().NotContain(".Complete(");
    }

    [Fact]
    public void Readme_DocumentsVerifiedUserCloseDisconnectAndRecoveryLimits()
    {
        var readme = File.ReadAllText(Path.Combine(FindRepositoryRoot(), "README.md"));
        var closeSection = ExtractBetween(
            readme,
            "### Closing the Windows app and using WireGuard directly",
            "## Self-test outputs").ReplaceLineEndings(" ");
        var updateSection = ExtractBetween(
            readme,
            "## Windows automatic updates (v0.2.0 and later)",
            "## macOS Apple Silicon release").ReplaceLineEndings(" ");

        closeSection.Should().Contain("existing application-managed route cleanup runs first");
        closeSection.Should().Contain("stops and uninstalls **all** installed `WireGuardTunnel$` services");
        closeSection.Should().Contain("including tunnels created outside this app");
        closeSection.Should().Contain("If no tunnel services are installed, no elevation is requested");
        closeSection.Should().Contain("verified that every targeted service is absent");
        closeSection.Should().Contain("saves final application state");
        closeSection.Should().Contain("exact unresolved service names");
        closeSection.Should().Contain("**Retry**");
        closeSection.Should().Contain("**Close anyway**");
        closeSection.Should().Contain("separately confirmed");
        closeSection.Should().Contain("does not authorize a staged update or mark cleanup successful");
        closeSection.Should().Contain("Installer-maintenance close preserves tunnels");
        closeSection.Should().Contain("only the recorded targets and any recorded pending Enable Now tunnel");
        closeSection.Should().Contain("before automatic enable or route renewal");
        closeSection.Should().Contain("Task Manager termination, power loss, or a crash before a close request");
        closeSection.Should().Contain("outside this guarantee");
        closeSection.Should().Contain("Offline tests do not prove live service removal, route restoration, updater handoff, or network restoration");
        updateSection.Should().Contain("verified tunnel disconnect and final state save");
    }

    private static string ReadAppSource() =>
        File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "WireguardSplitTunnel.App",
            "MainWindow.xaml.cs"));

    private static string ExtractBetween(
        string source,
        string startMarker,
        string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0, startMarker);
        var end = source.IndexOf(endMarker, start, StringComparison.Ordinal);
        end.Should().BeGreaterThan(start, endMarker);
        return source[start..end];
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md"))
                && Directory.Exists(Path.Combine(directory, "src"))
                && Directory.Exists(Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
