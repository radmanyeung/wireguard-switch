using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class IncrementalDnsTimerIntegrationTests
{
    [Fact]
    public void WindowsMainWindow_WiresIncrementalDnsLearningTimerLifecycle()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");

        source.Should().Contain(
            "private readonly DispatcherTimer dnsCacheLearningTimer = new() { Interval = TimeSpan.FromSeconds(10) };");
        source.Should().Contain(
            "incrementalDnsRouteReconciler = new IncrementalDnsRouteReconciler(dnsCacheReader);");
        source.Should().Contain(
            "dnsCacheLearningTimer.Tick += OnDnsCacheLearningTimerTick;");
        source.Should().Contain("dnsCacheLearningTimer.Start();");
        source.Should().Contain(
            "if (!await renewSemaphore.WaitAsync(0))");
        source.Should().Contain(
            "await incrementalDnsRouteReconciler.ReconcileAsync(");
        source.Should().Contain(
            "await ApplyRoutesViaCurrentWireGuardAsync(toAdd, [], CancellationToken.None);");
        source.Should().Contain(
            "await HealMissingDomainRoutesAsync(toAdd.ToList(), CancellationToken.None);");
        source.Should().Contain(
            "if (!result.StateChanged && !incrementalDomainStateSavePending)");

        var stopMonitorMethod = ExtractBetween(
            source,
            "private void StopNetworkMonitor()",
            "private async void OnMonitorTimerTick");
        stopMonitorMethod.Should().NotContain("dnsCacheLearningTimer");
        stopMonitorMethod.Should().NotContain("dnsCacheLearningCts");

        var closingMethod = ExtractBetween(
            source,
            "private async void OnWindowClosing",
            "private async void OnLoaded");
        closingMethod.Should().Contain("dnsCacheLearningTimer.Stop();");
        closingMethod.Should().Contain("dnsCacheLearningCts.Cancel();");
        closingMethod.Should().Contain(
            "applicationCloseOrchestrator");
        closingMethod.Should().Contain(".RunOnceAsync(");
        // Close must never hang on a stuck restore: orchestration is
        // cancellable and the window force-closes after a hard timeout.
        closingMethod.Should().Contain("Task.WhenAny(");
        closingMethod.Should().NotContain(
            "DomainRouteOperationSerializer.RunAsync");

        var lockedRenewMethod = ExtractBetween(
            source,
            "private async Task<bool> RenewDomainRoutesLockedAsync",
            "private async Task WaitForDomainRenewIdleAsync");
        lockedRenewMethod.Should().Contain("if (isWindowClosing)");
    }

    [Fact]
    public void WindowsMainWindow_SerializesDomainStateInvalidatingMutationsWithRouteRenew()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");

        var mutationMethods = new[]
        {
            ExtractBetween(
                source,
                "private async void OnLoadTempClicked",
                "private async void OnAddDomainRuleClicked"),
            ExtractBetween(
                source,
                "private async void OnToggleDomainEnabledClicked",
                "private async void OnDeleteDomainRuleClicked"),
            ExtractBetween(
                source,
                "private async void OnDeleteDomainRuleClicked",
                "private void OnViewDomainIpsClicked"),
            ExtractBetween(
                source,
                "private async void OnRollbackClicked",
                "private void OnAddSoftwareRuleClicked")
        };

        mutationMethods.Should().AllSatisfy(method =>
        {
            method.Should().Contain(
                "await DomainRouteOperationSerializer.RunAsync(renewSemaphore, () =>");
            method.Should().Contain("if (isWindowClosing)");
        });

        var toggleMethod = mutationMethods[1];
        toggleMethod.Should().Contain("var currentRule = state.DomainRules.FirstOrDefault");
        toggleMethod.Should().Contain("!currentRule.Enabled");
        toggleMethod.Should().NotContain("!selected.Enabled");

        var softwareApplyMethod = ExtractBetween(
            source,
            "private async Task ApplySoftwarePoliciesAsync",
            "private async void OnApplySoftwareClicked");
        var gateAcquire = softwareApplyMethod.IndexOf(
            "await softwareApplySemaphore.WaitAsync(cancellationToken)",
            StringComparison.Ordinal);
        var closingRecheck = softwareApplyMethod.IndexOf(
            "if (isWindowClosing)",
            gateAcquire < 0 ? 0 : gateAcquire,
            StringComparison.Ordinal);
        gateAcquire.Should().BeGreaterThanOrEqualTo(0);
        closingRecheck.Should().BeGreaterThan(gateAcquire);
    }

    private static string ExtractBetween(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        var end = source.IndexOf(endMarker, start, StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        end.Should().BeGreaterThan(start);
        return source[start..end];
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(
            root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
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
