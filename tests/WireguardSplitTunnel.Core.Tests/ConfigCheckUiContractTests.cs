using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckUiContractTests
{
    [Theory]
    [InlineData(ConfigCheckStatus.Healthy, false)]
    [InlineData(ConfigCheckStatus.Repaired, false)]
    [InlineData(ConfigCheckStatus.Unrepaired, true)]
    public void OnlyUnrepairedMayOfferRecycle(ConfigCheckStatus status, bool expected)
    {
        ConfigCheckDeletePolicy.MayOffer(status).Should().Be(expected);
    }

    [Theory]
    [InlineData("GB", "GB")]
    [InlineData("US", "US")]
    [InlineData("", "")]
    [InlineData("gb", "")]
    [InlineData("GBR", "")]
    [InlineData("G1", "")]
    [InlineData("US\r\nPrivateKey = synthetic-secret", "")]
    [InlineData(null, "")]
    public void ResultCountryDiagnostic_AdmitsOnlyTwoUppercaseAsciiLetters(string? value, string expected)
    {
        var result = new ConfigCheckResult(ConfigCheckStatus.Unrepaired, "test.conf", "uk6000.nordvpn.com:51820", "ExitCountryMismatch")
        {
            ObservedCountry = value!
        };

        result.ObservedCountry.Should().Be(expected);
    }

    [Fact]
    public void CompletedResult_LogsExpectedAndSanitizedObservedCountry()
    {
        var source = ReadCoordinatorSource();

        source.Should().Contain(
            "LogConfigCheck(completed.Status.ToString(), completed.ConfigPath, completed.Endpoint, completed.Reason, config.Country, completed.ObservedCountry);");
        source.Should().Contain("expected={expectedCountry}, observed={observedCountry}");
    }

    [Fact]
    public void XamlAndConstructor_WireTestConfigButtonBeforeEnablePanel()
    {
        var xaml = ReadAppSource("MainWindow.xaml");
        var configArea = ExtractBetween(
            xaml,
            "<Border Grid.Row=\"1\"",
            "        <Border Grid.Row=\"2\"");
        var testButton = ExtractBetween(
            configArea,
            "<Button Grid.Column=\"4\"",
            "<StackPanel Grid.Column=\"5\"");

        (configArea.Split(
                "<ColumnDefinition",
                StringSplitOptions.None).Length - 1)
            .Should().Be(6);
        testButton.Should().Contain("x:Name=\"TestConfigButton\"");
        testButton.Should().Contain("Content=\"Test Config\"");
        testButton.Should().Contain("MinWidth=\"110\"");
        testButton.Should().Contain("Margin=\"0,0,8,0\"");
        testButton.Should().Contain("Padding=\"10,6\"");
        testButton.Should().Contain("VerticalAlignment=\"Top\"");
        configArea.IndexOf("x:Name=\"TestConfigButton\"", StringComparison.Ordinal)
            .Should().BeLessThan(configArea.IndexOf("x:Name=\"EnableTunnelButton\"", StringComparison.Ordinal));

        var window = ReadAppSource("MainWindow.xaml.cs");
        window.Should().Contain("TestConfigButton.Click += OnTestConfigClicked;");
    }

    [Fact]
    public void Coordinator_CapturesFullSelectedPathBeforeDefaultNoWarning()
    {
        var source = ReadCoordinatorSource();
        var parse = source.IndexOf("CheckedConfig.Parse(selectedFullPath)", StringComparison.Ordinal);
        var warning = source.IndexOf("internet access may be interrupted", StringComparison.Ordinal);

        source.Should().Contain("TunnelConfigCombo.SelectedValue as string");
        source.Should().Contain("Path.GetFullPath(selectedPath)");
        parse.Should().BeGreaterThanOrEqualTo(0);
        warning.Should().BeGreaterThan(parse);
        source.Should().Contain("{selectedFullPath}");
        source.Should().Contain("MessageBoxButton.YesNo");
        source.Should().Contain("MessageBoxResult.No");
    }

    [Fact]
    public void Coordinator_OffersDefaultNoRecycleOnlyForMatchingUnrepairedResult()
    {
        var source = ReadCoordinatorSource();
        var policy = source.IndexOf("ConfigCheckDeletePolicy.MayOffer(completed.Status)", StringComparison.Ordinal);
        var pathGuard = source.IndexOf(
            "string.Equals(completed.ConfigPath, selectedFullPath, StringComparison.OrdinalIgnoreCase)",
            policy,
            StringComparison.Ordinal);
        var prompt = source.IndexOf(
            "$\"Connection could not be repaired:\\n{completed.ConfigPath}\\n\\nMove this file to the Recycle Bin?\"",
            pathGuard,
            StringComparison.Ordinal);
        var defaultNo = source.IndexOf("MessageBoxResult.No", prompt, StringComparison.Ordinal);

        policy.Should().BeGreaterThanOrEqualTo(0);
        pathGuard.Should().BeGreaterThan(policy);
        prompt.Should().BeGreaterThan(pathGuard);
        defaultNo.Should().BeGreaterThan(prompt);
        source.Should().Contain("MessageBoxImage.Warning");
    }

    [Fact]
    public void Coordinator_RestoresOnlyOriginallyActiveSelectedTunnelRoutesThroughCoreRenewal()
    {
        var source = ReadCoordinatorSource();

        source.Should().Contain("restoreRoutesAsync: RestoreRoutesAsync");
        source.Should().NotContain("OriginalSelectedTunnelIsActive");
        source.Should().Contain("SoftwareTunnelSelector.Select(state.SelectedTunnelConfigPath");
        source.Should().Contain("ConfigCheckRecoveredService");
        source.Should().Contain("restoreRoutesAsync");
        source.Should().Contain("RenewDomainRoutesAsync(");
        source.Should().Contain("CancellationToken.None");
        source.Should().NotContain("RenewDomainRoutesLockedAsync(");
    }

    [Fact]
    public void Coordinator_ReconcilesExactDerivedConfigThroughPreRestartCallback()
    {
        var source = ReadCoordinatorSource();

        source.Should().Contain("derivedConfigPath:");
        source.Should().Contain("reconcileDerivedConfigAsync: ReconcileDerivedConfigAsync");
        source.Should().Contain("ConfigCheckRestoreContext");
        source.Should().Contain("WireguardAllowedIpsSanitizer.ReconcileRepairedConfigFile(");
        source.Should().Contain("context.SourceFingerprint");
    }

    [Fact]
    public void Startup_RecoversAllJournalsBeforeAutoEnableRenewalDnsAndSoftwareWork()
    {
        var window = ReadAppSource("MainWindow.xaml.cs");
        var recovery = ReadCoordinatorSource();
        var recoveryCall = window.IndexOf(
            "await RecoverConfigCheckTransactionsOnStartupAsync();",
            StringComparison.Ordinal);
        var autoEnable = window.IndexOf(
            "TryEnableSelectedTunnel(autoTriggered: true);",
            StringComparison.Ordinal);
        var startupRenewal = window.IndexOf(
            "await AutoRenewDomainRoutesOnStartAsync();",
            StringComparison.Ordinal);
        var dnsTimer = window.IndexOf("dnsCacheLearningTimer.Start();", StringComparison.Ordinal);
        var softwareLearning = window.IndexOf("StartSoftwareLearning();", StringComparison.Ordinal);
        var softwareReapply = window.IndexOf("ScheduleSoftwareReapply(\"startup\");", StringComparison.Ordinal);

        recoveryCall.Should().BeGreaterThanOrEqualTo(0);
        autoEnable.Should().BeGreaterThan(recoveryCall);
        startupRenewal.Should().BeGreaterThan(recoveryCall);
        dnsTimer.Should().BeGreaterThan(recoveryCall);
        softwareLearning.Should().BeGreaterThan(recoveryCall);
        softwareReapply.Should().BeGreaterThan(recoveryCall);
        window.Should().Contain("new ConfigCheckStartupRecoveryCoordinator(");
        window.Should().Contain("installCommitted && startupRecoveryCompleted && !isWindowClosing");
        window.Should().Contain("private volatile bool suppressAutoSoftwareReapply = true;");
        window.Should().Contain("suppressAutoSoftwareReapply = !startupRecoveryCompleted ||");
        window.Should().Contain("!configCheckStartupRecoveryCoordinator.CloseWasRequested");
        recovery.Should().Contain("configCheckStartupRecoveryCoordinator.RunAsync(");
        recovery.Should().Contain("reconcileDerivedConfigAsync: ReconcileDerivedConfigAsync");
        recovery.Should().Contain("SoftwareTunnelSelector.Select(state.SelectedTunnelConfigPath");
        recovery.Should().Contain("RenewDomainRoutesAsync(");
        recovery.Should().Contain("fromStartup: false");
        recovery.Should().Contain("CancellationToken.None");
    }

    [Fact]
    public void StartupRecovery_CloseDefersForcedCloseAndSkipsRemainingStartupUi()
    {
        var window = ReadAppSource("MainWindow.xaml.cs");
        var closing = ExtractBetween(
            window,
            "private async void OnWindowClosing",
            "private void ResumeWindowCloseAfterConfigCheck");
        var loaded = ExtractBetween(
            window,
            "private async void OnLoaded",
            "private async Task WaitForInstallCommitAsync");
        var startupDeferral = closing.IndexOf(
            "configCheckStartupRecoveryCoordinator.TryDeferClose()",
            StringComparison.Ordinal);
        var closeTimeout = closing.IndexOf("closeTimeoutCts", StringComparison.Ordinal);

        window.Should().MatchRegex(
            @"new ConfigCheckStartupRecoveryCoordinator\(\s*softwareApplySemaphore,\s*renewSemaphore,\s*ResumeWindowCloseAfterConfigCheck\);");
        startupDeferral.Should().BeGreaterThanOrEqualTo(0);
        closeTimeout.Should().BeGreaterThan(startupDeferral,
            "normal forced-close timeout must not start while startup recovery is active");
        loaded.Should().Contain("configCheckStartupRecoveryCoordinator.CloseWasRequested");
        loaded.Should().Contain("configCheckStartupRecoveryCoordinator.CompletePending();");
        loaded.Should().Contain("if (configCheckStartupRecoveryCoordinator.CloseWasRequested) return;");
    }

    [Fact]
    public void Enable_ManualAutomaticAndPostGateChecksBlockForPersistentRecoveryAndSanitizeInsideFactory()
    {
        var window = ReadAppSource("MainWindow.xaml.cs");
        var entry = ExtractBetween(
            window,
            "private void TryEnableSelectedTunnel",
            "private static string? ResolveWireguardExecutablePath");
        var tracking = ExtractBetween(
            window,
            "private async Task TrackEnableTunnelProcessAsync",
            "private void SaveStateAndRefreshConfigSelection");
        var queue = entry.IndexOf("_ = TrackEnableTunnelProcessAsync(", StringComparison.Ordinal);
        var sanitize = entry.IndexOf(
            "WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(",
            StringComparison.Ordinal);
        var discovery = entry.IndexOf(
            "WindowsTunnelServiceDiscovery.ListInstalledTunnelNames()",
            StringComparison.Ordinal);

        entry.Should().Contain("configCheckStartupRecoveryCoordinator.IsTunnelEnableBlocked");
        tracking.Should().Contain("configCheckStartupRecoveryCoordinator.IsTunnelEnableBlocked");
        tracking.Should().Contain("() => !isWindowClosing && !configCheckCoordinator.IsActive &&");
        queue.Should().BeGreaterThanOrEqualTo(0);
        sanitize.Should().BeGreaterThan(queue,
            "derived selection and sanitizer I/O must run inside the routing-gated factory");
        discovery.Should().BeGreaterThan(sanitize,
            "service discovery stays fresh and follows successful derived validation");
        window.Should().Contain("TryEnableSelectedTunnel(autoTriggered: true);");
        window.Should().Contain("TryEnableSelectedTunnel(autoTriggered: false);");
    }

    [Fact]
    public void SoftwareApply_SchedulingAndExecutionShareConfigAndStartupRecoveryGuards()
    {
        var window = ReadAppSource("MainWindow.xaml.cs");
        var schedule = ExtractBetween(
            window,
            "private void ScheduleSoftwareReapply",
            "private void NormalizeUnifiedGlobalModeOnLoad");
        var apply = ExtractBetween(
            window,
            "private async Task ApplySoftwarePoliciesAsync",
            "private async void OnApplySoftwareClicked");

        window.Should().Contain(
            "private bool CanApplySoftwarePolicies() =>");
        window.Should().Contain(
            "!isWindowClosing && !configCheckCoordinator.IsActive && !suppressAutoSoftwareReapply;");
        window.Should().MatchRegex(
            @"new ConfigCheckCoordinator\(\s*softwareApplySemaphore,\s*renewSemaphore,");
        window.Should().MatchRegex(
            @"new ConfigCheckStartupRecoveryCoordinator\(\s*softwareApplySemaphore,\s*renewSemaphore,\s*ResumeWindowCloseAfterConfigCheck\);");
        schedule.Split("CanApplySoftwarePolicies()", StringSplitOptions.None)
            .Should().HaveCountGreaterThanOrEqualTo(4,
                "queueing, debounce completion, and post-renew waiting must all recheck the shared guard");
        apply.Should().Contain("softwareApplyCoordinator.RunAsync(");
        apply.Should().Contain("CanApplySoftwarePolicies,");
    }

    [Fact]
    public void WorkflowFailure_LogsFullExceptionForDiagnosis()
    {
        var source = ReadCoordinatorSource();
        var workflowCatch = ExtractBetween(
            source,
            "catch (Exception)",
            "async Task RestoreRoutesAsync");

        workflowCatch.Should().Contain(
            "logger.Error(\"Config check workflow failed.\", ex);");
    }

    private static string ReadCoordinatorSource() =>
        ReadAppSource("MainWindow.ConfigCheck.cs");

    private static string ReadAppSource(string fileName) =>
        File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "WireguardSplitTunnel.App",
            fileName));

    private static string ExtractBetween(
        string source,
        string startMarker,
        string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        var end = source.IndexOf(endMarker, start, StringComparison.Ordinal);
        end.Should().BeGreaterThan(start);
        return source[start..end];
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md")) &&
                Directory.Exists(Path.Combine(directory, "src")) &&
                Directory.Exists(Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
