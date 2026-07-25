using FluentAssertions;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacMainWindowCleanupContractTests
{
    [Fact]
    public void CleanupWiring_UsesPersistedDnsDebtAndPerComponentReducer()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");

        source.Should().Contain("MacDnsRepairService.CaptureSnapshotAsync");
        source.Should().Contain("RawTunnelDnsCleanupDebt");
        source.Should().Contain("MacCleanupStateReducer.Apply");
        source.Should().NotContain("DiscoverTunnelDnsServicesAsync");
    }

    [Fact]
    public void RawTunnelStart_UsesDurablePrivilegedJournalInsteadOfPrePromptSnapshot()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");

        source.Should().Contain("MacDnsJournalService.CreateJournalPath");
        source.Should().Contain("MacDnsRepairService.CreatePendingCleanupDebt");
        source.Should().Contain("InstallAndStartAsync(rawConfigPath, dnsJournalPath, ct)");
        source.Should().Contain("MacDnsJournalService.RecoverDebt");
        source.Should().NotContain("MacDnsRepairService.RefineCleanupDebtAfterStart");
    }

    [Fact]
    public void SplitTunnelStart_PersistsExactGeneratedCleanupTarget()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");

        source.Should().Contain("ActiveSplitTunnelConfigPath = splitConfigPath");
    }

    [Fact]
    public void ManualDisable_IncludesManagedRoutesWithTunnelWorkAndRouteDebtPreventsEarlyReturn()
    {
        var source = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");
        var disableMethod = source[
            source.IndexOf("private async void OnDisableTunnelClick", StringComparison.Ordinal)
            ..source.IndexOf("private void OnRefreshStatusClick", StringComparison.Ordinal)];

        disableMethod.Should().Contain(
            "var managedRoutes = appState.ManagedRouteSnapshot.ToList();");
        disableMethod.Should().Contain(
            "if (targets.Count == 0\n"
            + "            && managedRoutes.Count == 0\n"
            + "            && appState.RawTunnelDnsCleanupDebt is null)");

        var request = disableMethod[
            disableMethod.IndexOf("var request = new MacCleanupRequest", StringComparison.Ordinal)
            ..disableMethod.IndexOf(
                "var result = await MacExitCleanupService.RunAsync",
                StringComparison.Ordinal)];
        request.Should().Contain("SplitConfigPath = splitTarget");
        request.Should().Contain("RawTunnelName = rawTarget");
        request.Should().Contain("ManagedRoutesToRemove = managedRoutes");
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
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
