using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SoftwareRulePathRepairTests
{
    [Fact]
    public void RepairEnabledRulePaths_ExpandsStaleRuleToAllResolvedPaths()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var mainPath = CreateExe(tempDirectory, "app", "Codex.exe");
            var resourcePath = CreateExe(tempDirectory, Path.Combine("app", "resources"), "codex.exe");
            var stalePath = Path.Combine(tempDirectory, "old", "Codex.exe");
            var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
                [new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, stalePath)],
                DomainRouteMode.BypassWireGuard,
                DomainRouteMode.BypassWireGuard);

            var result = SoftwareRulePathRepair.RepairEnabledRulePaths(
                state,
                new FakeSoftwareExecutableLocator(new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["codex.exe"] = [mainPath, resourcePath]
                }));

            result.Updated.Should().Be(1);
            result.Added.Should().Be(1);
            result.UnresolvedProcessNames.Should().BeEmpty();
            state.SoftwareRules.Should().HaveCount(2);
            state.SoftwareRules!.Select(rule => rule.ExecutablePath).Should().Equal(mainPath, resourcePath);
            state.SoftwareRules!.Should().OnlyContain(rule =>
                rule.ProcessName == "codex.exe"
                && rule.Enabled
                && rule.Mode == DomainRouteMode.UseWireGuard
                && rule.IncludeSubprocesses);
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void RepairEnabledRulePaths_AddsMissingAlternatePathWhenCurrentPathStillExists()
    {
        var tempDirectory = CreateTempDirectory();
        try
        {
            var mainPath = CreateExe(tempDirectory, "app", "Codex.exe");
            var resourcePath = CreateExe(tempDirectory, Path.Combine("app", "resources"), "codex.exe");
            var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
                [new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, mainPath)],
                DomainRouteMode.BypassWireGuard,
                DomainRouteMode.BypassWireGuard);

            var result = SoftwareRulePathRepair.RepairEnabledRulePaths(
                state,
                new FakeSoftwareExecutableLocator(new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["codex.exe"] = [mainPath, resourcePath]
                }));

            result.Updated.Should().Be(0);
            result.Added.Should().Be(1);
            result.UnresolvedProcessNames.Should().BeEmpty();
            state.SoftwareRules!.Select(rule => rule.ExecutablePath).Should().Equal(mainPath, resourcePath);
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    [Fact]
    public void RepairEnabledRulePaths_ReportsMissingPathWhenNoCandidatesExist()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
            [new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, "C:\\missing\\codex.exe")],
            DomainRouteMode.BypassWireGuard,
            DomainRouteMode.BypassWireGuard);

        var result = SoftwareRulePathRepair.RepairEnabledRulePaths(
            state,
            new FakeSoftwareExecutableLocator(new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)));

        result.Updated.Should().Be(0);
        result.Added.Should().Be(0);
        result.UnresolvedProcessNames.Should().Equal("codex.exe");
        state.SoftwareRules.Should().ContainSingle(rule => rule.ExecutablePath == "C:\\missing\\codex.exe");
    }

    private static string CreateTempDirectory()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), $"wgst-repair-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDirectory);
        return tempDirectory;
    }

    private static string CreateExe(string root, string subdirectory, string exeName)
    {
        var directory = Path.Combine(root, subdirectory);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, exeName);
        File.WriteAllText(path, "");
        return path;
    }

    private sealed class FakeSoftwareExecutableLocator(Dictionary<string, IReadOnlyList<string>> pathsByProcessName) : ISoftwareExecutableLocator
    {
        public bool TryResolvePath(string processName, out string executablePath)
        {
            var paths = ResolvePaths(processName);
            executablePath = paths.FirstOrDefault() ?? string.Empty;
            return paths.Count > 0;
        }

        public IReadOnlyList<string> ResolvePaths(string processName)
        {
            return pathsByProcessName.TryGetValue(processName, out var paths)
                ? paths
                : [];
        }
    }
}
