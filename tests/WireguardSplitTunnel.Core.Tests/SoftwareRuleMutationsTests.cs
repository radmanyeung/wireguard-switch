using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SoftwareRuleMutationsTests
{
    [Fact]
    public void TryAddSoftwareRule_AddsUniqueExe()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false, [], DomainRouteMode.BypassWireGuard, DomainRouteMode.BypassWireGuard);

        var first = SoftwareRuleMutations.TryAddSoftwareRule(state, "chrome.exe", DomainRouteMode.UseWireGuard, true, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        var second = SoftwareRuleMutations.TryAddSoftwareRule(state, "CHROME.EXE", DomainRouteMode.BypassWireGuard, false, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");

        first.Should().BeTrue();
        second.Should().BeFalse();
        state.SoftwareRules.Should().ContainSingle(rule =>
            rule.ProcessName == "chrome.exe"
            && rule.Mode == DomainRouteMode.UseWireGuard
            && rule.IncludeSubprocesses
            && rule.ExecutablePath == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    }

    [Fact]
    public void TryAddSoftwareRule_AllowsSameProcessNameWithDifferentExecutablePaths()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false, [], DomainRouteMode.BypassWireGuard, DomainRouteMode.BypassWireGuard);

        var mainAdded = SoftwareRuleMutations.TryAddSoftwareRule(state, "codex.exe", DomainRouteMode.UseWireGuard, true, "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\Codex.exe");
        var resourceAdded = SoftwareRuleMutations.TryAddSoftwareRule(state, "CODEX.EXE", DomainRouteMode.UseWireGuard, true, "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\resources\\codex.exe");
        var duplicateAdded = SoftwareRuleMutations.TryAddSoftwareRule(state, "codex.exe", DomainRouteMode.UseWireGuard, true, "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\Codex.exe");

        mainAdded.Should().BeTrue();
        resourceAdded.Should().BeTrue();
        duplicateAdded.Should().BeFalse();
        state.SoftwareRules.Should().HaveCount(2);
        state.SoftwareRules!.Select(rule => rule.ExecutablePath).Should().Equal(
            "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\Codex.exe",
            "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\resources\\codex.exe");
    }

    [Fact]
    public void TryAddSoftwareRule_WithoutExecutablePathKeepsProcessNameUnique()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
            [new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\Codex.exe")],
            DomainRouteMode.BypassWireGuard,
            DomainRouteMode.BypassWireGuard);

        var added = SoftwareRuleMutations.TryAddSoftwareRule(state, "codex.exe");

        added.Should().BeFalse();
        state.SoftwareRules.Should().ContainSingle();
    }

    [Fact]
    public void TrySetEnabled_UpdatesExistingRule()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
            [new SoftwareRule("steam.exe", true, DomainRouteMode.UseWireGuard, true, "C:\\Program Files (x86)\\Steam\\steam.exe")],
            DomainRouteMode.BypassWireGuard,
            DomainRouteMode.BypassWireGuard);

        var changed = SoftwareRuleMutations.TrySetEnabled(state, "steam.exe", false);

        changed.Should().BeTrue();
        state.SoftwareRules.Should().NotBeNull();
        state.SoftwareRules!.Single().Enabled.Should().BeFalse();
    }

    [Fact]
    public void TrySetEnabled_WithExecutablePath_TargetsSelectedDuplicateRow()
    {
        var mainPath = "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\Codex.exe";
        var resourcePath = "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\resources\\codex.exe";
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
            [
                new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, mainPath),
                new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, resourcePath)
            ],
            DomainRouteMode.BypassWireGuard,
            DomainRouteMode.BypassWireGuard);

        var changed = SoftwareRuleMutations.TrySetEnabled(state, "codex.exe", resourcePath, false);

        changed.Should().BeTrue();
        state.SoftwareRules![0].Enabled.Should().BeTrue();
        state.SoftwareRules![1].Enabled.Should().BeFalse();
    }

    [Fact]
    public void UpsertSoftwareRulePath_UpdatesStaleExistingPathBeforeAddingDuplicate()
    {
        var oldPath = "C:\\Program Files\\WindowsApps\\OpenAI.Codex_old\\app\\Codex.exe";
        var newPath = "C:\\Program Files\\WindowsApps\\OpenAI.Codex_new\\app\\Codex.exe";
        var state = new AppState([], new Dictionary<string, List<string>>(), [], null, false,
            [new SoftwareRule("codex.exe", true, DomainRouteMode.UseWireGuard, true, oldPath)],
            DomainRouteMode.BypassWireGuard,
            DomainRouteMode.BypassWireGuard);

        var result = SoftwareRuleMutations.UpsertSoftwareRulePath(
            state,
            "codex.exe",
            DomainRouteMode.UseWireGuard,
            includeSubprocesses: true,
            newPath,
            pathExists: path => string.Equals(path, newPath, StringComparison.OrdinalIgnoreCase));

        result.Should().Be(SoftwareRulePathMutationResult.Updated);
        state.SoftwareRules.Should().ContainSingle(rule => rule.ExecutablePath == newPath);
    }
}
