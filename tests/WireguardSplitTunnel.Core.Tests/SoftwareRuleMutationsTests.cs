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
        var second = SoftwareRuleMutations.TryAddSoftwareRule(state, "CHROME.EXE", DomainRouteMode.BypassWireGuard, false, "C:\\Other\\chrome.exe");

        first.Should().BeTrue();
        second.Should().BeFalse();
        state.SoftwareRules.Should().ContainSingle(rule =>
            rule.ProcessName == "chrome.exe"
            && rule.Mode == DomainRouteMode.UseWireGuard
            && rule.IncludeSubprocesses
            && rule.ExecutablePath == "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
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
}
