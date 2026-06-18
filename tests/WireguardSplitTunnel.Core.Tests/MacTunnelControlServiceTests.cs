using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Interoperability",
    "CA1416:Validate platform compatibility",
    Justification = "These tests exercise platform-neutral macOS script composition helpers without executing macOS commands.")]
public sealed class MacTunnelControlServiceTests
{
    [Fact]
    public void DiscoverActiveTunnelNamesFromRunEntries_UsesNameFileBaseNames()
    {
        var names = MacTunnelControlService.DiscoverActiveTunnelNamesFromRunEntries(
            [
                "/var/run/wireguard/HK.name",
                "/var/run/wireguard/JP.name",
                "/var/run/wireguard/utun4.sock",
                "/var/run/wireguard/readme.txt"
            ]);

        names.Should().Equal("HK", "JP");
    }

    [Fact]
    public void BuildInstallAndStartScript_DownsActiveTunnelsBeforeStartingSelectedConfig()
    {
        var script = MacTunnelControlService.BuildInstallAndStartScript(
            "/opt/homebrew/bin/wg-quick",
            "/opt/homebrew/etc/wireguard/US.conf",
            ["HK", "JP"]);

        script.Should().Contain("/opt/homebrew/bin/wg-quick down \"HK\" >/dev/null 2>&1 || true");
        script.Should().Contain("/opt/homebrew/bin/wg-quick down \"JP\" >/dev/null 2>&1 || true");
        script.Should().Contain("/opt/homebrew/bin/wg-quick down \"/opt/homebrew/etc/wireguard/US.conf\" >/dev/null 2>&1 || true");
        script.Should().Contain("/opt/homebrew/bin/wg-quick up \"/opt/homebrew/etc/wireguard/US.conf\"");
        script.IndexOf("down \"HK\"", StringComparison.Ordinal)
            .Should().BeLessThan(script.IndexOf("up \"/opt/homebrew/etc/wireguard/US.conf\"", StringComparison.Ordinal));
        script.IndexOf("down \"JP\"", StringComparison.Ordinal)
            .Should().BeLessThan(script.IndexOf("up \"/opt/homebrew/etc/wireguard/US.conf\"", StringComparison.Ordinal));
    }
}
