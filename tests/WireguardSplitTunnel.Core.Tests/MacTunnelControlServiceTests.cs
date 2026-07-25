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
    public void BuildInstallAndStartScript_DoesNotStopUnrelatedActiveTunnels()
    {
        var script = MacTunnelControlService.BuildInstallAndStartScript(
            "/opt/homebrew/bin/wg-quick",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["HK", "JP"]);

        script.Should().NotContain("/opt/homebrew/bin/wg-quick down \"HK\"");
        script.Should().NotContain("/opt/homebrew/bin/wg-quick down \"JP\"");
        script.Should().Contain("/opt/homebrew/bin/wg-quick down \"/opt/homebrew/etc/wireguard/SG.conf\" >/dev/null 2>&1 || true");
        script.Should().Contain("/opt/homebrew/bin/wg-quick up \"/opt/homebrew/etc/wireguard/SG.conf\"");
        script.IndexOf("down \"/opt/homebrew/etc/wireguard/SG.conf\"", StringComparison.Ordinal)
            .Should().BeLessThan(script.IndexOf("up \"/opt/homebrew/etc/wireguard/SG.conf\"", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildInstallAndStartScript_MakesOnlySelectedMappingReadableAfterUp()
    {
        var script = MacTunnelControlService.BuildInstallAndStartScript(
            "/opt/homebrew/bin/wg-quick",
            "/opt/homebrew/etc/wireguard/SG $prod.conf",
            ["HK", "JP"]);

        const string up =
            "/opt/homebrew/bin/wg-quick up \"/opt/homebrew/etc/wireguard/SG \\$prod.conf\"";
        const string chmod =
            "/bin/chmod 0644 \"/var/run/wireguard/SG \\$prod.name\"";

        script.Should().Contain(chmod + Environment.NewLine);
        script.Should().NotContain(chmod + " || true");
        script.IndexOf(up, StringComparison.Ordinal)
            .Should().BeLessThan(script.IndexOf(chmod, StringComparison.Ordinal));
        script.Should().NotContain("/var/run/wireguard/HK.name");
        script.Should().NotContain("/var/run/wireguard/JP.name");
    }

    [Fact]
    public void BuildInstallAndStartScript_DurablyCapturesDnsImmediatelyBeforeUp()
    {
        const string journalPath =
            "/Users/u/Application Support/WireguardSplitTunnel/.wgst-dns-journal-0123456789abcdef0123456789abcdef.v1";
        var script = MacTunnelControlService.BuildInstallAndStartScript(
            "/opt/homebrew/bin/wg-quick",
            "/opt/homebrew/etc/wireguard/SG.conf",
            [],
            journalPath);

        var down = script.IndexOf("wg-quick down", StringComparison.Ordinal);
        var capture = script.IndexOf("networksetup -listallnetworkservices", StringComparison.Ordinal);
        var publish = script.IndexOf("/bin/mv -f", StringComparison.Ordinal);
        var sync = script.IndexOf("/bin/sync", StringComparison.Ordinal);
        var up = script.IndexOf("wg-quick up", StringComparison.Ordinal);

        down.Should().BeLessThan(capture);
        capture.Should().BeLessThan(publish);
        publish.Should().BeLessThan(sync);
        sync.Should().BeLessThan(up);
    }

    [Fact]
    public void BuildStopScript_MaliciousBareTunnelName_RejectsBeforeElevation()
    {
        var act = () => MacTunnelControlService.BuildStopScript(
            "/opt/homebrew/bin/wg-quick",
            "x\"; /usr/bin/touch /tmp/pwned; #");

        act.Should().Throw<ArgumentException>()
            .WithMessage("*valid WireGuard interface name*");
    }

    [Fact]
    public void BuildStopScript_SelectedConfigPathWithShellMetacharacters_QuotesWholePath()
    {
        const string configPath = "/tmp/x\"; /usr/bin/touch /tmp/pwned; #.conf";

        var script = MacTunnelControlService.BuildStopScript(
            "/opt/homebrew/bin/wg-quick",
            configPath);

        script.Should().Be(
            "\"/opt/homebrew/bin/wg-quick\" down \"/tmp/x\\\"; /usr/bin/touch /tmp/pwned; #.conf\"");
        script.Split('\n', StringSplitOptions.RemoveEmptyEntries).Should().ContainSingle();
    }
}
