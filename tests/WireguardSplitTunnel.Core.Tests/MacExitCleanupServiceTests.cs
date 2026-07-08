using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacExitCleanupServiceTests
{
    private const string WgQuick = "/opt/homebrew/bin/wg-quick";

    [Fact]
    public void BuildCleanupScript_AllInputs_EmitsDownsThenRouteDeletesThenDnsResets()
    {
        var script = MacExitCleanupService.BuildCleanupScript(
            WgQuick,
            "/data/wgst-split.conf",
            "SG",
            ["1.2.3.4", "5.6.7.8"],
            ["Wi-Fi"]);

        var lines = script.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        lines.Should().HaveCount(5);
        lines[0].Should().Be($"{WgQuick} down \"/data/wgst-split.conf\" >/dev/null 2>&1 || true");
        lines[1].Should().Be($"{WgQuick} down \"SG\" >/dev/null 2>&1 || true");
        lines[2].Should().Be("/sbin/route -n delete -host 1.2.3.4 >/dev/null 2>&1 || true");
        lines[3].Should().Be("/sbin/route -n delete -host 5.6.7.8 >/dev/null 2>&1 || true");
        lines[4].Should().Be("/usr/sbin/networksetup -setdnsservers \"Wi-Fi\" Empty");
    }

    [Fact]
    public void BuildCleanupScript_NoInputs_ReturnsEmpty()
    {
        MacExitCleanupService.BuildCleanupScript(WgQuick, null, null, [], [])
            .Should().BeEmpty();
    }

    [Fact]
    public void BuildCleanupScript_NoWgQuick_SkipsTunnelDownsButKeepsRestOfCleanup()
    {
        var script = MacExitCleanupService.BuildCleanupScript(
            null,
            "/data/wgst-split.conf",
            "SG",
            ["1.2.3.4"],
            []);

        script.Should().NotContain("wg-quick");
        script.Should().Contain("/sbin/route -n delete -host 1.2.3.4");
    }

    [Fact]
    public void BuildCleanupScript_QuotesPathsWithSpaces()
    {
        var script = MacExitCleanupService.BuildCleanupScript(
            WgQuick,
            "/Users/u/Application Support/wgst-split.conf",
            null,
            [],
            ["My Service"]);

        script.Should().Contain("down \"/Users/u/Application Support/wgst-split.conf\"");
        script.Should().Contain("-setdnsservers \"My Service\" Empty");
    }
}
