using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WireguardAllowedIpsSanitizerTests
{
    [Theory]
    // Full-range IPv4 triggers the WireGuard Windows kill switch: must become the /1 pair.
    [InlineData("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1", true)]
    [InlineData("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1", true)]
    [InlineData("allowedips=0.0.0.0/0", "allowedips= 0.0.0.0/1, 128.0.0.0/1", true)]
    // IPv6 entries are dropped because route management is IPv4-only.
    [InlineData("AllowedIPs = 10.0.0.0/8, ::/0", "AllowedIPs = 10.0.0.0/8", true)]
    // Already sanitized or IPv4-only configs pass through untouched.
    [InlineData("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1", "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1", false)]
    [InlineData("AllowedIPs = 104.18.32.47/32, 172.64.155.209/32", "AllowedIPs = 104.18.32.47/32, 172.64.155.209/32", false)]
    // IPv6-only configs are left alone: dropping every entry would break the peer.
    [InlineData("AllowedIPs = ::/0", "AllowedIPs = ::/0", false)]
    // Non-AllowedIPs lines are never touched.
    [InlineData("PrivateKey = AAAA", "PrivateKey = AAAA", false)]
    [InlineData("# AllowedIPs = 0.0.0.0/0", "# AllowedIPs = 0.0.0.0/0", false)]
    public void SanitizeText_AllowedIpsLine_ReturnsExpected(
        string input,
        string expected,
        bool expectedChanged)
    {
        var result = WireguardAllowedIpsSanitizer.SanitizeText(input);

        result.Changed.Should().Be(expectedChanged);
        result.Text.Should().Be(expected);
    }

    [Fact]
    public void SanitizeText_MixedEntries_KeepsIpv4AndSplitsFullRange()
    {
        var result = WireguardAllowedIpsSanitizer.SanitizeText(
            "AllowedIPs = 10.0.0.0/8, 0.0.0.0/0, ::/0, 192.168.0.0/16");

        result.Changed.Should().BeTrue();
        result.Text.Should().Be("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, 10.0.0.0/8, 192.168.0.0/16");
    }

    [Fact]
    public void SanitizeText_FullConfig_RewritesOnlyAllowedIpsAndPreservesOtherLines()
    {
        var config =
            "[Interface]\n" +
            "PrivateKey = KEY123\n" +
            "Address = 10.5.0.2/32\n" +
            "DNS = 103.86.96.100\n" +
            "\n" +
            "[Peer]\n" +
            "PublicKey = PUB456\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\n" +
            "Endpoint = us9973.nordvpn.com:51820\n";

        var result = WireguardAllowedIpsSanitizer.SanitizeText(config);

        result.Changed.Should().BeTrue();
        result.Text.Should().Contain("PrivateKey = KEY123");
        result.Text.Should().Contain("PublicKey = PUB456");
        result.Text.Should().Contain("Endpoint = us9973.nordvpn.com:51820");
        result.Text.Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1");
        result.Text.Should().NotContain("0.0.0.0/0");
        result.Text.Should().NotContain("::/0");
    }

    [Fact]
    public void EnsureSanitizedConfigFile_UnchangedConfig_ReturnsSourcePath()
    {
        var directory = CreateTempDirectory();
        var source = Path.Combine(directory, "safe.conf");
        File.WriteAllText(source, "AllowedIPs = 10.0.0.0/8\n");

        var result = WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            source,
            Path.Combine(directory, "derived"));

        result.Should().Be(source);
        Directory.Exists(Path.Combine(directory, "derived")).Should().BeFalse();
    }

    [Fact]
    public void EnsureSanitizedConfigFile_KillSwitchConfig_WritesDerivedCopyWithSameFileName()
    {
        var directory = CreateTempDirectory();
        var source = Path.Combine(directory, "nordusa1.conf");
        File.WriteAllText(
            source,
            "[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = example.com:51820\n");

        var derivedDir = Path.Combine(directory, "derived");
        var result = WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(source, derivedDir);

        result.Should().Be(Path.Combine(derivedDir, "nordusa1.conf"));
        WireguardConfigCatalog.GetTunnelName(result)
            .Should().Be(WireguardConfigCatalog.GetTunnelName(source));

        var derivedText = File.ReadAllText(result);
        derivedText.Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1");
        File.ReadAllText(source).Should().Contain("0.0.0.0/0",
            "the user's original config file must never be modified");
    }

    [Fact]
    public void EnsureSanitizedConfigFile_DpapiConfig_PassesThrough()
    {
        var result = WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            @"C:\somewhere\tunnel.conf.dpapi",
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")));

        result.Should().Be(@"C:\somewhere\tunnel.conf.dpapi");
    }

    [Fact]
    public void EnsureSanitizedConfigFile_MissingFile_PassesThrough()
    {
        var missing = Path.Combine(CreateTempDirectory(), "missing.conf");

        WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(missing, CreateTempDirectory())
            .Should().Be(missing);
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "wgst-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
