using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WireguardConfigCatalogTests
{
    [Theory]
    [InlineData("C:\\Program Files\\WireGuard\\Data\\Configurations\\home.conf.dpapi", "home")]
    [InlineData("D:\\vpn\\office.conf", "office")]
    [InlineData("D:\\vpn\\custom-name", "custom-name")]
    public void GetTunnelName_ReturnsExpected(string path, string expected)
    {
        WireguardConfigCatalog.GetTunnelName(path).Should().Be(expected);
    }

    [Fact]
    public void BuildInstallTunnelArgs_QuotesPath()
    {
        var path = "C:\\Program Files\\WireGuard\\Data\\Configurations\\home.conf.dpapi";

        WireguardConfigCatalog.BuildInstallTunnelArgs(path)
            .Should().Be("/installtunnelservice \"C:\\Program Files\\WireGuard\\Data\\Configurations\\home.conf.dpapi\"");
    }

    [Fact]
    public void DefaultConfigDirectories_ContainsNordPath()
    {
        WireguardConfigCatalog.DefaultConfigDirectories
            .Should().Contain("C:\\wireguard nord\\");
    }

    [Fact]
    public void DiscoverConfigPaths_FindsConfAndDpapi()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"wg-catalog-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            File.WriteAllText(Path.Combine(tempDir, "one.conf"), "dummy");
            File.WriteAllText(Path.Combine(tempDir, "two.conf.dpapi"), "dummy");
            File.WriteAllText(Path.Combine(tempDir, "ignore.txt"), "dummy");

            var paths = WireguardConfigCatalog.DiscoverConfigPaths([tempDir]);

            paths.Should().HaveCount(2);
            paths.Should().OnlyContain(path =>
                path.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".conf.dpapi", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
