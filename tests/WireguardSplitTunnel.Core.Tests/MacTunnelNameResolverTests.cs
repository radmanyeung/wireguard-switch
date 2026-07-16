using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacTunnelNameResolverTests
{
    [Theory]
    [InlineData("utun4", "utun4")]
    [InlineData("utun12\n", "utun12")]
    [InlineData("  utun0  ", "utun0")]
    public void ParseUtunName_ValidContent_ReturnsTrimmedName(string content, string expected)
    {
        MacTunnelNameResolver.ParseUtunName(content).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n")]
    [InlineData("utun")]
    [InlineData("utunX")]
    [InlineData("en0")]
    [InlineData("utun4; rm -rf /")]
    public void ParseUtunName_InvalidContent_ReturnsNull(string content)
    {
        MacTunnelNameResolver.ParseUtunName(content).Should().BeNull();
    }

    [Fact]
    public void ChooseUnambiguousSocketInterface_SingleSocket_ReturnsItsName()
    {
        MacTunnelNameResolver.ChooseUnambiguousSocketInterface(["/var/run/wireguard/utun4.sock"])
            .Should().Be("utun4");
    }

    [Fact]
    public void ChooseUnambiguousSocketInterface_MultipleSockets_ReturnsNull()
    {
        MacTunnelNameResolver.ChooseUnambiguousSocketInterface(
            ["/var/run/wireguard/utun4.sock", "/var/run/wireguard/utun7.sock"])
            .Should().BeNull();
    }

    [Fact]
    public void ChooseUnambiguousSocketInterface_NoSockets_ReturnsNull()
    {
        MacTunnelNameResolver.ChooseUnambiguousSocketInterface([]).Should().BeNull();
    }

    [Fact]
    public void ChooseUnambiguousSocketInterface_IgnoresNonUtunSockets()
    {
        MacTunnelNameResolver.ChooseUnambiguousSocketInterface(
            ["/var/run/wireguard/other.sock", "/var/run/wireguard/utun9.sock"])
            .Should().Be("utun9");
    }

    [Fact]
    public void GetExactMappingPresence_ExistingEntry_ReturnsPresentForExactName()
    {
        string? inspectedPath = null;

        var result = MacTunnelNameResolver.GetExactMappingPresence(
            "SG",
            path =>
            {
                inspectedPath = path;
                return FileAttributes.Normal;
            });

        result.Should().Be(MacTunnelMappingPresence.Present);
        inspectedPath.Should().Be("/var/run/wireguard/SG.name");
    }

    [Fact]
    public void GetExactMappingPresence_MissingEntry_ReturnsAbsent()
    {
        var result = MacTunnelNameResolver.GetExactMappingPresence(
            "SG",
            _ => throw new FileNotFoundException());

        result.Should().Be(MacTunnelMappingPresence.Absent);
    }

    [Fact]
    public void GetExactMappingPresence_UnreadableMetadata_ReturnsUnknown()
    {
        var result = MacTunnelNameResolver.GetExactMappingPresence(
            "SG",
            _ => throw new UnauthorizedAccessException());

        result.Should().Be(MacTunnelMappingPresence.Unknown);
    }
}
