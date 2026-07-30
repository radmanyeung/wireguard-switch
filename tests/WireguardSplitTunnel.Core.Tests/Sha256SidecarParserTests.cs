using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class Sha256SidecarParserTests
{
    private const string Digest = "0123456789aBcDeF0123456789aBcDeF0123456789aBcDeF0123456789aBcDeF";
    private static readonly string Valid = $"{Digest}  {UpdateReleaseContract.WindowsAssetName}";

    [Theory]
    [InlineData("")]
    [InlineData("A1")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF001122334455667z  wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677 wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677   wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677\twireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  *wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  WIREGUARD-SPLIT-TUNNEL-WIN-X64.ZIP")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  path/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip.bak")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip\nextra")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip\r")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip\0")]
    public void Parse_StringRejectsMalformedContentWithoutThrowing(string value)
    {
        var action = () => Sha256SidecarParser.Parse(value);

        action.Should().NotThrow();
        var result = Sha256SidecarParser.Parse(value);
        result.Success.Should().BeFalse();
        result.ErrorCode.Should().NotBe(Sha256SidecarParseError.None);
        result.ErrorMessage.Should().NotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("")]
    [InlineData("\uFEFFA1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip")]
    [InlineData("A1b2C3d4E5f60718293a4B5c6D7e8F90123456789aBcDeF0011223344556677  wireguard-split-tunnel-win-x64.zip\n\n")]
    public void Parse_StringRejectsForbiddenTerminatorsOrBom(string value)
    {
        var result = Sha256SidecarParser.Parse(value);

        result.Success.Should().BeFalse();
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public void Parse_AcceptsTheExactSidecarWithAllowedFinalTerminator(string terminator)
    {
        var result = Sha256SidecarParser.Parse(Valid + terminator);

        result.Success.Should().BeTrue();
        result.Digest.Should().Be(Digest.ToLowerInvariant());
        result.ErrorCode.Should().Be(Sha256SidecarParseError.None);
        result.ErrorMessage.Should().BeNull();
    }

    [Fact]
    public void Parse_NullStringReturnsTypedFailure()
    {
        var result = Sha256SidecarParser.Parse((string?)null);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(Sha256SidecarParseError.NullInput);
    }

    [Fact]
    public void Parse_BytesRejectsBomAndInvalidUtf8WithoutThrowing()
    {
        var bom = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(Valid)).ToArray();
        var invalidUtf8 = new byte[] { 0xC3, 0x28 };

        var bomAction = () => Sha256SidecarParser.Parse(bom);
        var invalidAction = () => Sha256SidecarParser.Parse(invalidUtf8);

        bomAction.Should().NotThrow();
        invalidAction.Should().NotThrow();
        bomAction().ErrorCode.Should().Be(Sha256SidecarParseError.Utf8Bom);
        invalidAction().ErrorCode.Should().Be(Sha256SidecarParseError.InvalidUtf8);
    }

    [Fact]
    public void Parse_BytesRejectsInputOverConfiguredLimitBeforeParsing()
    {
        var bytes = new byte[checked((int)UpdateNetworkLimits.ChecksumBytes + 1)];

        var result = Sha256SidecarParser.Parse(bytes);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(Sha256SidecarParseError.TooLarge);
    }

    [Fact]
    public void Parse_StringUsesStrictUtf8ByteLimitAndRejectsUnpairedSurrogates()
    {
        var byteOverflow = new string('é', checked((int)UpdateNetworkLimits.ChecksumBytes / 2) + 1);
        var unpaired = "checksum\uD800";

        Sha256SidecarParser.Parse(byteOverflow).ErrorCode.Should().Be(Sha256SidecarParseError.TooLarge);
        Sha256SidecarParser.Parse(unpaired).ErrorCode.Should().Be(Sha256SidecarParseError.InvalidUtf8);
    }
}
