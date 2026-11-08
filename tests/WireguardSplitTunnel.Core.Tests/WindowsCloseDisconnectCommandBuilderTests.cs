using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsCloseDisconnectCommandBuilderTests
{
    private const string ExePath = "C:\\Program Files\\WireGuard\\wireguard.exe";

    [Fact]
    public void FromServiceName_PreservesServiceAndTunnelCasing()
    {
        var identity = WindowsTunnelServiceIdentity.FromServiceName("wireguardtunnel$SG");

        identity.ServiceName.Should().Be("wireguardtunnel$SG");
        identity.TunnelName.Should().Be("SG");
    }

    [Fact]
    public void FromTunnelName_ConstructsExactServiceIdentity()
    {
        var identity = WindowsTunnelServiceIdentity.FromTunnelName("Site_1=A+B.c-d");

        identity.ServiceName.Should().Be("WireGuardTunnel$Site_1=A+B.c-d");
        identity.TunnelName.Should().Be("Site_1=A+B.c-d");
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("bad tunnel")]
    [InlineData("bad\ttunnel")]
    [InlineData("bad\ntunnel")]
    [InlineData("bad\" & calc")]
    [InlineData("bad'tunnel")]
    [InlineData("bad;tunnel")]
    [InlineData("bad&tunnel")]
    [InlineData("bad|tunnel")]
    [InlineData("bad<tunnel")]
    [InlineData("bad>tunnel")]
    [InlineData("bad$tunnel")]
    [InlineData("bad`tunnel")]
    [InlineData("bad!tunnel")]
    [InlineData("bad*tunnel")]
    [InlineData("bad/tunnel")]
    [InlineData("bad\\tunnel")]
    [InlineData("bad:tunnel")]
    [InlineData("tünnel")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../SG")]
    public void FromTunnelName_RejectsMalformedSuffixes(string tunnelName)
    {
        var parse = () => WindowsTunnelServiceIdentity.FromTunnelName(tunnelName);

        parse.Should().Throw<ArgumentException>();
        WindowsTunnelServiceIdentity.IsValidTunnelName(tunnelName).Should().BeFalse();
    }

    [Theory]
    [InlineData("WireGuardTunnelSG")]
    [InlineData("XWireGuardTunnel$SG")]
    [InlineData(" WireGuardTunnel$SG")]
    [InlineData("WireGuardTunnel$")]
    [InlineData("WireGuardTunnel$bad\" & calc")]
    public void FromServiceName_RequiresExactPrefixAndValidSuffix(string serviceName)
    {
        var parse = () => WindowsTunnelServiceIdentity.FromServiceName(serviceName);

        parse.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ParseInstalledServiceIdentities_IncludesAppAndExternalTunnelsAndDedupesCaseInsensitively()
    {
        var identities = WindowsTunnelServiceDiscovery.ParseInstalledServiceIdentities(
        [
            "WireGuardTunnel$SG",
            "WireGuardTunnel$external",
            "wireguardtunnel$sg",
            "Schedule",
            "WpnService",
            "NotWireGuardTunnel$TW"
        ]);

        identities.Select(identity => identity.ServiceName).Should().Equal(
            "WireGuardTunnel$external",
            "WireGuardTunnel$SG");
        identities.Select(identity => identity.TunnelName).Should().Equal("external", "SG");
    }

    [Fact]
    public void ParseInstalledServiceIdentities_RejectsMalformedSuffixBeforeCommandCreation()
    {
        var parse = () => WindowsTunnelServiceDiscovery.ParseInstalledServiceIdentities(
        [
            "WireGuardTunnel$SG",
            "WireGuardTunnel$bad\" & calc"
        ]);

        parse.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void RegistryEnumerator_ImplementsServiceEnumerationBoundary()
    {
        typeof(IWindowsTunnelServiceEnumerator)
            .IsAssignableFrom(typeof(RegistryWindowsTunnelServiceEnumerator))
            .Should().BeTrue();
    }

    [Fact]
    public void BuildArguments_NoTargets_ReturnsEmpty()
    {
        WindowsCloseDisconnectCommandBuilder.BuildArguments(ExePath, []).Should().BeEmpty();
    }

    [Fact]
    public void BuildArguments_UsesExactNonShortCircuitCommandsForEveryTargetAndRetainsFailure()
    {
        var args = WindowsCloseDisconnectCommandBuilder.BuildArguments(
            ExePath,
            [
                WindowsTunnelServiceIdentity.FromServiceName("WireGuardTunnel$SG"),
                WindowsTunnelServiceIdentity.FromTunnelName("external"),
                WindowsTunnelServiceIdentity.FromTunnelName("TW")
            ]);

        args.Should().Be(
            "set \"__WST_CLOSE_DISCONNECT_FAILED=\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"external\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"SG\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"TW\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & if defined __WST_CLOSE_DISCONNECT_FAILED exit /b 1");
        args.Should().NotContain("&&");
        args.Should().NotContain("sc ");
        args.Should().NotContain("powershell", because: "targets must not be enumerated by a shell");
        args.Should().NotContain("%__WST_CLOSE_DISCONNECT_FAILED%", because: "the flag must be read when each command executes");
    }

    [Fact]
    public void BuildArguments_FirstFailureLastSuccess_AttemptsBothAndReturnsAggregateFailure()
    {
        var args = WindowsCloseDisconnectCommandBuilder.BuildArguments(
            ExePath,
            [
                WindowsTunnelServiceIdentity.FromTunnelName("SG"),
                WindowsTunnelServiceIdentity.FromTunnelName("TW")
            ]);
        var segments = args.Split(" & ", StringSplitOptions.None);
        var exitCodes = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["\"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"SG\""] = 1,
            ["\"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"TW\""] = 0
        };

        segments.Should().HaveCount(4);
        segments[0].Should().Be("set \"__WST_CLOSE_DISCONNECT_FAILED=\"");
        segments[3].Should().Be("if defined __WST_CLOSE_DISCONNECT_FAILED exit /b 1");

        var failed = false;
        var attempted = new List<string>();
        foreach (var segment in segments.Skip(1).Take(2))
        {
            const string failureMarker = " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\"";
            segment.Should().EndWith(failureMarker);
            var command = segment[..^failureMarker.Length];
            exitCodes.Should().ContainKey(command);
            attempted.Add(command);
            if (exitCodes[command] != 0) failed = true;
        }

        attempted.Should().Equal(exitCodes.Keys);
        failed.Should().BeTrue("the last successful uninstall must not clear the earlier failure");
    }

    [Fact]
    public void BuildArguments_DedupesCaseInsensitivelyAndPreservesFirstCasing()
    {
        var args = WindowsCloseDisconnectCommandBuilder.BuildArguments(
            ExePath,
            [
                WindowsTunnelServiceIdentity.FromServiceName("WireGuardTunnel$SG"),
                WindowsTunnelServiceIdentity.FromServiceName("wireguardtunnel$sg")
            ]);

        args.Should().Be(
            "set \"__WST_CLOSE_DISCONNECT_FAILED=\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"SG\""
            + " || set \"__WST_CLOSE_DISCONNECT_FAILED=1\""
            + " & if defined __WST_CLOSE_DISCONNECT_FAILED exit /b 1");
    }
}
