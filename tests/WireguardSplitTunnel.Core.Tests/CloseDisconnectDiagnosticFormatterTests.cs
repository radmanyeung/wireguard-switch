using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class CloseDisconnectDiagnosticFormatterTests
{
    [Fact]
    public void Format_NullResult_ReturnsNoneForBothFields()
    {
        CloseDisconnectDiagnosticFormatter.Format(null).Should().Be(
            "disconnectFailures=None, disconnectUnresolved=None");
    }

    [Fact]
    public void Format_EmptyResult_ReturnsNoneForBothFields()
    {
        var result = new CloseDisconnectResult(true, [], []);

        CloseDisconnectDiagnosticFormatter.Format(result).Should().Be(
            "disconnectFailures=None, disconnectUnresolved=None");
    }

    [Fact]
    public void Format_FailuresAndTargets_PreservesFailureOrderAndNormalizesTargets()
    {
        var result = new CloseDisconnectResult(
            false,
            [
                new CloseDisconnectFailure(CloseDisconnectFailureKind.Stop, "first failure"),
                new CloseDisconnectFailure(CloseDisconnectFailureKind.Verification, "second failure")
            ],
            [Target("external.tunnel-1"), Target("gb"), Target("GB")]);

        CloseDisconnectDiagnosticFormatter.Format(result).Should().Be(
            "disconnectFailures=Stop+Verification, disconnectUnresolved=external.tunnel-1+gb");
    }

    [Fact]
    public void Format_SecretFailureMessage_NeverCrossesDiagnosticBoundary()
    {
        const string secret = "PRIVATE-KEY-MUST-NOT-LOG";
        var result = new CloseDisconnectResult(
            false,
            [new CloseDisconnectFailure(
                CloseDisconnectFailureKind.Stop,
                $"{secret} 192.0.2.1 netsh interface ip show config")],
            [Target("GB")]);

        var formatted = CloseDisconnectDiagnosticFormatter.Format(result);

        formatted.Should().Be("disconnectFailures=Stop, disconnectUnresolved=GB");
        formatted.Should().NotContain(secret);
        formatted.Should().NotContain("192.0.2.1");
        formatted.Should().NotContain("netsh");
        formatted.Should().NotContain("WireGuardTunnel$");
    }

    private static WindowsTunnelServiceIdentity Target(string name) =>
        WindowsTunnelServiceIdentity.FromTunnelName(name);
}
