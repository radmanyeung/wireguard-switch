using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RouteDiffEngineTests
{
    [Fact]
    public void Calculate_ReturnsCaseInsensitiveSetDiff()
    {
        var result = RouteDiffEngine.Calculate(
            oldIps: ["10.0.0.1", "192.168.1.1", "172.16.0.1"],
            newIps: ["10.0.0.1", "192.168.1.2", "172.16.0.1"]);

        result.ToAdd.Should().BeEquivalentTo(["192.168.1.2"]);
        result.ToRemove.Should().BeEquivalentTo(["192.168.1.1"]);
    }

    [Fact]
    public void Calculate_DeduplicatesAndTreatsDifferentCasingAsTheSameIp()
    {
        var result = RouteDiffEngine.Calculate(
            oldIps: ["FE80::1", "10.0.0.1"],
            newIps: ["fe80::1", "10.0.0.2", "10.0.0.2"]);

        result.ToAdd.Should().BeEquivalentTo(["10.0.0.2"]);
        result.ToRemove.Should().BeEquivalentTo(["10.0.0.1"]);
    }
}
