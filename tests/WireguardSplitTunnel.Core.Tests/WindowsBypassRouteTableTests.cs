using System.Net.NetworkInformation;
using System.Net.Sockets;
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsBypassRouteTableTests
{
    [Fact]
    public void ReadMetric_ReadsTheExistingPhysicalDefaultWithoutChangingIt()
    {
        if (!OperatingSystem.IsWindows()) return;
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            n.OperationalStatus == OperationalStatus.Up && n.Supports(NetworkInterfaceComponent.IPv4)
            && n.GetIPProperties().GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0"));
        if (adapter is null) return;
        var gateway = adapter.GetIPProperties().GatewayAddresses.First(g =>
            g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0");
        var route = new BypassRouteKey("0.0.0.0", 0,
            adapter.GetIPProperties().GetIPv4Properties()!.Index, adapter.Id, gateway.Address.ToString());

        var table = new WindowsBypassRouteTable();
        var metric = table.ReadMetric(route);

        metric.Should().NotBeNull("the known physical gateway has a default route");
        table.ReadMetric(route).Should().Be(metric);
        table.ReadMetric(route with { InterfaceId = Guid.NewGuid().ToString() }).Should().BeNull();
    }

    [Fact]
    public void ReadMetric_RejectsAHostRouteInCleanupMetadata()
    {
        if (!OperatingSystem.IsWindows()) return;
        Action read = () =>
        {
            if (OperatingSystem.IsWindows())
                new WindowsBypassRouteTable().ReadMetric(
                    new("8.8.8.8", 32, 27, "adapter", "192.168.68.253"));
        };
        read.Should().Throw<ArgumentException>();
    }
}
