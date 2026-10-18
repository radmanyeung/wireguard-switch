using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
namespace WireguardSplitTunnel.Core.Services;

// IP Helper operates on an exact route key; never shells out to wildcard `route delete`.
[SupportedOSPlatform("windows")]
public sealed class WindowsSoftwareRouteWriter : ISoftwareRouteWriter
{
    public Task<SoftwareOwnedRoute?> ReadExactAsync(SoftwareOwnedRoute route, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var row = Row(route); var status = GetIpForwardEntry2(ref row);
        if (status == 1168) return Task.FromResult<SoftwareOwnedRoute?>(null);
        if (status != 0) throw new Win32Exception((int)status, "Exact route lookup failed");
        return Task.FromResult<SoftwareOwnedRoute?>(route with { Metric = checked((int)row.Metric) });
    }
    public Task<bool> EnsureAsync(SoftwareOwnedRoute route, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var row = Row(route); var status = GetIpForwardEntry2(ref row);
        if (status == 0) return Task.FromResult(false);
        if (status != 1168) throw new Win32Exception((int)status, "Route lookup failed");
        row = Row(route); status = CreateIpForwardEntry2(ref row);
        if (status == 5010) return Task.FromResult(false); // Another owner won the race; do not adopt.
        if (status != 0) throw new Win32Exception((int)status, "Software host route creation failed");
        // CreateIpForwardEntry2 confirms installation synchronously. Do not throw on cancellation
        // after creation: the caller must journal the newly acquired cleanup responsibility.
        return Task.FromResult(true);
    }
    public Task DeleteAsync(SoftwareOwnedRoute route, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var row = Row(route); var status = GetIpForwardEntry2(ref row);
        if (status == 1168) return Task.CompletedTask;
        if (status != 0) throw new Win32Exception((int)status, "Software host route lookup failed");
        if (row.Metric != route.Metric) return Task.CompletedTask; // Replaced by another owner.
        status = DeleteIpForwardEntry2(ref row);
        if (status is not (0 or 1168)) throw new Win32Exception((int)status, "Software host route deletion failed");
        return Task.CompletedTask;
    }
    private static ForwardRow Row(SoftwareOwnedRoute route)
    {
        if (!IPAddress.TryParse(route.IpAddress, out var address) || address.AddressFamily != AddressFamily.InterNetwork
            || !IPAddress.TryParse(route.NextHop, out var hop) || hop.AddressFamily != AddressFamily.InterNetwork
            || route.InterfaceIndex <= 0 || route.Metric < 0) throw new ArgumentException("Invalid exact IPv4 route");
        var row = new ForwardRow(); InitializeIpForwardEntry(ref row);
        row.InterfaceIndex = (uint)route.InterfaceIndex; row.DestinationFamily = row.NextHopFamily = 2;
        row.DestinationAddress = BitConverter.ToUInt32(address.GetAddressBytes());
        row.NextHopAddress = BitConverter.ToUInt32(hop.GetAddressBytes());
        row.PrefixLength = 32; row.Metric = (uint)route.Metric; row.Protocol = 3; // MIB_IPPROTO_NETMGMT
        return row;
    }
    [StructLayout(LayoutKind.Explicit, Size = 104)] private struct ForwardRow
    {
        [FieldOffset(0)] public ulong InterfaceLuid;
        [FieldOffset(8)] public uint InterfaceIndex;
        [FieldOffset(12)] public ushort DestinationFamily;
        [FieldOffset(16)] public uint DestinationAddress;
        [FieldOffset(40)] public byte PrefixLength;
        [FieldOffset(44)] public ushort NextHopFamily;
        [FieldOffset(48)] public uint NextHopAddress;
        [FieldOffset(84)] public uint Metric;
        [FieldOffset(88)] public uint Protocol;
    }
    [DllImport("iphlpapi.dll")] private static extern void InitializeIpForwardEntry(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint GetIpForwardEntry2(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint CreateIpForwardEntry2(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint DeleteIpForwardEntry2(ref ForwardRow row);
}
