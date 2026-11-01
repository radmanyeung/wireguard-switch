using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

[SupportedOSPlatform("windows")]
public sealed class WindowsBypassRouteTable : IBypassRouteTable
{
    public int? ReadMetric(BypassRouteKey route)
    {
        var row = Row(route);
        if (!InterfaceStillMatches(route)) return null;
        var status = GetIpForwardEntry2(ref row);
        if (status == 1168) return null;
        Check(status, "read");
        return checked((int)row.Metric);
    }

    public void SetMetric(BypassRouteKey route, int metric)
    {
        if (metric < 0) throw new ArgumentOutOfRangeException(nameof(metric));
        var row = Row(route);
        if (!InterfaceStillMatches(route))
            throw new InvalidOperationException("The bypass adapter changed before route apply.");
        var status = GetIpForwardEntry2(ref row);
        var create = status == 1168;
        if (!create) Check(status, "read before update");
        row.Metric = (uint)metric;
        Check(create ? CreateIpForwardEntry2(ref row) : SetIpForwardEntry2(ref row), "update");
    }

    public void Delete(BypassRouteKey route)
    {
        var row = Row(route);
        if (!InterfaceStillMatches(route)) return;
        var status = GetIpForwardEntry2(ref row);
        if (status == 1168) return;
        Check(status, "read before delete");
        Check(DeleteIpForwardEntry2(ref row), "delete", allowMissing: true);
    }

    private static bool InterfaceStillMatches(BypassRouteKey route) =>
        NetworkInterface.GetAllNetworkInterfaces().Any(n =>
            string.Equals(n.Id, route.InterfaceId, StringComparison.OrdinalIgnoreCase)
            && n.GetIPProperties().GetIPv4Properties()?.Index == route.InterfaceIndex);

    private static ForwardRow Row(BypassRouteKey route)
    {
        if (route.InterfaceIndex <= 0 || string.IsNullOrWhiteSpace(route.InterfaceId)
            || !((route.PrefixLength == 0 && route.Destination == "0.0.0.0")
                || (route.PrefixLength == 1 && route.Destination is "0.0.0.0" or "128.0.0.0"))
            || !IPAddress.TryParse(route.Gateway, out var gateway)
            || gateway.AddressFamily != AddressFamily.InterNetwork || gateway.Equals(IPAddress.Any))
            throw new ArgumentException("Invalid bypass default route.");
        var row = new ForwardRow();
        InitializeIpForwardEntry(ref row);
        row.InterfaceIndex = (uint)route.InterfaceIndex;
        row.DestinationFamily = row.NextHopFamily = 2;
        row.DestinationAddress = BitConverter.ToUInt32(IPAddress.Parse(route.Destination).GetAddressBytes());
        row.NextHopAddress = BitConverter.ToUInt32(gateway.GetAddressBytes());
        row.PrefixLength = (byte)route.PrefixLength;
        row.Protocol = 3;
        return row;
    }

    private static void Check(uint status, string action, bool allowMissing = false)
    {
        if (status != 0 && !(allowMissing && status == 1168))
            throw new Win32Exception((int)status, $"Bypass route {action} failed");
    }

    [StructLayout(LayoutKind.Explicit, Size = 104)]
    private struct ForwardRow
    {
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
    [DllImport("iphlpapi.dll")] private static extern uint SetIpForwardEntry2(ref ForwardRow row);
    [DllImport("iphlpapi.dll")] private static extern uint DeleteIpForwardEntry2(ref ForwardRow row);
}
