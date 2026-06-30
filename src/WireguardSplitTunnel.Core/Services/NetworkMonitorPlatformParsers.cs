using System.Net;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class MacLsofTcpConnectionParser
{
    public static IReadOnlyList<NetworkConnection> Parse(string output)
    {
        var connections = new List<NetworkConnection>();
        foreach (var rawLine in output.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            if (!rawLine.Contains("(ESTABLISHED)", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = rawLine.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !int.TryParse(parts[1], out var pid))
            {
                continue;
            }

            var tcpIndex = rawLine.IndexOf(" TCP ", StringComparison.OrdinalIgnoreCase);
            if (tcpIndex < 0)
            {
                continue;
            }

            var tcpText = rawLine[(tcpIndex + 5)..];
            var arrowIndex = tcpText.IndexOf("->", StringComparison.Ordinal);
            if (arrowIndex < 0)
            {
                continue;
            }

            var remoteText = tcpText[(arrowIndex + 2)..]
                .Split([' ', '('], StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (TryParseEndpoint(remoteText, out var address, out var port))
            {
                connections.Add(new NetworkConnection(pid, address, port));
            }
        }

        return connections;
    }

    private static bool TryParseEndpoint(string? endpoint, out IPAddress address, out int port)
    {
        address = IPAddress.None;
        port = 0;

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return false;
        }

        if (endpoint.StartsWith("[", StringComparison.Ordinal))
        {
            var endBracket = endpoint.IndexOf("]:", StringComparison.Ordinal);
            if (endBracket <= 1)
            {
                return false;
            }

            var addressText = endpoint[1..endBracket];
            var portText = endpoint[(endBracket + 2)..];
            return IPAddress.TryParse(addressText, out address!) && int.TryParse(portText, out port);
        }

        var separator = endpoint.LastIndexOf(':');
        if (separator <= 0 || separator == endpoint.Length - 1)
        {
            return false;
        }

        return IPAddress.TryParse(endpoint[..separator], out address!) && int.TryParse(endpoint[(separator + 1)..], out port);
    }
}

public sealed record MacLsofParseResult(
    IReadOnlyList<NetworkConnection> Connections,
    string? Warning);

public static class MacLsofResultParser
{
    public static MacLsofParseResult Parse(int exitCode, string stdout, string stderr)
    {
        var connections = MacLsofTcpConnectionParser.Parse(stdout);
        if (connections.Count > 0)
        {
            return new MacLsofParseResult(connections, null);
        }

        if (exitCode == 0)
        {
            return new MacLsofParseResult(connections, null);
        }

        var warning = string.IsNullOrWhiteSpace(stderr)
            ? "lsof could not read active connections."
            : $"lsof could not read active connections: {stderr.Trim()}";

        return new MacLsofParseResult(connections, warning);
    }
}

public static class MacRouteGetParser
{
    public static string? ParseInterface(string output)
    {
        foreach (var rawLine in output.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith("interface:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = line["interface:".Length..].Trim();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        return null;
    }

    public static NetworkPathKind ClassifyInterface(string? routeInterface, string? wireGuardInterfaceName)
    {
        if (string.IsNullOrWhiteSpace(routeInterface) || string.IsNullOrWhiteSpace(wireGuardInterfaceName))
        {
            return NetworkPathKind.Unknown;
        }

        return string.Equals(routeInterface, wireGuardInterfaceName, StringComparison.OrdinalIgnoreCase)
            ? NetworkPathKind.Vpn
            : NetworkPathKind.Normal;
    }
}

public static class NetworkPingCommandBuilder
{
    public static string BuildVpnArguments(string sourceAddress, bool isMacOs) =>
        isMacOs
            ? $"-S {sourceAddress} -c 1 -W 1000 1.1.1.1"
            : $"-S {sourceAddress} -n 1 -w 1000 1.1.1.1";

    public static string BuildNormalArguments(string targetAddress, bool isMacOs) =>
        isMacOs
            ? $"-c 1 -W 1000 {targetAddress}"
            : $"-n 1 -w 1000 {targetAddress}";
}
