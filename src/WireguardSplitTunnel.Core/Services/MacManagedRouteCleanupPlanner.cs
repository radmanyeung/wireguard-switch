using System.Text;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

internal enum MacManagedRouteCleanupDisposition
{
    Unknown,
    ExactOwnedRoute,
    AlreadyAbsent,
    ReplacedByOtherInterface
}

internal static class MacManagedRouteCleanupPlanner
{
    internal static MacManagedRouteCleanupDisposition Classify(
        int exitCode,
        string routeGetOutput,
        ManagedRouteEntry route)
    {
        if (exitCode != 0
            || MacTunnelNameResolver.ParseUtunName(route.InterfaceName ?? string.Empty) is null
            || string.IsNullOrWhiteSpace(routeGetOutput))
        {
            return MacManagedRouteCleanupDisposition.Unknown;
        }

        var fields = routeGetOutput
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split(':', 2, StringSplitOptions.TrimEntries))
            .Where(parts => parts.Length == 2)
            .GroupBy(parts => parts[0], StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First()[1], StringComparer.OrdinalIgnoreCase);

        if (!fields.TryGetValue("destination", out var destination)
            || !fields.TryGetValue("interface", out var interfaceName))
        {
            return MacManagedRouteCleanupDisposition.Unknown;
        }

        if (!string.Equals(destination, route.IpAddress, StringComparison.OrdinalIgnoreCase))
        {
            return MacManagedRouteCleanupDisposition.AlreadyAbsent;
        }

        return string.Equals(interfaceName, route.InterfaceName, StringComparison.OrdinalIgnoreCase)
            ? MacManagedRouteCleanupDisposition.ExactOwnedRoute
            : MacManagedRouteCleanupDisposition.ReplacedByOtherInterface;
    }

    internal static void AppendReconciliationScript(
        StringBuilder script,
        ManagedRouteEntry route,
        string deletedMarker,
        string absentMarker,
        string replacedMarker)
    {
        var ip = ShellQuoting.Quote(route.IpAddress);
        var expectedInterface = ShellQuoting.Quote(route.InterfaceName!);

        script.AppendLine($"route_output=$(/sbin/route -n get {ip} 2>/dev/null) || route_output=");
        script.AppendLine("route_destination=$(/usr/bin/printf '%s\\n' \"$route_output\" | /usr/bin/awk '$1 == \"destination:\" { print $2; exit }')");
        script.AppendLine("route_interface=$(/usr/bin/printf '%s\\n' \"$route_output\" | /usr/bin/awk '$1 == \"interface:\" { print $2; exit }')");
        script.AppendLine($"if [[ -n \"$route_destination\" && \"$route_destination\" != {ip} ]]; then");
        script.AppendLine($"  /usr/bin/printf '%s\\n' '{absentMarker}'");
        script.AppendLine($"elif [[ \"$route_destination\" == {ip} && -n \"$route_interface\" && \"$route_interface\" != {expectedInterface} ]]; then");
        script.AppendLine($"  /usr/bin/printf '%s\\n' '{replacedMarker}'");
        script.AppendLine($"elif [[ \"$route_destination\" == {ip} && \"$route_interface\" == {expectedInterface} ]] && /sbin/route -n delete -host {ip} >/dev/null 2>&1; then");
        script.AppendLine($"  /usr/bin/printf '%s\\n' '{deletedMarker}'");
        script.AppendLine("fi");
    }
}
