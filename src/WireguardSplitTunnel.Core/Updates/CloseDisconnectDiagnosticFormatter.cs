namespace WireguardSplitTunnel.Core.Updates;

/// <summary>
/// Formats only typed close-disconnect diagnostics; failure messages never cross this boundary.
/// </summary>
public static class CloseDisconnectDiagnosticFormatter
{
    public static string Format(CloseDisconnectResult? result)
    {
        var failures = result?.Failures is { Count: > 0 } items
            ? string.Join("+", items.Select(item => item.Kind))
            : "None";
        var unresolved = result?.UnresolvedTargets is { Count: > 0 } targets
            ? string.Join("+", targets
                .Select(target => target.TunnelName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
            : "None";

        return $"disconnectFailures={failures}, disconnectUnresolved={unresolved}";
    }
}
