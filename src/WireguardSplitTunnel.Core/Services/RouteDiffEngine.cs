using System.Collections.Generic;
using System.Linq;

namespace WireguardSplitTunnel.Core.Services;

public static class RouteDiffEngine
{
    public static RouteDiff Calculate(IEnumerable<string>? oldIps, IEnumerable<string>? newIps)
    {
        var previous = new HashSet<string>(oldIps ?? [], StringComparer.OrdinalIgnoreCase);
        var current = new HashSet<string>(newIps ?? [], StringComparer.OrdinalIgnoreCase);

        var toAdd = DistinctBy(newIps ?? [], StringComparer.OrdinalIgnoreCase)
            .Where(ip => !previous.Contains(ip))
            .ToArray();

        var toRemove = DistinctBy(oldIps ?? [], StringComparer.OrdinalIgnoreCase)
            .Where(ip => !current.Contains(ip))
            .ToArray();

        return new RouteDiff(toAdd, toRemove);
    }

    private static IEnumerable<string> DistinctBy(IEnumerable<string> values, StringComparer comparer)
    {
        var seen = new HashSet<string>(comparer);

        foreach (var value in values)
        {
            if (seen.Add(value))
            {
                yield return value;
            }
        }
    }
}

public sealed record RouteDiff(IReadOnlyList<string> ToAdd, IReadOnlyList<string> ToRemove);
