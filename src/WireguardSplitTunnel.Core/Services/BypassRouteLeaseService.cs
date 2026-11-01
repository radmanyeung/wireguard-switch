namespace WireguardSplitTunnel.Core.Services;

public sealed record BypassRouteKey(
    string Destination, int PrefixLength, int InterfaceIndex, string InterfaceId, string Gateway);

public sealed record BypassRouteChange(BypassRouteKey Route, int AppliedMetric, int? PreviousMetric);

public interface IBypassRouteTable
{
    int? ReadMetric(BypassRouteKey route);
    void SetMetric(BypassRouteKey route, int metric);
    void Delete(BypassRouteKey route);
}

public sealed class BypassRouteLeaseService(IBypassRouteTable routes)
{
    public const int HalfDefaultMetric = 5;

    public void EnsureDefault(BypassRouteKey route, List<BypassRouteChange> changes, Action save)
        => Ensure(route, 1, changes, save);

    public void EnsureHalfDefaults(
        IReadOnlyList<BypassRouteKey> pair, List<BypassRouteChange> changes,
        Action save, bool migrateLegacyPair)
    {
        AdoptLegacyPair(pair, changes, save, migrateLegacyPair);
        foreach (var route in pair)
            Ensure(route, HalfDefaultMetric, changes, save);
    }

    public void AdoptLegacyPair(
        IReadOnlyList<BypassRouteKey> pair, List<BypassRouteChange> changes,
        Action save, bool enabled)
    {
        // Older releases always left these two metric-5 routes behind. Migrate
        // only the complete pair on the caller's known normal gateway.
        if (!enabled || pair.Count != 2
            || pair[0].Destination != "0.0.0.0" || pair[1].Destination != "128.0.0.0"
            || pair.Any(r => r.PrefixLength != 1)
            || pair[0].InterfaceId != pair[1].InterfaceId
            || pair[0].InterfaceIndex != pair[1].InterfaceIndex
            || pair[0].Gateway != pair[1].Gateway
            || pair.Any(r => changes.Any(c => c.Route == r)
                || routes.ReadMetric(r) != HalfDefaultMetric))
            return;

        changes.AddRange(pair.Select(r => new BypassRouteChange(r, HalfDefaultMetric, null)));
        save();
    }

    private void Ensure(BypassRouteKey route, int metric, List<BypassRouteChange> changes, Action save)
    {
        var current = routes.ReadMetric(route);
        var existing = changes.FirstOrDefault(c => c.Route == route);
        if (existing is null)
        {
            changes.Add(new(route, metric, current));
        }
        else if (current is not null && current != existing.AppliedMetric)
        {
            changes[changes.IndexOf(existing)] = existing with { PreviousMetric = current, AppliedMetric = metric };
        }

        // Also re-save on retries: an earlier save may have failed after the
        // in-memory cleanup record was added.
        save();
        routes.SetMetric(route, metric);
    }

    public int Restore(List<BypassRouteChange> changes, Action save, CancellationToken cancellationToken)
    {
        var restored = 0;
        var errors = new List<Exception>();
        foreach (var change in changes.OrderByDescending(c => c.Route.PrefixLength).ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var current = routes.ReadMetric(change.Route);
                if (current == change.AppliedMetric)
                {
                    if (change.PreviousMetric is int previous)
                        routes.SetMetric(change.Route, previous);
                    else
                        routes.Delete(change.Route);

                    if (routes.ReadMetric(change.Route) != change.PreviousMetric)
                        throw new InvalidOperationException("Bypass route restore could not be verified.");
                    restored++;
                }

                // A missing adapter or a changed metric means this exact route
                // was removed/replaced externally; do not overwrite its new owner.
                changes.Remove(change);
                save();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add(ex); // Still try the other half, keeping failed debt for retry.
            }
        }
        if (errors.Count > 0)
            throw new InvalidOperationException("Some bypass routes could not be restored; cleanup records were retained.",
                new AggregateException(errors));
        return restored;
    }
}
