using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record IncrementalDnsRouteReconcileResult(
    int LearnedIpCount,
    int AddedRouteCount,
    bool StateChanged);

public sealed class IncrementalDnsRouteReconciler(IDnsCacheReader dnsCacheReader)
{
    public async Task<IncrementalDnsRouteReconcileResult> ReconcileAsync(
        AppState state,
        Func<IReadOnlyCollection<string>, CancellationToken, Task> addRoutesAsync,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entries = await dnsCacheReader.ReadAsync(cancellationToken);
        var learnedRules = DnsCacheLearningService.LearnFromCache(state.DomainRules, entries);
        var plan = IncrementalDomainRouteApplyPlanner.Build(state, learnedRules);
        cancellationToken.ThrowIfCancellationRequested();

        if (plan.ToAdd.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await addRoutesAsync(plan.ToAdd, cancellationToken);
        }

        var resolutionStateChanged = ResolutionStateUpdater.MergeIncremental(state, plan.LearnedRules);
        var snapshotChanged = !state.ManagedRouteSnapshot.SequenceEqual(plan.Snapshot);
        if (snapshotChanged)
        {
            state.ManagedRouteSnapshot.Clear();
            state.ManagedRouteSnapshot.AddRange(plan.Snapshot);
        }

        return new IncrementalDnsRouteReconcileResult(
            plan.LearnedRules
                .SelectMany(rule => rule.ResolvedIps)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(),
            plan.ToAdd.Count,
            resolutionStateChanged || snapshotChanged);
    }
}