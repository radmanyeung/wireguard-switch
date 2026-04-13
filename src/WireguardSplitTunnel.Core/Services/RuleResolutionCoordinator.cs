using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record ResolvedRule(DomainRule Rule, IReadOnlyCollection<string> ResolvedIps);

public sealed class RuleResolutionCoordinator
{
    private readonly IDomainResolver resolver;

    public RuleResolutionCoordinator(IDomainResolver resolver)
    {
        this.resolver = resolver;
    }

    public async Task<IReadOnlyCollection<ResolvedRule>> ResolveEnabledRulesAsync(
        IEnumerable<DomainRule> rules,
        CancellationToken cancellationToken)
    {
        var output = new List<ResolvedRule>();

        foreach (var rule in rules.Where(rule => rule.Enabled))
        {
            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyCollection<string> resolvedIps;
            try
            {
                resolvedIps = await resolver.ResolveAsync(rule.Domain, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                continue;
            }

            output.Add(new ResolvedRule(rule, resolvedIps));
        }

        return output;
    }
}
