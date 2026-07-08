using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class RuleStateMutations
{
    public static bool TryAddDomainRule(AppState state, string domain, DomainRouteMode mode = DomainRouteMode.UseWireGuard)
    {
        var normalized = NormalizeDomain(domain);
        if (string.IsNullOrWhiteSpace(normalized) || !DomainValidator.IsValidDomain(normalized))
        {
            return false;
        }

        if (state.DomainRules.Any(rule => string.Equals(rule.Domain, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        state.DomainRules.Add(new DomainRule(normalized, true, mode));
        return true;
    }

    public static bool TrySetRuleEnabled(AppState state, string domain, bool enabled)
    {
        var index = state.DomainRules.FindIndex(rule => string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        state.DomainRules[index] = state.DomainRules[index] with { Enabled = enabled };
        return true;
    }

    public static bool TrySetRuleMode(AppState state, string domain, DomainRouteMode mode)
    {
        var index = state.DomainRules.FindIndex(rule => string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        state.DomainRules[index] = state.DomainRules[index] with { Mode = mode };
        return true;
    }

    public static bool RemoveRule(AppState state, string domain)
    {
        var index = state.DomainRules.FindIndex(rule => string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        state.DomainRules.RemoveAt(index);
        return true;
    }

    public static AppState Clone(AppState state)
    {
        var rules = state.DomainRules.Select(rule => rule with { }).ToList();
        var software = (state.SoftwareRules ?? []).Select(rule => rule with { }).ToList();
        var resolved = state.LastKnownResolvedIps.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToList(),
            StringComparer.OrdinalIgnoreCase);
        var snapshot = state.ManagedRouteSnapshot.Select(route => route with { }).ToList();
        var details = state.LastKnownResolvedIpDetails.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.Select(detail => detail with { }).ToList(),
            StringComparer.OrdinalIgnoreCase);

        // `with` keeps scalar fields (including ones added later) without this
        // method having to enumerate them; only collections need deep copies.
        return state with
        {
            DomainRules = rules,
            LastKnownResolvedIps = resolved,
            ManagedRouteSnapshot = snapshot,
            SoftwareRules = software,
            LastKnownResolvedIpDetails = details,
            MacTunnelProfiles = state.MacTunnelProfiles.Select(profile => profile with { }).ToList(),
            MacSoftwareRules = state.MacSoftwareRules.Select(rule => rule with { }).ToList(),
            MacDomainProfileAssignments = state.MacDomainProfileAssignments.Select(assignment => assignment with { }).ToList()
        };
    }

    private static string NormalizeDomain(string domain) => domain.Trim().ToLowerInvariant();
}
