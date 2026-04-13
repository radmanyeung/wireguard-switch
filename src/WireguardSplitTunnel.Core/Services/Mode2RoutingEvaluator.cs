using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class Mode2RoutingEvaluator
{
    public static Mode2EffectiveProfile ResolveEffectiveProfile(int enabledSoftwareRuleCount) =>
        enabledSoftwareRuleCount > 0
            ? Mode2EffectiveProfile.SoftwarePriority
            : Mode2EffectiveProfile.DomainPriority;

    public static RoutingCompatibility Evaluate(
        DomainRouteMode unifiedMode,
        int enabledSoftwareRuleCount,
        bool wireGuardHalfDefaultsPresent,
        bool bypassHalfDefaultsPresent,
        bool defaultViaWireGuard)
    {
        var profile = ResolveEffectiveProfile(enabledSoftwareRuleCount);

        if (unifiedMode != DomainRouteMode.BypassWireGuard)
        {
            return new RoutingCompatibility(
                profile,
                RoutingStatus.Pass,
                "Unified mode 1 uses WireGuard default routing.");
        }

        if (wireGuardHalfDefaultsPresent && bypassHalfDefaultsPresent && !defaultViaWireGuard)
        {
            return new RoutingCompatibility(
                profile,
                RoutingStatus.Pass,
                "Mode 2 OR routing is healthy: both WireGuard and bypass /1 routes are present.");
        }

        var reasons = new List<string>();
        if (!wireGuardHalfDefaultsPresent)
        {
            reasons.Add("WireGuard /1 routes missing");
        }

        if (!bypassHalfDefaultsPresent)
        {
            reasons.Add("bypass /1 routes missing");
        }

        if (defaultViaWireGuard)
        {
            reasons.Add("effective default still prefers WireGuard");
        }

        if (profile == Mode2EffectiveProfile.SoftwarePriority && !wireGuardHalfDefaultsPresent)
        {
            return new RoutingCompatibility(
                profile,
                RoutingStatus.Fail,
                $"Software-priority mode needs WireGuard /1 routes. Current state: {string.Join("; ", reasons)}.");
        }

        if (profile == Mode2EffectiveProfile.DomainPriority && !bypassHalfDefaultsPresent)
        {
            return new RoutingCompatibility(
                profile,
                RoutingStatus.Fail,
                $"Domain-priority mode needs bypass /1 routes. Current state: {string.Join("; ", reasons)}.");
        }

        return new RoutingCompatibility(
            profile,
            RoutingStatus.Warning,
            $"Mode 2 is running in degraded state: {string.Join("; ", reasons)}.");
    }
}
