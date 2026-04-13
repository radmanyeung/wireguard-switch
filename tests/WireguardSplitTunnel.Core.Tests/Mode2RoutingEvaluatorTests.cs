using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class Mode2RoutingEvaluatorTests
{
    [Fact]
    public void ResolveEffectiveProfile_WithEnabledSoftwareRules_ReturnsSoftwarePriority()
    {
        var profile = Mode2RoutingEvaluator.ResolveEffectiveProfile(2);

        profile.Should().Be(Mode2EffectiveProfile.SoftwarePriority);
    }

    [Fact]
    public void ResolveEffectiveProfile_WithoutEnabledSoftwareRules_ReturnsDomainPriority()
    {
        var profile = Mode2RoutingEvaluator.ResolveEffectiveProfile(0);

        profile.Should().Be(Mode2EffectiveProfile.DomainPriority);
    }

    [Fact]
    public void Evaluate_Mode2WithDualHalfDefaults_ReturnsPass()
    {
        var compatibility = Mode2RoutingEvaluator.Evaluate(
            DomainRouteMode.BypassWireGuard,
            enabledSoftwareRuleCount: 2,
            wireGuardHalfDefaultsPresent: true,
            bypassHalfDefaultsPresent: true,
            defaultViaWireGuard: false);

        compatibility.Status.Should().Be(RoutingStatus.Pass);
        compatibility.Profile.Should().Be(Mode2EffectiveProfile.SoftwarePriority);
    }

    [Fact]
    public void Evaluate_Mode2SoftwarePriorityWithoutWireGuardHalfDefaults_ReturnsFail()
    {
        var compatibility = Mode2RoutingEvaluator.Evaluate(
            DomainRouteMode.BypassWireGuard,
            enabledSoftwareRuleCount: 1,
            wireGuardHalfDefaultsPresent: false,
            bypassHalfDefaultsPresent: true,
            defaultViaWireGuard: false);

        compatibility.Status.Should().Be(RoutingStatus.Fail);
    }

    [Fact]
    public void Evaluate_Mode2DomainPriorityWithoutWireGuardHalfDefaults_ReturnsWarning()
    {
        var compatibility = Mode2RoutingEvaluator.Evaluate(
            DomainRouteMode.BypassWireGuard,
            enabledSoftwareRuleCount: 0,
            wireGuardHalfDefaultsPresent: false,
            bypassHalfDefaultsPresent: true,
            defaultViaWireGuard: false);

        compatibility.Status.Should().Be(RoutingStatus.Warning);
        compatibility.Profile.Should().Be(Mode2EffectiveProfile.DomainPriority);
    }
}
