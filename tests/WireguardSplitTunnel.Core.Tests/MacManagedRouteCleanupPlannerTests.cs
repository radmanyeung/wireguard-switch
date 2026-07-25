using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacManagedRouteCleanupPlannerTests
{
    private static readonly ManagedRouteEntry OwnedRoute =
        new("one.example", "198.51.100.10", "utun4");

    [Fact]
    public void Classify_ExactHostRouteOnExpectedInterface_IsOwned()
    {
        const string output = "route to: 198.51.100.10\n"
            + "destination: 198.51.100.10\n"
            + "interface: utun4\n";

        MacManagedRouteCleanupPlanner.Classify(0, output, OwnedRoute)
            .Should().Be(MacManagedRouteCleanupDisposition.ExactOwnedRoute);
    }

    [Fact]
    public void Classify_EffectiveDefaultRoute_MeansManagedHostRouteIsAlreadyAbsent()
    {
        const string output = "route to: 198.51.100.10\n"
            + "destination: default\n"
            + "interface: en0\n";

        MacManagedRouteCleanupPlanner.Classify(0, output, OwnedRoute)
            .Should().Be(MacManagedRouteCleanupDisposition.AlreadyAbsent);
    }

    [Fact]
    public void Classify_ReplacementHostRouteOnAnotherInterface_IsLeftUntouched()
    {
        const string output = "route to: 198.51.100.10\n"
            + "destination: 198.51.100.10\n"
            + "interface: utun5\n";

        MacManagedRouteCleanupPlanner.Classify(0, output, OwnedRoute)
            .Should().Be(MacManagedRouteCleanupDisposition.ReplacedByOtherInterface);
    }

    [Fact]
    public void Classify_UnparseableOrLegacyOwnership_RemainsUnknown()
    {
        MacManagedRouteCleanupPlanner.Classify(1, "route lookup failed", OwnedRoute)
            .Should().Be(MacManagedRouteCleanupDisposition.Unknown);
        MacManagedRouteCleanupPlanner.Classify(
                0,
                "destination: 198.51.100.10\ninterface: utun4",
                OwnedRoute with { InterfaceName = null })
            .Should().Be(MacManagedRouteCleanupDisposition.Unknown);
    }
}
