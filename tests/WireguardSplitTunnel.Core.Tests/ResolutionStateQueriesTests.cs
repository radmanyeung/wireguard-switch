using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ResolutionStateQueriesTests
{
    [Fact]
    public void GetResolvedIps_ReturnsIpsForMatchingDomainCaseInsensitive()
    {
        var state = new AppState(
            [new DomainRule("example.com", true)],
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["EXAMPLE.com"] = ["203.0.113.1", "203.0.113.2"]
            },
            []);

        var ips = ResolutionStateQueries.GetResolvedIps(state, "example.COM");

        ips.Should().Equal("203.0.113.1", "203.0.113.2");
    }

    [Fact]
    public void GetResolvedIps_ReturnsEmptyWhenNoEntryExists()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), []);

        var ips = ResolutionStateQueries.GetResolvedIps(state, "missing.com");

        ips.Should().BeEmpty();
    }
}
