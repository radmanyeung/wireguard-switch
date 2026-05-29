using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DnsCacheLearningServiceTests
{
    [Fact]
    public void LearnFromCache_ReturnsIpv4SubdomainMatchesForEnabledWildcardRules()
    {
        var rules = new[]
        {
            new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard),
            new DomainRule("*.disabled.com", false, DomainRouteMode.UseWireGuard),
            new DomainRule("*.bypass.com", true, DomainRouteMode.BypassWireGuard),
            new DomainRule("api.openai.com", true, DomainRouteMode.UseWireGuard)
        };
        var entries = new[]
        {
            new DnsCacheEntry("auth.openai.com", "198.51.100.10"),
            new DnsCacheEntry("api.openai.com", "198.51.100.11"),
            new DnsCacheEntry("openai.com", "198.51.100.12"),
            new DnsCacheEntry("cdn.disabled.com", "198.51.100.13"),
            new DnsCacheEntry("cdn.bypass.com", "198.51.100.14"),
            new DnsCacheEntry("other.example.com", "198.51.100.15"),
            new DnsCacheEntry("chat.openai.com", "2001:db8::1"),
            new DnsCacheEntry("bad.openai.com", "not-an-ip")
        };

        var learned = DnsCacheLearningService.LearnFromCache(rules, entries);

        learned.Should().ContainSingle();
        var result = learned.Single();
        result.Rule.Domain.Should().Be("*.openai.com");
        result.ResolvedIps.Should().Equal("198.51.100.10", "198.51.100.11");
        result.IpDetails.Should().BeEquivalentTo(new[]
        {
            new ResolvedIpDetail("198.51.100.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
            new ResolvedIpDetail("198.51.100.11", "api.openai.com", ResolvedIpSourceKind.Learned)
        });
    }
}
