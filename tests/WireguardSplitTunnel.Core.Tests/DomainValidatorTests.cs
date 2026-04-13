using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DomainValidatorTests
{
    [Theory]
    [InlineData("example.com", true)]
    [InlineData("sub.example.com", true)]
    [InlineData("*.example.com", true)]
    [InlineData("http://example.com", false)]
    [InlineData("", false)]
    [InlineData("-bad.example.com", false)]
    [InlineData("bad-.example.com", false)]
    [InlineData("*.-bad.example.com", false)]
    [InlineData("*.bad-.example.com", false)]
    public void IsValidDomain_ReturnsExpectedResult(string input, bool expected)
    {
        DomainValidator.IsValidDomain(input).Should().Be(expected);
    }
}


