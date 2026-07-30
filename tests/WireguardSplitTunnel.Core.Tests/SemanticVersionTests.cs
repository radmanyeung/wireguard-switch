using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SemanticVersionTests
{
    [Theory]
    [InlineData("v0.0.0", 0, 0, 0)]
    [InlineData("v1.2.3", 1, 2, 3)]
    [InlineData("v2147483647.2147483647.2147483647", int.MaxValue, int.MaxValue, int.MaxValue)]
    public void TryParseTag_AcceptsOnlyCanonicalLowercaseVTags(string value, int major, int minor, int patch)
    {
        SemanticVersion.TryParseTag(value, out var version).Should().BeTrue();
        version.Should().Be(new SemanticVersion(major, minor, patch));
    }

    [Theory]
    [InlineData("0.0.0", 0, 0, 0)]
    [InlineData("1.2.3", 1, 2, 3)]
    [InlineData("2147483647.2147483647.2147483647", int.MaxValue, int.MaxValue, int.MaxValue)]
    public void TryParseNormalized_AcceptsOnlyCanonicalAsciiVersions(string value, int major, int minor, int patch)
    {
        SemanticVersion.TryParseNormalized(value, out var version).Should().BeTrue();
        version.Should().Be(new SemanticVersion(major, minor, patch));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("v1.2.3 ")]
    [InlineData("V1.2.3")]
    [InlineData("+v1.2.3")]
    [InlineData("v+1.2.3")]
    [InlineData("v-1.2.3")]
    [InlineData("v01.2.3")]
    [InlineData("v1.02.3")]
    [InlineData("v1.2.03")]
    [InlineData("v1.2")]
    [InlineData("v1.2.3.4")]
    [InlineData("v1.2.3-beta")]
    [InlineData("v1.2.3+build")]
    [InlineData("v١.2.3")]
    [InlineData("v2147483648.0.0")]
    public void TryParseTag_RejectsAnythingOutsideCanonicalFormat(string? value)
    {
        SemanticVersion.TryParseTag(value, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("1.2.3 ")]
    [InlineData("v1.2.3")]
    [InlineData("+1.2.3")]
    [InlineData("-1.2.3")]
    [InlineData("01.2.3")]
    [InlineData("1.02.3")]
    [InlineData("1.2.03")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3-rc.1")]
    [InlineData("1.2.3+build")]
    [InlineData("１.2.3")]
    [InlineData("1.2147483648.3")]
    public void TryParseNormalized_RejectsAnythingOutsideCanonicalFormat(string? value)
    {
        SemanticVersion.TryParseNormalized(value, out _).Should().BeFalse();
    }

    [Fact]
    public void CompareTo_UsesNumericComponentOrder()
    {
        new SemanticVersion(1, 10, 0).CompareTo(new SemanticVersion(1, 2, 99)).Should().BeGreaterThan(0);
        new SemanticVersion(1, 2, 3).CompareTo(new SemanticVersion(1, 2, 3)).Should().Be(0);
        new SemanticVersion(1, 2, 3).CompareTo(new SemanticVersion(2, 0, 0)).Should().BeLessThan(0);
    }

    [Fact]
    public void ToString_ReturnsNormalizedVersion()
    {
        new SemanticVersion(1, 2, 3).ToString().Should().Be("1.2.3");
    }
}
