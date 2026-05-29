using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class VersionDisplayTests
{
    [Fact]
    public void FromInformationalVersion_AddsVersionPrefix()
    {
        VersionDisplay.FromInformationalVersion("0.1.4").Should().Be("v0.1.4");
    }

    [Fact]
    public void FromInformationalVersion_RemovesBuildMetadata()
    {
        VersionDisplay.FromInformationalVersion("0.1.4+local-build").Should().Be("v0.1.4");
    }
}