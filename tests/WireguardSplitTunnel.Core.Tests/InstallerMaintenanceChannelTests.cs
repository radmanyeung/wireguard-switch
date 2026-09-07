using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class InstallerMaintenanceChannelTests
{
    [Fact]
    public void CreateEventName_BindsTheExactProcessIdentity()
    {
        InstallerMaintenanceChannel.CreateEventName(42, 1337)
            .Should().Be("Local\\WireguardSplitTunnel.InstallerMaintenance.42.1337");
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(-1, 1)]
    public void CreateEventName_RejectsInvalidIdentity(int processId, long creationTime)
    {
        var action = () => InstallerMaintenanceChannel.CreateEventName(processId, creationTime);
        action.Should().Throw<ArgumentOutOfRangeException>();
    }
}
