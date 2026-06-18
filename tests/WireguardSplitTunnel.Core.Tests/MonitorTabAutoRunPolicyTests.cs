using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MonitorTabAutoRunPolicyTests
{
    [Theory]
    [InlineData(false, true, MonitorTabAutoRunAction.Start)]
    [InlineData(true, false, MonitorTabAutoRunAction.Stop)]
    [InlineData(false, false, MonitorTabAutoRunAction.None)]
    [InlineData(true, true, MonitorTabAutoRunAction.None)]
    public void GetAction_ReturnsExpectedActionForMonitorTabTransitions(
        bool wasMonitorTabSelected,
        bool isMonitorTabSelected,
        MonitorTabAutoRunAction expected)
    {
        var action = MonitorTabAutoRunPolicy.GetAction(wasMonitorTabSelected, isMonitorTabSelected);

        action.Should().Be(expected);
    }
}
