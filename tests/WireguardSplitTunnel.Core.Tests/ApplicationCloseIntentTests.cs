using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ApplicationCloseIntentTests
{
    [Fact]
    public void ApplicationCloseIntent_HasTheSpecifiedOrderedValues()
    {
        Enum.GetValues<ApplicationCloseIntent>().Should().Equal(
            ApplicationCloseIntent.UnknownOrAbnormal,
            ApplicationCloseIntent.UserOrApplicationClose,
            ApplicationCloseIntent.SessionEnding,
            ApplicationCloseIntent.ElevationHandoff);
        Enum.GetValues<ApplicationCloseIntent>().Select(value => (int)value).Should().Equal(0, 1, 2, 3);
    }

    [Fact]
    public void Tracker_DefaultsToUnknown()
    {
        new ApplicationCloseIntentTracker().Current.Should().Be(ApplicationCloseIntent.UnknownOrAbnormal);
    }

    [Fact]
    public void ResolveNormalClose_OnlyChangesUnknown()
    {
        var tracker = new ApplicationCloseIntentTracker();
        tracker.ResolveNormalClose();
        tracker.Current.Should().Be(ApplicationCloseIntent.UserOrApplicationClose);
        tracker.RecordElevationHandoff();
        tracker.ResolveNormalClose();
        tracker.Current.Should().Be(ApplicationCloseIntent.ElevationHandoff);
    }

    [Fact]
    public void ElevationHandoff_OverridesUnknownAndUserButNeverSessionEnding()
    {
        var tracker = new ApplicationCloseIntentTracker();
        tracker.RecordElevationHandoff();
        tracker.Current.Should().Be(ApplicationCloseIntent.ElevationHandoff);

        tracker = new ApplicationCloseIntentTracker();
        tracker.ResolveNormalClose();
        tracker.RecordElevationHandoff();
        tracker.Current.Should().Be(ApplicationCloseIntent.ElevationHandoff);

        tracker.RecordSessionEnding();
        tracker.RecordElevationHandoff();
        tracker.Current.Should().Be(ApplicationCloseIntent.SessionEnding);
    }

    [Fact]
    public async Task SessionEnding_OverridesEveryStateAndIsTerminalUnderConcurrency()
    {
        var tracker = new ApplicationCloseIntentTracker();
        using var startGate = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, Environment.ProcessorCount * 4)
            .Select(index => Task.Run(() =>
            {
                startGate.Wait();
                for (var attempt = 0; attempt < 1_000; attempt++)
                {
                    if (index == 0) tracker.RecordSessionEnding();
                    else if ((index & 1) == 0) tracker.ResolveNormalClose();
                    else tracker.RecordElevationHandoff();
                }
            }))
            .ToArray();

        startGate.Set();
        await Task.WhenAll(tasks);
        tracker.Current.Should().Be(ApplicationCloseIntent.SessionEnding);

        Parallel.For(0, 1_000, index =>
        {
            if ((index & 1) == 0) tracker.ResolveNormalClose();
            else tracker.RecordElevationHandoff();
        });

        tracker.Current.Should().Be(ApplicationCloseIntent.SessionEnding);
    }
}
