using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class LatestOperationSerializerTests
{
    [Fact]
    public async Task NewerRequestSupersedesOlderCompletionWhileExecutionRemainsSerialized()
    {
        var serializer = new LatestOperationSerializer();
        var events = new List<string>();
        var firstEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var first = serializer.Begin();
        var firstRun = first.RunSerializedAsync(
            async cancellationToken =>
            {
                events.Add("first-start");
                firstEntered.TrySetResult();
                await releaseFirst.Task.WaitAsync(
                    cancellationToken);
                events.Add("first-end");
            },
            CancellationToken.None);
        await firstEntered.Task.WaitAsync(
            TimeSpan.FromSeconds(5));

        var second = serializer.Begin();
        var secondRun = second.RunSerializedAsync(
            _ =>
            {
                events.Add("second");
                return Task.CompletedTask;
            },
            CancellationToken.None);

        first.IsLatest.Should().BeFalse();
        second.IsLatest.Should().BeTrue();
        events.Should().Equal("first-start");

        releaseFirst.TrySetResult();
        await Task.WhenAll(firstRun, secondRun)
            .WaitAsync(TimeSpan.FromSeconds(5));

        events.Should().Equal(
            "first-start",
            "first-end",
            "second");
        first.IsLatest.Should().BeFalse();
        second.IsLatest.Should().BeTrue();
    }

    [Fact]
    public async Task CancelledQueuedRequestNeverRunsItsAction()
    {
        var serializer = new LatestOperationSerializer();
        var firstEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var first = serializer.Begin();
        var firstRun = first.RunSerializedAsync(
            async cancellationToken =>
            {
                firstEntered.TrySetResult();
                await releaseFirst.Task.WaitAsync(
                    cancellationToken);
            },
            CancellationToken.None);
        await firstEntered.Task.WaitAsync(
            TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource();
        var invoked = false;
        var queued = serializer.Begin();
        var queuedRun = queued.RunSerializedAsync(
            _ =>
            {
                invoked = true;
                return Task.CompletedTask;
            },
            cancellation.Token);

        cancellation.Cancel();
        await FluentActions.Awaiting(() => queuedRun)
            .Should()
            .ThrowAsync<OperationCanceledException>();
        invoked.Should().BeFalse();

        releaseFirst.TrySetResult();
        await firstRun.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void StatusGate_RetainsExactOldGenerationAcrossQueuedOperationGap()
    {
        var serializer = new LatestOperationSerializer();
        var gate = new LatestOperationStatusGate(serializer);
        var first = serializer.Begin();
        gate.SetSource(first);
        var delayedFirstStatus = gate.Capture();

        var second = serializer.Begin();
        var gapStatus = gate.Capture();

        first.Generation.Should().BeGreaterThan(0);
        second.Generation.Should().BeGreaterThan(
            first.Generation);
        gapStatus.Generation.Should().Be(first.Generation);
        gapStatus.IsLatest.Should().BeFalse();
        delayedFirstStatus.IsLatest.Should().BeFalse();

        gate.SetSource(second);
        var secondStatus = gate.Capture();
        secondStatus.Generation.Should().Be(second.Generation);
        secondStatus.IsLatest.Should().BeTrue();
    }

    [Fact]
    public void DelayedStatusCallbackCannotApplyAfterNewerRequestBegins()
    {
        var serializer = new LatestOperationSerializer();
        var gate = new LatestOperationStatusGate(serializer);
        var first = serializer.Begin();
        gate.SetSource(first);
        var stamp = gate.Capture();
        var applied = false;
        Action delayedCallback = () =>
        {
            if (stamp.IsLatest)
            {
                applied = true;
            }
        };

        _ = serializer.Begin();
        delayedCallback();

        applied.Should().BeFalse();
    }

    [Fact]
    public void RejectedTerminalStatusStillReconcilesLatestRuntimeBusySnapshot()
    {
        var serializer = new LatestOperationSerializer();
        var gate = new LatestOperationStatusGate(serializer);
        var first = serializer.Begin();
        gate.SetSource(first);
        var checking = gate.CaptureStatus(isBusy: true);
        var uiBusy = checking.IsLatest;

        var enable = serializer.Begin();
        var terminal = gate.CaptureStatus(isBusy: false);
        if (terminal.IsLatest)
        {
            uiBusy = false;
        }

        uiBusy.Should().BeTrue();
        terminal.Generation.Should().Be(first.Generation);
        terminal.IsLatest.Should().BeFalse();

        gate.SetSource(enable);
        uiBusy = gate.LatestStatusIsBusy;

        uiBusy.Should().BeFalse();
    }
}
