using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class UpdateSchedulePolicyTests
{
    [Fact]
    public void Constants_AreFixed()
    {
        UpdateSchedulePolicy.AutomaticInterval.Should().Be(TimeSpan.FromHours(24));
        UpdateSchedulePolicy.FutureTolerance.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1439)]
    [InlineData(1440)]
    public void IsDue_UsesThe24HourBoundary(int elapsedMinutes)
    {
        var lastAttempt = new DateTimeOffset(2026, 7, 29, 8, 0, 0, TimeSpan.Zero);

        UpdateSchedulePolicy.IsDue(lastAttempt, lastAttempt.AddMinutes(elapsedMinutes)).Should().Be(elapsedMinutes >= 1440);
    }

    [Fact]
    public void IsDue_IsDueWithoutAnAttempt()
    {
        UpdateSchedulePolicy.IsDue(null, DateTimeOffset.UtcNow).Should().BeTrue();
    }

    [Theory]
    [InlineData(5, false)]
    [InlineData(6, true)]
    public void FutureTimestampBoundary_IsExact(int minutesAhead, bool invalid)
    {
        var now = new DateTimeOffset(2026, 7, 29, 8, 0, 0, TimeSpan.Zero);
        var lastAttempt = now.AddMinutes(minutesAhead);

        UpdateSchedulePolicy.IsFutureTimestampInvalid(lastAttempt, now).Should().Be(invalid);
        UpdateSchedulePolicy.IsDue(lastAttempt, now).Should().Be(invalid);
    }

    [Theory]
    [InlineData(PendingUpdateSource.Automatic)]
    [InlineData(PendingUpdateSource.Manual)]
    public void BeginAttempt_PreservesMetadataAndOnlyAutomaticUpdatesTheDueTime(PendingUpdateSource source)
    {
        var originalAttempt = new DateTimeOffset(2026, 7, 28, 9, 0, 0, TimeSpan.FromHours(8));
        var staged = new LocalStagedUpdate(new SemanticVersion(1, 2, 4), "archive.zip", "archive.sha256", "release-manifest.json", "candidate", "archive-hash", "manifest-hash", PendingUpdateSource.Automatic);
        var metadata = new LocalUpdateMetadata(originalAttempt, staged, "network unavailable", true);
        var now = new DateTimeOffset(2026, 7, 29, 9, 0, 0, TimeSpan.FromHours(8));

        var updated = UpdateSchedulePolicy.BeginAttempt(metadata, source, now);

        updated.StagedUpdate.Should().BeSameAs(staged);
        updated.LastError.Should().Be(metadata.LastError);
        updated.ProtectedRemovalPending.Should().BeTrue();
        if (source == PendingUpdateSource.Automatic)
        {
            updated.LastAutomaticAttemptUtc.Should().Be(now.ToUniversalTime());
        }
        else
        {
            updated.Should().BeSameAs(metadata);
            updated.LastAutomaticAttemptUtc.Should().Be(originalAttempt);
        }
    }

    [Theory]
    [InlineData(0, false, null)]
    [InlineData(1, false, "network unavailable")]
    [InlineData(2, true, null)]
    public void BeginAttempt_AutomaticTimestampPersistsAcrossCompletionOutcomes(int outcome, bool removalPending, string? error)
    {
        var now = new DateTimeOffset(2026, 7, 29, 8, 0, 0, TimeSpan.Zero);

        var begun = UpdateSchedulePolicy.BeginAttempt(new LocalUpdateMetadata(null, null, null, false), PendingUpdateSource.Automatic, now);
        var completed = outcome switch
        {
            0 => begun with { StagedUpdate = new LocalStagedUpdate(new SemanticVersion(1, 2, 4), "archive", "checksum", "manifest", "candidate", "archive-hash", "manifest-hash", PendingUpdateSource.Automatic) },
            1 => begun with { LastError = error },
            _ => begun with { ProtectedRemovalPending = removalPending }
        };

        completed.LastAutomaticAttemptUtc.Should().Be(now);
        completed.ProtectedRemovalPending.Should().Be(removalPending);
        completed.LastError.Should().Be(error);
    }

    [Theory]
    [InlineData(0, 1440)]
    [InlineData(60, 1380)]
    [InlineData(1439, 1)]
    [InlineData(1440, 0)]
    [InlineData(1441, 0)]
    public void GetRemainingDelay_UsesOnlyMonotonicElapsedTime(int elapsedMinutes, int expectedMinutes)
    {
        UpdateSchedulePolicy.GetRemainingDelay(TimeSpan.FromMinutes(elapsedMinutes)).Should().Be(TimeSpan.FromMinutes(expectedMinutes));
    }

    [Fact]
    public void GetRemainingDelay_FailsSafeForNegativeElapsedTime()
    {
        UpdateSchedulePolicy.GetRemainingDelay(TimeSpan.FromMinutes(-1)).Should().Be(UpdateSchedulePolicy.AutomaticInterval);
    }

    [Fact]
    public void Metadata_ProvidesSafeEmptyDefaults()
    {
        LocalUpdateMetadata.Empty.Should().Be(new LocalUpdateMetadata(null, null, null, false));
    }
}
