namespace WireguardSplitTunnel.Core.Updates;

public static class UpdateSchedulePolicy
{
    public static readonly TimeSpan AutomaticInterval = TimeSpan.FromHours(24);
    public static readonly TimeSpan FutureTolerance = TimeSpan.FromMinutes(5);

    public static bool IsDue(DateTimeOffset? lastAttempt, DateTimeOffset now)
    {
        if (lastAttempt is null)
        {
            return true;
        }

        if (IsFutureTimestampInvalid(lastAttempt.Value, now))
        {
            return true;
        }

        return now - lastAttempt.Value >= AutomaticInterval;
    }

    public static bool IsFutureTimestampInvalid(DateTimeOffset lastAttempt, DateTimeOffset now) =>
        lastAttempt - now > FutureTolerance;

    public static LocalUpdateMetadata BeginAttempt(LocalUpdateMetadata metadata, PendingUpdateSource source, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!Enum.IsDefined(source))
        {
            throw new ArgumentOutOfRangeException(nameof(source));
        }

        return source == PendingUpdateSource.Automatic
            ? metadata with { LastAutomaticAttemptUtc = now.ToUniversalTime() }
            : metadata;
    }

    public static TimeSpan GetRemainingDelay(TimeSpan elapsedSinceAttempt)
    {
        if (elapsedSinceAttempt < TimeSpan.Zero)
        {
            return AutomaticInterval;
        }

        return elapsedSinceAttempt >= AutomaticInterval
            ? TimeSpan.Zero
            : AutomaticInterval - elapsedSinceAttempt;
    }
}
