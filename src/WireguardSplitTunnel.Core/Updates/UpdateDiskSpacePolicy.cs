namespace WireguardSplitTunnel.Core.Updates;

public enum UpdateDiskSpaceError
{
    None,
    InvalidLimits,
    NegativeInput,
    ArithmeticOverflow,
    InsufficientSpace
}

public readonly record struct UpdateDiskSpaceResult(bool Success, long? RequiredBytes, UpdateDiskSpaceError ErrorCode)
{
    public static UpdateDiskSpaceResult Valid(long requiredBytes) => new(true, requiredBytes, UpdateDiskSpaceError.None);

    public static UpdateDiskSpaceResult Failure(UpdateDiskSpaceError errorCode, long? requiredBytes = null) =>
        new(false, requiredBytes, errorCode);
}

public static class UpdateDiskSpacePolicy
{
    public static UpdateDiskSpaceResult Evaluate(
        long availableBytes,
        long archiveBytes,
        long expandedCandidateBytes,
        long currentManagedBytes,
        UpdatePackageLimits limits)
    {
        if (!limits.Validate().Success)
        {
            return UpdateDiskSpaceResult.Failure(UpdateDiskSpaceError.InvalidLimits);
        }

        if (availableBytes < 0 || archiveBytes < 0 || expandedCandidateBytes < 0 || currentManagedBytes < 0)
        {
            return UpdateDiskSpaceResult.Failure(UpdateDiskSpaceError.NegativeInput);
        }

        if (!TryAdd(archiveBytes, expandedCandidateBytes, out var archiveAndExpanded)
            || !TryAdd(archiveAndExpanded, currentManagedBytes, out var beforeReserve)
            || !TryAdd(beforeReserve, limits.ReserveBytes, out var requiredBytes))
        {
            return UpdateDiskSpaceResult.Failure(UpdateDiskSpaceError.ArithmeticOverflow);
        }

        return availableBytes >= requiredBytes
            ? UpdateDiskSpaceResult.Valid(requiredBytes)
            : UpdateDiskSpaceResult.Failure(UpdateDiskSpaceError.InsufficientSpace, requiredBytes);
    }

    private static bool TryAdd(long left, long right, out long sum)
    {
        try
        {
            sum = checked(left + right);
            return true;
        }
        catch (OverflowException)
        {
            sum = 0;
            return false;
        }
    }
}
