namespace WireguardSplitTunnel.Core.Updates;

public readonly record struct UpdatePackageLimits(
    int MaximumEntries,
    long MaximumFileBytes,
    long MaximumExpandedBytes,
    double MaximumCompressionRatio,
    long ReserveBytes)
{
    public static UpdatePackageLimits Default { get; } = new(
        WindowsReleasePathPolicy.MaximumArchiveEntries,
        512L * 1024 * 1024,
        1024L * 1024 * 1024,
        200d,
        256L * 1024 * 1024);

    public static UpdatePackageLimitsValidationResult TryCreate(
        int maximumEntries,
        long maximumFileBytes,
        long maximumExpandedBytes,
        double maximumCompressionRatio,
        long reserveBytes)
    {
        var limits = new UpdatePackageLimits(
            maximumEntries,
            maximumFileBytes,
            maximumExpandedBytes,
            maximumCompressionRatio,
            reserveBytes);

        return limits.Validate();
    }

    public UpdatePackageLimitsValidationResult Validate()
    {
        if (MaximumEntries != WindowsReleasePathPolicy.MaximumArchiveEntries
            || MaximumFileBytes <= 0
            || MaximumExpandedBytes <= 0
            || MaximumCompressionRatio <= 0
            || double.IsNaN(MaximumCompressionRatio)
            || double.IsInfinity(MaximumCompressionRatio)
            || ReserveBytes < 0)
        {
            return UpdatePackageLimitsValidationResult.Invalid;
        }

        return UpdatePackageLimitsValidationResult.Valid(this);
    }
}

public readonly record struct UpdatePackageLimitsValidationResult(bool Success, UpdatePackageLimits? Limits)
{
    public static UpdatePackageLimitsValidationResult Invalid { get; } = new(false, null);

    public static UpdatePackageLimitsValidationResult Valid(UpdatePackageLimits limits) => new(true, limits);
}
