using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class UpdateDiskSpacePolicyTests
{
    [Fact]
    public void DefaultLimits_AreTheFixedPackageSafetyBoundaries()
    {
        var limits = UpdatePackageLimits.Default;

        limits.MaximumEntries.Should().Be(4096);
        limits.MaximumEntries.Should().Be(WindowsReleasePathPolicy.MaximumArchiveEntries);
        limits.MaximumFileBytes.Should().Be(512L * 1024 * 1024);
        limits.MaximumExpandedBytes.Should().Be(1024L * 1024 * 1024);
        limits.MaximumCompressionRatio.Should().Be(200d);
        limits.ReserveBytes.Should().Be(256L * 1024 * 1024);
    }

    [Fact]
    public void CustomLimits_AreSupportedWhenSane()
    {
        var created = UpdatePackageLimits.TryCreate(WindowsReleasePathPolicy.MaximumArchiveEntries, 3, 4, 5d, 6);

        created.Success.Should().BeTrue();
        created.Limits.Should().Be(new UpdatePackageLimits(WindowsReleasePathPolicy.MaximumArchiveEntries, 3, 4, 5d, 6));
    }

    [Fact]
    public void Evaluate_AcceptsExactRequiredSpace()
    {
        var result = UpdateDiskSpacePolicy.Evaluate(10, 2, 3, 4, Limits(reserveBytes: 1));

        result.Success.Should().BeTrue();
        result.RequiredBytes.Should().Be(10);
        result.ErrorCode.Should().Be(UpdateDiskSpaceError.None);
    }

    [Fact]
    public void Evaluate_RejectsOneByteLessThanRequiredSpace()
    {
        var result = UpdateDiskSpacePolicy.Evaluate(9, 2, 3, 4, Limits(reserveBytes: 1));

        result.Success.Should().BeFalse();
        result.RequiredBytes.Should().Be(10);
        result.ErrorCode.Should().Be(UpdateDiskSpaceError.InsufficientSpace);
    }

    [Fact]
    public void Evaluate_AcceptsAbundantSpace()
    {
        var result = UpdateDiskSpacePolicy.Evaluate(100, 2, 3, 4, Limits(reserveBytes: 1));

        result.Success.Should().BeTrue();
        result.RequiredBytes.Should().Be(10);
    }

    [Fact]
    public void Evaluate_AllowsZeroSpaceComponents()
    {
        var result = UpdateDiskSpacePolicy.Evaluate(0, 0, 0, 0, Limits(reserveBytes: 0));

        result.Success.Should().BeTrue();
        result.RequiredBytes.Should().Be(0);
    }

    [Theory]
    [InlineData(-1L, 0L, 0L, 0L)]
    [InlineData(0L, -1L, 0L, 0L)]
    [InlineData(0L, 0L, -1L, 0L)]
    [InlineData(0L, 0L, 0L, -1L)]
    public void Evaluate_RejectsEachNegativeInput(long available, long archive, long expanded, long currentManaged)
    {
        var result = UpdateDiskSpacePolicy.Evaluate(available, archive, expanded, currentManaged, Limits(reserveBytes: 0));

        result.Success.Should().BeFalse();
        result.RequiredBytes.Should().BeNull();
        result.ErrorCode.Should().Be(UpdateDiskSpaceError.NegativeInput);
    }

    [Theory]
    [InlineData(0L, long.MaxValue, 1L, 0L, 0L)]
    [InlineData(0L, long.MaxValue, 0L, 1L, 0L)]
    [InlineData(0L, long.MaxValue, 0L, 0L, 1L)]
    public void Evaluate_RejectsOverflowAtEachRequiredBytesAddition(long available, long archive, long expanded, long currentManaged, long reserve)
    {
        var result = UpdateDiskSpacePolicy.Evaluate(available, archive, expanded, currentManaged, Limits(reserveBytes: reserve));

        result.Success.Should().BeFalse();
        result.RequiredBytes.Should().BeNull();
        result.ErrorCode.Should().Be(UpdateDiskSpaceError.ArithmeticOverflow);
    }

    [Theory]
    [InlineData(0, 1, 1, 1d, 0)]
    [InlineData(4097, 1, 1, 1d, 0)]
    [InlineData(4096, 0, 1, 1d, 0)]
    [InlineData(4096, 1, 0, 1d, 0)]
    [InlineData(4096, 1, 1, 0d, 0)]
    [InlineData(4096, 1, 1, -1d, 0)]
    [InlineData(4096, 1, 1, double.PositiveInfinity, 0)]
    [InlineData(4096, 1, 1, double.NaN, 0)]
    [InlineData(4096, 1, 1, 1d, -1)]
    public void Evaluate_RejectsInvalidLimits(int entries, long maximumFileBytes, long maximumExpandedBytes, double ratio, long reserveBytes)
    {
        var limits = new UpdatePackageLimits(entries, maximumFileBytes, maximumExpandedBytes, ratio, reserveBytes);
        var result = UpdateDiskSpacePolicy.Evaluate(0, 0, 0, 0, limits);

        result.Success.Should().BeFalse();
        result.RequiredBytes.Should().BeNull();
        result.ErrorCode.Should().Be(UpdateDiskSpaceError.InvalidLimits);
    }

    [Fact]
    public void Evaluate_IsPureAndDoesNotMutateTheLimits()
    {
        var limits = Limits(reserveBytes: 1);
        var before = limits;

        UpdateDiskSpacePolicy.Evaluate(10, 2, 3, 4, limits).Should().Be(UpdateDiskSpacePolicy.Evaluate(10, 2, 3, 4, limits));
        limits.Should().Be(before);
    }

    private static UpdatePackageLimits Limits(long reserveBytes) =>
        new(WindowsReleasePathPolicy.MaximumArchiveEntries, 100, 100, 2d, reserveBytes);
}
