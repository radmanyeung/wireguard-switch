using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class UpdateLifecycleTests
{
    [Fact]
    public void ProtectedUpdatePhase_HasTheSpecifiedOrderedValues()
    {
        Enum.GetValues<ProtectedUpdatePhase>().Should().Equal(
            ProtectedUpdatePhase.ProtectedStaged,
            ProtectedUpdatePhase.CloseAuthorized,
            ProtectedUpdatePhase.Prepared,
            ProtectedUpdatePhase.BackingUp,
            ProtectedUpdatePhase.Applying,
            ProtectedUpdatePhase.AppliedAwaitingHealth,
            ProtectedUpdatePhase.Committed,
            ProtectedUpdatePhase.RollingBack,
            ProtectedUpdatePhase.RolledBack,
            ProtectedUpdatePhase.RecoveryBlocked);
        Enum.GetValues<ProtectedUpdatePhase>().Select(value => (int)value).Should().Equal(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    }

    [Fact]
    public void AuthorizationContext_IsValidForANormalElevatedClose()
    {
        var context = ValidContext();

        context.IsValid.Should().BeTrue();
        UpdateCloseEligibility.IsEligible(context).Should().BeTrue();
    }

    [Theory]
    [InlineData("C:\\app\\app.exe")]
    [InlineData("z:/app/app.exe")]
    public void AuthorizationContext_AcceptsStrictWindowsDrivePathsOnEveryHost(string imagePath)
    {
        var context = ValidContext() with { ImagePath = imagePath };

        context.IsValid.Should().BeTrue();
        UpdateCloseAuthorizationContext.TryCreate(
            context.Intent,
            context.IsElevated,
            context.IsPostInstallSelfTest,
            context.ProcessId,
            context.CreationTimeFileTimeUtc,
            context.ImagePath,
            out var created).Should().BeTrue();
        created.Should().Be(context);
    }

    [Theory]
    [InlineData(0, 1L, "C:\\app\\app.exe")]
    [InlineData(42, 0L, "C:\\app\\app.exe")]
    [InlineData(42, 1L, "")]
    [InlineData(42, 1L, "app.exe")]
    [InlineData(42, 1L, "C:app.exe")]
    [InlineData(42, 1L, "/usr/local/bin/app")]
    [InlineData(42, 1L, "\\\\server\\share\\app.exe")]
    [InlineData(42, 1L, "C:\\")]
    [InlineData(42, 1L, "C:\\app\0.exe")]
    public void AuthorizationContext_RejectsInvalidProcessIdentityOrImagePath(int processId, long creationTimeFileTimeUtc, string imagePath)
    {
        var context = ValidContext() with { ProcessId = processId, CreationTimeFileTimeUtc = creationTimeFileTimeUtc, ImagePath = imagePath };

        context.IsValid.Should().BeFalse();
        UpdateCloseEligibility.IsEligible(context).Should().BeFalse();
        UpdateCloseAuthorizationContext.TryCreate(
            context.Intent,
            context.IsElevated,
            context.IsPostInstallSelfTest,
            context.ProcessId,
            context.CreationTimeFileTimeUtc,
            context.ImagePath,
            out var created).Should().BeFalse();
        created.Should().BeNull();
    }

    [Theory]
    [InlineData(ApplicationCloseIntent.UnknownOrAbnormal, true, false)]
    [InlineData(ApplicationCloseIntent.SessionEnding, true, false)]
    [InlineData(ApplicationCloseIntent.ElevationHandoff, true, false)]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, false, false)]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, true, true)]
    public void CloseEligibility_RejectsEveryNonNormalAuthorization(ApplicationCloseIntent intent, bool elevated, bool selfTest)
    {
        var context = ValidContext() with { Intent = intent, IsElevated = elevated, IsPostInstallSelfTest = selfTest };

        UpdateCloseEligibility.IsEligible(context).Should().BeFalse();
    }

    [Fact]
    public void AuthorizationResult_UsesTypedOutcomesAndOptionalErrorCode()
    {
        UpdateCloseAuthorizationResult.NoProtectedTransaction().Outcome.Should().Be(UpdateCloseAuthorizationOutcome.NoProtectedTransaction);
        UpdateCloseAuthorizationResult.HelperReady().Outcome.Should().Be(UpdateCloseAuthorizationOutcome.HelperReady);
        var failure = UpdateCloseAuthorizationResult.RecoverableFailure("helper_launch_failed");
        failure.Outcome.Should().Be(UpdateCloseAuthorizationOutcome.RecoverableFailure);
        failure.ErrorCode.Should().Be("helper_launch_failed");
    }

    [Fact]
    public void AuthorizationOutcome_HasStableNumericValues()
    {
        Enum.GetValues<UpdateCloseAuthorizationOutcome>().Select(value => (int)value).Should().Equal(0, 1, 2);
    }

    [Theory]
    [InlineData(" HELPER_LAUNCH_FAILED ", "helper_launch_failed")]
    [InlineData("helper\nlaunch", null)]
    [InlineData("helper-launch", null)]
    [InlineData("", null)]
    public void RecoverableFailure_SanitizesErrorCode(string errorCode, string? expected)
    {
        UpdateCloseAuthorizationResult.RecoverableFailure(errorCode).ErrorCode.Should().Be(expected);
    }

    [Fact]
    public void RecoverableFailure_DropsOversizeErrorCode()
    {
        UpdateCloseAuthorizationResult.RecoverableFailure(new string('a', 65)).ErrorCode.Should().BeNull();
    }

    [Fact]
    public void AuthorizationResult_CannotBeDirectlyConstructed()
    {
        typeof(UpdateCloseAuthorizationResult).GetConstructors().Should().BeEmpty();
    }

    private static UpdateCloseAuthorizationContext ValidContext() => new(
        ApplicationCloseIntent.UserOrApplicationClose, true, false, 42, 1, "C:\\app\\app.exe");
}
