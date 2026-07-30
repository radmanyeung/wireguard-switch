using Microsoft.Win32.SafeHandles;
using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class WindowsProcessIdentityServiceTests
{
    private const int ProcessId = 4242;
    private const long CreationTime = 133_700_000;
    private const string ImagePath = @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe";

    [Fact]
    public void CaptureCurrent_OpensTheCurrentProcessWithOnlyTheRequiredRights()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);

        var result = subject.CaptureCurrent();

        result.Success.Should().BeTrue();
        result.Status.Should().Be(ProcessIdentityOpenStatus.Success);
        result.Identity.Should().Be(new ProcessIdentity(ProcessId, CreationTime, ImagePath));
        result.Lease.Should().NotBeNull();
        native.OpenCalls.Should().ContainSingle().Which.Should().Be(
            new OpenCall(
                WindowsProcessIdentityService.RequiredProcessAccess,
                InheritHandle: false,
                ProcessId));
        native.OpenHandle.IsClosed.Should().BeFalse();

        result.Lease!.Dispose();
        native.OpenHandle.IsClosed.Should().BeTrue();
    }

    [Fact]
    public void CaptureTarget_ReturnsTypedUnavailableAndNoLeaseWhenOpenProcessFails()
    {
        var native = FakeNative.Unavailable(error: 5);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);

        var result = subject.Capture(ProcessId);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.ProcessUnavailable);
        result.NativeErrorCode.Should().Be(5);
        result.Identity.Should().BeNull();
        result.Lease.Should().BeNull();
    }

    [Fact]
    public void CaptureTarget_FailsClosedAndDisposesTheHandleWhenCreationTimeCannotBeRead()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        native.CreationQuerySucceeds = false;
        native.CreationQueryError = 6;
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);

        var result = subject.Capture(ProcessId);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.CreationTimeUnavailable);
        result.NativeErrorCode.Should().Be(6);
        result.Lease.Should().BeNull();
        native.OpenHandle.IsClosed.Should().BeTrue();
    }

    [Fact]
    public void CaptureTarget_FailsClosedAndDisposesTheHandleWhenImagePathCannotBeRead()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        native.ImageQuerySucceeds = false;
        native.ImageQueryError = 299;
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);

        var result = subject.Capture(ProcessId);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.ImagePathUnavailable);
        result.NativeErrorCode.Should().Be(299);
        result.Lease.Should().BeNull();
        native.OpenHandle.IsClosed.Should().BeTrue();
    }

    [Fact]
    public void ReopenValidated_RejectsAnObservedPidThatDoesNotMatchTheDurableIdentity()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var expected = new ProcessIdentity(ProcessId, CreationTime, ImagePath);

        var result = subject.ReopenValidated(ProcessId + 1, expected);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.ProcessIdMismatch);
        result.Lease.Should().BeNull();
        native.OpenCalls.Should().BeEmpty();
    }

    [Fact]
    public void ReopenValidated_RejectsPidReuseByRawCreationFileTimeAndDisposesTheHandle()
    {
        var native = FakeNative.Available(CreationTime + 1, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var expected = new ProcessIdentity(ProcessId, CreationTime, ImagePath);

        var result = subject.ReopenValidated(expected);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.CreationTimeMismatch);
        result.Lease.Should().BeNull();
        native.OpenHandle.IsClosed.Should().BeTrue();
    }

    [Fact]
    public void ReopenValidated_RejectsAnImageMismatchAndDisposesTheHandle()
    {
        var native = FakeNative.Available(
            CreationTime,
            @"C:\Program Files\WireguardSplitTunnel\Unexpected.exe");
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var expected = new ProcessIdentity(ProcessId, CreationTime, ImagePath);

        var result = subject.ReopenValidated(expected);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.ImagePathMismatch);
        result.Lease.Should().BeNull();
        native.OpenHandle.IsClosed.Should().BeTrue();
    }

    [Fact]
    public void ReopenValidated_AcceptsEquivalentWindowsPathCasingAndReturnsAHeldLease()
    {
        var native = FakeNative.Available(CreationTime, ImagePath.ToUpperInvariant());
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var expected = new ProcessIdentity(ProcessId, CreationTime, ImagePath);

        var result = subject.ReopenValidated(expected);

        result.Success.Should().BeTrue();
        result.Identity.Should().Be(expected);
        result.Lease.Should().NotBeNull();
        native.OpenHandle.IsClosed.Should().BeFalse();

        result.Lease!.Dispose();
    }

    [Theory]
    [InlineData(@"C:\Program Files\WireguardSplitTunnel\..\Unexpected.exe")]
    [InlineData(@"WireguardSplitTunnel.App.exe")]
    [InlineData("")]
    public void ReopenValidated_RejectsNonCanonicalDurableImagePathsWithoutOpeningAProcess(
        string durableImagePath)
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var expected = new ProcessIdentity(ProcessId, CreationTime, durableImagePath);

        var result = subject.ReopenValidated(expected);

        result.Success.Should().BeFalse();
        result.Status.Should().Be(ProcessIdentityOpenStatus.InvalidIdentity);
        result.Lease.Should().BeNull();
        native.OpenCalls.Should().BeEmpty();
    }

    [Fact]
    public void Lease_WaitsOnTheHeldHandleAndReportsRunningThenExited()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        native.WaitResults.Enqueue(WindowsProcessNativeWaitResult.TimedOut());
        native.WaitResults.Enqueue(WindowsProcessNativeWaitResult.Signaled());
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        using var lease = subject.Capture(ProcessId).Lease!;

        var running = lease.WaitForExit(TimeSpan.Zero);
        var exited = lease.WaitForExit(TimeSpan.FromSeconds(2));

        running.Status.Should().Be(ProcessWaitStatus.StillRunning);
        exited.Status.Should().Be(ProcessWaitStatus.Exited);
        native.WaitCalls.Should().HaveCount(2);
        native.WaitCalls[0].Handle.Should().BeSameAs(native.OpenHandle);
        native.WaitCalls[0].Handle.IsClosed.Should().BeFalse();
        native.WaitCalls[0].Milliseconds.Should().Be(0);
        native.WaitCalls[1].Milliseconds.Should().Be(2_000);
    }

    [Fact]
    public void Lease_ReturnsTypedFailureWhenNativeWaitFails()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        native.WaitResults.Enqueue(WindowsProcessNativeWaitResult.Failed(error: 6));
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        using var lease = subject.Capture(ProcessId).Lease!;

        var result = lease.WaitForExit(TimeSpan.Zero);

        result.Status.Should().Be(ProcessWaitStatus.Failed);
        result.NativeErrorCode.Should().Be(6);
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(4_294_967_294.5d)]
    [InlineData(4_294_967_295d)]
    public void Lease_RejectsInvalidFiniteTimeoutsWithoutCallingNative(double milliseconds)
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        using var lease = subject.Capture(ProcessId).Lease!;

        var result = lease.WaitForExit(TimeSpan.FromMilliseconds(milliseconds));

        result.Status.Should().Be(ProcessWaitStatus.InvalidTimeout);
        native.WaitCalls.Should().BeEmpty();
    }

    [Fact]
    public void Lease_ReturnsDisposedAfterItReleasesTheHandle()
    {
        var native = FakeNative.Available(CreationTime, ImagePath);
        var subject = new WindowsProcessIdentityService(native, () => ProcessId);
        var lease = subject.Capture(ProcessId).Lease!;

        lease.Dispose();
        var result = lease.WaitForExit(TimeSpan.Zero);

        result.Status.Should().Be(ProcessWaitStatus.Disposed);
        native.WaitCalls.Should().BeEmpty();
    }

    [Fact]
    public void WindowsNativeAdapter_CapturesTheCurrentProcessAndReportsItRunning()
    {
        var subject = new WindowsProcessIdentityService();
        using var resultLease = subject.CaptureCurrent().Lease;

        resultLease.Should().NotBeNull();
        resultLease!.Identity.ProcessId.Should().Be(Environment.ProcessId);
        resultLease.Identity.CreationTimeFileTimeUtc.Should().BePositive();
        resultLease.Identity.ImagePath.Should().Match(
            path => string.Equals(
                path,
                Path.GetFullPath(Environment.ProcessPath!),
                StringComparison.OrdinalIgnoreCase));
        resultLease.WaitForExit(TimeSpan.Zero).Status.Should().Be(ProcessWaitStatus.StillRunning);
    }

    private sealed class FakeNative : IWindowsProcessNative
    {
        private FakeNative(
            SafeProcessHandle openHandle,
            int openError,
            long creationTime,
            string imagePath)
        {
            OpenHandle = openHandle;
            OpenError = openError;
            CreationTime = creationTime;
            ImagePath = imagePath;
        }

        public SafeProcessHandle OpenHandle { get; }
        public int OpenError { get; }
        public long CreationTime { get; }
        public string ImagePath { get; }
        public bool CreationQuerySucceeds { get; set; } = true;
        public int CreationQueryError { get; set; }
        public bool ImageQuerySucceeds { get; set; } = true;
        public int ImageQueryError { get; set; }
        public List<OpenCall> OpenCalls { get; } = [];
        public List<WaitCall> WaitCalls { get; } = [];
        public Queue<WindowsProcessNativeWaitResult> WaitResults { get; } = [];

        public static FakeNative Available(long creationTime, string imagePath) =>
            new(
                new SafeProcessHandle(new IntPtr(0x4242), ownsHandle: false),
                openError: 0,
                creationTime,
                imagePath);

        public static FakeNative Unavailable(int error) =>
            new(
                new SafeProcessHandle(IntPtr.Zero, ownsHandle: false),
                error,
                creationTime: 0,
                imagePath: string.Empty);

        public SafeProcessHandle OpenProcess(
            uint desiredAccess,
            bool inheritHandle,
            int processId,
            out int error)
        {
            OpenCalls.Add(new OpenCall(desiredAccess, inheritHandle, processId));
            error = OpenError;
            return OpenHandle;
        }

        public bool TryGetCreationTime(
            SafeProcessHandle process,
            out long creationTimeFileTimeUtc,
            out int error)
        {
            creationTimeFileTimeUtc = CreationTime;
            error = CreationQueryError;
            return CreationQuerySucceeds;
        }

        public bool TryGetImagePath(
            SafeProcessHandle process,
            out string imagePath,
            out int error)
        {
            imagePath = ImagePath;
            error = ImageQueryError;
            return ImageQuerySucceeds;
        }

        public WindowsProcessNativeWaitResult Wait(
            SafeProcessHandle process,
            uint milliseconds)
        {
            WaitCalls.Add(new WaitCall(process, milliseconds));
            return WaitResults.Count == 0
                ? WindowsProcessNativeWaitResult.TimedOut()
                : WaitResults.Dequeue();
        }
    }

    private sealed record OpenCall(uint DesiredAccess, bool InheritHandle, int ProcessId);

    private sealed record WaitCall(SafeProcessHandle Handle, uint Milliseconds);
}
