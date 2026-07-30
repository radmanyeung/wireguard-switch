using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Processes;

public enum ProcessIdentityOpenStatus
{
    Success,
    InvalidIdentity,
    ProcessIdMismatch,
    ProcessUnavailable,
    CreationTimeUnavailable,
    ImagePathUnavailable,
    CreationTimeMismatch,
    ImagePathMismatch,
    NativeFailure
}

public sealed record ProcessIdentityOpenResult(
    bool Success,
    ProcessIdentityOpenStatus Status,
    ProcessIdentity? Identity,
    [property: JsonIgnore] WindowsProcessIdentityLease? Lease,
    int NativeErrorCode);

public enum ProcessWaitStatus
{
    Exited,
    StillRunning,
    Failed,
    InvalidTimeout,
    Disposed
}

public sealed record ProcessWaitResult(
    ProcessWaitStatus Status,
    int NativeErrorCode = 0);

public sealed class WindowsProcessIdentityLease : IDisposable
{
    private readonly object _gate = new();
    private readonly IWindowsProcessNative _native;
    private SafeProcessHandle? _handle;

    internal WindowsProcessIdentityLease(
        ProcessIdentity identity,
        SafeProcessHandle handle,
        IWindowsProcessNative native)
    {
        Identity = identity;
        _handle = handle;
        _native = native;
    }

    public ProcessIdentity Identity { get; }

    public ProcessWaitResult WaitForExit(TimeSpan timeout)
    {
        if (!TryConvertTimeout(timeout, out var milliseconds))
        {
            return new ProcessWaitResult(ProcessWaitStatus.InvalidTimeout);
        }

        lock (_gate)
        {
            if (_handle is null || _handle.IsClosed || _handle.IsInvalid)
            {
                return new ProcessWaitResult(ProcessWaitStatus.Disposed);
            }

            try
            {
                var result = _native.Wait(_handle, milliseconds);
                return result.Status switch
                {
                    WindowsProcessNativeWaitStatus.Signaled =>
                        new ProcessWaitResult(ProcessWaitStatus.Exited),
                    WindowsProcessNativeWaitStatus.TimedOut =>
                        new ProcessWaitResult(ProcessWaitStatus.StillRunning),
                    _ => new ProcessWaitResult(ProcessWaitStatus.Failed, result.Error)
                };
            }
            catch (Exception exception) when (!IsFatal(exception))
            {
                return new ProcessWaitResult(ProcessWaitStatus.Failed);
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _handle?.Dispose();
            _handle = null;
        }
    }

    private static bool TryConvertTimeout(TimeSpan timeout, out uint milliseconds)
    {
        if (timeout == Timeout.InfiniteTimeSpan)
        {
            milliseconds = uint.MaxValue;
            return true;
        }

        var totalMilliseconds = timeout.TotalMilliseconds;
        if (totalMilliseconds < 0
            || double.IsNaN(totalMilliseconds))
        {
            milliseconds = 0;
            return false;
        }

        var roundedMilliseconds = Math.Ceiling(totalMilliseconds);
        if (roundedMilliseconds >= uint.MaxValue)
        {
            milliseconds = 0;
            return false;
        }

        milliseconds = checked((uint)roundedMilliseconds);
        return true;
    }

    private static bool IsFatal(Exception exception) =>
        exception is OutOfMemoryException
            or StackOverflowException
            or AccessViolationException;
}

public sealed class WindowsProcessIdentityService
{
    internal const uint SynchronizeAccess = 0x0010_0000;
    internal const uint QueryLimitedInformationAccess = 0x0000_1000;
    internal const uint RequiredProcessAccess =
        SynchronizeAccess | QueryLimitedInformationAccess;

    private readonly IWindowsProcessNative _native;
    private readonly Func<int> _currentProcessId;

    public WindowsProcessIdentityService()
        : this(new WindowsProcessNative(), () => Environment.ProcessId)
    {
    }

    internal WindowsProcessIdentityService(
        IWindowsProcessNative native,
        Func<int> currentProcessId)
    {
        _native = native ?? throw new ArgumentNullException(nameof(native));
        _currentProcessId = currentProcessId
            ?? throw new ArgumentNullException(nameof(currentProcessId));
    }

    public ProcessIdentityOpenResult CaptureCurrent()
    {
        try
        {
            return Capture(_currentProcessId());
        }
        catch (Exception exception) when (!IsFatal(exception))
        {
            return Failed(ProcessIdentityOpenStatus.NativeFailure);
        }
    }

    public ProcessIdentityOpenResult Capture(int processId)
    {
        if (processId <= 0)
        {
            return Failed(ProcessIdentityOpenStatus.InvalidIdentity);
        }

        return OpenAndInspect(processId, expected: null);
    }

    public ProcessIdentityOpenResult ReopenValidated(ProcessIdentity expected) =>
        expected is null
            ? Failed(ProcessIdentityOpenStatus.InvalidIdentity)
            : ReopenValidated(expected.ProcessId, expected);

    public ProcessIdentityOpenResult ReopenValidated(
        int observedProcessId,
        ProcessIdentity expected)
    {
        if (!TryValidateDurableIdentity(expected, out var canonicalExpectedPath))
        {
            return Failed(ProcessIdentityOpenStatus.InvalidIdentity);
        }

        if (observedProcessId != expected.ProcessId)
        {
            return Failed(ProcessIdentityOpenStatus.ProcessIdMismatch);
        }

        return OpenAndInspect(
            observedProcessId,
            expected with { ImagePath = canonicalExpectedPath });
    }

    private ProcessIdentityOpenResult OpenAndInspect(
        int processId,
        ProcessIdentity? expected)
    {
        SafeProcessHandle? handle = null;
        try
        {
            handle = _native.OpenProcess(
                RequiredProcessAccess,
                inheritHandle: false,
                processId,
                out var openError);
            if (handle is null || handle.IsInvalid || handle.IsClosed)
            {
                handle?.Dispose();
                return Failed(
                    ProcessIdentityOpenStatus.ProcessUnavailable,
                    openError);
            }

            if (!_native.TryGetCreationTime(
                    handle,
                    out var creationTimeFileTimeUtc,
                    out var creationError)
                || creationTimeFileTimeUtc <= 0)
            {
                handle.Dispose();
                return Failed(
                    ProcessIdentityOpenStatus.CreationTimeUnavailable,
                    creationError);
            }

            if (expected is not null
                && creationTimeFileTimeUtc != expected.CreationTimeFileTimeUtc)
            {
                handle.Dispose();
                return Failed(ProcessIdentityOpenStatus.CreationTimeMismatch);
            }

            if (!_native.TryGetImagePath(handle, out var imagePath, out var imageError)
                || !TryCanonicalizeImagePath(imagePath, out var canonicalImagePath))
            {
                handle.Dispose();
                return Failed(
                    ProcessIdentityOpenStatus.ImagePathUnavailable,
                    imageError);
            }

            if (expected is not null
                && !string.Equals(
                    canonicalImagePath,
                    expected.ImagePath,
                    StringComparison.OrdinalIgnoreCase))
            {
                handle.Dispose();
                return Failed(ProcessIdentityOpenStatus.ImagePathMismatch);
            }

            var identity = expected
                ?? new ProcessIdentity(
                    processId,
                    creationTimeFileTimeUtc,
                    canonicalImagePath);
            var lease = new WindowsProcessIdentityLease(identity, handle, _native);
            handle = null;
            return new ProcessIdentityOpenResult(
                Success: true,
                ProcessIdentityOpenStatus.Success,
                identity,
                lease,
                NativeErrorCode: 0);
        }
        catch (Exception exception) when (!IsFatal(exception))
        {
            handle?.Dispose();
            return Failed(ProcessIdentityOpenStatus.NativeFailure);
        }
    }

    private static bool TryValidateDurableIdentity(
        ProcessIdentity? identity,
        out string canonicalImagePath)
    {
        canonicalImagePath = string.Empty;
        return identity is not null
            && identity.ProcessId > 0
            && identity.CreationTimeFileTimeUtc > 0
            && TryCanonicalizeImagePath(identity.ImagePath, out canonicalImagePath)
            && string.Equals(
                identity.ImagePath,
                canonicalImagePath,
                StringComparison.OrdinalIgnoreCase);
    }

    internal static bool TryCanonicalizeImagePath(
        string? imagePath,
        out string canonicalImagePath)
    {
        canonicalImagePath = string.Empty;
        try
        {
            if (string.IsNullOrWhiteSpace(imagePath)
                || imagePath.IndexOf('\0') >= 0)
            {
                return false;
            }

            var normalized = NormalizeWin32Prefix(imagePath);
            if (!Path.IsPathFullyQualified(normalized))
            {
                return false;
            }

            var fullPath = Path.GetFullPath(normalized);
            if (!Path.IsPathFullyQualified(fullPath))
            {
                return false;
            }

            canonicalImagePath = fullPath;
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            return false;
        }
    }

    private static string NormalizeWin32Prefix(string path)
    {
        const string extendedUncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        const string objectManagerUncPrefix = @"\??\UNC\";
        const string objectManagerPrefix = @"\??\";

        if (path.StartsWith(extendedUncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[extendedUncPrefix.Length..];
        }

        if (path.StartsWith(extendedPrefix, StringComparison.Ordinal))
        {
            return path[extendedPrefix.Length..];
        }

        if (path.StartsWith(objectManagerUncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[objectManagerUncPrefix.Length..];
        }

        return path.StartsWith(objectManagerPrefix, StringComparison.Ordinal)
            ? path[objectManagerPrefix.Length..]
            : path;
    }

    private static ProcessIdentityOpenResult Failed(
        ProcessIdentityOpenStatus status,
        int nativeErrorCode = 0) =>
        new(
            Success: false,
            status,
            Identity: null,
            Lease: null,
            nativeErrorCode);

    private static bool IsFatal(Exception exception) =>
        exception is OutOfMemoryException
            or StackOverflowException
            or AccessViolationException;
}

internal enum WindowsProcessNativeWaitStatus
{
    Signaled,
    TimedOut,
    Failed
}

internal sealed record WindowsProcessNativeWaitResult(
    WindowsProcessNativeWaitStatus Status,
    int Error)
{
    internal static WindowsProcessNativeWaitResult Signaled() =>
        new(WindowsProcessNativeWaitStatus.Signaled, 0);

    internal static WindowsProcessNativeWaitResult TimedOut() =>
        new(WindowsProcessNativeWaitStatus.TimedOut, 0);

    internal static WindowsProcessNativeWaitResult Failed(int error) =>
        new(WindowsProcessNativeWaitStatus.Failed, error);
}

internal interface IWindowsProcessNative
{
    SafeProcessHandle OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId,
        out int error);

    bool TryGetCreationTime(
        SafeProcessHandle process,
        out long creationTimeFileTimeUtc,
        out int error);

    bool TryGetImagePath(
        SafeProcessHandle process,
        out string imagePath,
        out int error);

    WindowsProcessNativeWaitResult Wait(
        SafeProcessHandle process,
        uint milliseconds);
}

internal sealed class WindowsProcessNative : IWindowsProcessNative
{
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorGenFailure = 31;
    private const int InitialImagePathCapacity = 260;
    private const int MaximumImagePathCapacity = 32_768;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 0x0000_0102;
    private const uint WaitFailed = 0xffff_ffff;

    public SafeProcessHandle OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId,
        out int error)
    {
        var handle = OpenProcessNative(desiredAccess, inheritHandle, processId);
        error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    public bool TryGetCreationTime(
        SafeProcessHandle process,
        out long creationTimeFileTimeUtc,
        out int error)
    {
        if (!GetProcessTimes(
                process,
                out var creationTime,
                out _,
                out _,
                out _))
        {
            creationTimeFileTimeUtc = 0;
            error = Marshal.GetLastWin32Error();
            return false;
        }

        var rawValue =
            ((ulong)creationTime.HighDateTime << 32)
            | creationTime.LowDateTime;
        creationTimeFileTimeUtc = unchecked((long)rawValue);
        error = 0;
        return true;
    }

    public bool TryGetImagePath(
        SafeProcessHandle process,
        out string imagePath,
        out int error)
    {
        for (var capacity = InitialImagePathCapacity;
             capacity <= MaximumImagePathCapacity;
             capacity = NextCapacity(capacity))
        {
            var buffer = new StringBuilder(capacity);
            var length = capacity;
            if (QueryFullProcessImageName(
                    process,
                    flags: 0,
                    buffer,
                    ref length))
            {
                imagePath = buffer.ToString(0, length);
                error = 0;
                return true;
            }

            error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer
                || capacity == MaximumImagePathCapacity)
            {
                imagePath = string.Empty;
                return false;
            }
        }

        imagePath = string.Empty;
        error = ErrorInsufficientBuffer;
        return false;
    }

    public WindowsProcessNativeWaitResult Wait(
        SafeProcessHandle process,
        uint milliseconds)
    {
        var result = WaitForSingleObject(process, milliseconds);
        return result switch
        {
            WaitObject0 => WindowsProcessNativeWaitResult.Signaled(),
            WaitTimeout => WindowsProcessNativeWaitResult.TimedOut(),
            WaitFailed => WindowsProcessNativeWaitResult.Failed(
                Marshal.GetLastWin32Error()),
            _ => WindowsProcessNativeWaitResult.Failed(ErrorGenFailure)
        };
    }

    private static int NextCapacity(int current) =>
        current >= MaximumImagePathCapacity / 2
            ? MaximumImagePathCapacity
            : current * 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [DllImport("kernel32.dll", EntryPoint = "OpenProcess", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcessNative(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        SafeProcessHandle hProcess,
        out FileTime lpCreationTime,
        out FileTime lpExitTime,
        out FileTime lpKernelTime,
        out FileTime lpUserTime);

    [DllImport(
        "kernel32.dll",
        EntryPoint = "QueryFullProcessImageNameW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle hProcess,
        uint flags,
        StringBuilder exeName,
        ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        SafeProcessHandle hHandle,
        uint dwMilliseconds);
}
