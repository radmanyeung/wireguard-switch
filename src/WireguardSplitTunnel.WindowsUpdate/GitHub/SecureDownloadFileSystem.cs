using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.GitHub;

internal sealed class DownloadDestination : IDisposable
{
    private PinnedLocalDirectoryLease? _directory;

    internal DownloadDestination(
        string path,
        string parentPath,
        PinnedLocalDirectoryLease? directory = null)
    {
        Path = path;
        ParentPath = parentPath;
        _directory = directory;
    }

    public string Path { get; }
    public string ParentPath { get; }
    internal PinnedLocalDirectoryLease? Directory => _directory;

    public void Dispose()
    {
        _directory?.Dispose();
        _directory = null;
    }
}

internal enum DownloadFileOpenStatus
{
    Opened,
    Exists,
    Failed
}

internal sealed record DownloadFileOpenResult(DownloadFileOpenStatus Status, DownloadFileLease? Lease)
{
    internal static DownloadFileOpenResult Opened(DownloadFileLease lease) =>
        new(DownloadFileOpenStatus.Opened, lease);

    internal static DownloadFileOpenResult Exists() =>
        new(DownloadFileOpenStatus.Exists, null);

    internal static DownloadFileOpenResult Failed() =>
        new(DownloadFileOpenStatus.Failed, null);
}

internal abstract class DownloadFileLease : IAsyncDisposable
{
    public abstract Stream Stream { get; }
    public abstract ValueTask DisposeAsync();
}

internal interface IDownloadFileSystem
{
    bool TryCaptureDestination(string path, out DownloadDestination destination);
    bool IsSafeDestination(DownloadDestination destination);
    DownloadFileOpenResult OpenNew(DownloadDestination destination);
    bool IsSafeOpenFile(DownloadFileLease lease, DownloadDestination destination);
    ValueTask FlushToDiskAsync(DownloadFileLease lease, CancellationToken cancellationToken);
    bool CommitOwned(DownloadFileLease lease);
    void DeleteOwned(DownloadFileLease lease);
}

internal interface IDownloadFileDisposition
{
    bool TrySetDeletePending(
        SafeFileHandle handle,
        bool deletePending,
        out int error);
}

internal sealed class WindowsDownloadFileDisposition : IDownloadFileDisposition
{
    private const int FileDispositionInfo = 4;

    public bool TrySetDeletePending(
        SafeFileHandle handle,
        bool deletePending,
        out int error)
    {
        var disposition = new FileDispositionInformation { DeleteFile = deletePending };
        var succeeded = SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            ref disposition,
            (uint)Marshal.SizeOf<FileDispositionInformation>());
        error = succeeded ? 0 : Marshal.GetLastWin32Error();
        return succeeded;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileDispositionInformation lpFileInformation,
        uint dwBufferSize);
}

/// <summary>
/// Pins the complete no-follow directory chain and creates the fixed leaf relative to the
/// pinned staging handle. The new file is delete-pending until a validated download commits it.
/// </summary>
internal sealed class SecureDownloadFileSystem : IDownloadFileSystem
{
    private const int FileIdInfo = 18;
    private readonly IPinnedLocalDirectoryService _directories;
    private readonly IDownloadFileDisposition _disposition;

    public SecureDownloadFileSystem()
        : this(new WindowsPinnedLocalDirectoryService(), new WindowsDownloadFileDisposition())
    {
    }

    internal SecureDownloadFileSystem(
        IPinnedLocalDirectoryService directories,
        IDownloadFileDisposition disposition)
    {
        _directories = directories ?? throw new ArgumentNullException(nameof(directories));
        _disposition = disposition ?? throw new ArgumentNullException(nameof(disposition));
    }

    public bool TryCaptureDestination(string path, out DownloadDestination destination)
    {
        destination = null!;
        PinnedLocalDirectoryLease? directory = null;
        try
        {
            if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(path, out var canonical)
                || canonical is null)
            {
                return false;
            }

            var parent = Path.GetDirectoryName(canonical);
            if (string.IsNullOrEmpty(parent))
            {
                return false;
            }

            var opened = _directories.OpenExisting(parent);
            directory = opened.Lease;
            if (opened.Status != PinnedDirectoryStatus.Opened
                || directory is null
                || !_directories.IsSafe(directory, parent))
            {
                directory?.Dispose();
                return false;
            }

            destination = new DownloadDestination(canonical, parent, directory);
            directory = null;
            return true;
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            directory?.Dispose();
            return false;
        }
    }

    public bool IsSafeDestination(DownloadDestination destination)
    {
        try
        {
            return destination.Directory is { } directory
                && string.Equals(
                    Path.GetDirectoryName(destination.Path),
                    destination.ParentPath,
                    StringComparison.OrdinalIgnoreCase)
                && _directories.IsSafe(directory, destination.ParentPath);
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return false;
        }
    }

    public DownloadFileOpenResult OpenNew(DownloadDestination destination)
    {
        SafeFileHandle? handle = null;
        try
        {
            if (!IsSafeDestination(destination)
                || destination.Directory is not { } directory)
            {
                return DownloadFileOpenResult.Failed();
            }

            var childName = Path.GetFileName(destination.Path);
            var opened = _directories.CreateNewFile(
                directory,
                childName,
                destination.Path);
            handle = opened.Handle;
            if (opened.Status == PinnedDirectoryStatus.Exists)
            {
                handle?.Dispose();
                return DownloadFileOpenResult.Exists();
            }

            if (opened.Status != PinnedDirectoryStatus.Opened
                || handle is null
                || handle.IsInvalid)
            {
                handle?.Dispose();
                return DownloadFileOpenResult.Failed();
            }

            if (!_disposition.TrySetDeletePending(handle, deletePending: true, out _)
                || !TryReadIdentity(handle, out var identity)
                || !TryGetFinalPath(handle, out var finalPath)
                || !string.Equals(finalPath, destination.Path, StringComparison.OrdinalIgnoreCase)
                || !IsSafeDestination(destination))
            {
                handle.Dispose();
                return DownloadFileOpenResult.Failed();
            }

            var stream = new FileStream(handle, FileAccess.Write, 81920, isAsync: true);
            handle = null;
            return DownloadFileOpenResult.Opened(
                new NativeDownloadFileLease(stream, identity));
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            handle?.Dispose();
            return DownloadFileOpenResult.Failed();
        }
    }

    public bool IsSafeOpenFile(
        DownloadFileLease lease,
        DownloadDestination destination)
    {
        if (lease is not NativeDownloadFileLease native
            || native.Handle.IsInvalid
            || native.Handle.IsClosed
            || !IsSafeDestination(destination))
        {
            return false;
        }

        try
        {
            return TryReadIdentity(native.Handle, out var identity)
                && identity == native.Identity
                && TryGetFinalPath(native.Handle, out var finalPath)
                && string.Equals(finalPath, destination.Path, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return false;
        }
    }

    public async ValueTask FlushToDiskAsync(
        DownloadFileLease lease,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await lease.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
    }

    public bool CommitOwned(DownloadFileLease lease)
    {
        if (lease is not NativeDownloadFileLease native
            || native.Handle.IsInvalid
            || native.Handle.IsClosed)
        {
            return false;
        }

        if (!_disposition.TrySetDeletePending(
                native.Handle,
                deletePending: false,
                out var error))
        {
            throw CreateDispositionException("commit", error);
        }

        native.DeletePending = false;
        return true;
    }

    public void DeleteOwned(DownloadFileLease lease)
    {
        if (lease is not NativeDownloadFileLease native
            || native.Handle.IsInvalid
            || native.Handle.IsClosed)
        {
            return;
        }

        if (!_disposition.TrySetDeletePending(
                native.Handle,
                deletePending: true,
                out var error))
        {
            throw CreateDispositionException("delete", error);
        }

        native.DeletePending = true;
    }

    private static bool TryReadIdentity(
        SafeFileHandle handle,
        out DownloadFileIdentity identity)
    {
        identity = default;
        if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                out var information,
                (uint)Marshal.SizeOf<FileIdInformation>()))
        {
            return false;
        }

        identity = new DownloadFileIdentity(
            information.VolumeSerialNumber,
            information.FileId.LowPart,
            information.FileId.HighPart);
        return true;
    }

    private static bool TryGetFinalPath(SafeFileHandle handle, out string? path)
    {
        path = null;
        var required = GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0)
        {
            return false;
        }

        var buffer = new StringBuilder(checked((int)required + 1));
        var written = GetFinalPathNameByHandleW(
            handle,
            buffer,
            (uint)buffer.Capacity,
            0);
        if (written == 0 || written >= buffer.Capacity)
        {
            return false;
        }

        var value = buffer.ToString();
        if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            value = @"\\" + value[8..];
        }
        else if (value.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            value = value[4..];
        }

        path = Path.GetFullPath(value);
        return true;
    }

    private static IOException CreateDispositionException(string operation, int error) =>
        new(
            $"Could not {operation} the exact owned download handle.",
            new Win32Exception(error));

    private static bool IsExpectedFileException(Exception exception) => exception is IOException
        or UnauthorizedAccessException
        or ArgumentException
        or NotSupportedException
        or ObjectDisposedException
        or InvalidOperationException
        or System.Security.SecurityException;

    private readonly record struct DownloadFileIdentity(
        ulong VolumeSerialNumber,
        ulong FileIdLow,
        ulong FileIdHigh);

    private sealed class NativeDownloadFileLease(
        FileStream stream,
        DownloadFileIdentity identity) : DownloadFileLease
    {
        public SafeFileHandle Handle => stream.SafeFileHandle;
        public DownloadFileIdentity Identity { get; } = identity;
        public bool DeletePending { get; set; } = true;
        public override Stream Stream => stream;
        public override ValueTask DisposeAsync() => stream.DisposeAsync();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        public ulong LowPart;
        public ulong HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong VolumeSerialNumber;
        public FileId128 FileId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        out FileIdInformation lpFileInformation,
        uint dwBufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder? lpszFilePath,
        uint cchFilePath,
        uint dwFlags);
}
