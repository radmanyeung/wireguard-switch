using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

internal enum PinnedDirectoryStatus
{
    Opened,
    Missing,
    Exists,
    Unsafe,
    Failed
}

internal abstract class PinnedLocalDirectoryLease : IDisposable
{
    public abstract string Path { get; }
    public abstract void Dispose();
}

internal sealed record PinnedDirectoryOpenResult(
    PinnedDirectoryStatus Status,
    PinnedLocalDirectoryLease? Lease);

internal sealed record PinnedFileOpenResult(
    PinnedDirectoryStatus Status,
    SafeFileHandle? Handle);

internal interface IPinnedLocalDirectoryService
{
    PinnedDirectoryStatus EnsureDirectory(
        string anchorPath,
        IReadOnlyList<string> relativeSegments);

    PinnedDirectoryOpenResult OpenExisting(string path);

    bool IsSafe(PinnedLocalDirectoryLease lease, string expectedPath);

    PinnedFileOpenResult CreateNewFile(
        PinnedLocalDirectoryLease parent,
        string childName,
        string expectedPath);
}

/// <summary>
/// Pins every no-follow directory component without delete sharing. Child directories and
/// files are opened relative to the final pinned handle, so a path swap cannot redirect an
/// operation between validation and creation.
/// </summary>
internal sealed class WindowsPinnedLocalDirectoryService : IPinnedLocalDirectoryService
{
    private const uint GenericWrite = 0x40000000;
    private const uint FileAppendData = 0x00000004;
    private const uint DeleteAccess = 0x00010000;
    private const uint Synchronize = 0x00100000;
    private const uint FileTraverse = 0x00000020;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExistingDisposition = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeDevice = 0x00000040;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint FileCreate = 2;
    private const uint FileOpen = 1;
    private const uint FileOpenIf = 3;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileWriteThrough = 0x00000002;
    private const uint FileSequentialOnly = 0x00000004;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const int FileIdInfo = 18;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorFileExists = 80;
    private const int ErrorAlreadyExists = 183;
    private const int StatusObjectNameNotFound = unchecked((int)0xC0000034);
    private const int StatusObjectNameCollision = unchecked((int)0xC0000035);
    private const int StatusObjectPathNotFound = unchecked((int)0xC000003A);

    public PinnedDirectoryStatus EnsureDirectory(
        string anchorPath,
        IReadOnlyList<string> relativeSegments)
    {
        WindowsPinnedDirectoryLease? chain = null;
        try
        {
            var opened = OpenExisting(anchorPath);
            if (opened.Status != PinnedDirectoryStatus.Opened
                || opened.Lease is not WindowsPinnedDirectoryLease initial)
            {
                opened.Lease?.Dispose();
                return opened.Status;
            }

            chain = initial;
            foreach (var segment in relativeSegments)
            {
                if (!IsSingleSegment(segment) || !IsSafe(chain, chain.Path))
                {
                    return PinnedDirectoryStatus.Unsafe;
                }

                var expectedPath = Path.Combine(chain.Path, segment);
                var child = OpenRelativeDirectory(chain.FinalHandle, segment, expectedPath, FileOpen);
                if (child.Status == PinnedDirectoryStatus.Missing)
                {
                    child = OpenRelativeDirectory(chain.FinalHandle, segment, expectedPath, FileCreate);
                }

                if (child.Status != PinnedDirectoryStatus.Opened
                    || child.Handle is null
                    || child.Snapshot is null)
                {
                    child.Handle?.Dispose();
                    return child.Status;
                }

                chain.Add(child.Handle, child.Snapshot);
            }

            return IsSafe(chain, chain.Path)
                ? PinnedDirectoryStatus.Opened
                : PinnedDirectoryStatus.Unsafe;
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return PinnedDirectoryStatus.Failed;
        }
        finally
        {
            chain?.Dispose();
        }
    }

    public PinnedDirectoryOpenResult OpenExisting(string path)
    {
        WindowsPinnedDirectoryLease? chain = null;
        try
        {
            var canonical = GetCanonicalPath(path);
            var root = Path.GetPathRoot(canonical);
            if (string.IsNullOrEmpty(root))
            {
                return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            var rootHandle = OpenAbsoluteDirectory(root, out var rootError);
            if (rootHandle.IsInvalid)
            {
                rootHandle.Dispose();
                return new PinnedDirectoryOpenResult(
                    IsMissingWin32(rootError)
                        ? PinnedDirectoryStatus.Missing
                        : PinnedDirectoryStatus.Failed,
                    null);
            }

            var rootSnapshot = ReadSnapshot(rootHandle, Path.GetFullPath(root));
            if (!IsSafeDirectory(rootSnapshot, Path.GetFullPath(root)))
            {
                rootHandle.Dispose();
                return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            chain = new WindowsPinnedDirectoryLease(rootHandle, rootSnapshot);
            var relative = canonical[root.Length..];
            foreach (var segment in relative.Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                if (!IsSingleSegment(segment))
                {
                    chain.Dispose();
                    return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Unsafe, null);
                }

                var expectedPath = Path.Combine(chain.Path, segment);
                var child = OpenRelativeDirectory(chain.FinalHandle, segment, expectedPath, FileOpen);
                if (child.Status != PinnedDirectoryStatus.Opened
                    || child.Handle is null
                    || child.Snapshot is null)
                {
                    child.Handle?.Dispose();
                    chain.Dispose();
                    return new PinnedDirectoryOpenResult(child.Status, null);
                }

                chain.Add(child.Handle, child.Snapshot);
            }

            if (!IsSafe(chain, canonical))
            {
                chain.Dispose();
                return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            var result = chain;
            chain = null;
            return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Opened, result);
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            chain?.Dispose();
            return new PinnedDirectoryOpenResult(PinnedDirectoryStatus.Failed, null);
        }
    }

    public bool IsSafe(PinnedLocalDirectoryLease lease, string expectedPath)
    {
        if (lease is not WindowsPinnedDirectoryLease native)
        {
            return false;
        }

        try
        {
            var canonical = GetCanonicalPath(expectedPath);
            if (!string.Equals(native.Path, canonical, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            foreach (var entry in native.Entries)
            {
                if (entry.Handle.IsClosed
                    || entry.Handle.IsInvalid
                    || !SameSnapshot(entry.Snapshot, ReadSnapshot(entry.Handle, entry.Snapshot.Path)))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return false;
        }
    }

    public PinnedFileOpenResult CreateNewFile(
        PinnedLocalDirectoryLease parent,
        string childName,
        string expectedPath)
    {
        SafeFileHandle? handle = null;
        try
        {
            if (parent is not WindowsPinnedDirectoryLease native
                || !IsSingleSegment(childName)
                || !IsSafe(native, native.Path))
            {
                return new PinnedFileOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            var canonical = GetCanonicalPath(expectedPath);
            if (!string.Equals(Path.GetDirectoryName(canonical), native.Path, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(Path.GetFileName(canonical), childName, StringComparison.Ordinal))
            {
                return new PinnedFileOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            var status = CreateRelative(
                native.FinalHandle,
                childName,
                GenericWrite | DeleteAccess | FileReadAttributes,
                FileAttributeNormal,
                FileShareRead,
                FileCreate,
                FileNonDirectoryFile | FileSequentialOnly | FileWriteThrough | FileOpenReparsePoint,
                out handle);
            if (!NtSuccess(status))
            {
                handle?.Dispose();
                return new PinnedFileOpenResult(
                    IsCollision(status)
                        ? PinnedDirectoryStatus.Exists
                        : IsMissingStatus(status)
                            ? PinnedDirectoryStatus.Missing
                            : PinnedDirectoryStatus.Failed,
                    null);
            }

            var snapshot = ReadSnapshot(handle!, canonical);
            if (!IsSafeFile(snapshot, canonical)
                || snapshot.Identity.VolumeSerialNumber
                != native.Entries[^1].Snapshot.Identity.VolumeSerialNumber
                || !IsSafe(native, native.Path))
            {
                handle!.Dispose();
                return new PinnedFileOpenResult(PinnedDirectoryStatus.Unsafe, null);
            }

            var result = handle;
            handle = null;
            return new PinnedFileOpenResult(PinnedDirectoryStatus.Opened, result);
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            handle?.Dispose();
            return new PinnedFileOpenResult(PinnedDirectoryStatus.Failed, null);
        }
    }

    internal bool TryAppendFile(
        PinnedLocalDirectoryLease parent,
        string childName,
        string expectedPath,
        byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        SafeFileHandle? handle = null;
        try
        {
            if (parent is not WindowsPinnedDirectoryLease native
                || !IsSingleSegment(childName)
                || !IsSafe(native, native.Path))
            {
                return false;
            }

            var canonical = GetCanonicalPath(expectedPath);
            if (!string.Equals(
                    Path.GetDirectoryName(canonical),
                    native.Path,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    Path.GetFileName(canonical),
                    childName,
                    StringComparison.Ordinal))
            {
                return false;
            }

            var status = CreateRelative(
                native.FinalHandle,
                childName,
                FileAppendData
                    | FileReadAttributes
                    | Synchronize,
                FileAttributeNormal,
                FileShareRead,
                FileOpenIf,
                FileNonDirectoryFile
                    | FileSynchronousIoNonAlert
                    | FileWriteThrough
                    | FileOpenReparsePoint,
                out handle);
            if (!NtSuccess(status)
                || handle is null
                || handle.IsInvalid)
            {
                return false;
            }

            var before = ReadSnapshot(handle, canonical);
            if (!IsSafeFile(before, canonical)
                || before.Identity.VolumeSerialNumber
                    != native.Entries[^1]
                        .Snapshot.Identity.VolumeSerialNumber
                || !IsSafe(native, native.Path))
            {
                return false;
            }

            var byteCount = checked((uint)bytes.Length);
            if (!WriteFile(
                    handle,
                    bytes,
                    byteCount,
                    out var written,
                    IntPtr.Zero)
                || written != byteCount
                || !FlushFileBuffers(handle))
            {
                return false;
            }

            var after = ReadSnapshot(handle, canonical);
            return SameSnapshot(before, after)
                && IsSafeFile(after, canonical)
                && IsSafe(native, native.Path);
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return false;
        }
        finally
        {
            handle?.Dispose();
        }
    }

    private static RelativeDirectoryOpenResult OpenRelativeDirectory(
        SafeFileHandle parent,
        string childName,
        string expectedPath,
        uint disposition)
    {
        var status = CreateRelative(
            parent,
            childName,
            FileTraverse | FileReadAttributes | Synchronize,
            FileAttributeNormal,
            FileShareRead | FileShareWrite,
            disposition,
            FileDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint,
            out var handle);
        if (!NtSuccess(status))
        {
            handle?.Dispose();
            return new RelativeDirectoryOpenResult(
                IsMissingStatus(status)
                    ? PinnedDirectoryStatus.Missing
                    : IsCollision(status)
                        ? PinnedDirectoryStatus.Exists
                        : PinnedDirectoryStatus.Failed,
                null,
                null);
        }

        var snapshot = ReadSnapshot(handle!, expectedPath);
        return IsSafeDirectory(snapshot, expectedPath)
            ? new RelativeDirectoryOpenResult(PinnedDirectoryStatus.Opened, handle, snapshot)
            : DisposeUnsafe(handle!);
    }

    private static RelativeDirectoryOpenResult DisposeUnsafe(SafeFileHandle handle)
    {
        handle.Dispose();
        return new RelativeDirectoryOpenResult(PinnedDirectoryStatus.Unsafe, null, null);
    }

    private static SafeFileHandle OpenAbsoluteDirectory(string path, out int error)
    {
        var handle = CreateFileW(
            path,
            FileTraverse | FileReadAttributes,
            FileShareRead | FileShareWrite,
            IntPtr.Zero,
            OpenExistingDisposition,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    private static int CreateRelative(
        SafeFileHandle parent,
        string childName,
        uint desiredAccess,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        out SafeFileHandle? handle)
    {
        handle = null;
        using var name = new NativeUnicodeString(childName);
        var parentReferenceAdded = false;
        try
        {
            parent.DangerousAddRef(ref parentReferenceAdded);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = name.Structure,
                Attributes = ObjCaseInsensitive
            };
            var ioStatus = new IoStatusBlock();
            var status = NtCreateFile(
                out var rawHandle,
                desiredAccess,
                ref attributes,
                ref ioStatus,
                IntPtr.Zero,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                IntPtr.Zero,
                0);
            if (NtSuccess(status))
            {
                handle = new SafeFileHandle(
                    rawHandle,
                    ownsHandle: true);
            }

            return status;
        }
        finally
        {
            if (parentReferenceAdded)
            {
                parent.DangerousRelease();
            }
        }
    }

    private static FileSnapshot ReadSnapshot(SafeFileHandle handle, string expectedPath)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw CreateIoException("read attributes", expectedPath, Marshal.GetLastWin32Error());
        }

        if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                out var identity,
                (uint)Marshal.SizeOf<FileIdInformation>()))
        {
            throw CreateIoException("read identity", expectedPath, Marshal.GetLastWin32Error());
        }

        return new FileSnapshot(
            GetCanonicalPath(expectedPath),
            GetFinalPath(handle, expectedPath),
            new PinnedLocalFileIdentity(
                identity.VolumeSerialNumber,
                identity.FileId.LowPart,
                identity.FileId.HighPart),
            information.FileAttributes,
            information.NumberOfLinks);
    }

    private static bool IsSafeDirectory(FileSnapshot snapshot, string expectedPath) =>
        (snapshot.Attributes & FileAttributeDirectory) != 0
        && (snapshot.Attributes & (FileAttributeReparsePoint | FileAttributeDevice)) == 0
        && string.Equals(snapshot.FinalPath, expectedPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeFile(FileSnapshot snapshot, string expectedPath) =>
        (snapshot.Attributes & (FileAttributeDirectory | FileAttributeReparsePoint | FileAttributeDevice)) == 0
        && snapshot.NumberOfLinks == 1
        && string.Equals(snapshot.FinalPath, expectedPath, StringComparison.OrdinalIgnoreCase);

    private static bool SameSnapshot(FileSnapshot expected, FileSnapshot current) =>
        expected.Identity == current.Identity
        && expected.Attributes == current.Attributes
        && expected.NumberOfLinks == current.NumberOfLinks
        && string.Equals(expected.Path, current.Path, StringComparison.OrdinalIgnoreCase)
        && string.Equals(expected.FinalPath, current.FinalPath, StringComparison.OrdinalIgnoreCase);

    private static string GetFinalPath(SafeFileHandle handle, string expectedPath)
    {
        var required = GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0)
        {
            throw CreateIoException("read final path", expectedPath, Marshal.GetLastWin32Error());
        }

        var buffer = new StringBuilder(checked((int)required + 1));
        var written = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity)
        {
            throw CreateIoException("read final path", expectedPath, Marshal.GetLastWin32Error());
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

        return Path.GetFullPath(value);
    }

    private static string GetCanonicalPath(string path)
    {
        var canonical = Path.GetFullPath(path);
        if (!string.Equals(canonical, path, StringComparison.OrdinalIgnoreCase)
            || canonical.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new IOException("Pinned path is not a canonical local DOS path.");
        }

        return canonical;
    }

    private static bool IsSingleSegment(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value is not "." and not ".."
        && value.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, ':']) < 0
        && string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal);

    private static bool NtSuccess(int status) => status >= 0;
    private static bool IsMissingStatus(int status) =>
        status is StatusObjectNameNotFound or StatusObjectPathNotFound;
    private static bool IsCollision(int status) => status == StatusObjectNameCollision;
    private static bool IsMissingWin32(int error) => error is ErrorFileNotFound or ErrorPathNotFound;

    private static bool IsExpectedFileException(Exception exception) => exception is IOException
        or UnauthorizedAccessException
        or ArgumentException
        or NotSupportedException
        or ObjectDisposedException
        or InvalidOperationException
        or System.Security.SecurityException;

    private static IOException CreateIoException(string operation, string path, int error) =>
        new($"Could not {operation} for pinned path '{path}'.", new Win32Exception(error));

    private readonly record struct PinnedLocalFileIdentity(
        ulong VolumeSerialNumber,
        ulong FileIdLow,
        ulong FileIdHigh);

    private sealed record FileSnapshot(
        string Path,
        string FinalPath,
        PinnedLocalFileIdentity Identity,
        uint Attributes,
        uint NumberOfLinks);

    private sealed record DirectoryEntry(SafeFileHandle Handle, FileSnapshot Snapshot);

    private sealed class WindowsPinnedDirectoryLease : PinnedLocalDirectoryLease
    {
        private readonly List<DirectoryEntry> _entries;

        public WindowsPinnedDirectoryLease(SafeFileHandle handle, FileSnapshot snapshot)
        {
            _entries = [new DirectoryEntry(handle, snapshot)];
        }

        public IReadOnlyList<DirectoryEntry> Entries => _entries;
        public SafeFileHandle FinalHandle => _entries[^1].Handle;
        public override string Path => _entries[^1].Snapshot.Path;

        public void Add(SafeFileHandle handle, FileSnapshot snapshot) =>
            _entries.Add(new DirectoryEntry(handle, snapshot));

        public override void Dispose()
        {
            for (var index = _entries.Count - 1; index >= 0; index--)
            {
                _entries[index].Handle.Dispose();
            }

            _entries.Clear();
        }
    }

    private sealed record RelativeDirectoryOpenResult(
        PinnedDirectoryStatus Status,
        SafeFileHandle? Handle,
        FileSnapshot? Snapshot);

    private sealed class NativeUnicodeString : IDisposable
    {
        private readonly IntPtr _buffer;

        public NativeUnicodeString(string value)
        {
            var byteLength = checked(value.Length * sizeof(char));
            if (byteLength > ushort.MaxValue - sizeof(char))
            {
                throw new ArgumentException("Relative path segment is too long.", nameof(value));
            }

            _buffer = Marshal.StringToHGlobalUni(value);
            var unicode = new UnicodeString
            {
                Length = (ushort)byteLength,
                MaximumLength = (ushort)(byteLength + sizeof(char)),
                Buffer = _buffer
            };
            Structure = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, Structure, fDeleteOld: false);
        }

        public IntPtr Structure { get; }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Structure);
            Marshal.FreeHGlobal(_buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out IntPtr fileHandle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        ref IoStatusBlock ioStatusBlock,
        IntPtr allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        out FileIdInformation lpFileInformation,
        uint dwBufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(
        SafeFileHandle hFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder? lpszFilePath,
        uint cchFilePath,
        uint dwFlags);
}
