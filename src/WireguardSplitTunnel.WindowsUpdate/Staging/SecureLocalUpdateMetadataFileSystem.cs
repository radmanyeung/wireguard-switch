using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

internal enum LocalUpdateMetadataOpenStatus
{
    Opened,
    Missing,
    Unsafe
}

internal enum LocalUpdateMetadataEntryState
{
    Missing,
    File,
    Unsafe
}

internal readonly record struct LocalUpdateMetadataFileIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal sealed record LocalUpdateMetadataDestination(
    LocalUpdateMetadataEntryState State,
    LocalUpdateMetadataFileIdentity Identity);

internal interface ILocalUpdateMetadataDirectoryLease : IDisposable;

internal interface ILocalUpdateMetadataReadLease : IDisposable;

internal interface ILocalUpdateMetadataWriteLease : IDisposable;

internal interface ILocalUpdateMetadataFileSystem
{
    LocalUpdateMetadataOpenStatus OpenDirectory(
        string expectedPath,
        out ILocalUpdateMetadataDirectoryLease? lease);

    bool IsSafeDirectory(ILocalUpdateMetadataDirectoryLease lease, string expectedPath);

    LocalUpdateMetadataOpenStatus OpenRead(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath,
        out ILocalUpdateMetadataReadLease? lease);

    bool IsSafeRead(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataReadLease file,
        string expectedPath);

    byte[]? ReadBounded(ILocalUpdateMetadataReadLease file, long maximumBytes);

    LocalUpdateMetadataDestination InspectDestination(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath);

    LocalUpdateMetadataOpenStatus CreateNewTemp(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath,
        out ILocalUpdateMetadataWriteLease? lease);

    bool IsSafeTemp(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string expectedPath);

    void Write(ILocalUpdateMetadataWriteLease file, byte[] bytes);

    void FlushToDisk(ILocalUpdateMetadataWriteLease file);

    bool Move(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath);

    bool Replace(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath,
        LocalUpdateMetadataFileIdentity expectedDestinationIdentity);

    bool IsCommitted(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath);

    void DeleteOwned(ILocalUpdateMetadataWriteLease file);
}

/// <summary>
/// Pins the verified metadata directory, opens children without following the child itself,
/// and commits or deletes the exact created temporary file through its held handle.
/// </summary>
internal sealed class WindowsLocalUpdateMetadataFileSystem : ILocalUpdateMetadataFileSystem
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileTraverse = 0x00000020;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeDevice = 0x00000040;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorAccessDenied = 5;
    private const int ErrorFileExists = 80;
    private const int ErrorAlreadyExists = 183;
    private const int FileRenameInfo = 3;
    private const int FileDispositionInfo = 4;
    private const int FileIdInfoClass = 18;
    private const int FileRenameInfoEx = 22;
    private const uint FileRenameReplaceIfExists = 0x00000001;
    private const uint FileRenamePosixSemantics = 0x00000002;

    public LocalUpdateMetadataOpenStatus OpenDirectory(
        string expectedPath,
        out ILocalUpdateMetadataDirectoryLease? lease)
    {
        lease = null;
        var canonical = GetCanonicalPath(expectedPath);
        var handle = Open(
            canonical,
            FileTraverse | FileReadAttributes,
            FileShareRead | FileShareWrite,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            out var error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return IsMissing(error)
                ? LocalUpdateMetadataOpenStatus.Missing
                : throw CreateIoException("open metadata directory", canonical, error);
        }

        try
        {
            var snapshot = ReadSnapshot(handle, canonical);
            if (!IsSafeDirectorySnapshot(snapshot, canonical))
            {
                handle.Dispose();
                return LocalUpdateMetadataOpenStatus.Unsafe;
            }

            lease = new WindowsDirectoryLease(handle, snapshot);
            return LocalUpdateMetadataOpenStatus.Opened;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public bool IsSafeDirectory(ILocalUpdateMetadataDirectoryLease lease, string expectedPath)
    {
        if (lease is not WindowsDirectoryLease directory
            || directory.Handle.IsClosed
            || directory.Handle.IsInvalid)
        {
            return false;
        }

        var canonical = GetCanonicalPath(expectedPath);
        var current = ReadSnapshot(directory.Handle, canonical);
        return IsSafeDirectorySnapshot(current, canonical)
            && SameSnapshot(directory.Snapshot, current);
    }

    public LocalUpdateMetadataOpenStatus OpenRead(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath,
        out ILocalUpdateMetadataReadLease? lease)
    {
        lease = null;
        if (directory is not WindowsDirectoryLease parent
            || !IsDirectChild(parent, expectedPath)
            || !IsSafeDirectory(parent, parent.Snapshot.Path))
        {
            return LocalUpdateMetadataOpenStatus.Unsafe;
        }

        var canonical = GetCanonicalPath(expectedPath);
        var handle = Open(
            canonical,
            GenericRead | FileReadAttributes,
            FileShareRead,
            OpenExisting,
            FileFlagSequentialScan | FileFlagOpenReparsePoint,
            out var error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return IsMissing(error)
                ? LocalUpdateMetadataOpenStatus.Missing
                : throw CreateIoException("open metadata file", canonical, error);
        }

        try
        {
            var snapshot = ReadSnapshot(handle, canonical);
            if (!IsSafeFileSnapshot(snapshot, canonical, parent.Snapshot.Identity.VolumeSerialNumber))
            {
                handle.Dispose();
                return LocalUpdateMetadataOpenStatus.Unsafe;
            }

            lease = new WindowsReadLease(
                new FileStream(handle, FileAccess.Read, 81920, isAsync: false),
                snapshot);
            return LocalUpdateMetadataOpenStatus.Opened;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public bool IsSafeRead(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataReadLease file,
        string expectedPath)
    {
        if (directory is not WindowsDirectoryLease parent
            || file is not WindowsReadLease read
            || read.Stream.SafeFileHandle.IsClosed
            || !IsSafeDirectory(parent, parent.Snapshot.Path)
            || !IsDirectChild(parent, expectedPath))
        {
            return false;
        }

        var canonical = GetCanonicalPath(expectedPath);
        var current = ReadSnapshot(read.Stream.SafeFileHandle, canonical);
        return IsSafeFileSnapshot(current, canonical, parent.Snapshot.Identity.VolumeSerialNumber)
            && SameSnapshot(read.Snapshot, current);
    }

    public byte[]? ReadBounded(ILocalUpdateMetadataReadLease file, long maximumBytes)
    {
        if (file is not WindowsReadLease read || maximumBytes < 0)
        {
            return null;
        }

        var stream = read.Stream;
        var length = stream.Length;
        if (length < 0 || length > maximumBytes || length > int.MaxValue)
        {
            return null;
        }

        var bytes = new byte[(int)length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var count = stream.Read(bytes, offset, bytes.Length - offset);
            if (count == 0) return null;
            offset += count;
        }

        return stream.Length == length && stream.ReadByte() == -1 ? bytes : null;
    }

    public LocalUpdateMetadataDestination InspectDestination(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath)
    {
        if (directory is not WindowsDirectoryLease parent
            || !IsDirectChild(parent, expectedPath)
            || !IsSafeDirectory(parent, parent.Snapshot.Path))
        {
            return UnsafeDestination();
        }

        var canonical = GetCanonicalPath(expectedPath);
        using var handle = Open(
            canonical,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            OpenExisting,
            FileFlagOpenReparsePoint,
            out var error);
        if (handle.IsInvalid)
        {
            return IsMissing(error)
                ? new LocalUpdateMetadataDestination(LocalUpdateMetadataEntryState.Missing, default)
                : throw CreateIoException("inspect metadata destination", canonical, error);
        }

        var snapshot = ReadSnapshot(handle, canonical);
        return IsSafeFileSnapshot(snapshot, canonical, parent.Snapshot.Identity.VolumeSerialNumber)
            ? new LocalUpdateMetadataDestination(LocalUpdateMetadataEntryState.File, snapshot.Identity)
            : UnsafeDestination();
    }

    public LocalUpdateMetadataOpenStatus CreateNewTemp(
        ILocalUpdateMetadataDirectoryLease directory,
        string expectedPath,
        out ILocalUpdateMetadataWriteLease? lease)
    {
        lease = null;
        if (directory is not WindowsDirectoryLease parent
            || !IsDirectChild(parent, expectedPath)
            || !IsSafeDirectory(parent, parent.Snapshot.Path))
        {
            return LocalUpdateMetadataOpenStatus.Unsafe;
        }

        var canonical = GetCanonicalPath(expectedPath);
        var handle = Open(
            canonical,
            GenericWrite | DeleteAccess | FileReadAttributes,
            FileShareRead,
            CreateNew,
            FileAttributeNormal | FileFlagWriteThrough | FileFlagSequentialScan | FileFlagOpenReparsePoint,
            out var error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return error is ErrorFileExists or ErrorAlreadyExists
                ? LocalUpdateMetadataOpenStatus.Unsafe
                : throw CreateIoException("create metadata temporary file", canonical, error);
        }

        try
        {
            var snapshot = ReadSnapshot(handle, canonical);
            if (!IsSafeFileSnapshot(snapshot, canonical, parent.Snapshot.Identity.VolumeSerialNumber))
            {
                TryDeleteHandle(handle);
                handle.Dispose();
                return LocalUpdateMetadataOpenStatus.Unsafe;
            }

            lease = new WindowsWriteLease(
                new FileStream(handle, FileAccess.Write, 81920, isAsync: false),
                snapshot);
            return LocalUpdateMetadataOpenStatus.Opened;
        }
        catch
        {
            TryDeleteHandle(handle);
            handle.Dispose();
            throw;
        }
    }

    public bool IsSafeTemp(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string expectedPath)
    {
        if (directory is not WindowsDirectoryLease parent
            || file is not WindowsWriteLease write
            || write.Renamed
            || write.Stream.SafeFileHandle.IsClosed
            || !IsSafeDirectory(parent, parent.Snapshot.Path)
            || !IsDirectChild(parent, expectedPath))
        {
            return false;
        }

        var canonical = GetCanonicalPath(expectedPath);
        var current = ReadSnapshot(write.Stream.SafeFileHandle, canonical);
        return IsSafeFileSnapshot(current, canonical, parent.Snapshot.Identity.VolumeSerialNumber)
            && SameSnapshot(write.Snapshot, current);
    }

    public void Write(ILocalUpdateMetadataWriteLease file, byte[] bytes)
    {
        if (file is not WindowsWriteLease write)
        {
            throw new IOException("Metadata temporary-file lease is invalid.");
        }

        write.Stream.Write(bytes);
    }

    public void FlushToDisk(ILocalUpdateMetadataWriteLease file)
    {
        if (file is not WindowsWriteLease write)
        {
            throw new IOException("Metadata temporary-file lease is invalid.");
        }

        write.Stream.Flush(flushToDisk: true);
    }

    public bool Move(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath)
    {
        if (directory is not WindowsDirectoryLease parent
            || file is not WindowsWriteLease write
            || !IsSafeTemp(parent, write, write.Snapshot.Path)
            || !IsDirectChild(parent, destinationPath)
            || InspectDestination(parent, destinationPath).State != LocalUpdateMetadataEntryState.Missing)
        {
            return false;
        }

        var error = RenameHandle(parent, write, destinationPath, replace: false);
        if (error != 0)
        {
            return error is ErrorFileExists or ErrorAlreadyExists or ErrorAccessDenied
                && InspectDestination(parent, destinationPath).State != LocalUpdateMetadataEntryState.Missing
                ? false
                : throw CreateIoException("move metadata temporary file", destinationPath, error);
        }

        write.Renamed = true;
        write.CommittedPath = GetCanonicalPath(destinationPath);
        return true;
    }

    public bool Replace(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath,
        LocalUpdateMetadataFileIdentity expectedDestinationIdentity)
    {
        if (directory is not WindowsDirectoryLease parent
            || file is not WindowsWriteLease write
            || !IsSafeTemp(parent, write, write.Snapshot.Path)
            || !IsDirectChild(parent, destinationPath)
            || !TryOpenPinnedDestination(parent, destinationPath, expectedDestinationIdentity, out var destinationHandle))
        {
            return false;
        }

        using (destinationHandle)
        {
            var error = RenameHandle(parent, write, destinationPath, replace: true);
            if (error != 0)
            {
                throw CreateIoException("replace metadata destination", destinationPath, error);
            }
        }

        write.Renamed = true;
        write.CommittedPath = GetCanonicalPath(destinationPath);
        return true;
    }

    public bool IsCommitted(
        ILocalUpdateMetadataDirectoryLease directory,
        ILocalUpdateMetadataWriteLease file,
        string destinationPath)
    {
        if (directory is not WindowsDirectoryLease parent
            || file is not WindowsWriteLease write
            || !write.Renamed
            || write.CommittedPath is not string committedPath
            || !string.Equals(committedPath, GetCanonicalPath(destinationPath), StringComparison.OrdinalIgnoreCase)
            || !IsSafeDirectory(parent, parent.Snapshot.Path))
        {
            return false;
        }

        var current = ReadSnapshot(write.Stream.SafeFileHandle, committedPath);
        return IsSafeFileSnapshot(
                current,
                committedPath,
                parent.Snapshot.Identity.VolumeSerialNumber)
            && current.Identity == write.Snapshot.Identity;
    }

    public void DeleteOwned(ILocalUpdateMetadataWriteLease file)
    {
        if (file is not WindowsWriteLease write
            || write.Renamed
            || write.Deleted
            || write.Stream.SafeFileHandle.IsClosed)
        {
            return;
        }

        var current = ReadSnapshot(write.Stream.SafeFileHandle, write.Snapshot.Path);
        if (current.Identity != write.Snapshot.Identity || !current.IsFile || current.IsReparsePoint)
        {
            return;
        }

        if (!TryDeleteHandle(write.Stream.SafeFileHandle))
        {
            throw CreateIoException(
                "delete owned metadata temporary file",
                write.Snapshot.Path,
                Marshal.GetLastWin32Error());
        }

        write.Deleted = true;
    }

    private static bool TryOpenPinnedDestination(
        WindowsDirectoryLease parent,
        string destinationPath,
        LocalUpdateMetadataFileIdentity expectedIdentity,
        out SafeFileHandle handle)
    {
        var canonical = GetCanonicalPath(destinationPath);
        handle = Open(
            canonical,
            FileReadAttributes,
            FileShareRead | FileShareWrite,
            OpenExisting,
            FileFlagOpenReparsePoint,
            out var error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            handle = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
            if (IsMissing(error)) return false;
            throw CreateIoException("pin metadata destination", canonical, error);
        }

        var snapshot = ReadSnapshot(handle, canonical);
        if (!IsSafeFileSnapshot(snapshot, canonical, parent.Snapshot.Identity.VolumeSerialNumber)
            || snapshot.Identity != expectedIdentity)
        {
            handle.Dispose();
            handle = new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
            return false;
        }

        return true;
    }

    private static int RenameHandle(
        WindowsDirectoryLease parent,
        WindowsWriteLease source,
        string destinationPath,
        bool replace)
    {
        var fileName = GetCanonicalPath(destinationPath);
        var fileNameBytes = Encoding.Unicode.GetBytes(fileName);
        var rootOffset = IntPtr.Size;
        var lengthOffset = rootOffset + IntPtr.Size;
        var nameOffset = lengthOffset + sizeof(uint);
        var bufferSize = Align(nameOffset + fileNameBytes.Length + sizeof(char), IntPtr.Size);
        var buffer = new byte[bufferSize];
        if (replace)
        {
            BitConverter.GetBytes(FileRenameReplaceIfExists | FileRenamePosixSemantics)
                .CopyTo(buffer, 0);
        }

        BitConverter.GetBytes((uint)fileNameBytes.Length).CopyTo(buffer, lengthOffset);
        fileNameBytes.CopyTo(buffer, nameOffset);

        var pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var succeeded = SetFileInformationByHandle(
                source.Stream.SafeFileHandle,
                replace ? FileRenameInfoEx : FileRenameInfo,
                pinned.AddrOfPinnedObject(),
                (uint)buffer.Length);
            return succeeded ? 0 : Marshal.GetLastWin32Error();
        }
        finally
        {
            pinned.Free();
        }
    }

    private static int Align(int value, int alignment) =>
        checked((value + alignment - 1) / alignment * alignment);

    private static SafeFileHandle Open(
        string path,
        uint access,
        uint share,
        uint creationDisposition,
        uint flags,
        out int error)
    {
        var handle = CreateFileW(
            path,
            access,
            share,
            IntPtr.Zero,
            creationDisposition,
            flags,
            IntPtr.Zero);
        error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    private static FileSnapshot ReadSnapshot(SafeFileHandle handle, string expectedPath)
    {
        if (!GetFileInformationByHandle(handle, out var basicInformation))
        {
            throw CreateIoException("read metadata file attributes", expectedPath, Marshal.GetLastWin32Error());
        }

        if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfoClass,
                out var identityInformation,
                (uint)Marshal.SizeOf<FileIdInformation>()))
        {
            throw CreateIoException("read metadata file identity", expectedPath, Marshal.GetLastWin32Error());
        }

        return new FileSnapshot(
            GetCanonicalPath(expectedPath),
            GetFinalPath(handle, expectedPath),
            new LocalUpdateMetadataFileIdentity(
                identityInformation.VolumeSerialNumber,
                identityInformation.FileId.Low,
                identityInformation.FileId.High),
            (basicInformation.FileAttributes & FileAttributeDirectory) != 0,
            (basicInformation.FileAttributes & FileAttributeReparsePoint) != 0,
            (basicInformation.FileAttributes & FileAttributeDevice) != 0);
    }

    private static string GetFinalPath(SafeFileHandle handle, string expectedPath)
    {
        var required = GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0)
        {
            throw CreateIoException("read metadata final path", expectedPath, Marshal.GetLastWin32Error());
        }

        var buffer = new StringBuilder(checked((int)required + 1));
        var written = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity)
        {
            throw CreateIoException("read metadata final path", expectedPath, Marshal.GetLastWin32Error());
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

    private static bool IsSafeDirectorySnapshot(FileSnapshot snapshot, string expectedPath) =>
        snapshot.IsDirectory
        && !snapshot.IsReparsePoint
        && !snapshot.IsDevice
        && string.Equals(snapshot.FinalPath, expectedPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeFileSnapshot(
        FileSnapshot snapshot,
        string expectedPath,
        ulong expectedVolumeSerialNumber) =>
        snapshot.IsFile
        && !snapshot.IsReparsePoint
        && !snapshot.IsDevice
        && snapshot.Identity.VolumeSerialNumber == expectedVolumeSerialNumber
        && string.Equals(snapshot.FinalPath, expectedPath, StringComparison.OrdinalIgnoreCase);

    private static bool SameSnapshot(FileSnapshot expected, FileSnapshot current) =>
        expected.Identity == current.Identity
        && expected.IsDirectory == current.IsDirectory
        && expected.IsReparsePoint == current.IsReparsePoint
        && expected.IsDevice == current.IsDevice
        && string.Equals(expected.FinalPath, current.FinalPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsDirectChild(WindowsDirectoryLease directory, string path)
    {
        var canonical = GetCanonicalPath(path);
        return string.Equals(
            Path.GetDirectoryName(canonical),
            directory.Snapshot.Path,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string GetCanonicalPath(string path)
    {
        var canonical = Path.GetFullPath(path);
        if (!string.Equals(path, canonical, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("Metadata path is not canonical.");
        }

        return canonical;
    }

    private static bool IsMissing(int error) => error is ErrorFileNotFound or ErrorPathNotFound;

    private static LocalUpdateMetadataDestination UnsafeDestination() =>
        new(LocalUpdateMetadataEntryState.Unsafe, default);

    private static bool TryDeleteHandle(SafeFileHandle handle)
    {
        var disposition = new FileDispositionInformation { DeleteFile = true };
        return SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            ref disposition,
            (uint)Marshal.SizeOf<FileDispositionInformation>());
    }

    private static IOException CreateIoException(string operation, string path, int error) =>
        new($"Could not {operation} at '{path}'.", new Win32Exception(error));

    private sealed record FileSnapshot(
        string Path,
        string FinalPath,
        LocalUpdateMetadataFileIdentity Identity,
        bool IsDirectory,
        bool IsReparsePoint,
        bool IsDevice)
    {
        public bool IsFile => !IsDirectory && !IsDevice;
    }

    private sealed class WindowsDirectoryLease(SafeFileHandle handle, FileSnapshot snapshot)
        : ILocalUpdateMetadataDirectoryLease
    {
        public SafeFileHandle Handle { get; } = handle;
        public FileSnapshot Snapshot { get; } = snapshot;
        public void Dispose() => Handle.Dispose();
    }

    private sealed class WindowsReadLease(FileStream stream, FileSnapshot snapshot)
        : ILocalUpdateMetadataReadLease
    {
        public FileStream Stream { get; } = stream;
        public FileSnapshot Snapshot { get; } = snapshot;
        public void Dispose() => Stream.Dispose();
    }

    private sealed class WindowsWriteLease(FileStream stream, FileSnapshot snapshot)
        : ILocalUpdateMetadataWriteLease
    {
        public FileStream Stream { get; } = stream;
        public FileSnapshot Snapshot { get; } = snapshot;
        public bool Renamed { get; set; }
        public bool Deleted { get; set; }
        public string? CommittedPath { get; set; }
        public void Dispose() => Stream.Dispose();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool DeleteFile;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct FileId128
    {
        public ulong Low;
        public ulong High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInformation
    {
        public ulong VolumeSerialNumber;
        public FileId128 FileId;
    }

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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder? lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        IntPtr lpFileInformation,
        uint dwBufferSize);

    [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileDispositionInformation lpFileInformation,
        uint dwBufferSize);
}
