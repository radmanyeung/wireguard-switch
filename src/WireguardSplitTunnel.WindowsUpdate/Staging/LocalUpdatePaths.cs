using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

public enum LocalUpdatePathError
{
    None,
    InvalidVersion,
    InvalidRoot,
    UnsafePath,
    IoFailure,
    MetadataMismatch
}

public sealed record LocalUpdateLayout
{
    internal LocalUpdateLayout(
        SemanticVersion version,
        string productRoot,
        string metadataPath,
        string updatesRoot,
        string versionRoot,
        string stagingRoot,
        string archivePath,
        string checksumPath,
        string candidateRoot,
        string manifestPath)
    {
        Version = version;
        ProductRoot = productRoot;
        MetadataPath = metadataPath;
        UpdatesRoot = updatesRoot;
        VersionRoot = versionRoot;
        StagingRoot = stagingRoot;
        ArchivePath = archivePath;
        ChecksumPath = checksumPath;
        CandidateRoot = candidateRoot;
        ManifestPath = manifestPath;
    }

    public SemanticVersion Version { get; }
    public string ProductRoot { get; }
    public string MetadataPath { get; }
    public string UpdatesRoot { get; }
    public string VersionRoot { get; }
    public string StagingRoot { get; }
    public string ArchivePath { get; }
    public string ChecksumPath { get; }
    public string CandidateRoot { get; }
    public string ManifestPath { get; }
}

public sealed record LocalUpdatePathResult(
    bool Success,
    LocalUpdateLayout? Layout,
    LocalUpdatePathError Error)
{
    internal static LocalUpdatePathResult Failed(LocalUpdatePathError error) => new(false, null, error);
    internal static LocalUpdatePathResult Valid(LocalUpdateLayout layout) => new(true, layout, LocalUpdatePathError.None);
}

public sealed record LocalUpdateRootResult(
    bool Success,
    string? ProductRoot,
    string? MetadataPath,
    LocalUpdatePathError Error)
{
    internal static LocalUpdateRootResult Failed(LocalUpdatePathError error) => new(false, null, null, error);
    internal static LocalUpdateRootResult Valid(string root, string metadataPath) => new(true, root, metadataPath, LocalUpdatePathError.None);
}

internal enum LocalUpdateCleanupEntryKind
{
    Missing,
    File,
    Directory,
    ReparsePoint,
    Other
}

internal readonly record struct LocalUpdateCleanupIdentity(
    ulong VolumeSerialNumber,
    ulong FileIdLow,
    ulong FileIdHigh);

internal sealed record LocalUpdateCleanupEntry(
    string Path,
    string FinalPath,
    LocalUpdateCleanupEntryKind Kind,
    LocalUpdateCleanupIdentity Identity);

internal interface ILocalUpdateCleanupFileSystem
{
    LocalUpdateCleanupEntry Inspect(string path);
    bool IsSameEntry(LocalUpdateCleanupEntry entry);
    bool TryEnumerate(LocalUpdateCleanupEntry directory, out IReadOnlyList<LocalUpdateCleanupEntry> entries);
    bool DeleteFile(LocalUpdateCleanupEntry file);
    bool DeleteDirectory(LocalUpdateCleanupEntry directory);
}

/// <summary>Owns the fixed LocalAppData directory names used for unprivileged update staging.</summary>
public sealed class LocalUpdatePaths
{
    private const string ProductDirectoryName = "WireguardSplitTunnel";
    private const string MetadataFileName = "update-metadata.json";
    private const string ArchiveFileName = "wireguard-split-tunnel-win-x64.zip";
    private const string ChecksumFileName = "wireguard-split-tunnel-win-x64.zip.sha256";
    private const string ManifestFileName = "release-manifest.json";

    private readonly string? _localAppDataRoot;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private readonly Func<string, DriveType> _getDriveType;
    private readonly ILocalUpdateCleanupFileSystem _cleanupFileSystem;
    private readonly IPinnedLocalDirectoryService _directories;

    public LocalUpdatePaths()
        : this(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            new WindowsPathSafetyInspector(),
            root => new DriveInfo(root).DriveType,
            new WindowsLocalUpdateCleanupFileSystem(),
            new WindowsPinnedLocalDirectoryService())
    {
    }

    internal LocalUpdatePaths(
        string? localAppDataRoot,
        IPathSafetyInspector pathSafetyInspector,
        Func<string, DriveType> getDriveType)
        : this(
            localAppDataRoot,
            pathSafetyInspector,
            getDriveType,
            new WindowsLocalUpdateCleanupFileSystem(),
            new WindowsPinnedLocalDirectoryService())
    {
    }

    internal LocalUpdatePaths(
        string? localAppDataRoot,
        IPathSafetyInspector pathSafetyInspector,
        Func<string, DriveType> getDriveType,
        ILocalUpdateCleanupFileSystem cleanupFileSystem)
        : this(
            localAppDataRoot,
            pathSafetyInspector,
            getDriveType,
            cleanupFileSystem,
            new WindowsPinnedLocalDirectoryService())
    {
    }

    internal LocalUpdatePaths(
        string? localAppDataRoot,
        IPathSafetyInspector pathSafetyInspector,
        Func<string, DriveType> getDriveType,
        ILocalUpdateCleanupFileSystem cleanupFileSystem,
        IPinnedLocalDirectoryService directories)
    {
        _localAppDataRoot = localAppDataRoot;
        _pathSafetyInspector = pathSafetyInspector ?? throw new ArgumentNullException(nameof(pathSafetyInspector));
        _getDriveType = getDriveType ?? throw new ArgumentNullException(nameof(getDriveType));
        _cleanupFileSystem = cleanupFileSystem ?? throw new ArgumentNullException(nameof(cleanupFileSystem));
        _directories = directories ?? throw new ArgumentNullException(nameof(directories));
    }

    public LocalUpdateRootResult GetRoot()
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(_localAppDataRoot, _getDriveType, out var localAppDataRoot)
            || localAppDataRoot is null)
        {
            return LocalUpdateRootResult.Failed(LocalUpdatePathError.InvalidRoot);
        }

        var root = Path.Combine(localAppDataRoot, ProductDirectoryName);

        return IsSafeExistingAncestors(root)
            ? LocalUpdateRootResult.Valid(root, Path.Combine(root, MetadataFileName))
            : LocalUpdateRootResult.Failed(LocalUpdatePathError.UnsafePath);
    }

    public LocalUpdateRootResult EnsureRoot()
    {
        var root = GetRoot();
        if (!root.Success || root.ProductRoot is null)
        {
            return root;
        }

        try
        {
            var anchor = Path.GetDirectoryName(root.ProductRoot);
            if (string.IsNullOrEmpty(anchor))
            {
                return LocalUpdateRootResult.Failed(LocalUpdatePathError.InvalidRoot);
            }

            var status = _directories.EnsureDirectory(anchor, [ProductDirectoryName]);
            return status == PinnedDirectoryStatus.Opened
                && IsSafeExistingAncestors(root.ProductRoot)
                    ? root
                    : LocalUpdateRootResult.Failed(MapPinnedStatus(status));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return LocalUpdateRootResult.Failed(LocalUpdatePathError.IoFailure);
        }
    }

    public LocalUpdatePathResult GetLayout(SemanticVersion version)
    {
        if (!IsStrictVersion(version))
        {
            return LocalUpdatePathResult.Failed(LocalUpdatePathError.InvalidVersion);
        }

        var root = GetRoot();
        if (!root.Success || root.ProductRoot is null || root.MetadataPath is null)
        {
            return LocalUpdatePathResult.Failed(root.Error);
        }

        var updatesRoot = Path.Combine(root.ProductRoot, "updates");
        var versionRoot = Path.Combine(updatesRoot, version.ToString());
        var stagingRoot = Path.Combine(versionRoot, "staging");
        var candidateRoot = Path.Combine(versionRoot, "candidate");
        var layout = new LocalUpdateLayout(
            version,
            root.ProductRoot,
            root.MetadataPath,
            updatesRoot,
            versionRoot,
            stagingRoot,
            Path.Combine(stagingRoot, ArchiveFileName),
            Path.Combine(stagingRoot, ChecksumFileName),
            candidateRoot,
            Path.Combine(candidateRoot, ManifestFileName));

        return HasCanonicalContainedPaths(layout)
            ? LocalUpdatePathResult.Valid(layout)
            : LocalUpdatePathResult.Failed(LocalUpdatePathError.UnsafePath);
    }

    public LocalUpdatePathResult EnsureStaging(SemanticVersion version)
    {
        var result = GetLayout(version);
        if (!result.Success || result.Layout is null)
        {
            return result;
        }

        try
        {
            if (!IsSafeExistingAncestors(result.Layout.ProductRoot)
                || !IsSafeExistingAncestors(result.Layout.UpdatesRoot)
                || !IsSafeExistingAncestors(result.Layout.VersionRoot)
                || !IsSafeExistingAncestors(result.Layout.StagingRoot))
            {
                return LocalUpdatePathResult.Failed(LocalUpdatePathError.UnsafePath);
            }

            var anchor = Path.GetDirectoryName(result.Layout.ProductRoot);
            if (string.IsNullOrEmpty(anchor))
            {
                return LocalUpdatePathResult.Failed(LocalUpdatePathError.InvalidRoot);
            }

            var status = _directories.EnsureDirectory(
                anchor,
                [ProductDirectoryName, "updates", version.ToString(), "staging"]);
            return status == PinnedDirectoryStatus.Opened
                && IsSafeExistingAncestors(result.Layout.ProductRoot)
                && IsSafeExistingAncestors(result.Layout.UpdatesRoot)
                && IsSafeExistingAncestors(result.Layout.VersionRoot)
                && IsSafeExistingAncestors(result.Layout.StagingRoot)
                ? result
                : LocalUpdatePathResult.Failed(MapPinnedStatus(status));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return LocalUpdatePathResult.Failed(LocalUpdatePathError.IoFailure);
        }
    }

    /// <summary>Recomputes all staged paths; persisted values are only equality-checked hints.</summary>
    public LocalUpdatePathResult TryResolve(LocalStagedUpdate? stagedUpdate)
    {
        if (stagedUpdate is null || !IsStrictVersion(stagedUpdate.Version))
        {
            return LocalUpdatePathResult.Failed(LocalUpdatePathError.MetadataMismatch);
        }

        var result = GetLayout(stagedUpdate.Version);
        if (!result.Success || result.Layout is null)
        {
            return result;
        }

        var layout = result.Layout;
        return string.Equals(stagedUpdate.ArchivePath, layout.ArchivePath, StringComparison.Ordinal)
            && string.Equals(stagedUpdate.ChecksumPath, layout.ChecksumPath, StringComparison.Ordinal)
            && string.Equals(stagedUpdate.ManifestPath, layout.ManifestPath, StringComparison.Ordinal)
            && string.Equals(stagedUpdate.CandidateRoot, layout.CandidateRoot, StringComparison.Ordinal)
            ? result
            : LocalUpdatePathResult.Failed(LocalUpdatePathError.MetadataMismatch);
    }

    /// <summary>Recomputes and validates a layout rather than trusting caller-provided paths.</summary>
    public LocalUpdatePathResult TryValidateLayout(LocalUpdateLayout? layout)
    {
        if (layout is null || !IsStrictVersion(layout.Version))
        {
            return LocalUpdatePathResult.Failed(LocalUpdatePathError.MetadataMismatch);
        }

        var expected = GetLayout(layout.Version);
        if (!expected.Success || expected.Layout is null)
        {
            return expected;
        }

        var canonical = expected.Layout;
        return layout.Version == canonical.Version
            && string.Equals(layout.ProductRoot, canonical.ProductRoot, StringComparison.Ordinal)
            && string.Equals(layout.MetadataPath, canonical.MetadataPath, StringComparison.Ordinal)
            && string.Equals(layout.UpdatesRoot, canonical.UpdatesRoot, StringComparison.Ordinal)
            && string.Equals(layout.VersionRoot, canonical.VersionRoot, StringComparison.Ordinal)
            && string.Equals(layout.StagingRoot, canonical.StagingRoot, StringComparison.Ordinal)
            && string.Equals(layout.ArchivePath, canonical.ArchivePath, StringComparison.Ordinal)
            && string.Equals(layout.ChecksumPath, canonical.ChecksumPath, StringComparison.Ordinal)
            && string.Equals(layout.CandidateRoot, canonical.CandidateRoot, StringComparison.Ordinal)
            && string.Equals(layout.ManifestPath, canonical.ManifestPath, StringComparison.Ordinal)
            ? expected
            : LocalUpdatePathResult.Failed(LocalUpdatePathError.MetadataMismatch);
    }

    /// <summary>Deletes exactly one recomputed version tree with identity-bound, no-follow operations.</summary>
    public LocalUpdatePathResult CleanupVersion(SemanticVersion version)
    {
        var result = GetLayout(version);
        if (!result.Success || result.Layout is null)
        {
            return result;
        }

        try
        {
            if (!IsSafeExistingAncestors(result.Layout.ProductRoot)
                || !IsSafeExistingAncestors(result.Layout.UpdatesRoot)
                || !IsSafeExistingAncestors(result.Layout.VersionRoot)
                || !HasSafeCleanupAncestor(result.Layout.ProductRoot)
                || !HasSafeCleanupAncestor(result.Layout.UpdatesRoot))
            {
                return LocalUpdatePathResult.Failed(LocalUpdatePathError.UnsafePath);
            }

            var versionRoot = _cleanupFileSystem.Inspect(result.Layout.VersionRoot);
            if (versionRoot.Kind == LocalUpdateCleanupEntryKind.Missing)
            {
                return result;
            }

            return IsSafeCleanupEntry(versionRoot, LocalUpdateCleanupEntryKind.Directory)
                && TryDeleteTree(versionRoot)
                ? result
                : LocalUpdatePathResult.Failed(LocalUpdatePathError.UnsafePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return LocalUpdatePathResult.Failed(LocalUpdatePathError.IoFailure);
        }
    }

    /// <summary>Deletes only the recomputed candidate tree while preserving downloaded staging files.</summary>
    public LocalUpdatePathResult CleanupCandidate(SemanticVersion version)
    {
        var result = GetLayout(version);
        if (!result.Success || result.Layout is null)
        {
            return result;
        }

        try
        {
            if (!IsSafeExistingAncestors(result.Layout.ProductRoot)
                || !IsSafeExistingAncestors(result.Layout.UpdatesRoot)
                || !IsSafeExistingAncestors(result.Layout.VersionRoot)
                || !IsSafeExistingAncestors(result.Layout.CandidateRoot)
                || !HasSafeCleanupAncestor(result.Layout.ProductRoot)
                || !HasSafeCleanupAncestor(result.Layout.UpdatesRoot)
                || !HasSafeCleanupAncestor(result.Layout.VersionRoot))
            {
                return LocalUpdatePathResult.Failed(LocalUpdatePathError.UnsafePath);
            }

            var candidateRoot = _cleanupFileSystem.Inspect(
                result.Layout.CandidateRoot);
            if (candidateRoot.Kind
                == LocalUpdateCleanupEntryKind.Missing)
            {
                return result;
            }

            return IsSafeCleanupEntry(
                    candidateRoot,
                    LocalUpdateCleanupEntryKind.Directory)
                && TryDeleteTree(candidateRoot)
                ? result
                : LocalUpdatePathResult.Failed(
                    LocalUpdatePathError.UnsafePath);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException)
        {
            return LocalUpdatePathResult.Failed(
                LocalUpdatePathError.IoFailure);
        }
    }

    internal bool IsSafeExistingFile(string path)
    {
        try
        {
            return File.Exists(path)
                && !_pathSafetyInspector.IsReparsePoint(path)
                && IsSafeExistingAncestors(Path.GetDirectoryName(path));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private bool IsSafeExistingAncestors(string? path)
    {
        for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (Directory.Exists(current) && _pathSafetyInspector.IsReparsePoint(current))
            {
                return false;
            }

            var parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
        }

        return true;
    }

    private bool HasSafeCleanupAncestor(string path)
    {
        var entry = _cleanupFileSystem.Inspect(path);
        return entry.Kind == LocalUpdateCleanupEntryKind.Missing
            || IsSafeCleanupEntry(entry, LocalUpdateCleanupEntryKind.Directory)
            && _cleanupFileSystem.IsSameEntry(entry);
    }

    private bool TryDeleteTree(LocalUpdateCleanupEntry root)
    {
        var pending = new Stack<(LocalUpdateCleanupEntry Entry, bool ChildrenVisited)>();
        pending.Push((root, false));

        while (pending.Count > 0)
        {
            var (entry, childrenVisited) = pending.Pop();
            if (entry.Kind == LocalUpdateCleanupEntryKind.File)
            {
                if (!IsSafeCleanupEntry(entry, LocalUpdateCleanupEntryKind.File)
                    || !_cleanupFileSystem.IsSameEntry(entry)
                    || !_cleanupFileSystem.DeleteFile(entry)
                    || _cleanupFileSystem.Inspect(entry.Path).Kind != LocalUpdateCleanupEntryKind.Missing)
                {
                    return false;
                }

                continue;
            }

            if (!IsSafeCleanupEntry(entry, LocalUpdateCleanupEntryKind.Directory)
                || !_cleanupFileSystem.IsSameEntry(entry))
            {
                return false;
            }

            if (childrenVisited)
            {
                if (!_cleanupFileSystem.IsSameEntry(entry)
                    || !_cleanupFileSystem.DeleteDirectory(entry)
                    || _cleanupFileSystem.Inspect(entry.Path).Kind != LocalUpdateCleanupEntryKind.Missing)
                {
                    return false;
                }

                continue;
            }

            if (!_cleanupFileSystem.TryEnumerate(entry, out var children)
                || !_cleanupFileSystem.IsSameEntry(entry)
                || !HaveSafeDirectChildren(entry, children))
            {
                return false;
            }

            pending.Push((entry, true));
            for (var index = children.Count - 1; index >= 0; index--)
            {
                pending.Push((children[index], false));
            }
        }

        return true;
    }

    private static bool HaveSafeDirectChildren(
        LocalUpdateCleanupEntry directory,
        IReadOnlyList<LocalUpdateCleanupEntry> children)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in children)
        {
            if (child.Kind is not (LocalUpdateCleanupEntryKind.File or LocalUpdateCleanupEntryKind.Directory)
                || !string.Equals(Path.GetDirectoryName(child.Path), directory.Path, StringComparison.OrdinalIgnoreCase)
                || !seen.Add(child.Path)
                || !IsExpectedFinalPath(child))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSafeCleanupEntry(LocalUpdateCleanupEntry entry, LocalUpdateCleanupEntryKind expectedKind) =>
        entry.Kind == expectedKind && IsExpectedFinalPath(entry);

    private static bool IsExpectedFinalPath(LocalUpdateCleanupEntry entry) =>
        string.Equals(entry.Path, entry.FinalPath, StringComparison.OrdinalIgnoreCase);

    private static bool IsStrictVersion(SemanticVersion version) =>
        version.Major >= 0
        && version.Minor >= 0
        && version.Patch >= 0
        && SemanticVersion.TryParseNormalized(version.ToString(), out var roundTripped)
        && roundTripped == version;

    private static LocalUpdatePathError MapPinnedStatus(PinnedDirectoryStatus status) =>
        status is PinnedDirectoryStatus.Unsafe
            or PinnedDirectoryStatus.Exists
            or PinnedDirectoryStatus.Missing
            ? LocalUpdatePathError.UnsafePath
            : LocalUpdatePathError.IoFailure;

    private bool HasCanonicalContainedPaths(LocalUpdateLayout layout)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(layout.ProductRoot, _getDriveType, out var root)
            || root is null)
        {
            return false;
        }

        return new[]
            {
                layout.MetadataPath, layout.UpdatesRoot, layout.VersionRoot, layout.StagingRoot,
                layout.ArchivePath, layout.ChecksumPath, layout.CandidateRoot, layout.ManifestPath
            }
            .All(path => IsContainedBy(path, root));
    }

    private static bool IsContainedBy(string path, string root)
    {
        try
        {
            var canonical = Path.GetFullPath(path);
            return canonical.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or IOException)
        {
            return false;
        }
    }
}

/// <summary>
/// Captures identity and final path through no-follow handles. Enumeration pins the directory
/// against rename, and deletion marks the exact opened file-system object for removal.
/// </summary>
internal sealed class WindowsLocalUpdateCleanupFileSystem : ILocalUpdateCleanupFileSystem
{
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint DeleteAccess = 0x00010000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int FileDispositionInfo = 4;
    private const int FileIdInfo = 18;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeDevice = 0x00000040;
    private const uint FileAttributeReparsePoint = 0x00000400;

    public LocalUpdateCleanupEntry Inspect(string path)
    {
        var canonical = GetCanonicalPath(path);
        using var handle = Open(canonical, FileReadAttributes, FileShareRead | FileShareWrite | FileShareDelete, out var error);
        if (handle.IsInvalid)
        {
            return error is ErrorFileNotFound or ErrorPathNotFound
                ? Missing(canonical)
                : throw CreateIoException("open", canonical, error);
        }

        return ReadEntry(handle, canonical);
    }

    public bool IsSameEntry(LocalUpdateCleanupEntry entry)
    {
        if (entry.Kind == LocalUpdateCleanupEntryKind.Missing)
        {
            return Inspect(entry.Path).Kind == LocalUpdateCleanupEntryKind.Missing;
        }

        var current = Inspect(entry.Path);
        return SameEntry(entry, current);
    }

    public bool TryEnumerate(
        LocalUpdateCleanupEntry directory,
        out IReadOnlyList<LocalUpdateCleanupEntry> entries)
    {
        entries = [];
        using var handle = Open(
            directory.Path,
            FileListDirectory | FileReadAttributes,
            FileShareRead | FileShareWrite,
            out var error);
        if (handle.IsInvalid)
        {
            if (error is ErrorFileNotFound or ErrorPathNotFound) return false;
            throw CreateIoException("open directory", directory.Path, error);
        }

        if (!SameEntry(directory, ReadEntry(handle, directory.Path)))
        {
            return false;
        }

        var captured = new List<LocalUpdateCleanupEntry>();
        foreach (var path in Directory.EnumerateFileSystemEntries(directory.Path))
        {
            captured.Add(Inspect(path));
        }

        if (!SameEntry(directory, ReadEntry(handle, directory.Path)))
        {
            return false;
        }

        entries = captured;
        return true;
    }

    public bool DeleteFile(LocalUpdateCleanupEntry file) =>
        Delete(file, LocalUpdateCleanupEntryKind.File);

    public bool DeleteDirectory(LocalUpdateCleanupEntry directory) =>
        Delete(directory, LocalUpdateCleanupEntryKind.Directory);

    private static bool Delete(LocalUpdateCleanupEntry expected, LocalUpdateCleanupEntryKind expectedKind)
    {
        if (expected.Kind != expectedKind) return false;

        using var handle = Open(
            expected.Path,
            DeleteAccess | FileReadAttributes,
            FileShareRead | FileShareWrite,
            out var error);
        if (handle.IsInvalid)
        {
            if (error is ErrorFileNotFound or ErrorPathNotFound) return false;
            throw CreateIoException("open for deletion", expected.Path, error);
        }

        if (!SameEntry(expected, ReadEntry(handle, expected.Path)))
        {
            return false;
        }

        var disposition = new FileDispositionInformation { DeleteFile = true };
        if (!SetFileInformationByHandle(
                handle,
                FileDispositionInfo,
                ref disposition,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw CreateIoException("delete", expected.Path, Marshal.GetLastWin32Error());
        }

        return true;
    }

    private static SafeFileHandle Open(string path, uint access, uint share, out int error)
    {
        var handle = CreateFileW(
            path,
            access,
            share,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        error = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    private static LocalUpdateCleanupEntry ReadEntry(SafeFileHandle handle, string requestedPath)
    {
        if (!GetFileInformationByHandle(handle, out var information))
        {
            throw CreateIoException("read identity", requestedPath, Marshal.GetLastWin32Error());
        }

        var attributes = information.FileAttributes;
        var kind = (attributes & FileAttributeReparsePoint) != 0
            ? LocalUpdateCleanupEntryKind.ReparsePoint
            : (attributes & FileAttributeDirectory) != 0
                ? LocalUpdateCleanupEntryKind.Directory
                : (attributes & FileAttributeDevice) != 0
                    ? LocalUpdateCleanupEntryKind.Other
                    : LocalUpdateCleanupEntryKind.File;
        if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                out var identity,
                (uint)Marshal.SizeOf<FileIdInformation>()))
        {
            throw CreateIoException("read full identity", requestedPath, Marshal.GetLastWin32Error());
        }

        return new LocalUpdateCleanupEntry(
            requestedPath,
            GetFinalPath(handle, requestedPath),
            kind,
            new LocalUpdateCleanupIdentity(
                identity.VolumeSerialNumber,
                identity.FileId.LowPart,
                identity.FileId.HighPart));
    }

    private static string GetFinalPath(SafeFileHandle handle, string requestedPath)
    {
        var required = GetFinalPathNameByHandleW(handle, null, 0, 0);
        if (required == 0)
        {
            throw CreateIoException("read final path", requestedPath, Marshal.GetLastWin32Error());
        }

        var buffer = new StringBuilder(checked((int)required + 1));
        var written = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity)
        {
            throw CreateIoException("read final path", requestedPath, Marshal.GetLastWin32Error());
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
        if (!string.Equals(canonical, path, StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("Cleanup path is not canonical.");
        }

        return canonical;
    }

    private static bool SameEntry(LocalUpdateCleanupEntry expected, LocalUpdateCleanupEntry current) =>
        expected.Kind == current.Kind
        && expected.Identity == current.Identity
        && string.Equals(expected.Path, current.Path, StringComparison.OrdinalIgnoreCase)
        && string.Equals(expected.FinalPath, current.FinalPath, StringComparison.OrdinalIgnoreCase);

    private static LocalUpdateCleanupEntry Missing(string path) =>
        new(path, path, LocalUpdateCleanupEntryKind.Missing, default);

    private static IOException CreateIoException(string operation, string path, int error) =>
        new($"Could not {operation} update staging path '{path}'.", new Win32Exception(error));

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
        public ulong LowPart;
        public ulong HighPart;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int fileInformationClass,
        ref FileDispositionInformation lpFileInformation,
        uint dwBufferSize);
}
