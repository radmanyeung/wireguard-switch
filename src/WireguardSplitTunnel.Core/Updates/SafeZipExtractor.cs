using System.IO.Compression;
using System.Security.Cryptography;
using System.Buffers.Binary;

namespace WireguardSplitTunnel.Core.Updates;

public enum SafeZipError
{
    None,
    InvalidLimits,
    ArchiveOpenFailed,
    InvalidOrder,
    TooManyEntries,
    InvalidPath,
    PathCollision,
    SpecialFile,
    FileTooLarge,
    ExpandedTooLarge,
    CompressionRatio,
    ReparsePoint,
    DestinationExists,
    IoFailure,
    Cancelled,
    ManifestMissing,
    ManifestDuplicate,
    ManifestTooLarge
}

public sealed record SafeZipEntryMetadata(string Path, bool IsDirectory, long Length, long CompressedLength);

public readonly record struct SafeZipHashResult(bool Success, string? Digest, SafeZipError ErrorCode)
{
    public static SafeZipHashResult Failure(SafeZipError error) => new(false, null, error);
    public static SafeZipHashResult Valid(string digest) => new(true, digest, SafeZipError.None);
}

public readonly record struct SafeZipPreflightResult(bool Success, SafeZipError ErrorCode)
{
    public static SafeZipPreflightResult Failure(SafeZipError error) => new(false, error);
    public static SafeZipPreflightResult Valid => new(true, SafeZipError.None);
}

public readonly record struct SafeZipOpenResult(
    bool Success,
    SafeZipPreflightSession? Session,
    SafeZipError ErrorCode) : IDisposable
{
    public static SafeZipOpenResult Failure(SafeZipError error) => new(false, null, error);
    public static SafeZipOpenResult Valid(SafeZipPreflightSession session) => new(true, session, SafeZipError.None);
    public void Dispose() => Session?.Dispose();
}

public readonly record struct SafeZipExtractionResult(
    bool Success,
    SafeZipError ErrorCode,
    SafeZipArtifactLease? Artifacts) : IDisposable
{
    public static SafeZipExtractionResult Valid(SafeZipArtifactLease artifacts) =>
        new(true, SafeZipError.None, artifacts);

    public static SafeZipExtractionResult Failure(SafeZipError error) =>
        new(false, error, null);

    public void Dispose() => Artifacts?.Dispose();
}

public readonly record struct SafeZipManifestResult(bool Success, byte[]? Bytes, SafeZipError ErrorCode)
{
    public static SafeZipManifestResult Failure(SafeZipError error) => new(false, null, error);
    public static SafeZipManifestResult Valid(byte[] bytes) => new(true, bytes, SafeZipError.None);
}

public sealed class SafeZipArtifactLease : IDisposable
{
    private readonly IReadOnlyList<string> _createdFiles;
    private readonly IReadOnlyList<string> _createdDirectories;
    private bool _committed;
    private bool _disposed;

    internal SafeZipArtifactLease(IReadOnlyList<string> createdFiles, IReadOnlyList<string> createdDirectories)
    {
        _createdFiles = Array.AsReadOnly(createdFiles.ToArray());
        _createdDirectories = Array.AsReadOnly(createdDirectories.ToArray());
    }

    public IReadOnlyList<string> CreatedFiles => _createdFiles;
    public IReadOnlyList<string> CreatedDirectories => _createdDirectories;

    public void Commit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _committed = true;
    }

    public void Rollback()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (!_committed)
        {
            RollbackExact(_createdFiles, _createdDirectories);
        }
    }

    public void Dispose() => Rollback();

    internal static void RollbackExact(
        IReadOnlyList<string> createdFiles,
        IReadOnlyList<string> createdDirectories)
    {
        for (var index = createdFiles.Count - 1; index >= 0; index--)
        {
            try
            {
                File.Delete(createdFiles[index]);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        for (var index = createdDirectories.Count - 1; index >= 0; index--)
        {
            try
            {
                Directory.Delete(createdDirectories[index], recursive: false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}

public static class SafeZipExtractor
{
    public static SafeZipOpenResult Open(
        Stream archiveStream,
        UpdatePackageLimits limits,
        IPathSafetyInspector? inspector = null)
    {
        if (!limits.Validate().Success)
        {
            return SafeZipOpenResult.Failure(
                SafeZipError.InvalidLimits);
        }

        if (!PositionPreservingReadStream.TryCreate(
                archiveStream,
                out var retained)
            || retained is null)
        {
            return SafeZipOpenResult.Failure(
                SafeZipError.ArchiveOpenFailed);
        }

        return OpenOwnedStream(
            retained,
            limits,
            inspector);
    }

    public static SafeZipOpenResult Open(
        string archivePath,
        UpdatePackageLimits limits,
        IPathSafetyInspector? inspector = null)
    {
        if (!limits.Validate().Success)
        {
            return SafeZipOpenResult.Failure(SafeZipError.InvalidLimits);
        }

        FileStream stream;
        try
        {
            stream = new FileStream(
                archivePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return SafeZipOpenResult.Failure(SafeZipError.ArchiveOpenFailed);
        }

        return OpenOwnedStream(stream, limits, inspector);
    }

    internal static SafeZipOpenResult OpenOwnedStream(
        Stream stream,
        UpdatePackageLimits limits,
        IPathSafetyInspector? inspector = null)
    {
        if (!limits.Validate().Success)
        {
            stream.Dispose();
            return SafeZipOpenResult.Failure(SafeZipError.InvalidLimits);
        }

        try
        {
            return SafeZipOpenResult.Valid(
                new SafeZipPreflightSession(
                    stream,
                    limits,
                    inspector ?? new FileSystemPathSafetyInspector()));
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException)
        {
            stream.Dispose();
            return SafeZipOpenResult.Failure(SafeZipError.ArchiveOpenFailed);
        }
    }

    public static SafeZipOpenResult OpenPreflight(
        string archivePath,
        UpdatePackageLimits limits,
        IPathSafetyInspector? inspector = null)
    {
        var opened = Open(archivePath, limits, inspector);
        if (!opened.Success)
        {
            return opened;
        }

        try
        {
            var hash = opened.Session!.ComputeSha256Async().GetAwaiter().GetResult();
            var preflight = hash.Success
                ? opened.Session.Preflight()
                : SafeZipPreflightResult.Failure(hash.ErrorCode);
            if (preflight.Success)
            {
                return opened;
            }

            opened.Dispose();
            return SafeZipOpenResult.Failure(preflight.ErrorCode);
        }
        catch (OperationCanceledException)
        {
            opened.Dispose();
            return SafeZipOpenResult.Failure(SafeZipError.Cancelled);
        }
    }

    internal static bool TryAdd(long left, long right, out long sum)
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

public sealed class SafeZipPreflightSession : IDisposable
{
    private readonly Stream _stream;
    private readonly UpdatePackageLimits _limits;
    private readonly IPathSafetyInspector _inspector;
    private ZipArchive? _archive;
    private IReadOnlyList<SafeZipEntryMetadata> _entries = Array.Empty<SafeZipEntryMetadata>();
    private bool _hashComputed;
    private bool _preflightComplete;
    private bool _disposed;

    internal SafeZipPreflightSession(
        Stream stream,
        UpdatePackageLimits limits,
        IPathSafetyInspector inspector)
    {
        _stream = stream;
        _limits = limits;
        _inspector = inspector;
        ArchiveLength = stream.Length;
    }

    public long ArchiveLength { get; }
    public IReadOnlyList<SafeZipEntryMetadata> Entries => _entries;

    public async Task<SafeZipHashResult> ComputeSha256Async(
        CancellationToken cancellationToken = default)
    {
        if (_disposed || _archive is not null)
        {
            return SafeZipHashResult.Failure(SafeZipError.InvalidOrder);
        }

        try
        {
            _stream.Position = 0;
            using var sha256 = SHA256.Create();
            var digest = await sha256.ComputeHashAsync(_stream, cancellationToken).ConfigureAwait(false);
            _stream.Position = 0;
            _hashComputed = true;
            return SafeZipHashResult.Valid(Convert.ToHexString(digest).ToLowerInvariant());
        }
        catch (OperationCanceledException)
        {
            _stream.Position = 0;
            return SafeZipHashResult.Failure(SafeZipError.Cancelled);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            return SafeZipHashResult.Failure(SafeZipError.IoFailure);
        }
    }

    public SafeZipPreflightResult Preflight()
    {
        if (_disposed || !_hashComputed || _preflightComplete)
        {
            return SafeZipPreflightResult.Failure(SafeZipError.InvalidOrder);
        }

        ZipArchive? archive = null;
        try
        {
            _stream.Position = 0;
            var declaredCountError = ReadDeclaredEntryCount(out var declaredCount);
            if (declaredCountError != SafeZipError.None)
            {
                return SafeZipPreflightResult.Failure(declaredCountError);
            }

            if (declaredCount > _limits.MaximumEntries
                || declaredCount > WindowsReleasePathPolicy.MaximumArchiveEntries)
            {
                return SafeZipPreflightResult.Failure(SafeZipError.TooManyEntries);
            }

            _stream.Position = 0;
            archive = new ZipArchive(_stream, ZipArchiveMode.Read, leaveOpen: true);
            var error = ValidateEntries(archive, out var entries);
            if (error != SafeZipError.None)
            {
                archive.Dispose();
                return SafeZipPreflightResult.Failure(error);
            }

            _archive = archive;
            _entries = Array.AsReadOnly(entries);
            _preflightComplete = true;
            return SafeZipPreflightResult.Valid;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            archive?.Dispose();
            return SafeZipPreflightResult.Failure(SafeZipError.ArchiveOpenFailed);
        }
    }

    public SafeZipManifestResult ReadManifest()
    {
        if (_disposed || !_preflightComplete || _archive is null)
        {
            return SafeZipManifestResult.Failure(SafeZipError.InvalidOrder);
        }

        var found = _archive.Entries
            .Where(entry => entry.FullName.Equals(
                UpdateReleaseContract.ReleaseManifestPath,
                StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();
        if (found.Length == 0)
        {
            return SafeZipManifestResult.Failure(SafeZipError.ManifestMissing);
        }

        if (found.Length != 1)
        {
            return SafeZipManifestResult.Failure(SafeZipError.ManifestDuplicate);
        }

        var entry = found[0];
        if (entry.Length < 0 || entry.Length > UpdateNetworkLimits.MetadataBytes)
        {
            return SafeZipManifestResult.Failure(SafeZipError.ManifestTooLarge);
        }

        try
        {
            using var input = entry.Open();
            using var output = new MemoryStream((int)entry.Length);
            var buffer = new byte[81920];
            long total = 0;
            while (true)
            {
                var remaining = UpdateNetworkLimits.MetadataBytes + 1 - total;
                if (remaining <= 0)
                {
                    return SafeZipManifestResult.Failure(SafeZipError.ManifestTooLarge);
                }

                var read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read == 0)
                {
                    break;
                }

                total += read;
                output.Write(buffer, 0, read);
            }

            if (total != entry.Length)
            {
                return SafeZipManifestResult.Failure(SafeZipError.ArchiveOpenFailed);
            }

            return SafeZipManifestResult.Valid(output.ToArray());
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException)
        {
            return SafeZipManifestResult.Failure(SafeZipError.ArchiveOpenFailed);
        }
    }

    public SafeZipExtractionResult ExtractTo(
        string candidateRoot,
        CancellationToken cancellationToken = default)
    {
        var createdFiles = new List<string>();
        var createdDirectories = new List<string>();
        try
        {
            if (_disposed || !_preflightComplete || _archive is null)
            {
                return SafeZipExtractionResult.Failure(SafeZipError.InvalidOrder);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var root = Path.GetFullPath(candidateRoot);
            if (File.Exists(root) || Directory.Exists(root))
            {
                return SafeZipExtractionResult.Failure(SafeZipError.DestinationExists);
            }

            var parent = Path.GetDirectoryName(root);
            if (string.IsNullOrEmpty(parent) || !Directory.Exists(parent))
            {
                return SafeZipExtractionResult.Failure(SafeZipError.IoFailure);
            }

            if (!IsChainSafe(parent, includeMissingLeaf: false) || _inspector.IsReparsePoint(root))
            {
                return SafeZipExtractionResult.Failure(SafeZipError.ReparsePoint);
            }

            Directory.CreateDirectory(root);
            createdDirectories.Add(root);
            if (!IsChainSafe(root, includeMissingLeaf: false))
            {
                return FailAndClean(
                    SafeZipError.ReparsePoint,
                    createdFiles,
                    createdDirectories);
            }

            foreach (var metadata in _entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var destination = Path.GetFullPath(
                    Path.Combine(
                        root,
                        metadata.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (!destination.StartsWith(
                    root + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return FailAndClean(
                        SafeZipError.InvalidPath,
                        createdFiles,
                        createdDirectories);
                }

                if (metadata.IsDirectory)
                {
                    var directoryResult = EnsureDirectory(
                        destination,
                        root,
                        createdDirectories);
                    if (directoryResult != SafeZipError.None)
                    {
                        return FailAndClean(
                            directoryResult,
                            createdFiles,
                            createdDirectories);
                    }

                    continue;
                }

                var parentResult = EnsureDirectory(
                    Path.GetDirectoryName(destination)!,
                    root,
                    createdDirectories);
                if (parentResult != SafeZipError.None)
                {
                    return FailAndClean(
                        parentResult,
                        createdFiles,
                        createdDirectories);
                }

                if (!IsChainSafe(Path.GetDirectoryName(destination)!, includeMissingLeaf: false)
                    || _inspector.IsReparsePoint(destination))
                {
                    return FailAndClean(
                        SafeZipError.ReparsePoint,
                        createdFiles,
                        createdDirectories);
                }

                var entry = _archive.GetEntry(metadata.Path);
                if (entry is null)
                {
                    return FailAndClean(
                        SafeZipError.ArchiveOpenFailed,
                        createdFiles,
                        createdDirectories);
                }

                long copied;
                using (var input = entry.Open())
                using (var output = new FileStream(
                           destination,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None))
                {
                    createdFiles.Add(destination);
                    copied = CopyBounded(
                        input,
                        output,
                        metadata.Length,
                        cancellationToken);
                }

                if (copied != metadata.Length)
                {
                    return FailAndClean(
                        SafeZipError.IoFailure,
                        createdFiles,
                        createdDirectories);
                }
            }

            var lease = new SafeZipArtifactLease(createdFiles, createdDirectories);
            return SafeZipExtractionResult.Valid(lease);
        }
        catch (OperationCanceledException)
        {
            return FailAndClean(
                SafeZipError.Cancelled,
                createdFiles,
                createdDirectories);
        }
        catch (Exception exception) when (exception is IOException)
        {
            return FailAndClean(
                SafeZipError.DestinationExists,
                createdFiles,
                createdDirectories);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            return FailAndClean(
                SafeZipError.IoFailure,
                createdFiles,
                createdDirectories);
        }
    }

    private SafeZipError ValidateEntries(
        ZipArchive archive,
        out SafeZipEntryMetadata[] entries)
    {
        entries = Array.Empty<SafeZipEntryMetadata>();
        if (archive.Entries.Count > _limits.MaximumEntries
            || archive.Entries.Count > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return SafeZipError.TooManyEntries;
        }

        var snapshot = new SafeZipEntryMetadata[archive.Entries.Count];
        var paths = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        for (var index = 0; index < archive.Entries.Count; index++)
        {
            var entry = archive.Entries[index];
            if (IsSpecial(entry))
            {
                return SafeZipError.SpecialFile;
            }

            var directory = entry.FullName.EndsWith('/');
            var raw = directory ? entry.FullName[..^1] : entry.FullName;
            var validation = WindowsReleasePathPolicy.Validate(raw);
            if (!validation.Success)
            {
                return SafeZipError.InvalidPath;
            }

            var path = validation.CanonicalKey!;
            if (paths.ContainsKey(path)
                && path.Equals(
                    UpdateReleaseContract.ReleaseManifestPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return SafeZipError.ManifestDuplicate;
            }

            if (paths.ContainsKey(path) || HasPrefixConflict(paths, path, directory))
            {
                return SafeZipError.PathCollision;
            }

            if (!directory
                && (entry.Length < 0
                    || entry.Length > _limits.MaximumFileBytes
                    || entry.CompressedLength < 0))
            {
                return SafeZipError.FileTooLarge;
            }

            if (!directory
                && entry.Length > 0
                && (entry.CompressedLength == 0
                    || (double)entry.Length / entry.CompressedLength
                        > _limits.MaximumCompressionRatio))
            {
                return SafeZipError.CompressionRatio;
            }

            if (!directory
                && (!SafeZipExtractor.TryAdd(total, entry.Length, out total)
                    || total > _limits.MaximumExpandedBytes))
            {
                return SafeZipError.ExpandedTooLarge;
            }

            paths.Add(path, directory);
            snapshot[index] = new SafeZipEntryMetadata(
                path,
                directory,
                entry.Length,
                entry.CompressedLength);
        }

        entries = snapshot;
        return SafeZipError.None;
    }

    private SafeZipError ReadDeclaredEntryCount(out int count)
    {
        count = 0;
        const int endRecordBytes = 22;
        var tailLength = (int)Math.Min(_stream.Length, endRecordBytes + ushort.MaxValue);
        if (tailLength < endRecordBytes)
        {
            return SafeZipError.ArchiveOpenFailed;
        }

        var tail = new byte[tailLength];
        _stream.Position = _stream.Length - tailLength;
        var offset = 0;
        while (offset < tail.Length)
        {
            var read = _stream.Read(tail, offset, tail.Length - offset);
            if (read == 0)
            {
                return SafeZipError.ArchiveOpenFailed;
            }

            offset += read;
        }

        for (var index = tail.Length - endRecordBytes; index >= 0; index--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan(index, 4)) != 0x06054b50)
            {
                continue;
            }

            var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(index + 20, 2));
            if (index + endRecordBytes + commentLength != tail.Length)
            {
                continue;
            }

            var disk = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(index + 4, 2));
            var centralDirectoryDisk = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(index + 6, 2));
            var entriesOnDisk = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(index + 8, 2));
            var totalEntries = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan(index + 10, 2));
            if (disk != 0 || centralDirectoryDisk != 0 || entriesOnDisk != totalEntries)
            {
                return SafeZipError.ArchiveOpenFailed;
            }

            if (totalEntries == ushort.MaxValue)
            {
                return SafeZipError.TooManyEntries;
            }

            count = totalEntries;
            return SafeZipError.None;
        }

        return SafeZipError.ArchiveOpenFailed;
    }

    private SafeZipError EnsureDirectory(
        string directory,
        string root,
        List<string> createdDirectories)
    {
        if (directory.Equals(root, StringComparison.OrdinalIgnoreCase))
        {
            return IsChainSafe(root, includeMissingLeaf: false)
                ? SafeZipError.None
                : SafeZipError.ReparsePoint;
        }

        var chain = new Stack<string>();
        for (var current = directory;
             !current.Equals(root, StringComparison.OrdinalIgnoreCase);
             current = Path.GetDirectoryName(current)!)
        {
            if (string.IsNullOrEmpty(current))
            {
                return SafeZipError.InvalidPath;
            }

            chain.Push(current);
        }

        while (chain.Count > 0)
        {
            var path = chain.Pop();
            if (Directory.Exists(path))
            {
                if (!IsChainSafe(path, includeMissingLeaf: false))
                {
                    return SafeZipError.ReparsePoint;
                }

                continue;
            }

            if (!IsChainSafe(Path.GetDirectoryName(path)!, includeMissingLeaf: false)
                || _inspector.IsReparsePoint(path))
            {
                return SafeZipError.ReparsePoint;
            }

            Directory.CreateDirectory(path);
            createdDirectories.Add(path);
            if (!IsChainSafe(path, includeMissingLeaf: false))
            {
                return SafeZipError.ReparsePoint;
            }
        }

        return SafeZipError.None;
    }

    private bool IsChainSafe(string path, bool includeMissingLeaf)
    {
        for (var current = path;
             !string.IsNullOrEmpty(current);
             current = Path.GetDirectoryName(current))
        {
            if ((includeMissingLeaf
                    || File.Exists(current)
                    || Directory.Exists(current))
                && _inspector.IsReparsePoint(current))
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

    private static bool IsSpecial(ZipArchiveEntry entry) =>
        ((entry.ExternalAttributes >> 16) & 0xF000)
            is 0xA000 or 0x2000 or 0x6000 or 0x1000 or 0xC000
        || (entry.ExternalAttributes & 0x400) != 0;

    private static bool HasPrefixConflict(
        IReadOnlyDictionary<string, bool> paths,
        string path,
        bool directory)
    {
        foreach (var pair in paths)
        {
            if ((path.StartsWith(pair.Key + "/", StringComparison.OrdinalIgnoreCase)
                    && !pair.Value)
                || (pair.Key.StartsWith(path + "/", StringComparison.OrdinalIgnoreCase)
                    && !directory))
            {
                return true;
            }
        }

        return false;
    }

    private static long CopyBounded(
        Stream input,
        Stream output,
        long expected,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                return total;
            }

            if (!SafeZipExtractor.TryAdd(total, read, out total) || total > expected)
            {
                throw new InvalidDataException();
            }

            output.Write(buffer, 0, read);
        }
    }

    private static SafeZipExtractionResult FailAndClean(
        SafeZipError error,
        IReadOnlyList<string> files,
        IReadOnlyList<string> directories)
    {
        SafeZipArtifactLease.RollbackExact(files, directories);
        return SafeZipExtractionResult.Failure(error);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _archive?.Dispose();
        _stream.Dispose();
    }
}

internal sealed class PositionPreservingReadStream : Stream
{
    private readonly Stream _inner;
    private readonly long _originalPosition;
    private readonly SemaphoreSlim _gate = new(
        initialCount: 1,
        maxCount: 1);
    private long _position;
    private bool _disposed;
    private bool _positionIntegrityLost;

    private PositionPreservingReadStream(
        Stream inner,
        long originalPosition)
    {
        _inner = inner;
        _originalPosition = originalPosition;
    }

    public override bool CanRead =>
        !_disposed
        && !_positionIntegrityLost
        && _inner.CanRead;

    public override bool CanSeek =>
        !_disposed
        && !_positionIntegrityLost
        && _inner.CanSeek;

    public override bool CanWrite => false;

    public override long Length =>
        ExecuteMetadata(() => _inner.Length);

    public override long Position
    {
        get => ExecuteMetadata(() => _position);
        set => ExecuteMetadata(
            () =>
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(value));
                }

                _position = value;
                return true;
            });
    }

    internal static bool TryCreate(
        Stream? inner,
        out PositionPreservingReadStream? retained)
    {
        retained = null;
        if (inner is null)
        {
            return false;
        }

        try
        {
            if (!inner.CanRead
                || !inner.CanSeek)
            {
                return false;
            }

            var originalPosition = inner.Position;
            if (originalPosition < 0
                || inner.Length < 0)
            {
                return false;
            }

            inner.Position = originalPosition;
            if (inner.Position != originalPosition)
            {
                return false;
            }

            retained = new PositionPreservingReadStream(
                inner,
                originalPosition);
            return true;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or ObjectDisposedException)
        {
            return false;
        }
    }

    public override void Flush() =>
        ExecuteMetadata(() => true);

    public override int Read(
        byte[] buffer,
        int offset,
        int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return ExecuteRead(
            () => _inner.Read(buffer, offset, count));
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken) =>
        ReadAsync(
                buffer.AsMemory(offset, count),
                cancellationToken)
            .AsTask();

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            EnsureAvailable();
            EnsureCallerPosition();
            try
            {
                _inner.Position = _position;
                var read = await _inner
                    .ReadAsync(buffer, cancellationToken)
                    .ConfigureAwait(false);
                _position = checked(_position + read);
                return read;
            }
            finally
            {
                RestoreCallerPosition();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public override long Seek(
        long offset,
        SeekOrigin origin) =>
        ExecuteMetadata(
            () =>
            {
                var next = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current =>
                        checked(_position + offset),
                    SeekOrigin.End =>
                        checked(_inner.Length + offset),
                    _ => throw new ArgumentOutOfRangeException(
                        nameof(origin))
                };
                if (next < 0)
                {
                    throw new IOException(
                        "Cannot seek before the archive start.");
                }

                _position = next;
                return next;
            });

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(
        byte[] buffer,
        int offset,
        int count) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _gate.Wait();
            try
            {
                _disposed = true;
            }
            finally
            {
                _gate.Release();
            }
        }

        base.Dispose(disposing);
    }

    private int ExecuteRead(Func<int> read)
    {
        _gate.Wait();
        try
        {
            EnsureAvailable();
            EnsureCallerPosition();
            try
            {
                _inner.Position = _position;
                var count = read();
                _position = checked(_position + count);
                return count;
            }
            finally
            {
                RestoreCallerPosition();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private T ExecuteMetadata<T>(Func<T> action)
    {
        _gate.Wait();
        try
        {
            EnsureAvailable();
            EnsureCallerPosition();
            var result = action();
            EnsureCallerPosition();
            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    private void EnsureAvailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_positionIntegrityLost
            || !_inner.CanRead
            || !_inner.CanSeek)
        {
            throw new IOException(
                "The retained archive stream is unavailable.");
        }
    }

    private void EnsureCallerPosition()
    {
        try
        {
            if (_inner.Position != _originalPosition)
            {
                _positionIntegrityLost = true;
                throw new IOException(
                    "The retained archive stream position changed.");
            }
        }
        catch (Exception exception) when (
            exception is IOException
                or ObjectDisposedException
                or NotSupportedException
                or InvalidOperationException)
        {
            _positionIntegrityLost = true;
            throw new IOException(
                "The retained archive stream position is unavailable.",
                exception);
        }
    }

    private void RestoreCallerPosition()
    {
        try
        {
            _inner.Position = _originalPosition;
            if (_inner.Position != _originalPosition)
            {
                throw new IOException(
                    "The retained archive stream position was not restored.");
            }
        }
        catch (Exception exception) when (
            exception is IOException
                or ObjectDisposedException
                or NotSupportedException
                or InvalidOperationException)
        {
            _positionIntegrityLost = true;
            throw new IOException(
                "The retained archive stream position could not be restored.",
                exception);
        }
    }
}

internal sealed class FileSystemPathSafetyInspector : IPathSafetyInspector
{
    public bool IsReparsePoint(string path) =>
        (File.Exists(path) || Directory.Exists(path))
        && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
}
