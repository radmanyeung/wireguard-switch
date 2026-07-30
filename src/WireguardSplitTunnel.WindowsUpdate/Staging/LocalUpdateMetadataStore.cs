using System.Globalization;
using System.Text.Json;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

public enum LocalUpdateMetadataStoreError
{
    None,
    UnsafePath,
    SerializationFailed,
    IoFailure
}

internal enum PersistedLocalUpdateErrorCode
{
    DownloadFailed
}

public sealed record LocalUpdateMetadataStoreResult(bool Success, LocalUpdateMetadataStoreError Error)
{
    internal static LocalUpdateMetadataStoreResult Saved() => new(true, LocalUpdateMetadataStoreError.None);
    internal static LocalUpdateMetadataStoreResult Failed(LocalUpdateMetadataStoreError error) => new(false, error);
}

/// <summary>Strict, bounded LocalAppData metadata with atomic replacement and no path authority.</summary>
public sealed class LocalUpdateMetadataStore
{
    private const long MaximumBytes = UpdateNetworkLimits.MetadataBytes;
    private static readonly string[] RootProperties =
        ["lastAutomaticAttemptUtc", "stagedUpdate", "lastError", "protectedRemovalPending"];
    private static readonly string[] StagedProperties =
        ["version", "archivePath", "checksumPath", "manifestPath", "candidateRoot", "archiveSha256", "newManifestSha256", "source"];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false
    };

    private readonly LocalUpdatePaths _paths;
    private readonly ILocalUpdateMetadataFileSystem _fileSystem;

    public LocalUpdateMetadataStore(LocalUpdatePaths paths)
        : this(paths, new WindowsLocalUpdateMetadataFileSystem())
    {
    }

    internal LocalUpdateMetadataStore(
        LocalUpdatePaths paths,
        ILocalUpdateMetadataFileSystem fileSystem)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
    }

    public LocalUpdateMetadata Load()
    {
        var root = _paths.GetRoot();
        if (!root.Success || root.ProductRoot is null || root.MetadataPath is null)
        {
            return LocalUpdateMetadata.Empty;
        }

        try
        {
            var directoryStatus = _fileSystem.OpenDirectory(root.ProductRoot, out var directory);
            if (directoryStatus != LocalUpdateMetadataOpenStatus.Opened || directory is null)
            {
                return LocalUpdateMetadata.Empty;
            }

            using (directory)
            {
                if (!_fileSystem.IsSafeDirectory(directory, root.ProductRoot))
                {
                    return LocalUpdateMetadata.Empty;
                }

                var readStatus = _fileSystem.OpenRead(directory, root.MetadataPath, out var read);
                if (readStatus != LocalUpdateMetadataOpenStatus.Opened || read is null)
                {
                    return LocalUpdateMetadata.Empty;
                }

                using (read)
                {
                    if (!_fileSystem.IsSafeRead(directory, read, root.MetadataPath))
                    {
                        return LocalUpdateMetadata.Empty;
                    }

                    var bytes = _fileSystem.ReadBounded(read, MaximumBytes);
                    if (bytes is null
                        || !_fileSystem.IsSafeRead(directory, read, root.MetadataPath)
                        || !_fileSystem.IsSafeDirectory(directory, root.ProductRoot))
                    {
                        return LocalUpdateMetadata.Empty;
                    }

                    return TryParse(bytes, out var metadata) ? metadata! : LocalUpdateMetadata.Empty;
                }
            }
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return LocalUpdateMetadata.Empty;
        }
    }

    public LocalUpdateMetadataStoreResult Save(LocalUpdateMetadata? metadata)
    {
        if (metadata is null)
        {
            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.SerializationFailed);
        }

        if (!TryCreateDto(metadata, out var dto))
        {
            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.SerializationFailed);
        }

        byte[] bytes;
        try
        {
            bytes = JsonSerializer.SerializeToUtf8Bytes(dto, JsonOptions);
            if (bytes.LongLength > MaximumBytes)
            {
                return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.SerializationFailed);
            }
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or ArgumentException)
        {
            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.SerializationFailed);
        }

        var root = _paths.EnsureRoot();
        if (!root.Success || root.MetadataPath is null || root.ProductRoot is null)
        {
            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
        }

        try
        {
            var directoryStatus = _fileSystem.OpenDirectory(root.ProductRoot, out var directory);
            if (directoryStatus != LocalUpdateMetadataOpenStatus.Opened || directory is null)
            {
                return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
            }

            using (directory)
            {
                if (!_fileSystem.IsSafeDirectory(directory, root.ProductRoot))
                {
                    return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                }

                var destination = _fileSystem.InspectDestination(directory, root.MetadataPath);
                if (destination.State == LocalUpdateMetadataEntryState.Unsafe)
                {
                    return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                }

                var temporaryPath = Path.Combine(
                    root.ProductRoot,
                    $"update-metadata.json.{Guid.NewGuid():N}.tmp");
                var tempStatus = _fileSystem.CreateNewTemp(directory, temporaryPath, out var temporary);
                if (tempStatus != LocalUpdateMetadataOpenStatus.Opened || temporary is null)
                {
                    return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                }

                using (temporary)
                {
                    var committed = false;
                    try
                    {
                        if (!_fileSystem.IsSafeTemp(directory, temporary, temporaryPath))
                        {
                            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                        }

                        _fileSystem.Write(temporary, bytes);
                        if (!_fileSystem.IsSafeTemp(directory, temporary, temporaryPath))
                        {
                            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                        }

                        _fileSystem.FlushToDisk(temporary);
                        if (!_fileSystem.IsSafeTemp(directory, temporary, temporaryPath)
                            || !_fileSystem.IsSafeDirectory(directory, root.ProductRoot))
                        {
                            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                        }

                        var committedNow = destination.State switch
                        {
                            LocalUpdateMetadataEntryState.Missing =>
                                _fileSystem.Move(directory, temporary, root.MetadataPath),
                            LocalUpdateMetadataEntryState.File =>
                                _fileSystem.Replace(
                                    directory,
                                    temporary,
                                    root.MetadataPath,
                                    destination.Identity),
                            _ => false
                        };
                        if (!committedNow)
                        {
                            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                        }

                        committed = true;
                        return _fileSystem.IsCommitted(directory, temporary, root.MetadataPath)
                            && _fileSystem.IsSafeDirectory(directory, root.ProductRoot)
                            ? LocalUpdateMetadataStoreResult.Saved()
                            : LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.UnsafePath);
                    }
                    finally
                    {
                        if (!committed)
                        {
                            try
                            {
                                _fileSystem.DeleteOwned(temporary);
                            }
                            catch (Exception exception) when (IsExpectedFileException(exception))
                            {
                                // Cleanup stays bound to the held temp identity; never retry by pathname.
                            }
                        }
                    }
                }
            }

        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return LocalUpdateMetadataStoreResult.Failed(LocalUpdateMetadataStoreError.IoFailure);
        }
    }

    private bool TryParse(byte[] bytes, out LocalUpdateMetadata? metadata)
    {
        metadata = null;
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16
            });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(root, RootProperties)
                || root.GetProperty("lastAutomaticAttemptUtc").ValueKind is not (JsonValueKind.Null or JsonValueKind.String)
                || root.GetProperty("stagedUpdate").ValueKind is not (JsonValueKind.Null or JsonValueKind.Object)
                || root.GetProperty("lastError").ValueKind is not (JsonValueKind.Null or JsonValueKind.String)
                || root.GetProperty("protectedRemovalPending").ValueKind != JsonValueKind.True
                    && root.GetProperty("protectedRemovalPending").ValueKind != JsonValueKind.False)
            {
                return false;
            }

            DateTimeOffset? lastAttempt = null;
            var attempt = root.GetProperty("lastAutomaticAttemptUtc");
            if (attempt.ValueKind == JsonValueKind.String)
            {
                if (!DateTimeOffset.TryParseExact(
                        attempt.GetString(),
                        "O",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.None,
                        out var parsedAttempt)
                    || parsedAttempt.Offset != TimeSpan.Zero
                    || !string.Equals(
                        attempt.GetString(),
                        parsedAttempt.ToString("O", CultureInfo.InvariantCulture),
                        StringComparison.Ordinal))
                {
                    return false;
                }

                lastAttempt = parsedAttempt.ToUniversalTime();
            }

            string? error = null;
            var errorElement = root.GetProperty("lastError");
            if (errorElement.ValueKind == JsonValueKind.String)
            {
                error = errorElement.GetString();
                if (!TryParseErrorCode(error, out _)) return false;
            }

            LocalStagedUpdate? staged = null;
            var stagedElement = root.GetProperty("stagedUpdate");
            if (stagedElement.ValueKind == JsonValueKind.Object && !TryParseStaged(stagedElement, out staged))
            {
                return false;
            }

            metadata = new LocalUpdateMetadata(lastAttempt, staged, error, root.GetProperty("protectedRemovalPending").GetBoolean());
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private bool TryParseStaged(JsonElement element, out LocalStagedUpdate? staged)
    {
        staged = null;
        if (!HasExactProperties(element, StagedProperties)
            || StagedProperties.Any(property => element.GetProperty(property).ValueKind != JsonValueKind.String))
        {
            return false;
        }

        var versionText = element.GetProperty("version").GetString();
        var sourceText = element.GetProperty("source").GetString();
        if (!SemanticVersion.TryParseNormalized(versionText, out var version)
            || !string.Equals(versionText, version.ToString(), StringComparison.Ordinal)
            || sourceText is not ("Automatic" or "Manual")
            || !Enum.TryParse<PendingUpdateSource>(sourceText, ignoreCase: false, out var source)
            || !Enum.IsDefined(source)
            || !IsSha256(element.GetProperty("archiveSha256").GetString())
            || !IsSha256(element.GetProperty("newManifestSha256").GetString()))
        {
            return false;
        }

        var candidate = new LocalStagedUpdate(
            version,
            element.GetProperty("archivePath").GetString()!,
            element.GetProperty("checksumPath").GetString()!,
            element.GetProperty("manifestPath").GetString()!,
            element.GetProperty("candidateRoot").GetString()!,
            element.GetProperty("archiveSha256").GetString()!,
            element.GetProperty("newManifestSha256").GetString()!,
            source);
        if (!_paths.TryResolve(candidate).Success)
        {
            return false;
        }

        staged = candidate;
        return true;
    }

    private bool TryCreateDto(LocalUpdateMetadata metadata, out MetadataDto? dto)
    {
        dto = null;
        var normalizedAttempt = metadata.LastAutomaticAttemptUtc?.ToUniversalTime();

        if (metadata.LastError is not null && !TryParseErrorCode(metadata.LastError, out _))
        {
            metadata = metadata with { LastError = null };
        }

        StagedDto? staged = null;
        if (metadata.StagedUpdate is not null)
        {
            var resolved = _paths.TryResolve(metadata.StagedUpdate);
            if (!resolved.Success || !IsSha256(metadata.StagedUpdate.ArchiveSha256) || !IsSha256(metadata.StagedUpdate.NewManifestSha256)
                || !Enum.IsDefined(metadata.StagedUpdate.Source))
            {
                return false;
            }

            staged = new StagedDto(
                metadata.StagedUpdate.Version.ToString(), metadata.StagedUpdate.ArchivePath, metadata.StagedUpdate.ChecksumPath,
                metadata.StagedUpdate.ManifestPath, metadata.StagedUpdate.CandidateRoot, metadata.StagedUpdate.ArchiveSha256,
                metadata.StagedUpdate.NewManifestSha256, metadata.StagedUpdate.Source.ToString());
        }

        dto = new MetadataDto(
            normalizedAttempt?.ToString("O", CultureInfo.InvariantCulture),
            staged,
            metadata.LastError,
            metadata.ProtectedRemovalPending);
        return true;
    }

    private static bool HasExactProperties(JsonElement element, IReadOnlyCollection<string> expected)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            count++;
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name)) return false;
        }

        return count == expected.Count;
    }

    private static bool IsSha256(string? value) => value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool TryParseErrorCode(string? value, out PersistedLocalUpdateErrorCode code)
    {
        switch (value)
        {
            case "download_failed":
                code = PersistedLocalUpdateErrorCode.DownloadFailed;
                return true;
            default:
                code = default;
                return false;
        }
    }

    private static bool IsExpectedFileException(Exception exception) => exception is IOException
        or UnauthorizedAccessException
        or ArgumentException
        or NotSupportedException
        or ObjectDisposedException
        or InvalidOperationException
        or System.Security.SecurityException;

    private sealed record MetadataDto(
        string? LastAutomaticAttemptUtc,
        StagedDto? StagedUpdate,
        string? LastError,
        bool ProtectedRemovalPending);

    private sealed record StagedDto(
        string Version,
        string ArchivePath,
        string ChecksumPath,
        string ManifestPath,
        string CandidateRoot,
        string ArchiveSha256,
        string NewManifestSha256,
        string Source);
}
