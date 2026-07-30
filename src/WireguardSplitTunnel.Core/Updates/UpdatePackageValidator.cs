using System.Security.Cryptography;
using System.Text.Json;

namespace WireguardSplitTunnel.Core.Updates;

public enum UpdatePackageValidationError
{
    None,
    InvalidRequest,
    InvalidChecksumSidecar,
    ArchiveTooLarge,
    ArchiveHashFailed,
    ArchiveHashMismatch,
    ZipPreflightFailed,
    ManifestReadFailed,
    InvalidManifestJson,
    InvalidManifest,
    DiskSpaceFailed,
    InsufficientDiskSpace,
    ExtractionFailed,
    PayloadLengthMismatch,
    PayloadHashMismatch,
    ManifestCandidateMismatch,
    ProductVersionMismatch,
    Cancelled,
    IoFailure
}

public sealed record UpdatePackageValidationRequest(
    string ArchivePath,
    byte[]? ChecksumSidecarBytes,
    SemanticVersion CandidateVersion,
    SemanticVersion CurrentVersion,
    int SupportedStateSchemaVersion,
    long CurrentManagedBytes,
    string CandidateRoot,
    string DiskSpacePath,
    UpdatePackageLimits Limits);

/// <summary>A fully validated candidate package.</summary>
/// <remarks>
/// Committing validation keeps the candidate tree but does not make it immutable or protected.
/// The later protected staging operation must copy and revalidate every artifact before use.
/// </remarks>
public sealed record ValidatedUpdatePackage(
    SemanticVersion Version,
    string ArchivePath,
    string ManifestPath,
    string ArchiveSha256,
    string NewManifestSha256,
    string CandidateRoot,
    long ArchiveBytes,
    long ExpandedBytes,
    long RequiredDiskBytes,
    ReleaseManifest Manifest);

public readonly record struct UpdatePackageValidationResult(
    bool Success,
    ValidatedUpdatePackage? Package,
    UpdatePackageValidationError ErrorCode,
    string? DetailCode)
{
    public static UpdatePackageValidationResult Failure(
        UpdatePackageValidationError errorCode,
        string? detailCode = null) =>
        new(false, null, errorCode, detailCode);

    public static UpdatePackageValidationResult Valid(
        ValidatedUpdatePackage package) =>
        new(true, package, UpdatePackageValidationError.None, null);
}

public sealed class UpdatePackageValidator
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 32
    };

    private static readonly string[] ManifestProperties =
    [
        "schemaVersion",
        "version",
        "runtimeIdentifier",
        "minimumAutoUpdateVersion",
        "rollbackCompatibleFromVersion",
        "stateSchemaVersion",
        "entryPoint",
        "updaterEntryPoint",
        "requiredLaunchers",
        "files"
    ];

    private static readonly string[] ManifestFileProperties =
    [
        "path",
        "length",
        "sha256"
    ];

    private readonly IExecutableProductVersionReader _versionReader;
    private readonly IDiskSpaceProvider _diskSpaceProvider;
    private readonly IPathSafetyInspector? _pathSafetyInspector;

    public UpdatePackageValidator(
        IExecutableProductVersionReader versionReader,
        IDiskSpaceProvider diskSpaceProvider,
        IPathSafetyInspector? pathSafetyInspector = null)
    {
        _versionReader = versionReader;
        _diskSpaceProvider = diskSpaceProvider;
        _pathSafetyInspector = pathSafetyInspector;
    }

    public async Task<UpdatePackageValidationResult> ValidateAsync(
        UpdatePackageValidationRequest? request,
        CancellationToken cancellationToken = default)
    {
        if (request is null
            || string.IsNullOrWhiteSpace(request.ArchivePath)
            || string.IsNullOrWhiteSpace(request.CandidateRoot)
            || string.IsNullOrWhiteSpace(request.DiskSpacePath)
            || request.SupportedStateSchemaVersion <= 0)
        {
            return Fail(UpdatePackageValidationError.InvalidRequest);
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            // 1. The sidecar is bounded and strictly parsed before the archive is touched.
            var sidecar = Sha256SidecarParser.Parse(request.ChecksumSidecarBytes);
            if (!sidecar.Success)
            {
                return Fail(
                    UpdatePackageValidationError.InvalidChecksumSidecar,
                    sidecar.ErrorCode.ToString());
            }

            // 2. One read-only handle is opened and retained through every ZIP stage.
            using var opened = SafeZipExtractor.Open(
                request.ArchivePath,
                request.Limits,
                _pathSafetyInspector);
            if (!opened.Success || opened.Session is null)
            {
                return Fail(
                    UpdatePackageValidationError.ArchiveHashFailed,
                    opened.ErrorCode.ToString());
            }

            if (opened.Session.ArchiveLength > UpdateNetworkLimits.ArchiveBytes)
            {
                return Fail(UpdatePackageValidationError.ArchiveTooLarge);
            }

            var archiveHash = await opened.Session
                .ComputeSha256Async(cancellationToken)
                .ConfigureAwait(false);
            if (!archiveHash.Success)
            {
                return Fail(
                    archiveHash.ErrorCode == SafeZipError.Cancelled
                        ? UpdatePackageValidationError.Cancelled
                        : UpdatePackageValidationError.ArchiveHashFailed,
                    archiveHash.ErrorCode.ToString());
            }

            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(archiveHash.Digest!),
                    Convert.FromHexString(sidecar.Digest!)))
            {
                return Fail(UpdatePackageValidationError.ArchiveHashMismatch);
            }

            cancellationToken.ThrowIfCancellationRequested();

            // 3. Preflight consumes the same stream after hashing; no reopen occurs.
            var preflight = opened.Session.Preflight();
            if (!preflight.Success)
            {
                return Fail(
                    UpdatePackageValidationError.ZipPreflightFailed,
                    preflight.ErrorCode.ToString());
            }

            // 4. Manifest bytes and ZIP metadata remain tied to that same session.
            var manifestRead = opened.Session.ReadManifest();
            if (!manifestRead.Success || manifestRead.Bytes is null)
            {
                return Fail(
                    UpdatePackageValidationError.ManifestReadFailed,
                    manifestRead.ErrorCode.ToString());
            }

            if (!TryDeserializeStrictManifest(
                    manifestRead.Bytes,
                    out var untrustedManifest))
            {
                return Fail(UpdatePackageValidationError.InvalidManifestJson);
            }

            var regularFiles = opened.Session.Entries
                .Where(entry => !entry.IsDirectory)
                .Select(entry => (string?)entry.Path)
                .ToArray();
            var manifestValidation = ReleaseManifestValidator.Validate(
                untrustedManifest,
                request.CandidateVersion,
                request.CurrentVersion,
                request.SupportedStateSchemaVersion,
                regularFiles);
            if (!manifestValidation.IsValid || manifestValidation.Manifest is null)
            {
                return Fail(
                    UpdatePackageValidationError.InvalidManifest,
                    manifestValidation.ErrorCode);
            }

            var manifest = manifestValidation.Manifest;
            var manifestSha256 = Hex(SHA256.HashData(manifestRead.Bytes));

            // 5. Compatibility is now established; compute disk requirements checked.
            if (!TryExpandedBytes(opened.Session.Entries, out var expandedBytes))
            {
                return Fail(UpdatePackageValidationError.DiskSpaceFailed);
            }

            long availableBytes;
            try
            {
                availableBytes = _diskSpaceProvider.GetAvailableBytes(
                    request.DiskSpacePath);
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or ArgumentException
                    or InvalidOperationException)
            {
                return Fail(
                    UpdatePackageValidationError.DiskSpaceFailed,
                    exception.GetType().Name);
            }

            var disk = UpdateDiskSpacePolicy.Evaluate(
                availableBytes,
                opened.Session.ArchiveLength,
                expandedBytes,
                request.CurrentManagedBytes,
                request.Limits);
            if (!disk.Success)
            {
                return Fail(
                    disk.ErrorCode == UpdateDiskSpaceError.InsufficientSpace
                        ? UpdatePackageValidationError.InsufficientDiskSpace
                        : UpdatePackageValidationError.DiskSpaceFailed,
                    disk.ErrorCode.ToString());
            }

            cancellationToken.ThrowIfCancellationRequested();

            // 6. The candidate is a new, separate owned tree.
            using var extraction = opened.Session.ExtractTo(
                request.CandidateRoot,
                cancellationToken);
            if (!extraction.Success || extraction.Artifacts is null)
            {
                return Fail(
                    extraction.ErrorCode == SafeZipError.Cancelled
                        ? UpdatePackageValidationError.Cancelled
                        : UpdatePackageValidationError.ExtractionFailed,
                    extraction.ErrorCode.ToString());
            }

            var extractedManifestPath = CandidatePath(
                request.CandidateRoot,
                UpdateReleaseContract.ReleaseManifestPath);
            if (!await MatchesExactFileAsync(
                    extractedManifestPath,
                    manifestRead.Bytes,
                    cancellationToken)
                .ConfigureAwait(false))
            {
                return Fail(UpdatePackageValidationError.ManifestCandidateMismatch);
            }

            // 7. Verify every manifest payload from the extracted candidate.
            foreach (var payload in manifest.Files!)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var payloadPath = CandidatePath(request.CandidateRoot, payload.Path);
                var payloadResult = await ValidatePayloadAsync(
                        payloadPath,
                        payload,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (payloadResult != UpdatePackageValidationError.None)
                {
                    return Fail(payloadResult);
                }
            }

            // 8. Both executable ProductVersion values must be strict normalized SemVer.
            foreach (var executable in new[]
                     {
                         UpdateReleaseContract.WindowsApplicationPath,
                         UpdateReleaseContract.WindowsUpdaterPath
                     })
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? productVersion;
                try
                {
                    productVersion = _versionReader.ReadProductVersion(
                        CandidatePath(request.CandidateRoot, executable));
                }
                catch (Exception exception) when (
                    exception is IOException
                        or UnauthorizedAccessException
                        or ArgumentException
                        or InvalidOperationException)
                {
                    return Fail(
                        UpdatePackageValidationError.ProductVersionMismatch,
                        exception.GetType().Name);
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (!SemanticVersion.TryParseNormalized(
                        productVersion,
                        out var parsedVersion)
                    || parsedVersion != request.CandidateVersion)
                {
                    return Fail(
                        UpdatePackageValidationError.ProductVersionMismatch);
                }
            }

            // 9. Only fully validated candidate artifacts are committed.
            var package = new ValidatedUpdatePackage(
                request.CandidateVersion,
                Path.GetFullPath(request.ArchivePath),
                Path.GetFullPath(extractedManifestPath),
                archiveHash.Digest!,
                manifestSha256,
                Path.GetFullPath(request.CandidateRoot),
                opened.Session.ArchiveLength,
                expandedBytes,
                disk.RequiredBytes!.Value,
                manifest);
            extraction.Artifacts.Commit();
            return UpdatePackageValidationResult.Valid(package);
        }
        catch (OperationCanceledException)
        {
            return Fail(UpdatePackageValidationError.Cancelled);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or ArgumentException
                or JsonException
                or CryptographicException)
        {
            return Fail(
                UpdatePackageValidationError.IoFailure,
                exception.GetType().Name);
        }
    }

    private static async Task<UpdatePackageValidationError> ValidatePayloadAsync(
        string payloadPath,
        ReleasePayloadFile payload,
        CancellationToken cancellationToken)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(payloadPath);
            if (!info.Exists || info.Length != payload.Length)
            {
                return UpdatePackageValidationError.PayloadLengthMismatch;
            }

            await using var stream = new FileStream(
                payloadPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var sha256 = SHA256.Create();
            var digest = await sha256
                .ComputeHashAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            return CryptographicOperations.FixedTimeEquals(
                    digest,
                    Convert.FromHexString(payload.Sha256))
                ? UpdatePackageValidationError.None
                : UpdatePackageValidationError.PayloadHashMismatch;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or CryptographicException)
        {
            return UpdatePackageValidationError.PayloadHashMismatch;
        }
    }

    private static async Task<bool> MatchesExactFileAsync(
        string path,
        byte[] expectedBytes,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length != expectedBytes.LongLength)
        {
            return false;
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var sha256 = SHA256.Create();
        var actualHash = await sha256
            .ComputeHashAsync(stream, cancellationToken)
            .ConfigureAwait(false);
        return CryptographicOperations.FixedTimeEquals(
            actualHash,
            SHA256.HashData(expectedBytes));
    }

    private static bool TryDeserializeStrictManifest(
        byte[] bytes,
        out ReleaseManifest? manifest)
    {
        manifest = null;
        if (bytes.LongLength > UpdateNetworkLimits.MetadataBytes)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(root, ManifestProperties)
                || !HasManifestPrimitiveKinds(root))
            {
                return false;
            }

            var launchers = root.GetProperty("requiredLaunchers");
            var files = root.GetProperty("files");
            if (launchers.GetArrayLength() != UpdateReleaseContract.RequiredLauncherPaths.Count
                || files.GetArrayLength() is < 1 or > WindowsReleasePathPolicy.MaximumArchiveEntries - 1)
            {
                return false;
            }

            foreach (var launcher in launchers.EnumerateArray())
            {
                if (launcher.ValueKind != JsonValueKind.String)
                {
                    return false;
                }
            }

            foreach (var file in files.EnumerateArray())
            {
                if (file.ValueKind != JsonValueKind.Object
                    || !HasExactProperties(file, ManifestFileProperties)
                    || file.GetProperty("path").ValueKind != JsonValueKind.String
                    || file.GetProperty("length").ValueKind != JsonValueKind.Number
                    || file.GetProperty("sha256").ValueKind != JsonValueKind.String)
                {
                    return false;
                }
            }

            manifest = JsonSerializer.Deserialize<ReleaseManifest>(
                bytes,
                ManifestJsonOptions);
            return manifest is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool HasManifestPrimitiveKinds(JsonElement root) =>
        root.GetProperty("schemaVersion").ValueKind == JsonValueKind.Number
        && root.GetProperty("version").ValueKind == JsonValueKind.String
        && root.GetProperty("runtimeIdentifier").ValueKind == JsonValueKind.String
        && root.GetProperty("minimumAutoUpdateVersion").ValueKind == JsonValueKind.String
        && root.GetProperty("rollbackCompatibleFromVersion").ValueKind == JsonValueKind.String
        && root.GetProperty("stateSchemaVersion").ValueKind == JsonValueKind.Number
        && root.GetProperty("entryPoint").ValueKind == JsonValueKind.String
        && root.GetProperty("updaterEntryPoint").ValueKind == JsonValueKind.String
        && root.GetProperty("requiredLaunchers").ValueKind == JsonValueKind.Array
        && root.GetProperty("files").ValueKind == JsonValueKind.Array;

    private static bool HasExactProperties(
        JsonElement element,
        IReadOnlyCollection<string> expected)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            count++;
            if (!expected.Contains(property.Name, StringComparer.Ordinal)
                || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return count == expected.Count;
    }

    private static bool TryExpandedBytes(
        IReadOnlyList<SafeZipEntryMetadata> entries,
        out long expandedBytes)
    {
        expandedBytes = 0;
        foreach (var entry in entries)
        {
            if (!entry.IsDirectory
                && !SafeZipExtractor.TryAdd(
                    expandedBytes,
                    entry.Length,
                    out expandedBytes))
            {
                return false;
            }
        }

        return true;
    }

    private static string CandidatePath(string candidateRoot, string relativePath) =>
        Path.GetFullPath(
            Path.Combine(
                Path.GetFullPath(candidateRoot),
                relativePath.Replace('/', Path.DirectorySeparatorChar)));

    private static string Hex(byte[] bytes) =>
        Convert.ToHexString(bytes).ToLowerInvariant();

    private static UpdatePackageValidationResult Fail(
        UpdatePackageValidationError error,
        string? detail = null) =>
        UpdatePackageValidationResult.Failure(error, detail);
}
