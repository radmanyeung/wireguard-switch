using System.Text.Json;
using System.Security.Cryptography;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Validation;

public enum InstalledReleaseLocatorStatus
{
    Available,
    AutomaticInstallationUnavailable
}

public sealed record InstalledReleaseLocation(
    InstalledReleaseLocatorStatus Status,
    string? InstallationRoot,
    string? ApplicationPath,
    string? UpdaterPath,
    SemanticVersion? Version,
    long CurrentManagedBytes,
    string? DetailCode)
{
    internal static InstalledReleaseLocation Unavailable(string detailCode) =>
        new(InstalledReleaseLocatorStatus.AutomaticInstallationUnavailable, null, null, null, null, 0, detailCode);

    internal static InstalledReleaseLocation Available(
        string installationRoot,
        string applicationPath,
        string updaterPath,
        SemanticVersion version,
        long currentManagedBytes) =>
        new(InstalledReleaseLocatorStatus.Available, installationRoot, applicationPath, updaterPath, version, currentManagedBytes, null);
}

public sealed class InstalledReleaseLaunchLease : IDisposable
{
    private readonly object _gate = new();
    private IDisposable? _resource;
    private Func<bool>? _revalidate;

    internal InstalledReleaseLaunchLease(
        string applicationPath,
        IDisposable resource,
        Func<bool> revalidate)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                applicationPath,
                out var canonicalApplicationPath)
            || canonicalApplicationPath is null)
        {
            throw new ArgumentException(
                "The leased application path is invalid.",
                nameof(applicationPath));
        }

        ApplicationPath = canonicalApplicationPath;
        _resource = resource
            ?? throw new ArgumentNullException(nameof(resource));
        _revalidate = revalidate
            ?? throw new ArgumentNullException(nameof(revalidate));
    }

    public string ApplicationPath { get; }

    public bool Revalidate()
    {
        lock (_gate)
        {
            return _resource is not null
                && _revalidate is not null
                && _revalidate();
        }
    }

    public bool TryLaunch(Func<string, bool> launch)
    {
        ArgumentNullException.ThrowIfNull(launch);
        lock (_gate)
        {
            try
            {
                return _resource is not null
                    && _revalidate is not null
                    && _revalidate()
                    && launch(ApplicationPath);
            }
            finally
            {
                DisposeCore();
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            DisposeCore();
        }
    }

    private void DisposeCore()
    {
        var resource = _resource;
        _resource = null;
        _revalidate = null;
        resource?.Dispose();
    }
}

internal interface IInstalledReleaseSecurityValidator
{
    bool IsExpectedProtectedRoot(string installationRoot);

    bool HasExactInstalledSecurity(
        string installationRoot,
        IReadOnlyList<string> managedRelativePaths);

    InstalledReleaseLaunchLease? TryAcquireLaunchLease(
        string applicationPath);
}

internal sealed class WindowsInstalledReleaseSecurityValidator
    : IInstalledReleaseSecurityValidator
{
    private readonly string _expectedRoot;
    private readonly string _programFilesParent;
    private readonly string _expectedApplicationPath;
    private readonly ProtectedDirectoryAcl _acl;

    public WindowsInstalledReleaseSecurityValidator()
        : this(
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFiles),
                "WireguardSplitTunnel"),
            new ProtectedDirectoryAcl())
    {
    }

    internal WindowsInstalledReleaseSecurityValidator(
        string expectedRoot,
        ProtectedDirectoryAcl acl)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                expectedRoot,
                out var canonicalRoot)
            || canonicalRoot is null)
        {
            throw new ArgumentException(
                "The protected installation root is invalid.",
                nameof(expectedRoot));
        }

        _expectedRoot = canonicalRoot.TrimEnd(
            Path.DirectorySeparatorChar);
        _programFilesParent = Path.GetDirectoryName(_expectedRoot)
            ?? throw new ArgumentException(
                "The protected installation parent is invalid.",
                nameof(expectedRoot));
        _expectedApplicationPath = Path.GetFullPath(
            Path.Combine(
                _expectedRoot,
                UpdateReleaseContract.WindowsApplicationPath.Replace(
                    '/',
                    Path.DirectorySeparatorChar)));
        _acl = acl ?? throw new ArgumentNullException(nameof(acl));
    }

    public bool IsExpectedProtectedRoot(string installationRoot) =>
        WindowsLocalPath.TryGetCanonicalLocalDosPath(
            installationRoot,
            out var canonicalRoot)
        && string.Equals(
            canonicalRoot?.TrimEnd(Path.DirectorySeparatorChar),
            _expectedRoot,
            StringComparison.Ordinal);

    public bool HasExactInstalledSecurity(
        string installationRoot,
        IReadOnlyList<string> managedRelativePaths)
    {
        if (!IsExpectedProtectedRoot(installationRoot)
            || managedRelativePaths is null
            || managedRelativePaths.Count < 1)
        {
            return false;
        }

        using var inspected = _acl.InspectProtectedDirectory(
            installationRoot,
            ProtectedDirectoryInspectionPolicy.InstalledRelease);
        if (!inspected.Success || inspected.Lease is null)
        {
            return false;
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var relativePath in managedRelativePaths)
        {
            var validation = WindowsReleasePathPolicy.Validate(relativePath);
            if (!validation.Success
                || validation.CanonicalKey is null
                || !paths.Add(validation.CanonicalKey))
            {
                return false;
            }

            using var opened = _acl.OpenProtectedFileForRead(
                inspected.Lease,
                validation.CanonicalKey.Replace(
                    '/',
                    Path.DirectorySeparatorChar),
                ProtectedDirectoryInspectionPolicy.InstalledRelease);
            if (!opened.Success
                || opened.Lease is null
                || !opened.Lease.Revalidate())
            {
                return false;
            }
        }

        return inspected.Lease.Revalidate();
    }

    public InstalledReleaseLaunchLease? TryAcquireLaunchLease(
        string applicationPath)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                applicationPath,
                out var canonicalApplicationPath)
            || !string.Equals(
                canonicalApplicationPath,
                _expectedApplicationPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var opened = _acl.OpenInstalledApplicationForLaunch(
            _programFilesParent,
            _expectedRoot,
            _expectedApplicationPath);
        if (!opened.Success || opened.Lease is null)
        {
            opened.Dispose();
            return null;
        }

        return new InstalledReleaseLaunchLease(
            opened.Lease.ApplicationPath,
            opened.Lease,
            opened.Lease.Revalidate);
    }
}

/// <summary>Locates only a fully formed, updater-capable installed Release package.</summary>
public sealed class InstalledReleaseLocator
{
    private static readonly string[] ManifestProperties =
    [
        "schemaVersion", "version", "runtimeIdentifier", "minimumAutoUpdateVersion",
        "rollbackCompatibleFromVersion", "stateSchemaVersion", "entryPoint", "updaterEntryPoint",
        "requiredLaunchers", "files"
    ];

    private static readonly string[] ManifestFileProperties = ["path", "length", "sha256"];
    private readonly IExecutableProductVersionReader _versionReader;
    private readonly IPathSafetyInspector _pathSafetyInspector;
    private readonly IInstalledReleaseSecurityValidator _securityValidator;

    public InstalledReleaseLocator()
        : this(
            new WindowsExecutableProductVersionReader(),
            new WindowsPathSafetyInspector(),
            new WindowsInstalledReleaseSecurityValidator())
    {
    }

    internal InstalledReleaseLocator(
        IExecutableProductVersionReader versionReader,
        IPathSafetyInspector pathSafetyInspector)
        : this(
            versionReader,
            pathSafetyInspector,
            new WindowsInstalledReleaseSecurityValidator())
    {
    }

    internal InstalledReleaseLocator(
        IExecutableProductVersionReader versionReader,
        IPathSafetyInspector pathSafetyInspector,
        IInstalledReleaseSecurityValidator securityValidator)
    {
        _versionReader = versionReader ?? throw new ArgumentNullException(nameof(versionReader));
        _pathSafetyInspector = pathSafetyInspector ?? throw new ArgumentNullException(nameof(pathSafetyInspector));
        _securityValidator = securityValidator ?? throw new ArgumentNullException(nameof(securityValidator));
    }

    public InstalledReleaseLaunchLease? AcquireLaunchLease(
        string? runningExecutablePath)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                runningExecutablePath,
                out var canonicalApplicationPath)
            || canonicalApplicationPath is null)
        {
            return null;
        }

        InstalledReleaseLaunchLease? lease = null;
        try
        {
            lease = _securityValidator.TryAcquireLaunchLease(
                canonicalApplicationPath);
            if (lease is null)
            {
                return null;
            }

            var location = Locate(canonicalApplicationPath);
            if (location.Status
                    != InstalledReleaseLocatorStatus.Available
                || location.ApplicationPath is null
                || !string.Equals(
                    location.ApplicationPath,
                    canonicalApplicationPath,
                    StringComparison.OrdinalIgnoreCase)
                || !string.Equals(
                    lease.ApplicationPath,
                    canonicalApplicationPath,
                    StringComparison.OrdinalIgnoreCase)
                || !lease.Revalidate())
            {
                return null;
            }

            var acquired = lease;
            lease = null;
            return acquired;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException)
        {
            return null;
        }
        finally
        {
            lease?.Dispose();
        }
    }

    public InstalledReleaseLocation Locate(string? runningExecutablePath)
    {
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(runningExecutablePath, out var applicationPath))
        {
            return InstalledReleaseLocation.Unavailable("invalid_executable_path");
        }

        try
        {
            var canonicalApplicationPath = applicationPath!;
            var applicationDirectory = Path.GetDirectoryName(canonicalApplicationPath);
            if (applicationDirectory is null
                || !Path.GetFileName(canonicalApplicationPath).Equals("WireguardSplitTunnel.App.exe", StringComparison.Ordinal)
                || !Path.GetFileName(applicationDirectory).Equals("WireguardSplitTunnel", StringComparison.Ordinal))
            {
                return InstalledReleaseLocation.Unavailable("application_layout");
            }

            var installationRoot = Path.GetDirectoryName(applicationDirectory);
            if (string.IsNullOrEmpty(installationRoot)
                || HasDevelopmentOrTestSegment(installationRoot)
                || !IsSafeExistingChain(installationRoot)
                || !IsSafeExistingFile(canonicalApplicationPath))
            {
                return InstalledReleaseLocation.Unavailable("unsafe_installation_root");
            }

            if (!_securityValidator.IsExpectedProtectedRoot(installationRoot))
            {
                return InstalledReleaseLocation.Unavailable(
                    "unprotected_installation_root");
            }

            var manifestPath = Path.Combine(installationRoot, UpdateReleaseContract.ReleaseManifestPath);
            if (!TryReadManifest(manifestPath, out var manifest)
                || manifest is null
                || !TryValidateInstalledManifest(
                    manifest,
                    installationRoot,
                    out var version,
                    out var currentManagedBytes))
            {
                return InstalledReleaseLocation.Unavailable("release_manifest");
            }


            var managedPaths = new[]
                {
                    UpdateReleaseContract.ReleaseManifestPath
                }
                .Concat(manifest.Files!.Select(file => file.Path))
                .ToArray();
            if (!_securityValidator.HasExactInstalledSecurity(
                    installationRoot,
                    managedPaths))
            {
                return InstalledReleaseLocation.Unavailable(
                    "installed_release_acl");
            }

            var updaterPath = ReleasePath(installationRoot, UpdateReleaseContract.WindowsUpdaterPath);
            if (updaterPath is null
                || !IsSafeExistingFile(updaterPath)
                || !TryReadMatchingVersion(canonicalApplicationPath, version)
                || !TryReadMatchingVersion(updaterPath, version))
            {
                return InstalledReleaseLocation.Unavailable("release_version");
            }

            return InstalledReleaseLocation.Available(
                installationRoot,
                canonicalApplicationPath,
                updaterPath,
                version,
                currentManagedBytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or JsonException or InvalidDataException or NotSupportedException)
        {
            return InstalledReleaseLocation.Unavailable("filesystem_error");
        }
    }

    private bool TryValidateInstalledManifest(
        ReleaseManifest manifest,
        string installationRoot,
        out SemanticVersion version,
        out long currentManagedBytes)
    {
        version = default;
        currentManagedBytes = 0;
        if (manifest.SchemaVersion != 1
            || manifest.StateSchemaVersion != 1
            || manifest.RuntimeIdentifier != UpdateReleaseContract.WindowsRuntimeIdentifier
            || manifest.EntryPoint != UpdateReleaseContract.WindowsApplicationPath
            || manifest.UpdaterEntryPoint != UpdateReleaseContract.WindowsUpdaterPath
            || !SemanticVersion.TryParseNormalized(manifest.Version, out version)
            || !SemanticVersion.TryParseNormalized(manifest.MinimumAutoUpdateVersion, out var minimumVersion)
            || !SemanticVersion.TryParseNormalized(manifest.RollbackCompatibleFromVersion, out var rollbackVersion)
            || version.CompareTo(minimumVersion) < 0
            || version.CompareTo(rollbackVersion) < 0
            || !HasExactRequiredLaunchers(manifest.RequiredLaunchers)
            || manifest.Files is null
            || manifest.Files.Count is < 1 or >= WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return false;
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long aggregateLength = 0;
        foreach (var file in manifest.Files)
        {
            if (file is null
                || !IsSha256(file.Sha256)
                || file.Length < 0
                || file.Length > UpdatePackageLimits.Default.MaximumFileBytes
                || !WindowsReleasePathPolicy.Validate(file.Path).Success
                || ReleaseManagedPathPolicy.IsProtectedPayloadPath(file.Path)
                || !paths.Add(file.Path))
            {
                return false;
            }

            try { aggregateLength = checked(aggregateLength + file.Length); }
            catch (OverflowException) { return false; }
            if (aggregateLength > UpdatePackageLimits.Default.MaximumExpandedBytes)
            {
                return false;
            }

            var path = ReleasePath(installationRoot, file.Path);
            if (path is null || !IsSafeExistingFile(path) || !MatchesPayload(path, file))
            {
                return false;
            }
        }

        currentManagedBytes = aggregateLength;
        return paths.Contains(UpdateReleaseContract.WindowsApplicationPath)
            && paths.Contains(UpdateReleaseContract.WindowsUpdaterPath)
            && UpdateReleaseContract.RequiredLauncherPaths.All(paths.Contains);
    }

    private bool IsSafeExistingChain(string path)
    {
        for (var current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if (!Directory.Exists(current) || _pathSafetyInspector.IsReparsePoint(current))
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

    private bool IsSafeExistingFile(string path) =>
        File.Exists(path) && !_pathSafetyInspector.IsReparsePoint(path) && IsSafeExistingChain(Path.GetDirectoryName(path)!);

    private bool TryReadMatchingVersion(string executablePath, SemanticVersion expectedVersion)
    {
        try
        {
            return SemanticVersion.TryParseNormalized(_versionReader.ReadProductVersion(executablePath), out var actualVersion)
                && actualVersion == expectedVersion;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private bool TryReadManifest(string manifestPath, out ReleaseManifest? manifest)
    {
        manifest = null;
        if (!IsSafeExistingFile(manifestPath))
        {
            return false;
        }

        byte[] bytes;
        try
        {
            using var stream = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
            bytes = ReadBounded(stream, UpdateNetworkLimits.MetadataBytes);
            if (!IsSafeExistingFile(manifestPath)) return false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }

        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
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
            || files.GetArrayLength() is < 1 or >= WindowsReleasePathPolicy.MaximumArchiveEntries)
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

        manifest = JsonSerializer.Deserialize<ReleaseManifest>(bytes, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            AllowTrailingCommas = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 32
        });
        return manifest is not null;
    }

    private static bool HasExactRequiredLaunchers(IReadOnlyList<string>? launchers)
    {
        if (launchers is null || launchers.Count != UpdateReleaseContract.RequiredLauncherPaths.Count)
        {
            return false;
        }

        var validation = WindowsReleasePathPolicy.ValidateCollection(launchers.Cast<string?>().ToArray());
        return validation.Success
            && new HashSet<string>(launchers, StringComparer.Ordinal).SetEquals(UpdateReleaseContract.RequiredLauncherPaths)
            && new HashSet<string>(launchers, StringComparer.OrdinalIgnoreCase).Count == launchers.Count;
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

    private static bool HasExactProperties(JsonElement element, IReadOnlyCollection<string> expected)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            count++;
            if (!expected.Contains(property.Name, StringComparer.Ordinal) || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return count == expected.Count;
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');

    private static byte[] ReadBounded(Stream stream, long maximumBytes)
    {
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) return output.ToArray();
            if (output.Length > maximumBytes - read) throw new InvalidDataException("Manifest exceeds its byte limit.");
            output.Write(buffer, 0, read);
        }
    }

    private static bool MatchesPayload(string path, ReleasePayloadFile file)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length != file.Length) return false;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.SequentialScan);
            var actual = SHA256.HashData(stream);
            return CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(file.Sha256));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException)
        {
            return false;
        }
    }

    private static string? ReleasePath(string root, string relativePath)
    {
        var validation = WindowsReleasePathPolicy.Validate(relativePath);
        if (!validation.Success)
        {
            return null;
        }

        var fullPath = Path.GetFullPath(Path.Combine(root, validation.CanonicalKey!.Replace('/', Path.DirectorySeparatorChar)));
        return fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ? fullPath : null;
    }

    private static bool HasDevelopmentOrTestSegment(string root)
    {
        var segment = Path.GetFileName(root);
        return segment.Equals("bin", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("obj", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("TestResults", StringComparison.OrdinalIgnoreCase)
            || segment.Equals(".vs", StringComparison.OrdinalIgnoreCase);
    }

}
