using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.ReleaseTool;

public static class ReleaseToolApplication
{
    private const long MaximumPropsBytes = 1024 * 1024;
    private static readonly UTF8Encoding Utf8NoBom = new(false, true);
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
    private static readonly IComparer<string> DeterministicPathComparer =
        Comparer<string>.Create((left, right) =>
        {
            var comparison =
                StringComparer.OrdinalIgnoreCase.Compare(left, right);
            return comparison != 0
                ? comparison
                : StringComparer.Ordinal.Compare(left, right);
        });
    private static readonly JsonSerializerOptions ManifestJsonOptions =
        new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow,
            AllowTrailingCommas = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            WriteIndented = false,
            MaxDepth = 32
        };

    public static int Run(
        IReadOnlyList<string> arguments,
        TextWriter standardOutput,
        TextWriter standardError)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(standardOutput);
        ArgumentNullException.ThrowIfNull(standardError);

        try
        {
            if (arguments.Count == 0)
            {
                throw new CommandLineException(
                    "A command is required.");
            }

            switch (arguments[0])
            {
                case "generate-manifest":
                {
                    var options = StrictOptions.Parse(
                        arguments,
                        "--package-root",
                        "--props",
                        "--expected-tag");
                    var manifestPath = GenerateManifest(
                        options["--package-root"],
                        options["--props"],
                        options["--expected-tag"]);
                    standardOutput.WriteLine(manifestPath);
                    return 0;
                }
                case "validate-package":
                {
                    var options = StrictOptions.Parse(
                        arguments,
                        "--package-root",
                        "--props",
                        "--expected-tag");
                    ValidatePackage(
                        options["--package-root"],
                        options["--props"],
                        options["--expected-tag"]);
                    standardOutput.WriteLine(
                        "Release package is valid.");
                    return 0;
                }
                case "write-checksum":
                {
                    var options = StrictOptions.Parse(
                        arguments,
                        "--archive",
                        "--output");
                    var outputPath = WriteChecksum(
                        options["--archive"],
                        options["--output"]);
                    standardOutput.WriteLine(outputPath);
                    return 0;
                }
                default:
                    throw new CommandLineException(
                        $"Unknown command: {arguments[0]}");
            }
        }
        catch (CommandLineException exception)
        {
            standardError.WriteLine($"error: {exception.Message}");
            standardError.WriteLine(Usage);
            return 2;
        }
        catch (ReleaseToolException exception)
        {
            standardError.WriteLine($"error: {exception.Message}");
            return 1;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidDataException
                or JsonException
                or XmlException
                or CryptographicException
                or NotSupportedException)
        {
            standardError.WriteLine(
                $"error: {exception.GetType().Name}: {exception.Message}");
            return 1;
        }
    }

    private static string GenerateManifest(
        string packageRoot,
        string propsPath,
        string expectedTag)
    {
        var settings =
            ReadReleaseSettings(propsPath, expectedTag);
        var package = EnumeratePackage(packageRoot);
        var payload = package.Files
            .Where(file => !file.RelativePath.Equals(
                UpdateReleaseContract.ReleaseManifestPath,
                StringComparison.Ordinal))
            .OrderBy(file => file.RelativePath, DeterministicPathComparer)
            .ToArray();
        var manifest = CreateManifest(settings, payload);
        var packagePaths = payload
            .Select(file => (string?)file.RelativePath)
            .Append(UpdateReleaseContract.ReleaseManifestPath)
            .ToArray();
        EnsureProducerManifestIsValid(
            manifest,
            settings.Version,
            settings.StateSchemaVersion,
            packagePaths);

        var manifestPath = Path.Combine(
            package.RootPath,
            UpdateReleaseContract.ReleaseManifestPath);
        EnsureSafeOutputFile(
            manifestPath,
            package.RootPath,
            "Release manifest");
        var bytes = SerializeManifest(manifest);
        using (var stream = new FileStream(
                   manifestPath,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        return manifestPath;
    }

    private static void ValidatePackage(
        string packageRoot,
        string propsPath,
        string expectedTag)
    {
        var settings =
            ReadReleaseSettings(propsPath, expectedTag);
        var package = EnumeratePackage(packageRoot);
        var manifestFiles = package.Files
            .Where(file => file.RelativePath.Equals(
                UpdateReleaseContract.ReleaseManifestPath,
                StringComparison.Ordinal))
            .ToArray();
        if (manifestFiles.Length != 1)
        {
            throw new ReleaseToolException(
                "The package must contain exactly one release-manifest.json.");
        }

        var manifestFile = manifestFiles[0];
        if (manifestFile.Length > UpdateNetworkLimits.MetadataBytes)
        {
            throw new ReleaseToolException(
                "release-manifest.json exceeds the metadata size limit.");
        }

        ReleaseManifest manifest;
        try
        {
            var bytes = ReadExactRegularFile(manifestFile.FullPath);
            manifest = JsonSerializer.Deserialize<ReleaseManifest>(
                    bytes,
                    ManifestJsonOptions)
                ?? throw new JsonException(
                    "Manifest JSON resolved to null.");
        }
        catch (JsonException exception)
        {
            throw new ReleaseToolException(
                $"release-manifest.json is invalid: {exception.Message}");
        }

        var packagePaths = package.Files
            .Select(file => (string?)file.RelativePath)
            .ToArray();
        EnsureProducerManifestIsValid(
            manifest,
            settings.Version,
            settings.StateSchemaVersion,
            packagePaths);

        var payload = package.Files
            .Where(file => !file.RelativePath.Equals(
                UpdateReleaseContract.ReleaseManifestPath,
                StringComparison.Ordinal))
            .OrderBy(file => file.RelativePath, DeterministicPathComparer)
            .ToArray();
        var expectedManifest = CreateManifest(settings, payload);
        var actualBytes = ReadExactRegularFile(
            manifestFile.FullPath);
        var expectedBytes = SerializeManifest(expectedManifest);
        if (!CryptographicOperations.FixedTimeEquals(
                actualBytes,
                expectedBytes))
        {
            throw new ReleaseToolException(
                "release-manifest.json does not exactly match the deterministic package file set, lengths, hashes, or Release fields.");
        }

        ValidateProductVersion(
            package,
            UpdateReleaseContract.WindowsApplicationPath,
            settings.Version);
        ValidateProductVersion(
            package,
            UpdateReleaseContract.WindowsUpdaterPath,
            settings.Version);
    }

    private static string WriteChecksum(
        string archivePath,
        string outputPath)
    {
        var archive = RequirePlainFile(
            archivePath,
            "Release archive");
        if (!Path.GetFileName(archive).Equals(
                UpdateReleaseContract.WindowsAssetName,
                StringComparison.Ordinal))
        {
            throw new ReleaseToolException(
                $"Release archive must be named {UpdateReleaseContract.WindowsAssetName}.");
        }

        var output = Path.GetFullPath(
            RequireText(outputPath, "--output"));
        var expectedOutput = archive
            + ".sha256";
        if (!output.Equals(expectedOutput, PathComparison))
        {
            throw new ReleaseToolException(
                $"Checksum output must be the exact sidecar path {expectedOutput}.");
        }

        EnsureSafeOutputFile(
            output,
            Path.GetDirectoryName(archive)
                ?? throw new ReleaseToolException(
                    "Release archive has no parent directory."),
            "Checksum output");
        var digest = HashRegularFile(archive).Sha256;
        var content =
            $"{digest}  {UpdateReleaseContract.WindowsAssetName}\n";
        using (var stream = new FileStream(
                   output,
                   FileMode.Create,
                   FileAccess.Write,
                   FileShare.None))
        using (var writer = new StreamWriter(
                   stream,
                   Utf8NoBom,
                   bufferSize: 1024,
                   leaveOpen: false))
        {
            writer.NewLine = "\n";
            writer.Write(content);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        return output;
    }

    private static ReleaseManifest CreateManifest(
        ReleaseSettings settings,
        IReadOnlyList<PackageFile> payload) =>
        new(
            schemaVersion: 1,
            version: settings.Version.ToString(),
            runtimeIdentifier:
                UpdateReleaseContract.WindowsRuntimeIdentifier,
            minimumAutoUpdateVersion:
                settings.MinimumAutoUpdateVersion.ToString(),
            rollbackCompatibleFromVersion:
                settings.RollbackCompatibleFromVersion.ToString(),
            stateSchemaVersion: settings.StateSchemaVersion,
            entryPoint:
                UpdateReleaseContract.WindowsApplicationPath,
            updaterEntryPoint:
                UpdateReleaseContract.WindowsUpdaterPath,
            requiredLaunchers:
                Array.AsReadOnly(
                    UpdateReleaseContract.RequiredLauncherPaths
                        .ToArray()),
            files:
                Array.AsReadOnly(
                    payload
                        .Select(file => new ReleasePayloadFile(
                            file.RelativePath,
                            file.Length,
                            file.Sha256))
                        .ToArray()));

    private static byte[] SerializeManifest(
        ReleaseManifest manifest) =>
        JsonSerializer.SerializeToUtf8Bytes(
            manifest,
            ManifestJsonOptions);

    private static void EnsureProducerManifestIsValid(
        ReleaseManifest manifest,
        SemanticVersion expectedVersion,
        int stateSchemaVersion,
        IReadOnlyList<string?> packagePaths)
    {
        var validation =
            ReleaseManifestValidator.ValidateForProducer(
                manifest,
                expectedVersion,
                stateSchemaVersion,
                packagePaths);
        if (!validation.IsValid)
        {
            throw new ReleaseToolException(
                $"Release manifest validation failed ({validation.ErrorCode}): {validation.ErrorMessage}");
        }
    }

    private static void ValidateProductVersion(
        PackageSnapshot package,
        string relativePath,
        SemanticVersion expectedVersion)
    {
        var matches = package.Files
            .Where(file => file.RelativePath.Equals(
                relativePath,
                StringComparison.Ordinal))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new ReleaseToolException(
                $"ProductVersion validation requires {relativePath}.");
        }

        string? rawVersion;
        try
        {
            EnsurePlainExistingPath(
                matches[0].FullPath,
                expectDirectory: false,
                "ProductVersion executable");
            rawVersion = FileVersionInfo
                .GetVersionInfo(matches[0].FullPath)
                .ProductVersion;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException)
        {
            throw new ReleaseToolException(
                $"ProductVersion could not be read for {relativePath}: {exception.GetType().Name}.");
        }

        if (!SemanticVersion.TryParseNormalized(
                rawVersion,
                out var actualVersion)
            || actualVersion != expectedVersion
            || rawVersion != actualVersion.ToString())
        {
            throw new ReleaseToolException(
                $"ProductVersion mismatch for {relativePath}: expected {expectedVersion}, found {rawVersion ?? "<missing>"}.");
        }
    }

    private static ReleaseSettings ReadReleaseSettings(
        string propsPath,
        string expectedTag)
    {
        var props = RequirePlainFile(
            propsPath,
            "Directory.Build.props");
        var info = new FileInfo(props);
        if (info.Length <= 0
            || info.Length > MaximumPropsBytes)
        {
            throw new ReleaseToolException(
                "Directory.Build.props has an invalid size.");
        }

        XDocument document;
        try
        {
            using var stream = new FileStream(
                props,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);
            using var reader = XmlReader.Create(
                stream,
                new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = MaximumPropsBytes,
                    IgnoreComments = false,
                    IgnoreWhitespace = false,
                    CloseInput = false
                });
            document = XDocument.Load(
                reader,
                LoadOptions.PreserveWhitespace);
        }
        catch (Exception exception) when (
            exception is XmlException
                or IOException
                or UnauthorizedAccessException
                or InvalidDataException)
        {
            throw new ReleaseToolException(
                $"Directory.Build.props could not be read: {exception.Message}");
        }

        if (document.Root is null
            || document.Root.Name != XName.Get("Project"))
        {
            throw new ReleaseToolException(
                "Directory.Build.props must have an exact un-namespaced Project root.");
        }

        var rawVersion = ReadExactProperty(
            document,
            "VersionPrefix");
        var rawMinimum = ReadExactProperty(
            document,
            "MinimumAutoUpdateVersion");
        var rawRollback = ReadExactProperty(
            document,
            "RollbackCompatibleFromVersion");
        var rawSchema = ReadExactProperty(
            document,
            "StateSchemaVersion");

        var version = ParseCanonicalVersion(
            rawVersion,
            "VersionPrefix");
        var minimum = ParseCanonicalVersion(
            rawMinimum,
            "MinimumAutoUpdateVersion");
        var rollback = ParseCanonicalVersion(
            rawRollback,
            "RollbackCompatibleFromVersion");
        if (!int.TryParse(
                rawSchema,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var stateSchemaVersion)
            || stateSchemaVersion <= 0
            || rawSchema != stateSchemaVersion.ToString(
                CultureInfo.InvariantCulture))
        {
            throw new ReleaseToolException(
                "StateSchemaVersion must be one canonical positive integer.");
        }

        var tag = RequireText(
            expectedTag,
            "--expected-tag");
        if (!SemanticVersion.TryParseTag(
                tag,
                out var tagVersion)
            || tag != $"v{tagVersion}"
            || tagVersion != version)
        {
            throw new ReleaseToolException(
                $"Expected stable tag must exactly equal v{version}.");
        }

        if (minimum.CompareTo(version) > 0
            || rollback.CompareTo(version) > 0)
        {
            throw new ReleaseToolException(
                "Compatibility versions cannot be newer than VersionPrefix.");
        }

        return new ReleaseSettings(
            version,
            minimum,
            rollback,
            stateSchemaVersion);
    }

    private static string ReadExactProperty(
        XDocument document,
        string name)
    {
        var matches = document
            .Descendants(XName.Get(name))
            .Where(element =>
                element.Parent?.Name
                == XName.Get("PropertyGroup"))
            .ToArray();
        if (matches.Length != 1)
        {
            throw new ReleaseToolException(
                $"Directory.Build.props must contain exactly one {name} property.");
        }

        var element = matches[0];
        if (element.HasAttributes
            || element.HasElements
            || element.Value.Length == 0
            || element.Value != element.Value.Trim())
        {
            throw new ReleaseToolException(
                $"{name} must be one exact literal value without conditions or surrounding whitespace.");
        }

        return element.Value;
    }

    private static SemanticVersion ParseCanonicalVersion(
        string value,
        string propertyName)
    {
        if (!SemanticVersion.TryParseNormalized(
                value,
                out var version)
            || value != version.ToString())
        {
            throw new ReleaseToolException(
                $"{propertyName} must be a canonical stable semantic version.");
        }

        return version;
    }

    private static PackageSnapshot EnumeratePackage(
        string packageRoot)
    {
        var root = RequirePlainDirectory(
            packageRoot,
            "Package root");
        var files = new List<PackageFile>();
        var seenFiles =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
        var seenDirectories =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>();
        pending.Push(root);
        var entryCount = 0;

        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            EnsurePlainExistingPath(
                directory,
                expectDirectory: true,
                "Package directory");
            FileSystemInfo[] entries;
            try
            {
                entries = new DirectoryInfo(directory)
                    .GetFileSystemInfos();
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or NotSupportedException)
            {
                throw new ReleaseToolException(
                    $"Package directory could not be enumerated: {exception.Message}");
            }

            foreach (var entry in entries)
            {
                entryCount++;
                if (entryCount
                    > WindowsReleasePathPolicy.MaximumArchiveEntries)
                {
                    throw new ReleaseToolException(
                        "Package exceeds the maximum entry count.");
                }

                RejectReparsePoint(entry, "Package entry");
                var fullPath = Path.GetFullPath(entry.FullName);
                if (!IsStrictDescendant(root, fullPath))
                {
                    throw new ReleaseToolException(
                        $"Package entry escapes the package root: {entry.Name}");
                }

                var relativePath = Path.GetRelativePath(
                        root,
                        fullPath)
                    .Replace(
                        Path.DirectorySeparatorChar,
                        '/')
                    .Replace(
                        Path.AltDirectorySeparatorChar,
                        '/');
                if (entry is DirectoryInfo)
                {
                    var directoryValidation =
                        WindowsReleasePathPolicy.Validate(
                            $"{relativePath}/placeholder");
                    if (!directoryValidation.Success
                        || !seenDirectories.Add(relativePath))
                    {
                        throw new ReleaseToolException(
                            $"Package contains an unsafe or colliding directory path: {relativePath}.");
                    }

                    pending.Push(fullPath);
                    continue;
                }

                if (entry is not FileInfo)
                {
                    throw new ReleaseToolException(
                        $"Package contains an unsupported entry: {relativePath}.");
                }

                var pathValidation =
                    WindowsReleasePathPolicy.Validate(
                        relativePath);
                if (!pathValidation.Success
                    || !seenFiles.Add(
                        pathValidation.CanonicalKey!))
                {
                    throw new ReleaseToolException(
                        $"Package contains an unsafe or colliding file path: {relativePath}.");
                }

                if (!relativePath.Equals(
                        UpdateReleaseContract.ReleaseManifestPath,
                        StringComparison.Ordinal)
                    && ReleaseManagedPathPolicy
                        .IsProtectedPayloadPath(relativePath))
                {
                    throw new ReleaseToolException(
                        $"Package contains a protected runtime path: {relativePath}.");
                }

                var measured = HashRegularFile(fullPath);
                files.Add(
                    new PackageFile(
                        relativePath,
                        fullPath,
                        measured.Length,
                        measured.Sha256));
            }
        }

        return new PackageSnapshot(
            root,
            files
                .OrderBy(
                    file => file.RelativePath,
                    DeterministicPathComparer)
                .ToArray());
    }

    private static FileDigest HashRegularFile(
        string path)
    {
        EnsurePlainExistingPath(
            path,
            expectDirectory: false,
            "Package file");
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 128 * 1024,
                FileOptions.SequentialScan);
            var length = stream.Length;
            var digest = SHA256.HashData(stream);
            EnsurePlainExistingPath(
                path,
                expectDirectory: false,
                "Package file");
            return new FileDigest(
                length,
                Convert.ToHexString(digest)
                    .ToLowerInvariant());
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException
                or CryptographicException)
        {
            throw new ReleaseToolException(
                $"Package file could not be hashed: {path}: {exception.Message}");
        }
    }

    private static byte[] ReadExactRegularFile(
        string path)
    {
        EnsurePlainExistingPath(
            path,
            expectDirectory: false,
            "Package file");
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);
            if (stream.Length > int.MaxValue)
            {
                throw new ReleaseToolException(
                    $"Package file is too large to read: {path}");
            }

            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            EnsurePlainExistingPath(
                path,
                expectDirectory: false,
                "Package file");
            return bytes;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException)
        {
            throw new ReleaseToolException(
                $"Package file could not be read: {path}: {exception.Message}");
        }
    }

    private static string RequirePlainDirectory(
        string value,
        string label)
    {
        var fullPath = Path.GetFullPath(
            RequireText(value, label));
        EnsurePlainExistingPath(
            fullPath,
            expectDirectory: true,
            label);
        return Path.TrimEndingDirectorySeparator(
            fullPath);
    }

    private static string RequirePlainFile(
        string value,
        string label)
    {
        var fullPath = Path.GetFullPath(
            RequireText(value, label));
        EnsurePlainExistingPath(
            fullPath,
            expectDirectory: false,
            label);
        return fullPath;
    }

    private static void EnsureSafeOutputFile(
        string outputPath,
        string allowedRoot,
        string label)
    {
        var output = Path.GetFullPath(outputPath);
        var root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(allowedRoot));
        if (!IsStrictDescendant(root, output))
        {
            throw new ReleaseToolException(
                $"{label} escapes its allowed root.");
        }

        var parent = Path.GetDirectoryName(output)
            ?? throw new ReleaseToolException(
                $"{label} has no parent directory.");
        EnsurePlainExistingPath(
            parent,
            expectDirectory: true,
            $"{label} parent");
        if (File.Exists(output)
            || Directory.Exists(output))
        {
            EnsurePlainExistingPath(
                output,
                expectDirectory: false,
                label);
        }
    }

    private static void EnsurePlainExistingPath(
        string fullPath,
        bool expectDirectory,
        string label)
    {
        var normalized = Path.GetFullPath(fullPath);
        EnsureExistingAncestorsArePlain(
            normalized,
            label);
        var exists = expectDirectory
            ? Directory.Exists(normalized)
            : File.Exists(normalized);
        if (!exists)
        {
            throw new ReleaseToolException(
                $"{label} does not exist as a regular {(expectDirectory ? "directory" : "file")}: {normalized}");
        }

        FileSystemInfo info = expectDirectory
            ? new DirectoryInfo(normalized)
            : new FileInfo(normalized);
        RejectReparsePoint(info, label);
    }

    private static void EnsureExistingAncestorsArePlain(
        string fullPath,
        string label)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            throw new ReleaseToolException(
                $"{label} is not an absolute path.");
        }

        var current = root;
        var remainder = fullPath[root.Length..];
        foreach (var segment in remainder.Split(
                     [Path.DirectorySeparatorChar,
                         Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(
                current,
                segment);
            if (!File.Exists(current)
                && !Directory.Exists(current))
            {
                throw new ReleaseToolException(
                    $"{label} contains a missing path component: {current}");
            }

            var attributes = File.GetAttributes(current);
            if ((attributes
                    & FileAttributes.ReparsePoint) != 0)
            {
                throw new ReleaseToolException(
                    $"{label} contains a reparse point: {current}");
            }
        }
    }

    private static void RejectReparsePoint(
        FileSystemInfo info,
        string label)
    {
        try
        {
            info.Refresh();
            if ((info.Attributes
                    & FileAttributes.ReparsePoint) != 0
                || info.LinkTarget is not null)
            {
                throw new ReleaseToolException(
                    $"{label} cannot be a reparse point or symbolic link: {info.FullName}");
            }
        }
        catch (ReleaseToolException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException)
        {
            throw new ReleaseToolException(
                $"{label} safety could not be verified: {info.FullName}: {exception.Message}");
        }
    }

    private static bool IsStrictDescendant(
        string root,
        string path)
    {
        var normalizedRoot =
            Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(root));
        var normalizedPath =
            Path.GetFullPath(path);
        return normalizedPath.StartsWith(
            normalizedRoot
                + Path.DirectorySeparatorChar,
            PathComparison);
    }

    private static string RequireText(
        string? value,
        string name)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value != value.Trim())
        {
            throw new ReleaseToolException(
                $"{name} requires one non-empty exact value.");
        }

        return value;
    }

    private const string Usage =
        "Usage:\n"
        + "  generate-manifest --package-root <path> --props <path> --expected-tag <vX.Y.Z>\n"
        + "  validate-package --package-root <path> --props <path> --expected-tag <vX.Y.Z>\n"
        + "  write-checksum --archive <path> --output <path>";

    private sealed record ReleaseSettings(
        SemanticVersion Version,
        SemanticVersion MinimumAutoUpdateVersion,
        SemanticVersion RollbackCompatibleFromVersion,
        int StateSchemaVersion);

    private sealed record PackageSnapshot(
        string RootPath,
        IReadOnlyList<PackageFile> Files);

    private sealed record PackageFile(
        string RelativePath,
        string FullPath,
        long Length,
        string Sha256);

    private readonly record struct FileDigest(
        long Length,
        string Sha256);

    private sealed class StrictOptions
    {
        private readonly IReadOnlyDictionary<string, string> _values;

        private StrictOptions(
            IReadOnlyDictionary<string, string> values)
        {
            _values = values;
        }

        internal string this[string option] =>
            _values[option];

        internal static StrictOptions Parse(
            IReadOnlyList<string> arguments,
            params string[] requiredOptions)
        {
            if (arguments.Count
                != 1 + (requiredOptions.Length * 2))
            {
                throw new CommandLineException(
                    $"Command {arguments[0]} requires exactly {requiredOptions.Length} option/value pairs.");
            }

            var allowed = new HashSet<string>(
                requiredOptions,
                StringComparer.Ordinal);
            var values = new Dictionary<string, string>(
                StringComparer.Ordinal);
            for (var index = 1;
                 index < arguments.Count;
                 index += 2)
            {
                var option = arguments[index];
                if (!allowed.Contains(option))
                {
                    throw new CommandLineException(
                        $"Unknown option for {arguments[0]}: {option}");
                }

                if (!values.TryAdd(
                        option,
                        arguments[index + 1]))
                {
                    throw new CommandLineException(
                        $"Duplicate option for {arguments[0]}: {option}");
                }
            }

            foreach (var required in requiredOptions)
            {
                if (!values.TryGetValue(
                        required,
                        out var value)
                    || string.IsNullOrWhiteSpace(value)
                    || value.StartsWith(
                        "--",
                        StringComparison.Ordinal))
                {
                    throw new CommandLineException(
                        $"Missing value for {required}.");
                }
            }

            return new StrictOptions(values);
        }
    }

    private sealed class CommandLineException(
        string message)
        : Exception(message);

    private sealed class ReleaseToolException(
        string message)
        : Exception(message);
}
