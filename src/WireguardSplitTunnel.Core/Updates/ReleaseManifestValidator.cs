namespace WireguardSplitTunnel.Core.Updates;

public static class ReleaseManifestValidator
{
    private static readonly StringComparer PathComparer = StringComparer.OrdinalIgnoreCase;
    private static readonly IComparer<string> DeterministicPathComparer =
        Comparer<string>.Create((left, right) =>
        {
            var comparison = StringComparer.OrdinalIgnoreCase.Compare(left, right);
            return comparison != 0 ? comparison : StringComparer.Ordinal.Compare(left, right);
        });

    public static ManifestValidationResult Validate(
        ReleaseManifest? manifest,
        SemanticVersion expectedCandidate,
        SemanticVersion currentVersion,
        int supportedStateSchemaVersion,
        IReadOnlyList<string?>? archiveRegularFiles) =>
        ValidateCore(
            manifest,
            expectedCandidate,
            currentVersion,
            supportedStateSchemaVersion,
            archiveRegularFiles,
            requireNewerCandidate: true,
            requireDeterministicProducerOrder: false);

    /// <summary>
    /// Validates a manifest while it is being produced, before there is a
    /// distinct installed version to use as the consumer compatibility point.
    /// Compatibility floors may therefore equal the candidate version.
    /// </summary>
    public static ManifestValidationResult ValidateForProducer(
        ReleaseManifest? manifest,
        SemanticVersion expectedCandidate,
        int supportedStateSchemaVersion,
        IReadOnlyList<string?>? packageRegularFiles) =>
        ValidateCore(
            manifest,
            expectedCandidate,
            expectedCandidate,
            supportedStateSchemaVersion,
            packageRegularFiles,
            requireNewerCandidate: false,
            requireDeterministicProducerOrder: true);

    private static ManifestValidationResult ValidateCore(
        ReleaseManifest? manifest,
        SemanticVersion expectedCandidate,
        SemanticVersion currentVersion,
        int supportedStateSchemaVersion,
        IReadOnlyList<string?>? archiveRegularFiles,
        bool requireNewerCandidate,
        bool requireDeterministicProducerOrder)
    {
        if (manifest is null || archiveRegularFiles is null)
        {
            return Fail("null_input", "Manifest and archive paths are required.");
        }

        if (!TryGetCount(archiveRegularFiles, out var archiveCount)
            || archiveCount > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return Fail("too_many_entries", "Archive exceeds the maximum regular-file entry count.");
        }

        if (manifest.Files is null)
        {
            return Fail("files", "Manifest must declare payload files.");
        }

        if (!TryGetCount(manifest.Files, out var payloadCount)
            || payloadCount > WindowsReleasePathPolicy.MaximumArchiveEntries - 1)
        {
            return Fail("too_many_entries", "Manifest exceeds the maximum payload file count.");
        }

        if (!TrySnapshot(manifest.Files, payloadCount, out var manifestFiles)
            || !TrySnapshot(archiveRegularFiles, archiveCount, out var archiveFiles))
        {
            return Fail("collection_changed", "Manifest or archive collection changed during validation.");
        }

        if (manifest.SchemaVersion != 1 || supportedStateSchemaVersion <= 0 || manifest.StateSchemaVersion != supportedStateSchemaVersion)
        {
            return Fail("schema", "Manifest schema version is not supported.");
        }

        if (!SemanticVersion.TryParseNormalized(manifest.Version, out var manifestVersion)
            || manifestVersion != expectedCandidate
            || requireNewerCandidate && expectedCandidate.CompareTo(currentVersion) <= 0)
        {
            return Fail("version", "Manifest version must exactly match a newer selected release.");
        }

        if (manifest.RuntimeIdentifier != UpdateReleaseContract.WindowsRuntimeIdentifier
            || !TryFloor(manifest.MinimumAutoUpdateVersion, currentVersion, expectedCandidate)
            || !TryFloor(manifest.RollbackCompatibleFromVersion, currentVersion, expectedCandidate))
        {
            return Fail("compatibility", "Manifest runtime or version compatibility range is invalid.");
        }

        if (manifest.EntryPoint != UpdateReleaseContract.WindowsApplicationPath || manifest.UpdaterEntryPoint != UpdateReleaseContract.WindowsUpdaterPath)
        {
            return Fail("entrypoint", "Manifest entrypoints do not match the release contract.");
        }

        if (!TryGetCount(manifest.RequiredLaunchers, out var launcherCount)
            || launcherCount != UpdateReleaseContract.RequiredLauncherPaths.Count
            || !TrySnapshot(manifest.RequiredLaunchers!, launcherCount, out var launchers)
            || !ValidateExactLaunchers(launchers)
            || requireDeterministicProducerOrder
                && !launchers.SequenceEqual(
                    UpdateReleaseContract.RequiredLauncherPaths,
                    StringComparer.Ordinal))
        {
            return Fail("launchers", "Manifest launchers do not exactly match the release contract.");
        }

        if (manifestFiles.Count == 0)
        {
            return Fail("files", "Manifest must declare payload files.");
        }

        var files = new List<ReleasePayloadFile>(manifestFiles.Count);
        var filePaths = new HashSet<string>(PathComparer);
        foreach (var file in manifestFiles)
        {
            if (file is null || !ValidatePayload(file, filePaths))
            {
                return Fail("payload", "Manifest contains an invalid or protected payload file.");
            }

            files.Add(new ReleasePayloadFile(file.Path, file.Length, CanonicalHash(file.Sha256)));
        }

        if (filePaths.Contains(UpdateReleaseContract.ReleaseManifestPath) || !ContainsAllRequiredPayloads(filePaths))
        {
            return Fail("payload_contract", "Manifest payload files do not contain the required release files.");
        }

        if (requireDeterministicProducerOrder
            && !files.Select(file => file.Path).SequenceEqual(
                files.Select(file => file.Path).OrderBy(path => path, DeterministicPathComparer),
                StringComparer.Ordinal))
        {
            return Fail("payload_order", "Manifest payload files are not in deterministic path order.");
        }

        if (!ValidateArchiveSet(archiveFiles, files.Select(file => file.Path)))
        {
            return Fail("archive", "Archive regular files do not exactly match the manifest payload set.");
        }

        var snapshot = ReleaseManifest.CreateValidatedSnapshot(
            manifest.SchemaVersion, manifest.Version, manifest.RuntimeIdentifier, manifest.MinimumAutoUpdateVersion,
            manifest.RollbackCompatibleFromVersion, manifest.StateSchemaVersion, manifest.EntryPoint, manifest.UpdaterEntryPoint,
            launchers, files);
        return ManifestValidationResult.Valid(snapshot);
    }

    private static bool TryFloor(string? value, SemanticVersion current, SemanticVersion candidate) =>
        SemanticVersion.TryParseNormalized(value, out var floor) && current.CompareTo(floor) >= 0 && floor.CompareTo(candidate) <= 0;

    private static bool TryGetCount<T>(IReadOnlyList<T>? values, out int count)
    {
        if (values is null)
        {
            count = 0;
            return false;
        }

        try
        {
            count = values.Count;
            return count >= 0;
        }
        catch (Exception exception) when (IsCollectionAccessException(exception))
        {
            count = 0;
            return false;
        }
    }

    private static bool TrySnapshot<T>(IReadOnlyList<T> values, int expectedCount, out IReadOnlyList<T> snapshot)
    {
        var copy = new T[expectedCount];
        try
        {
            for (var index = 0; index < expectedCount; index++)
            {
                copy[index] = values[index];
            }

            if (values.Count != expectedCount)
            {
                snapshot = [];
                return false;
            }
        }
        catch (Exception exception) when (IsCollectionAccessException(exception))
        {
            snapshot = [];
            return false;
        }

        snapshot = Array.AsReadOnly(copy);
        return true;
    }

    private static bool IsCollectionAccessException(Exception exception) =>
        exception is InvalidOperationException or ArgumentOutOfRangeException or IndexOutOfRangeException or NotSupportedException;

    private static bool ValidateExactLaunchers(IReadOnlyList<string>? launchers)
    {
        if (launchers is null || launchers.Count != UpdateReleaseContract.RequiredLauncherPaths.Count)
        {
            return false;
        }

        var validation = WindowsReleasePathPolicy.ValidateCollection(launchers.Cast<string?>().ToList());
        return validation.Success
            && new HashSet<string>(launchers, StringComparer.Ordinal).SetEquals(UpdateReleaseContract.RequiredLauncherPaths)
            && new HashSet<string>(launchers, PathComparer).Count == launchers.Count;
    }

    private static bool ValidatePayload(ReleasePayloadFile file, HashSet<string> paths)
    {
        var path = WindowsReleasePathPolicy.Validate(file.Path);
        return path.Success
            && paths.Add(path.CanonicalKey!)
            && file.Length >= 0
            && IsSha256(file.Sha256)
            && !ReleaseManagedPathPolicy.IsProtectedPayloadPath(path.CanonicalKey!);
    }

    private static bool ContainsAllRequiredPayloads(HashSet<string> paths) =>
        paths.Contains(UpdateReleaseContract.WindowsApplicationPath)
        && paths.Contains(UpdateReleaseContract.WindowsUpdaterPath)
        && UpdateReleaseContract.RequiredLauncherPaths.All(paths.Contains);

    private static bool ValidateArchiveSet(IReadOnlyList<string?> archivePaths, IEnumerable<string> payloadPaths)
    {
        var archive = WindowsReleasePathPolicy.ValidateCollection(archivePaths);
        if (!archive.Success || !archive.CanonicalKeys.Contains(UpdateReleaseContract.ReleaseManifestPath, StringComparer.Ordinal))
        {
            return false;
        }

        var withoutManifest = archive.CanonicalKeys.Where(path => path != UpdateReleaseContract.ReleaseManifestPath).ToList();
        var expected = payloadPaths.ToList();
        return withoutManifest.Count == expected.Count
            && new HashSet<string>(withoutManifest, PathComparer).SetEquals(expected)
            && new HashSet<string>(withoutManifest, StringComparer.Ordinal).SetEquals(expected);
    }

    private static bool IsSha256(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
            {
                return false;
            }
        }

        return true;
    }

    private static string CanonicalHash(string value) => value.ToLowerInvariant();

    private static ManifestValidationResult Fail(string code, string message) => ManifestValidationResult.Failure(code, message);
}
