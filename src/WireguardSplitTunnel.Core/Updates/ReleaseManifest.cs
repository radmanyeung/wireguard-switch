namespace WireguardSplitTunnel.Core.Updates;

public sealed record ReleaseManifest
{
    public ReleaseManifest(
        int schemaVersion, string version, string runtimeIdentifier, string minimumAutoUpdateVersion,
        string rollbackCompatibleFromVersion, int stateSchemaVersion, string entryPoint, string updaterEntryPoint,
        IReadOnlyList<string>? requiredLaunchers, IReadOnlyList<ReleasePayloadFile>? files)
    {
        SchemaVersion = schemaVersion;
        Version = version;
        RuntimeIdentifier = runtimeIdentifier;
        MinimumAutoUpdateVersion = minimumAutoUpdateVersion;
        RollbackCompatibleFromVersion = rollbackCompatibleFromVersion;
        StateSchemaVersion = stateSchemaVersion;
        EntryPoint = entryPoint;
        UpdaterEntryPoint = updaterEntryPoint;
        RequiredLaunchers = requiredLaunchers;
        Files = files;
    }

    public int SchemaVersion { get; init; }
    public string Version { get; init; }
    public string RuntimeIdentifier { get; init; }
    public string MinimumAutoUpdateVersion { get; init; }
    public string RollbackCompatibleFromVersion { get; init; }
    public int StateSchemaVersion { get; init; }
    public string EntryPoint { get; init; }
    public string UpdaterEntryPoint { get; init; }
    public IReadOnlyList<string>? RequiredLaunchers { get; init; }
    public IReadOnlyList<ReleasePayloadFile>? Files { get; init; }

    internal static ReleaseManifest CreateValidatedSnapshot(
        int schemaVersion, string version, string runtimeIdentifier, string minimumAutoUpdateVersion,
        string rollbackCompatibleFromVersion, int stateSchemaVersion, string entryPoint, string updaterEntryPoint,
        IReadOnlyList<string> requiredLaunchers, IReadOnlyList<ReleasePayloadFile> files)
    {
        var snapshot = new ReleaseManifest(
            schemaVersion, version, runtimeIdentifier, minimumAutoUpdateVersion, rollbackCompatibleFromVersion,
            stateSchemaVersion, entryPoint, updaterEntryPoint, requiredLaunchers, files);
        return snapshot with
        {
            RequiredLaunchers = Array.AsReadOnly(requiredLaunchers.ToArray()),
            Files = Array.AsReadOnly(files.ToArray())
        };
    }
}

public sealed record ReleasePayloadFile(string Path, long Length, string Sha256);

public sealed record ManifestValidationResult(bool IsValid, ReleaseManifest? Manifest, string? ErrorCode, string? ErrorMessage)
{
    public static ManifestValidationResult Failure(string errorCode, string message) => new(false, null, errorCode, message);
    public static ManifestValidationResult Valid(ReleaseManifest manifest) => new(true, manifest, null, null);
}
