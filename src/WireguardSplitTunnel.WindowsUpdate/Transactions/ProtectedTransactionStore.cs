using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public enum ProtectedTransactionPhase
{
    ProtectedStaged,
    CloseAuthorized,
    Prepared,
    BackingUp,
    Applying,
    AppliedAwaitingHealth,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryBlocked
}

public sealed record ProtectedManagedFileIdentity(
    string RelativePath,
    long Length,
    string Sha256);

public sealed record ProtectedInstalledReleaseIdentity(
    string InstallRoot,
    ulong VolumeSerialNumber,
    ulong RootFileIdLow,
    ulong RootFileIdHigh,
    SemanticVersion CurrentVersion,
    SemanticVersion MinimumAutoUpdateVersion,
    SemanticVersion RollbackCompatibleFromVersion,
    int StateSchemaVersion,
    string ApplicationRelativePath,
    string UpdaterRelativePath,
    string CurrentManifestSha256,
    IReadOnlyList<ProtectedManagedFileIdentity> ManagedFiles);

public sealed record ProtectedCandidateIdentity(
    string ArchiveSha256,
    string NewManifestSha256,
    long ExpandedBytes);

public sealed record ProcessIdentity(
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ImagePath);

public sealed record ProtectedJournalMetadata(
    int SchemaVersion,
    long Generation,
    string? Sha256 = null);

public sealed record ProtectedStagedTransactionMaterial(
    ProtectedTransactionId TransactionId,
    SemanticVersion Version,
    PendingUpdateSource Source,
    ProtectedInstalledReleaseIdentity InstalledRelease,
    ProtectedCandidateIdentity Candidate,
    string HelperSha256,
    ProtectedJournalMetadata Journal);

public sealed record ProtectedActiveTransactionExpectation(
    ProtectedTransactionId TransactionId,
    SemanticVersion Version,
    PendingUpdateSource Source);

public sealed record ProtectedTransactionRecord(
    int SchemaVersion,
    ProtectedTransactionId TransactionId,
    SemanticVersion Version,
    PendingUpdateSource Source,
    ProtectedInstalledReleaseIdentity InstalledRelease,
    ProtectedCandidateIdentity Candidate,
    string HelperSha256,
    ProtectedTransactionPhase Phase,
    ProcessIdentity? AuthorizedProcess,
    ProtectedJournalMetadata Journal);

public enum ProtectedTransactionStoreError
{
    None,
    InvalidAuthority,
    InvalidData,
    UnsafePath,
    Missing,
    CorruptData,
    AclMismatch,
    VerificationFailed,
    Conflict,
    AtomicWriteFailed,
    IoFailure
}

public sealed record ProtectedTransactionStoreResult(
    bool Success,
    ProtectedTransactionStoreError Error)
{
    internal static ProtectedTransactionStoreResult Completed() =>
        new(true, ProtectedTransactionStoreError.None);

    internal static ProtectedTransactionStoreResult Failed(
        ProtectedTransactionStoreError error) =>
        new(false, error);
}

public sealed record ProtectedTransactionWriteResult(
    bool Success,
    ProtectedTransactionRecord? Record,
    ProtectedTransactionStoreError Error)
{
    internal static ProtectedTransactionWriteResult Completed(
        ProtectedTransactionRecord record) =>
        new(true, record, ProtectedTransactionStoreError.None);

    internal static ProtectedTransactionWriteResult Failed(
        ProtectedTransactionStoreError error) =>
        new(false, null, error);
}

public sealed record ProtectedTransactionReadResult(
    bool Success,
    ProtectedTransactionRecord? Record,
    ProtectedTransactionStoreError Error)
{
    internal static ProtectedTransactionReadResult Found(
        ProtectedTransactionRecord record) =>
        new(true, record, ProtectedTransactionStoreError.None);

    internal static ProtectedTransactionReadResult Failed(
        ProtectedTransactionStoreError error) =>
        new(false, null, error);
}

public sealed record ProtectedActiveTransactionReadResult(
    bool Success,
    ProtectedTransactionId? TransactionId,
    ProtectedTransactionStoreError Error)
{
    internal static ProtectedActiveTransactionReadResult Found(
        ProtectedTransactionId? transactionId) =>
        new(true, transactionId, ProtectedTransactionStoreError.None);

    internal static ProtectedActiveTransactionReadResult Failed(
        ProtectedTransactionStoreError error) =>
        new(false, null, error);
}

internal enum ProtectedJournalObservation
{
    Unavailable,
    AbsentInitial,
    MatchesBoundHash,
    PresentButUnbound,
    MissingButBound,
    HashMismatch
}

internal sealed record ProtectedJournalRecoveryReadResult(
    bool Success,
    ProtectedTransactionRecord? Record,
    ProtectedJournalObservation Observation,
    byte[]? RecordBytes,
    byte[]? JournalBytes,
    string? JournalSha256,
    ProtectedTransactionStoreError Error)
{
    internal static ProtectedJournalRecoveryReadResult Found(
        ProtectedTransactionRecord record,
        ProtectedJournalObservation observation,
        byte[] recordBytes,
        byte[]? journalBytes,
        string? journalSha256) =>
        new(
            true,
            record,
            observation,
            recordBytes,
            journalBytes,
            journalSha256,
            ProtectedTransactionStoreError.None);

    internal static ProtectedJournalRecoveryReadResult Failed(
        ProtectedTransactionStoreError error) =>
        new(
            false,
            null,
            ProtectedJournalObservation.Unavailable,
            null,
            null,
            null,
            error);
}

internal enum ProtectedTransactionFileState
{
    Missing,
    Protected,
    Unsafe
}

internal enum ProtectedAtomicCommitResult
{
    Committed,
    Conflict,
    Failed
}

internal sealed record ProtectedCandidateFileSnapshot(
    string RelativePath,
    long Length,
    string Sha256);

internal interface IProtectedFileSnapshotLease : IDisposable
{
    ProtectedFileIdentity128 Identity { get; }

    byte[] Bytes { get; }

    bool Revalidate();
}

internal interface IProtectedTransactionFileSystem
{
    bool ValidateProtectedDirectory(string path);

    ProtectedTransactionFileState InspectProtectedFile(
        string path);

    byte[]? ReadProtectedFile(
        string path,
        long maximumBytes);

    IProtectedFileSnapshotLease? OpenProtectedFileSnapshot(
        string path,
        long maximumBytes) =>
        null;

    ProtectedAtomicCommitResult AtomicCreate(
        string destinationPath,
        byte[] replacementBytes);

    ProtectedAtomicCommitResult AtomicCompareExchange(
        string destinationPath,
        byte[] expectedDestinationBytes,
        byte[] replacementBytes);

    ProtectedAtomicCommitResult AtomicCompareExchange(
        string destinationPath,
        ProtectedFileIdentity128 expectedIdentity,
        byte[] expectedDestinationBytes,
        byte[] replacementBytes) =>
        AtomicCompareExchange(
            destinationPath,
            expectedDestinationBytes,
            replacementBytes);

    bool HasProtectedProductVersion(
        string path,
        string expectedVersion,
        IExecutableProductVersionReader versionReader);

    string? ComputeProtectedSha256(
        string path,
        long maximumBytes);

    IReadOnlyList<ProtectedCandidateFileSnapshot>?
        SnapshotProtectedFiles(
            string path,
            int maximumEntries,
            long maximumBytes);

    long? MeasureProtectedDirectory(
        string path,
        long maximumBytes);
}

internal interface IProtectedInstalledReleaseVerifier
{
    bool Verify(
        ProtectedInstalledReleaseIdentity oldRelease,
        ProtectedInstalledReleaseIdentity newRelease,
        ProtectedInstalledReleaseVerification verification);
}

internal enum ProtectedInstalledReleaseVerification
{
    FullOld,
    NamespaceOnly,
    FullNew
}

internal enum InstalledReleaseSecurityScope
{
    RootDirectory,
    DescendantDirectory,
    ManagedFile
}

internal static class InstalledReleaseSecurityPolicy
{
    internal static bool HasExactDescriptor(
        byte[]? descriptorBytes,
        InstalledReleaseSecurityScope scope)
    {
        if (descriptorBytes is null
            || !Enum.IsDefined(scope))
        {
            return false;
        }

        return scope switch
        {
            InstalledReleaseSecurityScope.RootDirectory =>
                ProtectedDirectoryAcl
                    .HasExactInstalledRootDescriptor(
                        descriptorBytes),
            InstalledReleaseSecurityScope.DescendantDirectory =>
                ProtectedDirectoryAcl
                    .HasExactInstalledDescendantDescriptor(
                        descriptorBytes,
                        directory: true),
            InstalledReleaseSecurityScope.ManagedFile =>
                ProtectedDirectoryAcl
                    .HasExactInstalledDescendantDescriptor(
                        descriptorBytes,
                        directory: false),
            _ => false
        };
    }
}

/// <summary>
/// Persists the small protected transaction authority. All filesystem child
/// paths are recomputed through <see cref="ProtectedTransactionPaths"/>.
/// </summary>
public sealed class ProtectedTransactionStore
{
    public const int TransactionSchemaVersion = 1;
    public const int ActivePointerSchemaVersion = 1;
    public const int JournalSchemaVersion = 1;

    private const long MaximumPointerBytes = 256;
    private const long MaximumRecordBytes = 4L * 1024 * 1024;
    private const long MaximumJournalBytes = 16L * 1024 * 1024;
    private const int MaximumPathCharacters = 32767;

    private static readonly string[] RecordProperties =
    [
        "schemaVersion",
        "transactionId",
        "version",
        "source",
        "installedRelease",
        "candidate",
        "helperSha256",
        "phase",
        "authorizedProcess",
        "journal"
    ];

    private static readonly string[] ActivePointerProperties =
    [
        "schemaVersion",
        "transactionId"
    ];

    private static readonly string[] InstalledReleaseProperties =
    [
        "installRoot",
        "volumeSerialNumber",
        "rootFileIdLow",
        "rootFileIdHigh",
        "currentVersion",
        "minimumAutoUpdateVersion",
        "rollbackCompatibleFromVersion",
        "stateSchemaVersion",
        "applicationRelativePath",
        "updaterRelativePath",
        "currentManifestSha256",
        "managedFiles"
    ];

    private static readonly string[] ManagedFileProperties =
    [
        "relativePath",
        "length",
        "sha256"
    ];

    private static readonly string[] CandidateProperties =
    [
        "archiveSha256",
        "newManifestSha256",
        "expandedBytes"
    ];

    private static readonly string[] ProcessProperties =
    [
        "processId",
        "creationTimeFileTimeUtc",
        "imagePath"
    ];

    private static readonly string[] JournalProperties =
    [
        "schemaVersion",
        "generation",
        "sha256"
    ];

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

    private readonly ProtectedTransactionPaths _paths;
    private readonly IProtectedTransactionFileSystem _fileSystem;
    private readonly Func<string, DriveType> _getDriveType;
    private readonly IExecutableProductVersionReader _versionReader;
    private readonly IProtectedInstalledReleaseVerifier
        _installedReleaseVerifier;

    public ProtectedTransactionStore(
        ProtectedTransactionPaths paths)
        : this(
            paths,
            new WindowsProtectedTransactionFileSystem(),
            root => new DriveInfo(root).DriveType,
            new WindowsExecutableProductVersionReader(),
            new WindowsProtectedInstalledReleaseVerifier(
                new WindowsExecutableProductVersionReader(),
                new ProtectedDirectoryAcl()))
    {
    }

    internal ProtectedTransactionStore(
        ProtectedTransactionPaths paths,
        IProtectedTransactionFileSystem fileSystem,
        Func<string, DriveType> getDriveType,
        IExecutableProductVersionReader? versionReader = null,
        IProtectedInstalledReleaseVerifier?
            installedReleaseVerifier = null)
    {
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _fileSystem = fileSystem
            ?? throw new ArgumentNullException(nameof(fileSystem));
        _getDriveType = getDriveType
            ?? throw new ArgumentNullException(nameof(getDriveType));
        _versionReader = versionReader
            ?? new WindowsExecutableProductVersionReader();
        _installedReleaseVerifier = installedReleaseVerifier
            ?? new WindowsProtectedInstalledReleaseVerifier(
                _versionReader,
                new ProtectedDirectoryAcl());
    }

    public ProtectedTransactionWriteResult CreateProtectedStaged(
        ProtectedUpdateMutexContext? authority,
        ProtectedStagedTransactionMaterial? material)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return CreateProtectedStagedCore(
                    authority,
                    material);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionWriteResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionWriteResult
        CreateProtectedStagedCore(
            ProtectedUpdateMutexContext authority,
            ProtectedStagedTransactionMaterial? material)
    {
        if (!TryNormalizeMaterial(
                material,
                out var normalized))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var record = new ProtectedTransactionRecord(
            TransactionSchemaVersion,
            normalized!.TransactionId,
            normalized.Version,
            normalized.Source,
            normalized.InstalledRelease,
            normalized.Candidate,
            normalized.HelperSha256,
            ProtectedTransactionPhase.ProtectedStaged,
            AuthorizedProcess: null,
            normalized.Journal);

        var layoutResult = _paths.GetLayout(record.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var layout = layoutResult.Layout;
        var artifacts = ValidateDurableArtifacts(
            layout,
            record,
            ProtectedInstalledReleaseVerification.FullOld);
        if (!artifacts.Success)
        {
            return ProtectedTransactionWriteResult.Failed(
                artifacts.Error);
        }

        var bytes = SerializeRecord(record);
        if (bytes is null
            || bytes.LongLength > MaximumRecordBytes)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var existing = ReadTransactionCore(
            authority,
            record.TransactionId);
        if (existing.Success)
        {
            return RecordsEqual(existing.Record!, record)
                ? ProtectedTransactionWriteResult.Completed(
                    existing.Record!)
                : ProtectedTransactionWriteResult.Failed(
                    ProtectedTransactionStoreError.Conflict);
        }

        if (existing.Error
            is not ProtectedTransactionStoreError.Missing)
        {
            return ProtectedTransactionWriteResult.Failed(
                existing.Error);
        }

        var write = WriteProtectedFile(
            layout.TransactionRecordPath,
            bytes);
        return write.Success
            ? ProtectedTransactionWriteResult.Completed(record)
            : ProtectedTransactionWriteResult.Failed(write.Error);
    }

    internal ProtectedTransactionStoreResult
        CleanupInactiveTransaction(
            ProtectedUpdateMutexContext? authority,
            ProtectedStagedTransactionMaterial? expectedMaterial,
            Func<bool>? cleanup)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return CleanupInactiveTransactionCore(
                    authority,
                    expectedMaterial,
                    cleanup);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionStoreResult
        CleanupInactiveTransactionCore(
            ProtectedUpdateMutexContext authority,
            ProtectedStagedTransactionMaterial? expectedMaterial,
            Func<bool>? cleanup)
    {
        if (expectedMaterial is null
            || !expectedMaterial.TransactionId.IsValid
            || cleanup is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedTransactionStoreResult.Failed(
                active.Error);
        }

        if (active.TransactionId
            == expectedMaterial.TransactionId)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var current = ReadTransactionCore(
            authority,
            expectedMaterial.TransactionId);
        if (!current.Success)
        {
            if (current.Error
                != ProtectedTransactionStoreError.Missing)
            {
                return ProtectedTransactionStoreResult.Failed(
                    current.Error);
            }

            return cleanup()
                ? ProtectedTransactionStoreResult.Completed()
                : ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
        }

        if (!TryNormalizeMaterial(
                expectedMaterial,
                out var normalized))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var expectedRecord = new ProtectedTransactionRecord(
            TransactionSchemaVersion,
            normalized!.TransactionId,
            normalized.Version,
            normalized.Source,
            normalized.InstalledRelease,
            normalized.Candidate,
            normalized.HelperSha256,
            ProtectedTransactionPhase.ProtectedStaged,
            AuthorizedProcess: null,
            normalized.Journal);
        if (!RecordsEqual(
                current.Record!,
                expectedRecord))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        return cleanup()
            ? ProtectedTransactionStoreResult.Completed()
            : ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.IoFailure);
    }
    public ProtectedTransactionReadResult ReadTransaction(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionReadResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            try
            {
                return ReadTransactionCore(
                    authority,
                    transactionId);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionReadResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionReadResult ReadTransactionCore(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId)
    {
        var snapshot = ReadTransactionSnapshot(
            authority,
            transactionId);
        return snapshot.Success
            ? ProtectedTransactionReadResult.Found(
                snapshot.Record!)
            : ProtectedTransactionReadResult.Failed(
                snapshot.Error);
    }

    public ProtectedActiveTransactionReadResult ReadActive(
        ProtectedUpdateMutexContext? authority)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedActiveTransactionReadResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            try
            {
                return ReadActiveCore(authority);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedActiveTransactionReadResult
                    .Failed(
                        ProtectedTransactionStoreError
                            .IoFailure);
            }
        }
    }

    private ProtectedActiveTransactionReadResult ReadActiveCore(
        ProtectedUpdateMutexContext authority)
    {
        using var snapshot = ReadActiveSnapshot(authority);
        return snapshot.Success
            ? ProtectedActiveTransactionReadResult.Found(
                snapshot.TransactionId)
            : ProtectedActiveTransactionReadResult.Failed(
                snapshot.Error);
    }

    private ActivePointerSnapshot ReadActiveSnapshot(
        ProtectedUpdateMutexContext authority)
    {
        var rootResult = _paths.GetRoot();
        if (!rootResult.Success
            || rootResult.Layout is null)
        {
            return ActivePointerSnapshot.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var root = rootResult.Layout;
        if (!ValidateRootDirectoryChain(root))
        {
            return ActivePointerSnapshot.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        var state = _fileSystem.InspectProtectedFile(
            root.ActivePointerPath);
        if (state == ProtectedTransactionFileState.Missing)
        {
            return ActivePointerSnapshot.Found(
                transactionId: null,
                snapshot: null);
        }

        if (state != ProtectedTransactionFileState.Protected)
        {
            return ActivePointerSnapshot.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        try
        {
            var snapshot = _fileSystem.OpenProtectedFileSnapshot(
                root.ActivePointerPath,
                MaximumPointerBytes);
            if (snapshot is null
                || !TryParseActivePointer(
                    snapshot.Bytes,
                    out var transactionId))
            {
                snapshot?.Dispose();
                return ActivePointerSnapshot.Failed(
                    ProtectedTransactionStoreError.CorruptData);
            }

            return ActivePointerSnapshot.Found(
                transactionId,
                snapshot);
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return ActivePointerSnapshot.Failed(
                ProtectedTransactionStoreError.IoFailure);
        }
    }

    internal ProtectedTransactionStoreResult DeactivateTerminal(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionRecord? expectedRecord)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        using (authority.AcquireMutationLease())
        {
            try
            {
                return DeactivateTerminalCore(
                    authority,
                    expectedRecord);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionStoreResult
        DeactivateTerminalCore(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionRecord? expectedRecord)
    {
        if (!IsExactTerminalRecord(expectedRecord))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedTransactionStoreResult.Failed(
                active.Error);
        }

        if (active.TransactionId
                != expectedRecord!.TransactionId
            || active.Bytes is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var current = ReadJournalForRecoveryCore(
            authority,
            expectedRecord.TransactionId);
        if (!IsExactBoundTerminal(current, expectedRecord))
        {
            return ProtectedTransactionStoreResult.Failed(
                current.Success
                    ? ProtectedTransactionStoreError.Conflict
                    : current.Error);
        }

        var layoutResult = _paths.GetLayout(
            expectedRecord.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var artifacts = ValidateDurableArtifacts(
            layoutResult.Layout,
            expectedRecord,
            expectedRecord.Phase
                    == ProtectedTransactionPhase.Committed
                ? ProtectedInstalledReleaseVerification.FullNew
                : ProtectedInstalledReleaseVerification.FullOld);
        if (!artifacts.Success)
        {
            return artifacts;
        }

        var inactiveBytes = SerializeInactivePointer();
        var written = WriteProtectedFile(
            layoutResult.Layout.ActivePointerPath,
            inactiveBytes,
            active.Bytes,
            active.Identity);
        if (!written.Success)
        {
            return written;
        }

        using var inactive = ReadActiveSnapshot(authority);
        return inactive.Success
                && inactive.TransactionId is null
                && inactive.Bytes is not null
                && inactive.Bytes.AsSpan().SequenceEqual(
                    inactiveBytes)
            ? ProtectedTransactionStoreResult.Completed()
            : ProtectedTransactionStoreResult.Failed(
                inactive.Success
                    ? ProtectedTransactionStoreError
                        .AtomicWriteFailed
                    : inactive.Error);
    }

    internal ProtectedTransactionStoreResult
        CleanupInactiveTerminalTransaction(
            ProtectedUpdateMutexContext? authority,
            ProtectedTransactionRecord? expectedRecord,
            Func<bool>? cleanup)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        using (authority.AcquireMutationLease())
        {
            try
            {
                if (!IsExactTerminalRecord(expectedRecord)
                    || cleanup is null)
                {
                    return ProtectedTransactionStoreResult.Failed(
                        ProtectedTransactionStoreError.InvalidData);
                }

                using var active = ReadActiveSnapshot(authority);
                if (!active.Success)
                {
                    return ProtectedTransactionStoreResult.Failed(
                        active.Error);
                }

                var canonicalInactive =
                    SerializeInactivePointer();
                if (active.TransactionId is not null
                    || active.Bytes is null
                    || !active.Bytes.AsSpan().SequenceEqual(
                        canonicalInactive))
                {
                    return ProtectedTransactionStoreResult.Failed(
                        ProtectedTransactionStoreError.Conflict);
                }

                var current = ReadJournalForRecoveryCore(
                    authority,
                    expectedRecord!.TransactionId);
                if (!IsExactBoundTerminal(
                        current,
                        expectedRecord))
                {
                    return ProtectedTransactionStoreResult.Failed(
                        current.Success
                            ? ProtectedTransactionStoreError
                                .Conflict
                            : current.Error);
                }

                var layoutResult = _paths.GetLayout(
                    expectedRecord.TransactionId);
                if (!layoutResult.Success
                    || layoutResult.Layout is null)
                {
                    return ProtectedTransactionStoreResult.Failed(
                        ProtectedTransactionStoreError.UnsafePath);
                }

                var artifacts = ValidateDurableArtifacts(
                    layoutResult.Layout,
                    expectedRecord,
                    expectedRecord.Phase
                            == ProtectedTransactionPhase.Committed
                        ? ProtectedInstalledReleaseVerification
                            .FullNew
                        : ProtectedInstalledReleaseVerification
                            .FullOld);
                if (!artifacts.Success)
                {
                    return artifacts;
                }

                return cleanup()
                    ? ProtectedTransactionStoreResult.Completed()
                    : ProtectedTransactionStoreResult.Failed(
                        ProtectedTransactionStoreError.IoFailure);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    internal ProtectedTransactionStoreResult
        DeactivateProtectedStaged(
            ProtectedUpdateMutexContext? authority,
            ProtectedJournalRecoveryReadResult? expected)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        using (authority.AcquireMutationLease())
        {
            try
            {
                return DeactivateProtectedStagedCore(
                    authority,
                    expected);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionStoreResult
        DeactivateProtectedStagedCore(
            ProtectedUpdateMutexContext authority,
            ProtectedJournalRecoveryReadResult? expected)
    {
        if (expected is not
            {
                Success: true,
                Record:
                {
                    Phase:
                        ProtectedTransactionPhase.ProtectedStaged,
                    AuthorizedProcess: null
                } expectedRecord,
                RecordBytes: not null,
                Observation:
                    ProtectedJournalObservation.AbsentInitial,
                JournalBytes: null
            }
            || expectedRecord.Journal.Generation != 0
            || expectedRecord.Journal.Sha256 is not null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var rootResult = _paths.GetRoot();
        if (!rootResult.Success
            || rootResult.Layout is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedTransactionStoreResult.Failed(
                active.Error);
        }

        if (active.TransactionId
                != expectedRecord.TransactionId
            || active.Bytes is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var current = ReadJournalForRecoveryCore(
            authority,
            expectedRecord.TransactionId);
        if (!current.Success
            || current.RecordBytes is null
            || !current.RecordBytes.AsSpan().SequenceEqual(
                expected.RecordBytes)
            || current.Observation
                != ProtectedJournalObservation.AbsentInitial
            || current.JournalBytes is not null)
        {
            return ProtectedTransactionStoreResult.Failed(
                current.Success
                    ? ProtectedTransactionStoreError.Conflict
                    : current.Error);
        }

        var inactiveBytes = SerializeInactivePointer();
        var written = WriteProtectedFile(
            rootResult.Layout.ActivePointerPath,
            inactiveBytes,
            active.Bytes,
            active.Identity);
        if (!written.Success)
        {
            return written;
        }

        using var inactive = ReadActiveSnapshot(authority);
        return inactive.Success
                && inactive.TransactionId is null
                && inactive.Bytes is not null
                && inactive.Bytes.AsSpan().SequenceEqual(
                    inactiveBytes)
            ? ProtectedTransactionStoreResult.Completed()
            : ProtectedTransactionStoreResult.Failed(
                inactive.Success
                    ? ProtectedTransactionStoreError
                        .AtomicWriteFailed
                    : inactive.Error);
    }
    private bool IsExactTerminalRecord(
        ProtectedTransactionRecord? record) =>
        IsValidRecord(record)
        && record!.Phase is
            ProtectedTransactionPhase.Committed
                or ProtectedTransactionPhase.RolledBack;

    private static bool IsExactBoundTerminal(
        ProtectedJournalRecoveryReadResult current,
        ProtectedTransactionRecord expected) =>
        current.Success
        && current.Record is not null
        && current.RecordBytes is not null
        && current.Observation
            == ProtectedJournalObservation.MatchesBoundHash
        && RecordsEqual(current.Record, expected);

    public ProtectedTransactionStoreResult Activate(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionRecord? expectedRecord)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return ActivateCore(
                    authority,
                    expectedRecord,
                    expectedActive: null,
                    requireExpectedActive: false);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    public ProtectedTransactionStoreResult
        ActivateReplacingProtectedStaged(
            ProtectedUpdateMutexContext? authority,
            ProtectedTransactionRecord? expectedRecord,
            ProtectedActiveTransactionExpectation? expectedActive)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return ActivateCore(
                    authority,
                    expectedRecord,
                    expectedActive,
                    requireExpectedActive: true);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionStoreResult ActivateCore(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord? expectedRecord,
        ProtectedActiveTransactionExpectation? expectedActive,
        bool requireExpectedActive)
    {
        if (!IsValidRecord(expectedRecord)
            || expectedRecord!.Phase
                != ProtectedTransactionPhase.ProtectedStaged
            || expectedRecord.AuthorizedProcess is not null
            || requireExpectedActive
                && expectedActive is not null
                && (!expectedActive.TransactionId.IsValid
                    || !IsCanonicalVersion(expectedActive.Version)
                    || !Enum.IsDefined(expectedActive.Source)
                    || !IsAllowedProtectedReplacement(
                        expectedActive,
                        expectedRecord)))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var proposed = ReadTransactionCore(
            authority,
            expectedRecord.TransactionId);
        if (!proposed.Success
            || proposed.Record is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                proposed.Error);
        }

        if (!RecordsEqual(
                proposed.Record,
                expectedRecord))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var layoutResult = _paths.GetLayout(
            expectedRecord.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var artifacts = ValidateDurableArtifacts(
            layoutResult.Layout,
            proposed.Record,
            ProtectedInstalledReleaseVerification.FullOld);
        if (!artifacts.Success)
        {
            return artifacts;
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedTransactionStoreResult.Failed(
                active.Error);
        }

        if (active.TransactionId
            == expectedRecord.TransactionId)
        {
            return active.Revalidate()
                ? ProtectedTransactionStoreResult.Completed()
                : ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.Conflict);
        }

        if (requireExpectedActive
            && (expectedActive is null
                ? active.TransactionId is not null
                : active.TransactionId
                    != expectedActive.TransactionId))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        if (active.TransactionId is { } currentId)
        {
            var current = ReadTransactionCore(
                authority,
                currentId);
            if (!current.Success
                || current.Record is null
                || current.Record.Phase
                    != ProtectedTransactionPhase.ProtectedStaged
                || current.Record.AuthorizedProcess is not null
                || requireExpectedActive
                    && expectedActive is not null
                    && (current.Record.TransactionId
                            != expectedActive.TransactionId
                        || current.Record.Version
                            != expectedActive.Version
                        || current.Record.Source
                            != expectedActive.Source))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.Conflict);
            }
        }

        var pointerBytes = SerializeActivePointer(
            expectedRecord.TransactionId);
        if (pointerBytes.LongLength > MaximumPointerBytes)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        return WriteProtectedFile(
            layoutResult.Layout.ActivePointerPath,
            pointerBytes,
            active.Bytes,
            active.Identity);
    }

    private static bool IsAllowedProtectedReplacement(
        ProtectedActiveTransactionExpectation expectedActive,
        ProtectedTransactionRecord replacement)
    {
        var comparison = replacement.Version.CompareTo(
            expectedActive.Version);
        return comparison > 0
            || comparison == 0
            && expectedActive.Source
                == PendingUpdateSource.Automatic
            && replacement.Source
                == PendingUpdateSource.Manual;
    }

    internal ProtectedJournalRecoveryReadResult
        ReadJournalForRecovery(
            ProtectedUpdateMutexContext? authority,
            ProtectedTransactionId transactionId)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            try
            {
                return ReadJournalForRecoveryCore(
                    authority,
                    transactionId);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedJournalRecoveryReadResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedJournalRecoveryReadResult
        ReadJournalForRecoveryCore(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId)
    {
        var snapshot = ReadTransactionSnapshot(
            authority,
            transactionId);
        if (!snapshot.Success
            || snapshot.Record is null
            || snapshot.Bytes is null)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                snapshot.Error);
        }

        var layoutResult = _paths.GetLayout(transactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var layout = layoutResult.Layout;
        var state = _fileSystem.InspectProtectedFile(
            layout.JournalPath);
        if (state == ProtectedTransactionFileState.Unsafe)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        if (state == ProtectedTransactionFileState.Missing)
        {
            return ProtectedJournalRecoveryReadResult.Found(
                snapshot.Record,
                snapshot.Record.Journal.Generation == 0
                    ? ProtectedJournalObservation.AbsentInitial
                    : ProtectedJournalObservation
                        .MissingButBound,
                snapshot.Bytes.ToArray(),
                journalBytes: null,
                journalSha256: null);
        }

        var journalBytes = _fileSystem.ReadProtectedFile(
            layout.JournalPath,
            MaximumJournalBytes);
        if (journalBytes is null
            || _fileSystem.InspectProtectedFile(
                layout.JournalPath)
                != ProtectedTransactionFileState.Protected)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.CorruptData);
        }

        var journalSha256 = HashBytes(journalBytes);
        var isCanonical =
            UpdateOperationJournalCodec.TryParseCanonical(
                journalBytes,
                out var journal);
        var hasExpectedTransaction = isCanonical
            && journal!.TransactionId
                == snapshot.Record.TransactionId;
        var isBound = hasExpectedTransaction
            && snapshot.Record.Journal.Generation > 0
            && journal!.Generation
                == snapshot.Record.Journal.Generation
            && (journal.Generation != 1
                || UpdateOperationJournalCodec
                    .IsInitialPlan(journal))
            && string.Equals(
                journalSha256,
                snapshot.Record.Journal.Sha256,
                StringComparison.Ordinal);
        var isOneAhead = hasExpectedTransaction
            && IsNextJournalGeneration(
                snapshot.Record.Journal.Generation,
                journal!.Generation)
            && UpdateOperationJournalCodec
                .TryValidateCanonicalSuccessor(
                    journalBytes,
                    snapshot.Record.Journal.Sha256,
                    out _);
        var observation = isBound
            ? ProtectedJournalObservation.MatchesBoundHash
            : isOneAhead
                ? ProtectedJournalObservation.PresentButUnbound
                : ProtectedJournalObservation.HashMismatch;
        return ProtectedJournalRecoveryReadResult.Found(
            snapshot.Record,
            observation,
            snapshot.Bytes.ToArray(),
            journalBytes.ToArray(),
            journalSha256);
    }

    internal ProtectedJournalRecoveryReadResult
        PublishJournalCheckpoint(
            ProtectedUpdateMutexContext? authority,
            ProtectedJournalRecoveryReadResult? expected,
            ReadOnlyMemory<byte> nextJournal)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return PublishJournalCheckpointCore(
                    authority,
                    expected,
                    nextJournal);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedJournalRecoveryReadResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedJournalRecoveryReadResult
        PublishJournalCheckpointCore(
            ProtectedUpdateMutexContext authority,
            ProtectedJournalRecoveryReadResult? expected,
            ReadOnlyMemory<byte> nextJournal)
    {
        if (expected is not
            {
                Success: true,
                Record: not null,
                RecordBytes: not null
            }
            || expected.Record.Phase is not (
                ProtectedTransactionPhase.CloseAuthorized
                or ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.BackingUp
                or ProtectedTransactionPhase.Applying
                or ProtectedTransactionPhase
                    .AppliedAwaitingHealth
                or ProtectedTransactionPhase.RollingBack)
            || expected.Observation is not (
                ProtectedJournalObservation.AbsentInitial
                or ProtectedJournalObservation.MatchesBoundHash))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        if (nextJournal.Length <= 0
            || nextJournal.Length > MaximumJournalBytes)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var nextBytes = nextJournal.ToArray();
        var isCanonicalSuccessor =
            UpdateOperationJournalCodec
                .TryValidateCanonicalSuccessor(
                    nextBytes,
                    expected.Record.Journal.Sha256,
                    out var nextParsed);
        if (nextBytes.LongLength > MaximumJournalBytes
            || !isCanonicalSuccessor
            || nextParsed is null
            || nextParsed.TransactionId
                != expected.Record.TransactionId
            || !IsNextJournalGeneration(
                expected.Record.Journal.Generation,
                nextParsed.Generation)
            || expected.Observation
                    == ProtectedJournalObservation.AbsentInitial
                && (expected.Record.Journal.Generation != 0
                    || expected.Record.Journal.Sha256 is not null
                    || expected.JournalBytes is not null
                    || expected.JournalSha256 is not null)
            || expected.Observation
                    == ProtectedJournalObservation.MatchesBoundHash
                && (expected.Record.Journal.Generation <= 0
                    || expected.JournalBytes is null
                    || !UpdateOperationJournalCodec
                        .TryParseCanonical(
                            expected.JournalBytes,
                            out var currentParsed)
                    || currentParsed is null
                    || currentParsed.TransactionId
                        != expected.Record.TransactionId
                    || !UpdateOperationJournalCodec
                        .IsLegalTransition(
                            currentParsed,
                            nextParsed)
                    || !string.Equals(
                        expected.JournalSha256,
                        expected.Record.Journal.Sha256,
                        StringComparison.Ordinal)))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                active.Error);
        }

        if (active.TransactionId
            != expected.Record.TransactionId)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var current = ReadJournalForRecoveryCore(
            authority,
            expected.Record.TransactionId);
        if (!JournalRecoveryReadsEqual(
                current,
                expected))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                current.Success
                    ? ProtectedTransactionStoreError.Conflict
                    : current.Error);
        }

        var layoutResult = _paths.GetLayout(
            expected.Record.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var write = WriteProtectedFile(
            layoutResult.Layout.JournalPath,
            nextBytes,
            expected.Observation
                    == ProtectedJournalObservation
                        .MatchesBoundHash
                ? expected.JournalBytes
                : null);
        if (!write.Success)
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                write.Error);
        }

        var published = ReadJournalForRecoveryCore(
            authority,
            expected.Record.TransactionId);
        if (!published.Success
            || published.Observation
                != ProtectedJournalObservation.PresentButUnbound
            || published.Record is null
            || !RecordsEqual(
                published.Record,
                expected.Record)
            || published.RecordBytes is null
            || !published.RecordBytes.AsSpan().SequenceEqual(
                expected.RecordBytes)
            || published.JournalBytes is null
            || !published.JournalBytes.AsSpan().SequenceEqual(
                nextBytes)
            || !string.Equals(
                published.JournalSha256,
                HashBytes(nextBytes),
                StringComparison.Ordinal))
        {
            return ProtectedJournalRecoveryReadResult.Failed(
                published.Success
                    ? ProtectedTransactionStoreError
                        .AtomicWriteFailed
                    : published.Error);
        }

        using var activeAfter = ReadActiveSnapshot(authority);
        return activeAfter.Success
                && activeAfter.TransactionId
                    == expected.Record.TransactionId
            ? published
            : ProtectedJournalRecoveryReadResult.Failed(
                activeAfter.Success
                    ? ProtectedTransactionStoreError.Conflict
                    : activeAfter.Error);
    }

    internal ProtectedTransactionWriteResult
        EnterRecoveryBlocked(
            ProtectedUpdateMutexContext? authority,
            ProtectedTransactionRecord? expectedRecord)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return EnterRecoveryBlockedCore(
                    authority,
                    expectedRecord);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionWriteResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionWriteResult
        EnterRecoveryBlockedCore(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionRecord? expectedRecord)
    {
        if (!IsValidRecord(expectedRecord)
            || !IsLegalPhaseTransition(
                expectedRecord!.Phase,
                ProtectedTransactionPhase.RecoveryBlocked))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        using var active = ReadActiveSnapshot(authority);
        if (!active.Success)
        {
            return ProtectedTransactionWriteResult.Failed(
                active.Error);
        }

        if (active.TransactionId
            != expectedRecord.TransactionId)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var current = ReadTransactionSnapshot(
            authority,
            expectedRecord.TransactionId);
        if (!current.Success
            || current.Record is null
            || current.Bytes is null)
        {
            return ProtectedTransactionWriteResult.Failed(
                current.Error);
        }

        if (!RecordsEqual(
                current.Record,
                expectedRecord))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        if (current.Record.Phase
            == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return ProtectedTransactionWriteResult.Completed(
                current.Record);
        }

        var replacement = current.Record with
        {
            Phase = ProtectedTransactionPhase.RecoveryBlocked
        };
        var replacementBytes = SerializeRecord(replacement);
        if (replacementBytes is null
            || replacementBytes.LongLength > MaximumRecordBytes)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var layoutResult = _paths.GetLayout(
            replacement.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var write = WriteProtectedFile(
            layoutResult.Layout.TransactionRecordPath,
            replacementBytes,
            current.Bytes);
        if (!write.Success)
        {
            return ProtectedTransactionWriteResult.Failed(
                write.Error);
        }

        using var activeAfter = ReadActiveSnapshot(authority);
        return activeAfter.Success
                && activeAfter.TransactionId
                    == replacement.TransactionId
            ? ProtectedTransactionWriteResult.Completed(
                replacement)
            : ProtectedTransactionWriteResult.Failed(
                activeAfter.Success
                    ? ProtectedTransactionStoreError.Conflict
                    : activeAfter.Error);
    }

    private static bool JournalRecoveryReadsEqual(
        ProtectedJournalRecoveryReadResult current,
        ProtectedJournalRecoveryReadResult expected) =>
        current.Success
        && current.Record is not null
        && expected.Record is not null
        && current.RecordBytes is not null
        && expected.RecordBytes is not null
        && RecordsEqual(current.Record, expected.Record)
        && current.RecordBytes.AsSpan().SequenceEqual(
            expected.RecordBytes)
        && current.Observation == expected.Observation
        && NullableBytesEqual(
            current.JournalBytes,
            expected.JournalBytes)
        && string.Equals(
            current.JournalSha256,
            expected.JournalSha256,
            StringComparison.Ordinal);

    private static bool NullableBytesEqual(
        byte[]? first,
        byte[]? second) =>
        first is null
            ? second is null
            : second is not null
                && first.AsSpan().SequenceEqual(second);

    internal ProtectedTransactionWriteResult
        CompareExchangeTransaction(
            ProtectedUpdateMutexContext? authority,
            ProtectedJournalRecoveryReadResult? expected,
            ProtectedTransactionRecord? replacement)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            using var mutationLease =
                authority.AcquireMutationLease();
            try
            {
                return CompareExchangeTransactionCore(
                    authority,
                    expected,
                    replacement);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionWriteResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionWriteResult
        CompareExchangeTransactionCore(
            ProtectedUpdateMutexContext authority,
            ProtectedJournalRecoveryReadResult? expected,
            ProtectedTransactionRecord? replacement)
    {
        if (expected is not
            {
                Success: true,
                Record: not null,
                RecordBytes: not null
            }
            || !IsValidRecord(replacement)
            || replacement!.TransactionId
                != expected.Record.TransactionId
            || !HaveSameImmutableIdentity(
                expected.Record,
                replacement)
            || !IsLegalRecordTransition(
                expected.Record,
                replacement)
            || !IsSameOrNextJournalGeneration(
                expected.Record.Journal.Generation,
                replacement.Journal.Generation)
            || IsNextJournalGeneration(
                    expected.Record.Journal.Generation,
                    replacement.Journal.Generation)
                && (expected.Observation
                        != ProtectedJournalObservation
                            .PresentButUnbound
                    || !string.Equals(
                        expected.JournalSha256,
                        replacement.Journal.Sha256,
                        StringComparison.Ordinal))
            || replacement.Journal.Generation
                    == expected.Record.Journal.Generation
                && (!Equals(
                        replacement.Journal,
                        expected.Record.Journal)
                    || expected.Observation
                        != (replacement.Journal.Generation == 0
                            ? ProtectedJournalObservation
                                .AbsentInitial
                            : ProtectedJournalObservation
                                .MatchesBoundHash))
            || !TryParseRecord(
                expected.RecordBytes,
                out var expectedFromBytes)
            || !RecordsEqual(
                expectedFromBytes!,
                expected.Record))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var current = ReadTransactionSnapshot(
            authority,
            replacement.TransactionId);
        if (!current.Success
            || current.Record is null
            || current.Bytes is null)
        {
            return ProtectedTransactionWriteResult.Failed(
                current.Error);
        }

        if (!current.Bytes.AsSpan().SequenceEqual(
                expected.RecordBytes)
            || !RecordsEqual(
                current.Record,
                expected.Record))
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        var layoutResult = _paths.GetLayout(
            replacement.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var artifacts = ValidateDurableArtifacts(
            layoutResult.Layout,
            replacement,
            SelectInstalledReleaseVerification(
                expected.Record.Phase,
                replacement.Phase));
        if (!artifacts.Success)
        {
            return ProtectedTransactionWriteResult.Failed(
                artifacts.Error);
        }

        if (RecordsEqual(current.Record, replacement))
        {
            return ProtectedTransactionWriteResult.Completed(
                current.Record);
        }

        var replacementBytes = SerializeRecord(replacement);
        if (replacementBytes is null
            || replacementBytes.LongLength > MaximumRecordBytes)
        {
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var write = WriteProtectedFile(
            layoutResult.Layout.TransactionRecordPath,
            replacementBytes,
            expected.RecordBytes);
        return write.Success
            ? ProtectedTransactionWriteResult.Completed(
                replacement)
            : ProtectedTransactionWriteResult.Failed(
                write.Error);
    }

    public ProtectedTransactionStoreResult VerifyHelper(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId,
        string? expectedSha256)
    {
        if (authority is null
            || !authority.TryAcquireLease(
                out var authorityLease))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        {
            try
            {
                return VerifyHelperCoreEntry(
                    authority,
                    transactionId,
                    expectedSha256);
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.IoFailure);
            }
        }
    }

    private ProtectedTransactionStoreResult
        VerifyHelperCoreEntry(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId,
            string? expectedSha256)
    {
        if (!IsSha256(expectedSha256))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
        }

        var layoutResult = _paths.GetLayout(transactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        if (!ValidateTransactionDirectoryChain(
                layoutResult.Layout))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        return VerifyHelperCore(
            layoutResult.Layout,
            expectedSha256!);
    }

    private ProtectedTransactionStoreResult ValidateDurableArtifacts(
        ProtectedTransactionLayout layout,
        ProtectedTransactionRecord record,
        ProtectedInstalledReleaseVerification
            installedReleaseVerification)
    {
        if (!ValidateTransactionDirectoryChain(layout)
            || !_fileSystem.ValidateProtectedDirectory(
                layout.CandidateRoot)
            || !_fileSystem.ValidateProtectedDirectory(
                layout.HelperRoot))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        var journal = ValidateExactJournalBinding(
            layout,
            record);
        if (!journal.Success)
        {
            return journal;
        }

        var manifest = _paths.ResolveCandidatePayload(
            record.TransactionId,
            UpdateReleaseContract.ReleaseManifestPath);
        if (!manifest.Success
            || manifest.Path is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var candidateFiles = _fileSystem.SnapshotProtectedFiles(
            layout.CandidateRoot,
            WindowsReleasePathPolicy.MaximumArchiveEntries,
            UpdatePackageLimits.Default.MaximumExpandedBytes);
        if (candidateFiles is null
            || candidateFiles.Count is < 2
                or > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        var manifestBytes = _fileSystem.ReadProtectedFile(
            manifest.Path,
            UpdateNetworkLimits.MetadataBytes);
        if (manifestBytes is null
            || _fileSystem.InspectProtectedFile(manifest.Path)
                != ProtectedTransactionFileState.Protected
            || !string.Equals(
                HashBytes(manifestBytes),
                record.Candidate.NewManifestSha256,
                StringComparison.Ordinal)
            || !TryParseReleaseManifest(
                manifestBytes,
                out var parsedManifest))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        var archivePaths = candidateFiles
            .Select(file => (string?)file.RelativePath)
            .ToArray();
        var validation = ReleaseManifestValidator.Validate(
            parsedManifest,
            record.Version,
            record.InstalledRelease.CurrentVersion,
            record.InstalledRelease.StateSchemaVersion,
            archivePaths);
        if (!validation.IsValid
            || validation.Manifest?.Files is not { } manifestFiles
            || !TryValidateCandidateSnapshot(
                candidateFiles,
                manifestFiles,
                record.Candidate.ExpandedBytes,
                record.Candidate.NewManifestSha256))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        if (!TryCreateCandidateReleaseIdentity(
                record,
                validation.Manifest,
                out var newRelease)
            || !_installedReleaseVerifier.Verify(
                record.InstalledRelease,
                newRelease!,
                installedReleaseVerification))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        var application = _paths.ResolveCandidatePayload(
            record.TransactionId,
            record.InstalledRelease.ApplicationRelativePath);
        var updater = _paths.ResolveCandidatePayload(
            record.TransactionId,
            record.InstalledRelease.UpdaterRelativePath);
        var expectedVersion = record.Version.ToString();
        if (!application.Success
            || application.Path is null
            || !updater.Success
            || updater.Path is null
            || !_fileSystem.HasProtectedProductVersion(
                application.Path,
                expectedVersion,
                _versionReader)
            || !_fileSystem.HasProtectedProductVersion(
                updater.Path,
                expectedVersion,
                _versionReader))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        return VerifyHelperCore(
            layout,
            record.HelperSha256,
            expectedVersion);
    }

    private static ProtectedInstalledReleaseVerification
        SelectInstalledReleaseVerification(
            ProtectedTransactionPhase current,
            ProtectedTransactionPhase next)
    {
        if (next is
            ProtectedTransactionPhase.ProtectedStaged
                or ProtectedTransactionPhase.CloseAuthorized
                or ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.RolledBack
            || current == ProtectedTransactionPhase.Prepared
                && next == ProtectedTransactionPhase.BackingUp)
        {
            return ProtectedInstalledReleaseVerification.FullOld;
        }

        return next is
            ProtectedTransactionPhase.AppliedAwaitingHealth
                or ProtectedTransactionPhase.Committed
            ? ProtectedInstalledReleaseVerification.FullNew
            : ProtectedInstalledReleaseVerification.NamespaceOnly;
    }

    private static bool TryCreateCandidateReleaseIdentity(
        ProtectedTransactionRecord record,
        ReleaseManifest manifest,
        out ProtectedInstalledReleaseIdentity? identity)
    {
        identity = null;
        if (!TryParseCanonicalVersion(
                manifest.MinimumAutoUpdateVersion,
                out var minimumVersion)
            || !TryParseCanonicalVersion(
                manifest.RollbackCompatibleFromVersion,
                out var rollbackVersion)
            || manifest.Files is null)
        {
            return false;
        }

        identity = new ProtectedInstalledReleaseIdentity(
            record.InstalledRelease.InstallRoot,
            record.InstalledRelease.VolumeSerialNumber,
            record.InstalledRelease.RootFileIdLow,
            record.InstalledRelease.RootFileIdHigh,
            record.Version,
            minimumVersion,
            rollbackVersion,
            manifest.StateSchemaVersion,
            manifest.EntryPoint,
            manifest.UpdaterEntryPoint,
            record.Candidate.NewManifestSha256,
            manifest.Files
                .Select(file =>
                    new ProtectedManagedFileIdentity(
                        file.Path,
                        file.Length,
                        file.Sha256))
                .OrderBy(
                    file => file.RelativePath,
                    StringComparer.Ordinal)
                .ToArray());
        return true;
    }

    private ProtectedTransactionStoreResult VerifyHelperCore(
        ProtectedTransactionLayout layout,
        string expectedSha256,
        string? expectedVersion = null)
    {
        if (!_fileSystem.ValidateProtectedDirectory(
                layout.HelperRoot)
            || _fileSystem.InspectProtectedFile(
                layout.HelperPath)
                != ProtectedTransactionFileState.Protected)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        return string.Equals(
                    _fileSystem.ComputeProtectedSha256(
                        layout.HelperPath,
                        UpdatePackageLimits.Default.MaximumFileBytes),
                    expectedSha256,
                    StringComparison.Ordinal)
                && (expectedVersion is null
                    || _fileSystem.HasProtectedProductVersion(
                        layout.HelperPath,
                        expectedVersion,
                        _versionReader))
            ? ProtectedTransactionStoreResult.Completed()
            : ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
    }

    private static bool TryValidateCandidateSnapshot(
        IReadOnlyList<ProtectedCandidateFileSnapshot> candidateFiles,
        IReadOnlyList<ReleasePayloadFile> manifestFiles,
        long expectedExpandedBytes,
        string expectedManifestSha256)
    {
        try
        {
            var byPath =
                new Dictionary<string, ProtectedCandidateFileSnapshot>(
                    StringComparer.Ordinal);
            var insensitivePaths = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            long total = 0;
            foreach (var file in candidateFiles)
            {
                var path = WindowsReleasePathPolicy.Validate(
                    file.RelativePath);
                if (!path.Success
                    || path.CanonicalKey is null
                    || !string.Equals(
                        path.CanonicalKey,
                        file.RelativePath,
                        StringComparison.Ordinal)
                    || file.Length < 0
                    || file.Length
                        > UpdatePackageLimits.Default.MaximumFileBytes
                    || !IsSha256(file.Sha256)
                    || !byPath.TryAdd(file.RelativePath, file)
                    || !insensitivePaths.Add(file.RelativePath))
                {
                    return false;
                }

                total = checked(total + file.Length);
            }

            if (total != expectedExpandedBytes
                || !byPath.TryGetValue(
                    UpdateReleaseContract.ReleaseManifestPath,
                    out var manifestFile)
                || !string.Equals(
                    manifestFile.Sha256,
                    expectedManifestSha256,
                    StringComparison.Ordinal)
                || byPath.Count != manifestFiles.Count + 1)
            {
                return false;
            }

            foreach (var expected in manifestFiles)
            {
                if (!byPath.TryGetValue(
                        expected.Path,
                        out var actual)
                    || actual.Length != expected.Length
                    || !string.Equals(
                        actual.Sha256,
                        expected.Sha256,
                        StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (
            exception is OverflowException
                or ArgumentException)
        {
            return false;
        }
    }

    private static bool TryParseReleaseManifest(
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
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 32
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(
                    root,
                    ManifestProperties)
                || root.GetProperty("schemaVersion").ValueKind
                    != JsonValueKind.Number
                || !root.GetProperty("schemaVersion")
                    .TryGetInt32(out var schemaVersion)
                || root.GetProperty("version").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("runtimeIdentifier").ValueKind
                    != JsonValueKind.String
                || root.GetProperty(
                    "minimumAutoUpdateVersion").ValueKind
                    != JsonValueKind.String
                || root.GetProperty(
                    "rollbackCompatibleFromVersion").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("stateSchemaVersion").ValueKind
                    != JsonValueKind.Number
                || !root.GetProperty("stateSchemaVersion")
                    .TryGetInt32(out var stateSchemaVersion)
                || root.GetProperty("entryPoint").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("updaterEntryPoint").ValueKind
                    != JsonValueKind.String
                || root.GetProperty("requiredLaunchers").ValueKind
                    != JsonValueKind.Array
                || root.GetProperty("files").ValueKind
                    != JsonValueKind.Array)
            {
                return false;
            }

            var launcherElements =
                root.GetProperty("requiredLaunchers");
            var fileElements = root.GetProperty("files");
            if (launcherElements.GetArrayLength()
                    != UpdateReleaseContract
                        .RequiredLauncherPaths.Count
                || fileElements.GetArrayLength() is < 1
                    or > WindowsReleasePathPolicy
                        .MaximumArchiveEntries - 1)
            {
                return false;
            }

            var launchers = new List<string>(
                launcherElements.GetArrayLength());
            foreach (var launcher
                in launcherElements.EnumerateArray())
            {
                if (launcher.ValueKind
                    != JsonValueKind.String)
                {
                    return false;
                }

                launchers.Add(launcher.GetString()!);
            }

            var files = new List<ReleasePayloadFile>(
                fileElements.GetArrayLength());
            foreach (var file in fileElements.EnumerateArray())
            {
                if (file.ValueKind != JsonValueKind.Object
                    || !HasExactProperties(
                        file,
                        ManifestFileProperties)
                    || file.GetProperty("path").ValueKind
                        != JsonValueKind.String
                    || file.GetProperty("length").ValueKind
                        != JsonValueKind.Number
                    || !file.GetProperty("length")
                        .TryGetInt64(out var length)
                    || file.GetProperty("sha256").ValueKind
                        != JsonValueKind.String)
                {
                    return false;
                }

                files.Add(new ReleasePayloadFile(
                    file.GetProperty("path").GetString()!,
                    length,
                    file.GetProperty("sha256").GetString()!));
            }

            manifest = new ReleaseManifest(
                schemaVersion,
                root.GetProperty("version").GetString()!,
                root.GetProperty("runtimeIdentifier").GetString()!,
                root.GetProperty("minimumAutoUpdateVersion")
                    .GetString()!,
                root.GetProperty("rollbackCompatibleFromVersion")
                    .GetString()!,
                stateSchemaVersion,
                root.GetProperty("entryPoint").GetString()!,
                root.GetProperty("updaterEntryPoint").GetString()!,
                launchers,
                files);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string HashBytes(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

    private static bool IsSameOrNextJournalGeneration(
        long current,
        long replacement) =>
        replacement == current
        || IsNextJournalGeneration(current, replacement);

    private static bool IsNextJournalGeneration(
        long current,
        long candidate) =>
        current >= 0
        && current < long.MaxValue
        && candidate == current + 1;

    private ProtectedTransactionStoreResult
        ValidateExactJournalBinding(
            ProtectedTransactionLayout layout,
            ProtectedTransactionRecord record)
    {
        var state = _fileSystem.InspectProtectedFile(
            layout.JournalPath);
        if (state == ProtectedTransactionFileState.Unsafe)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        if (record.Journal.Generation == 0)
        {
            return state == ProtectedTransactionFileState.Missing
                ? ProtectedTransactionStoreResult.Completed()
                : ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError
                        .VerificationFailed);
        }

        if (state != ProtectedTransactionFileState.Protected)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
        }

        var bytes = _fileSystem.ReadProtectedFile(
            layout.JournalPath,
            MaximumJournalBytes);
        return bytes is not null
                && _fileSystem.InspectProtectedFile(
                    layout.JournalPath)
                    == ProtectedTransactionFileState.Protected
                && UpdateOperationJournalCodec
                    .TryParseCanonical(
                        bytes,
                        out var journal)
                && journal is not null
                && journal.TransactionId
                    == record.TransactionId
                && journal.Generation
                    == record.Journal.Generation
                && (journal.Generation != 1
                    || UpdateOperationJournalCodec
                        .IsInitialPlan(journal))
                && string.Equals(
                    HashBytes(bytes),
                    record.Journal.Sha256,
                    StringComparison.Ordinal)
            ? ProtectedTransactionStoreResult.Completed()
            : ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.VerificationFailed);
    }

    private ProtectedTransactionStoreResult WriteProtectedFile(
        string destinationPath,
        byte[] bytes,
        byte[]? expectedDestinationBytes = null,
        ProtectedFileIdentity128? expectedDestinationIdentity = null)
    {
        var parent = Path.GetDirectoryName(destinationPath);
        if (parent is null)
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        try
        {
            var commit = expectedDestinationBytes is null
                ? _fileSystem.AtomicCreate(
                    destinationPath,
                    bytes)
                : expectedDestinationIdentity is { IsValid: true }
                    ? _fileSystem.AtomicCompareExchange(
                        destinationPath,
                        expectedDestinationIdentity.Value,
                        expectedDestinationBytes,
                        bytes)
                    : _fileSystem.AtomicCompareExchange(
                        destinationPath,
                        expectedDestinationBytes,
                        bytes);
            if (commit != ProtectedAtomicCommitResult.Committed)
            {
                return ProtectedTransactionStoreResult.Failed(
                    commit == ProtectedAtomicCommitResult.Conflict
                        ? ProtectedTransactionStoreError.Conflict
                        : ProtectedTransactionStoreError
                            .AtomicWriteFailed);
            }

            var committedBytes = _fileSystem.ReadProtectedFile(
                destinationPath,
                bytes.LongLength);
            return _fileSystem.InspectProtectedFile(destinationPath)
                        == ProtectedTransactionFileState.Protected
                    && committedBytes is not null
                    && committedBytes.AsSpan().SequenceEqual(bytes)
                ? ProtectedTransactionStoreResult.Completed()
                : ProtectedTransactionStoreResult.Failed(
                    ProtectedTransactionStoreError.AtomicWriteFailed);
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return ProtectedTransactionStoreResult.Failed(
                ProtectedTransactionStoreError.IoFailure);
        }
    }

    private bool TryNormalizeMaterial(
        ProtectedStagedTransactionMaterial? material,
        out ProtectedStagedTransactionMaterial? normalized)
    {
        normalized = null;
        if (material is null)
        {
            return false;
        }

        var record = new ProtectedTransactionRecord(
            TransactionSchemaVersion,
            material.TransactionId,
            material.Version,
            material.Source,
            material.InstalledRelease,
            material.Candidate,
            material.HelperSha256,
            ProtectedTransactionPhase.ProtectedStaged,
            AuthorizedProcess: null,
            material.Journal);
        if (!IsValidRecord(record))
        {
            return false;
        }

        if (record.Journal.Generation != 0
            || record.Journal.Sha256 is not null)
        {
            return false;
        }

        try
        {
            var sourceFiles =
                record.InstalledRelease.ManagedFiles;
            var count = sourceFiles.Count;
            var managedFiles =
                new ProtectedManagedFileIdentity[count];
            for (var index = 0; index < count; index++)
            {
                var file = sourceFiles[index];
                if (file is null)
                {
                    return false;
                }

                managedFiles[index] = file with { };
            }

            if (sourceFiles.Count != count)
            {
                return false;
            }

            normalized = material with
            {
                InstalledRelease =
                    material.InstalledRelease with
                    {
                        ManagedFiles = managedFiles
                    },
                Candidate = material.Candidate with { },
                Journal = material.Journal with { }
            };
            return IsValidRecord(
                new ProtectedTransactionRecord(
                    TransactionSchemaVersion,
                    normalized.TransactionId,
                    normalized.Version,
                    normalized.Source,
                    normalized.InstalledRelease,
                    normalized.Candidate,
                    normalized.HelperSha256,
                    ProtectedTransactionPhase.ProtectedStaged,
                    AuthorizedProcess: null,
                    normalized.Journal));
        }
        catch (Exception exception) when (
            IsCollectionFailure(exception))
        {
            normalized = null;
            return false;
        }
    }

    private bool IsValidRecord(ProtectedTransactionRecord? record)
    {
        if (record is null
            || record.SchemaVersion != TransactionSchemaVersion
            || !record.TransactionId.IsValid
            || !IsCanonicalVersion(record.Version)
            || !Enum.IsDefined(record.Source)
            || !Enum.IsDefined(record.Phase)
            || !IsSha256(record.HelperSha256)
            || record.Journal is null
            || record.Journal.SchemaVersion != JournalSchemaVersion
            || record.Journal.Generation < 0
            || record.Journal.Generation == 0
                && record.Journal.Sha256 is not null
            || record.Journal.Generation > 0
                && !IsSha256(record.Journal.Sha256)
            || record.Candidate is null
            || !IsSha256(record.Candidate.ArchiveSha256)
            || !IsSha256(record.Candidate.NewManifestSha256)
            || record.Candidate.ExpandedBytes <= 0
            || record.Candidate.ExpandedBytes
                > UpdatePackageLimits.Default.MaximumExpandedBytes
            || record.InstalledRelease is null
            || !IsCanonicalLocalPath(
                record.InstalledRelease.InstallRoot)
            || !IsSha256(
                record.InstalledRelease.CurrentManifestSha256)
            || record.InstalledRelease.VolumeSerialNumber == 0
            || record.InstalledRelease.RootFileIdLow == 0
                && record.InstalledRelease.RootFileIdHigh == 0
            || record.InstalledRelease.CurrentVersion == default
            || record.InstalledRelease.MinimumAutoUpdateVersion
                == default
            || record.InstalledRelease
                .RollbackCompatibleFromVersion == default
            || !IsCanonicalVersion(
                record.InstalledRelease.CurrentVersion)
            || !IsCanonicalVersion(
                record.InstalledRelease
                    .MinimumAutoUpdateVersion)
            || !IsCanonicalVersion(
                record.InstalledRelease
                    .RollbackCompatibleFromVersion)
            || record.InstalledRelease
                    .MinimumAutoUpdateVersion
                    .CompareTo(
                        record.InstalledRelease
                            .CurrentVersion) > 0
            || record.InstalledRelease
                    .RollbackCompatibleFromVersion
                    .CompareTo(
                        record.InstalledRelease
                            .CurrentVersion) > 0
            || record.InstalledRelease.StateSchemaVersion <= 0
            || !string.Equals(
                record.InstalledRelease
                    .ApplicationRelativePath,
                UpdateReleaseContract.WindowsApplicationPath,
                StringComparison.Ordinal)
            || !string.Equals(
                record.InstalledRelease.UpdaterRelativePath,
                UpdateReleaseContract.WindowsUpdaterPath,
                StringComparison.Ordinal)
            || !IsValidManagedFiles(
                record.InstalledRelease.ManagedFiles)
            || !ContainsRequiredManagedPaths(
                record.InstalledRelease.ManagedFiles)
            || !IsValidProcessInvariant(
                record.Phase,
                record.AuthorizedProcess))
        {
            return false;
        }

        return true;
    }

    private static bool HaveSameImmutableIdentity(
        ProtectedTransactionRecord first,
        ProtectedTransactionRecord second) =>
        RecordsEqual(
            first with
            {
                Phase =
                    ProtectedTransactionPhase.ProtectedStaged,
                AuthorizedProcess = null,
                Journal = new ProtectedJournalMetadata(
                    JournalSchemaVersion,
                    Generation: 0)
            },
            second with
            {
                Phase =
                    ProtectedTransactionPhase.ProtectedStaged,
                AuthorizedProcess = null,
                Journal = new ProtectedJournalMetadata(
                    JournalSchemaVersion,
                    Generation: 0)
            });

    internal static bool IsLegalPhaseTransition(
        ProtectedTransactionPhase current,
        ProtectedTransactionPhase next)
    {
        if (!Enum.IsDefined(current)
            || !Enum.IsDefined(next))
        {
            return false;
        }

        return current == next
            || (current, next) switch
            {
                (
                    ProtectedTransactionPhase.ProtectedStaged,
                    ProtectedTransactionPhase.CloseAuthorized)
                    => true,
                (
                    ProtectedTransactionPhase.CloseAuthorized,
                    ProtectedTransactionPhase.Prepared)
                    => true,
                (
                    ProtectedTransactionPhase.Prepared,
                    ProtectedTransactionPhase.BackingUp)
                    => true,
                (
                    ProtectedTransactionPhase.BackingUp,
                    ProtectedTransactionPhase.Applying)
                    => true,
                (
                    ProtectedTransactionPhase.Applying,
                    ProtectedTransactionPhase
                        .AppliedAwaitingHealth)
                    => true,
                (
                    ProtectedTransactionPhase
                        .AppliedAwaitingHealth,
                    ProtectedTransactionPhase.Committed)
                    => true,
                (
                    ProtectedTransactionPhase.CloseAuthorized
                        or ProtectedTransactionPhase.Prepared
                        or ProtectedTransactionPhase.BackingUp
                        or ProtectedTransactionPhase.Applying
                        or ProtectedTransactionPhase
                            .AppliedAwaitingHealth,
                    ProtectedTransactionPhase.RollingBack)
                    => true,
                (
                    ProtectedTransactionPhase.RollingBack,
                    ProtectedTransactionPhase.RolledBack)
                    => true,
                (
                    ProtectedTransactionPhase.CloseAuthorized
                        or ProtectedTransactionPhase.Prepared
                        or ProtectedTransactionPhase.BackingUp
                        or ProtectedTransactionPhase.Applying
                        or ProtectedTransactionPhase
                            .AppliedAwaitingHealth
                        or ProtectedTransactionPhase.RollingBack,
                    ProtectedTransactionPhase.RecoveryBlocked)
                    => true,
                _ => false
            };
    }

    private static bool IsLegalRecordTransition(
        ProtectedTransactionRecord current,
        ProtectedTransactionRecord next)
    {
        if (!IsLegalPhaseTransition(
                current.Phase,
                next.Phase))
        {
            return false;
        }

        if (current.Phase
                == ProtectedTransactionPhase.ProtectedStaged
            && next.Phase
                == ProtectedTransactionPhase.CloseAuthorized)
        {
            if (current.AuthorizedProcess is not null
                || next.AuthorizedProcess is null)
            {
                return false;
            }
        }
        else if (!Equals(
            current.AuthorizedProcess,
            next.AuthorizedProcess))
        {
            return false;
        }

        if (current.Phase == next.Phase
            && current.Phase is
                ProtectedTransactionPhase.ProtectedStaged
                or ProtectedTransactionPhase.Committed
                or ProtectedTransactionPhase.RolledBack
                or ProtectedTransactionPhase.RecoveryBlocked
            && !Equals(current.Journal, next.Journal))
        {
            return false;
        }

        return true;
    }

    private bool IsValidManagedFiles(
        IReadOnlyList<ProtectedManagedFileIdentity>? files)
    {
        if (files is null)
        {
            return false;
        }

        int count;
        try
        {
            count = files.Count;
        }
        catch (Exception exception) when (
            IsCollectionFailure(exception))
        {
            return false;
        }

        if (count <= 0
            || count > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return false;
        }

        var paths = new string?[count];
        string? previous = null;
        for (var index = 0; index < count; index++)
        {
            ProtectedManagedFileIdentity file;
            try
            {
                file = files[index];
            }
            catch (Exception exception) when (
                IsCollectionFailure(exception))
            {
                return false;
            }

            var path = WindowsReleasePathPolicy.Validate(
                file?.RelativePath);
            if (file is null
                || !path.Success
                || path.CanonicalKey is null
                || !string.Equals(
                    path.CanonicalKey,
                    file.RelativePath,
                    StringComparison.Ordinal)
                || ReleaseManagedPathPolicy.IsProtectedPayloadPath(
                    file.RelativePath)
                || file.Length < 0
                || file.Length
                    > UpdatePackageLimits.Default.MaximumFileBytes
                || !IsSha256(file.Sha256)
                || previous is not null
                    && StringComparer.Ordinal.Compare(
                        previous,
                        file.RelativePath) >= 0)
            {
                return false;
            }

            previous = file.RelativePath;
            paths[index] = file.RelativePath;
        }

        try
        {
            return files.Count == count
                && WindowsReleasePathPolicy
                    .ValidateCollection(paths)
                    .Success;
        }
        catch (Exception exception) when (
            IsCollectionFailure(exception))
        {
            return false;
        }
    }

    private bool IsValidProcessInvariant(
        ProtectedTransactionPhase phase,
        ProcessIdentity? process)
    {
        if (phase == ProtectedTransactionPhase.ProtectedStaged)
        {
            return process is null;
        }

        if (process is null)
        {
            return phase is
                ProtectedTransactionPhase.AppliedAwaitingHealth
                or ProtectedTransactionPhase.Committed
                or ProtectedTransactionPhase.RollingBack
                or ProtectedTransactionPhase.RolledBack
                or ProtectedTransactionPhase.RecoveryBlocked;
        }

        return process.ProcessId > 0
            && process.CreationTimeFileTimeUtc > 0
            && IsCanonicalLocalPath(process.ImagePath);
    }

    private static bool ContainsRequiredManagedPaths(
        IReadOnlyList<ProtectedManagedFileIdentity> files)
    {
        var paths = new HashSet<string>(
            files.Select(file => file.RelativePath),
            StringComparer.Ordinal);
        return paths.Contains(
                UpdateReleaseContract.WindowsApplicationPath)
            && paths.Contains(
                UpdateReleaseContract.WindowsUpdaterPath)
            && UpdateReleaseContract.RequiredLauncherPaths
                .All(paths.Contains);
    }

    private bool IsCanonicalLocalPath(string? path)
    {
        if (path is not { Length: > 0 and <= MaximumPathCharacters }
            || !WindowsLocalPath.TryGetCanonicalLocalDosPath(
                path,
                _getDriveType,
                out var canonical)
            || canonical is null)
        {
            return false;
        }

        return string.Equals(
            path,
            canonical,
            StringComparison.Ordinal);
    }

    private static bool IsCanonicalVersion(
        SemanticVersion version) =>
        SemanticVersion.TryParseNormalized(
            version.ToString(),
            out var parsed)
        && parsed == version;

    private static byte[]? SerializeRecord(
        ProtectedTransactionRecord record)
    {
        try
        {
            using var output = new MemoryStream();
            using (var writer = new Utf8JsonWriter(output))
            {
                writer.WriteStartObject();
                writer.WriteNumber(
                    "schemaVersion",
                    record.SchemaVersion);
                writer.WriteString(
                    "transactionId",
                    record.TransactionId.DirectoryName);
                writer.WriteString(
                    "version",
                    record.Version.ToString());
                writer.WriteString(
                    "source",
                    record.Source.ToString());

                writer.WriteStartObject("installedRelease");
                writer.WriteString(
                    "installRoot",
                    record.InstalledRelease.InstallRoot);
                writer.WriteNumber(
                    "volumeSerialNumber",
                    record.InstalledRelease.VolumeSerialNumber);
                writer.WriteNumber(
                    "rootFileIdLow",
                    record.InstalledRelease.RootFileIdLow);
                writer.WriteNumber(
                    "rootFileIdHigh",
                    record.InstalledRelease.RootFileIdHigh);
                writer.WriteString(
                    "currentVersion",
                    record.InstalledRelease.CurrentVersion
                        .ToString());
                writer.WriteString(
                    "minimumAutoUpdateVersion",
                    record.InstalledRelease
                        .MinimumAutoUpdateVersion
                        .ToString());
                writer.WriteString(
                    "rollbackCompatibleFromVersion",
                    record.InstalledRelease
                        .RollbackCompatibleFromVersion
                        .ToString());
                writer.WriteNumber(
                    "stateSchemaVersion",
                    record.InstalledRelease.StateSchemaVersion);
                writer.WriteString(
                    "applicationRelativePath",
                    record.InstalledRelease
                        .ApplicationRelativePath);
                writer.WriteString(
                    "updaterRelativePath",
                    record.InstalledRelease
                        .UpdaterRelativePath);
                writer.WriteString(
                    "currentManifestSha256",
                    record.InstalledRelease
                        .CurrentManifestSha256);
                writer.WriteStartArray("managedFiles");
                foreach (var file
                    in record.InstalledRelease.ManagedFiles)
                {
                    writer.WriteStartObject();
                    writer.WriteString(
                        "relativePath",
                        file.RelativePath);
                    writer.WriteNumber(
                        "length",
                        file.Length);
                    writer.WriteString(
                        "sha256",
                        file.Sha256);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();

                writer.WriteStartObject("candidate");
                writer.WriteString(
                    "archiveSha256",
                    record.Candidate.ArchiveSha256);
                writer.WriteString(
                    "newManifestSha256",
                    record.Candidate.NewManifestSha256);
                writer.WriteNumber(
                    "expandedBytes",
                    record.Candidate.ExpandedBytes);
                writer.WriteEndObject();

                writer.WriteString(
                    "helperSha256",
                    record.HelperSha256);
                writer.WriteString(
                    "phase",
                    record.Phase.ToString());
                if (record.AuthorizedProcess is null)
                {
                    writer.WriteNull("authorizedProcess");
                }
                else
                {
                    writer.WriteStartObject("authorizedProcess");
                    writer.WriteNumber(
                        "processId",
                        record.AuthorizedProcess.ProcessId);
                    writer.WriteNumber(
                        "creationTimeFileTimeUtc",
                        record.AuthorizedProcess
                            .CreationTimeFileTimeUtc);
                    writer.WriteString(
                        "imagePath",
                        record.AuthorizedProcess.ImagePath);
                    writer.WriteEndObject();
                }

                writer.WriteStartObject("journal");
                writer.WriteNumber(
                    "schemaVersion",
                    record.Journal.SchemaVersion);
                writer.WriteNumber(
                    "generation",
                    record.Journal.Generation);
                if (record.Journal.Sha256 is null)
                {
                    writer.WriteNull("sha256");
                }
                else
                {
                    writer.WriteString(
                        "sha256",
                        record.Journal.Sha256);
                }

                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            return output.ToArray();
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or NotSupportedException)
        {
            return null;
        }
    }

    private static byte[] SerializeActivePointer(
        ProtectedTransactionId transactionId)
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            writer.WriteNumber(
                "schemaVersion",
                ActivePointerSchemaVersion);
            writer.WriteString(
                "transactionId",
                transactionId.DirectoryName);
            writer.WriteEndObject();
        }

        return output.ToArray();
    }

    private static byte[] SerializeInactivePointer()
    {
        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            writer.WriteNumber(
                "schemaVersion",
                ActivePointerSchemaVersion);
            writer.WriteNull("transactionId");
            writer.WriteEndObject();
        }

        return output.ToArray();
    }

    private static bool TryParseActivePointer(
        byte[] bytes,
        out ProtectedTransactionId? transactionId)
    {
        transactionId = default;
        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 4
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(
                    root,
                    ActivePointerProperties)
                || root.GetProperty("schemaVersion").ValueKind
                    != JsonValueKind.Number
                || !root.GetProperty("schemaVersion")
                    .TryGetInt32(out var schemaVersion)
                || schemaVersion != ActivePointerSchemaVersion
                )
            {
                return false;
            }

            var idProperty = root.GetProperty("transactionId");
            if (idProperty.ValueKind == JsonValueKind.Null)
            {
                var canonical = SerializeInactivePointer();
                if (!bytes.AsSpan().SequenceEqual(canonical))
                {
                    return false;
                }

                transactionId = null;
                return true;
            }

            if (idProperty.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var idText =
                idProperty.GetString();
            if (!Guid.TryParseExact(
                    idText,
                    "N",
                    out var guid))
            {
                return false;
            }

            var parsed = new ProtectedTransactionId(guid);
            if (!parsed.IsValid
                || !string.Equals(
                    idText,
                    parsed.DirectoryName,
                    StringComparison.Ordinal))
            {
                return false;
            }

            var canonicalActive = SerializeActivePointer(parsed);
            if (!bytes.AsSpan().SequenceEqual(canonicalActive))
            {
                return false;
            }

            transactionId = parsed;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private bool TryParseRecord(
        byte[] bytes,
        out ProtectedTransactionRecord? record)
    {
        record = null;
        try
        {
            using var document = JsonDocument.Parse(
                bytes,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling =
                        JsonCommentHandling.Disallow,
                    MaxDepth = 16
                });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !HasExactProperties(
                    root,
                    RecordProperties)
                || !TryReadRecord(
                    root,
                    out var candidate)
                || !IsValidRecord(candidate))
            {
                return false;
            }

            record = candidate;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private bool TryReadRecord(
        JsonElement root,
        out ProtectedTransactionRecord? record)
    {
        record = null;
        if (root.GetProperty("schemaVersion").ValueKind
                != JsonValueKind.Number
            || !root.GetProperty("schemaVersion")
                .TryGetInt32(out var schemaVersion)
            || root.GetProperty("transactionId").ValueKind
                != JsonValueKind.String
            || root.GetProperty("version").ValueKind
                != JsonValueKind.String
            || root.GetProperty("source").ValueKind
                != JsonValueKind.String
            || root.GetProperty("installedRelease").ValueKind
                != JsonValueKind.Object
            || root.GetProperty("candidate").ValueKind
                != JsonValueKind.Object
            || root.GetProperty("helperSha256").ValueKind
                != JsonValueKind.String
            || root.GetProperty("phase").ValueKind
                != JsonValueKind.String
            || root.GetProperty("authorizedProcess").ValueKind
                is not (
                    JsonValueKind.Null
                    or JsonValueKind.Object)
            || root.GetProperty("journal").ValueKind
                != JsonValueKind.Object)
        {
            return false;
        }

        var idText =
            root.GetProperty("transactionId").GetString();
        if (!Guid.TryParseExact(idText, "N", out var guid))
        {
            return false;
        }

        var transactionId = new ProtectedTransactionId(guid);
        var versionText =
            root.GetProperty("version").GetString();
        var sourceText =
            root.GetProperty("source").GetString();
        var phaseText =
            root.GetProperty("phase").GetString();
        if (!string.Equals(
                idText,
                transactionId.DirectoryName,
                StringComparison.Ordinal)
            || !SemanticVersion.TryParseNormalized(
                versionText,
                out var version)
            || !string.Equals(
                versionText,
                version.ToString(),
                StringComparison.Ordinal)
            || sourceText is not ("Automatic" or "Manual")
            || !Enum.TryParse<PendingUpdateSource>(
                sourceText,
                ignoreCase: false,
                out var source)
            || phaseText is null
            || !Enum.TryParse<ProtectedTransactionPhase>(
                phaseText,
                ignoreCase: false,
                out var phase)
            || !string.Equals(
                phaseText,
                phase.ToString(),
                StringComparison.Ordinal)
            || !TryReadInstalledRelease(
                root.GetProperty("installedRelease"),
                out var installedRelease)
            || !TryReadCandidate(
                root.GetProperty("candidate"),
                out var candidate)
            || !TryReadProcess(
                root.GetProperty("authorizedProcess"),
                out var process)
            || !TryReadJournal(
                root.GetProperty("journal"),
                out var journal))
        {
            return false;
        }

        record = new ProtectedTransactionRecord(
            schemaVersion,
            transactionId,
            version,
            source,
            installedRelease!,
            candidate!,
            root.GetProperty("helperSha256").GetString()!,
            phase,
            process,
            journal!);
        return true;
    }

    private static bool TryReadInstalledRelease(
        JsonElement element,
        out ProtectedInstalledReleaseIdentity? installed)
    {
        installed = null;
        if (!HasExactProperties(
                element,
                InstalledReleaseProperties)
            || element.GetProperty("installRoot").ValueKind
                != JsonValueKind.String
            || element.GetProperty("volumeSerialNumber").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("volumeSerialNumber")
                .TryGetUInt64(out var volume)
            || element.GetProperty("rootFileIdLow").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("rootFileIdLow")
                .TryGetUInt64(out var fileIdLow)
            || element.GetProperty("rootFileIdHigh").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("rootFileIdHigh")
                .TryGetUInt64(out var fileIdHigh)
            || element.GetProperty("currentVersion").ValueKind
                != JsonValueKind.String
            || element.GetProperty(
                    "minimumAutoUpdateVersion").ValueKind
                != JsonValueKind.String
            || element.GetProperty(
                    "rollbackCompatibleFromVersion").ValueKind
                != JsonValueKind.String
            || element.GetProperty("stateSchemaVersion").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("stateSchemaVersion")
                .TryGetInt32(out var stateSchemaVersion)
            || element.GetProperty(
                    "applicationRelativePath").ValueKind
                != JsonValueKind.String
            || element.GetProperty(
                    "updaterRelativePath").ValueKind
                != JsonValueKind.String
            || element.GetProperty(
                    "currentManifestSha256").ValueKind
                != JsonValueKind.String
            || element.GetProperty("managedFiles").ValueKind
                != JsonValueKind.Array)
        {
            return false;
        }

        var currentVersionText =
            element.GetProperty("currentVersion").GetString();
        var minimumVersionText = element.GetProperty(
            "minimumAutoUpdateVersion").GetString();
        var rollbackVersionText = element.GetProperty(
            "rollbackCompatibleFromVersion").GetString();
        if (!TryParseCanonicalVersion(
                currentVersionText,
                out var currentVersion)
            || !TryParseCanonicalVersion(
                minimumVersionText,
                out var minimumVersion)
            || !TryParseCanonicalVersion(
                rollbackVersionText,
                out var rollbackVersion))
        {
            return false;
        }

        var filesElement =
            element.GetProperty("managedFiles");
        if (filesElement.GetArrayLength() >
            WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return false;
        }

        var files =
            new List<ProtectedManagedFileIdentity>(
                filesElement.GetArrayLength());
        foreach (var file in filesElement.EnumerateArray())
        {
            if (file.ValueKind != JsonValueKind.Object
                || !HasExactProperties(
                    file,
                    ManagedFileProperties)
                || file.GetProperty("relativePath").ValueKind
                    != JsonValueKind.String
                || file.GetProperty("length").ValueKind
                    != JsonValueKind.Number
                || !file.GetProperty("length")
                    .TryGetInt64(out var length)
                || file.GetProperty("sha256").ValueKind
                    != JsonValueKind.String)
            {
                return false;
            }

            files.Add(new ProtectedManagedFileIdentity(
                file.GetProperty("relativePath").GetString()!,
                length,
                file.GetProperty("sha256").GetString()!));
        }

        installed = new ProtectedInstalledReleaseIdentity(
            element.GetProperty("installRoot").GetString()!,
            volume,
            fileIdLow,
            fileIdHigh,
            currentVersion,
            minimumVersion,
            rollbackVersion,
            stateSchemaVersion,
            element.GetProperty(
                "applicationRelativePath").GetString()!,
            element.GetProperty(
                "updaterRelativePath").GetString()!,
            element.GetProperty(
                "currentManifestSha256").GetString()!,
            files);
        return true;
    }

    private static bool TryReadCandidate(
        JsonElement element,
        out ProtectedCandidateIdentity? candidate)
    {
        candidate = null;
        if (!HasExactProperties(
                element,
                CandidateProperties)
            || element.GetProperty("archiveSha256").ValueKind
                != JsonValueKind.String
            || element.GetProperty("newManifestSha256").ValueKind
                != JsonValueKind.String
            || element.GetProperty("expandedBytes").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("expandedBytes")
                .TryGetInt64(out var expandedBytes))
        {
            return false;
        }

        candidate = new ProtectedCandidateIdentity(
            element.GetProperty("archiveSha256").GetString()!,
            element.GetProperty("newManifestSha256").GetString()!,
            expandedBytes);
        return true;
    }

    private static bool TryReadProcess(
        JsonElement element,
        out ProcessIdentity? process)
    {
        process = null;
        if (element.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (element.ValueKind != JsonValueKind.Object
            || !HasExactProperties(
                element,
                ProcessProperties)
            || element.GetProperty("processId").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("processId")
                .TryGetInt32(out var processId)
            || element.GetProperty(
                    "creationTimeFileTimeUtc").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty(
                    "creationTimeFileTimeUtc")
                .TryGetInt64(out var creationTime)
            || element.GetProperty("imagePath").ValueKind
                != JsonValueKind.String)
        {
            return false;
        }

        process = new ProcessIdentity(
            processId,
            creationTime,
            element.GetProperty("imagePath").GetString()!);
        return true;
    }

    private static bool TryReadJournal(
        JsonElement element,
        out ProtectedJournalMetadata? journal)
    {
        journal = null;
        if (!HasExactProperties(
                element,
                JournalProperties)
            || element.GetProperty("schemaVersion").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("schemaVersion")
                .TryGetInt32(out var schemaVersion)
            || element.GetProperty("generation").ValueKind
                != JsonValueKind.Number
            || !element.GetProperty("generation")
                .TryGetInt64(out var generation)
            || element.GetProperty("sha256").ValueKind
                is not (
                    JsonValueKind.Null
                    or JsonValueKind.String))
        {
            return false;
        }

        journal = new ProtectedJournalMetadata(
            schemaVersion,
            generation,
            element.GetProperty("sha256").ValueKind
                == JsonValueKind.Null
                ? null
                : element.GetProperty("sha256").GetString());
        return true;
    }

    private bool ValidateTransactionDirectoryChain(
        ProtectedTransactionLayout layout) =>
        ValidateRootDirectoryChain(
            new ProtectedTransactionRootLayout(
                layout.ProductRoot,
                layout.TransactionsRoot,
                layout.ActivePointerPath))
        && _fileSystem.ValidateProtectedDirectory(
            layout.TransactionRoot);

    private TransactionRecordSnapshot ReadTransactionSnapshot(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId)
    {
        var layoutResult = _paths.GetLayout(transactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is null)
        {
            return TransactionRecordSnapshot.Failed(
                ProtectedTransactionStoreError.UnsafePath);
        }

        var layout = layoutResult.Layout;
        if (!ValidateTransactionDirectoryChain(layout))
        {
            return TransactionRecordSnapshot.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        var state = _fileSystem.InspectProtectedFile(
            layout.TransactionRecordPath);
        if (state == ProtectedTransactionFileState.Missing)
        {
            return TransactionRecordSnapshot.Failed(
                ProtectedTransactionStoreError.Missing);
        }

        if (state != ProtectedTransactionFileState.Protected)
        {
            return TransactionRecordSnapshot.Failed(
                ProtectedTransactionStoreError.AclMismatch);
        }

        try
        {
            var bytes = _fileSystem.ReadProtectedFile(
                layout.TransactionRecordPath,
                MaximumRecordBytes);
            if (bytes is null
                || _fileSystem.InspectProtectedFile(
                    layout.TransactionRecordPath)
                    != ProtectedTransactionFileState.Protected
                || !TryParseRecord(bytes, out var record)
                || record!.TransactionId != transactionId)
            {
                return TransactionRecordSnapshot.Failed(
                    ProtectedTransactionStoreError.CorruptData);
            }

            return TransactionRecordSnapshot.Found(
                record,
                bytes);
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return TransactionRecordSnapshot.Failed(
                ProtectedTransactionStoreError.IoFailure);
        }
    }

    private sealed record TransactionRecordSnapshot(
        bool Success,
        ProtectedTransactionRecord? Record,
        byte[]? Bytes,
        ProtectedTransactionStoreError Error)
    {
        internal static TransactionRecordSnapshot Found(
            ProtectedTransactionRecord record,
            byte[] bytes) =>
            new(
                true,
                record,
                bytes,
                ProtectedTransactionStoreError.None);

        internal static TransactionRecordSnapshot Failed(
            ProtectedTransactionStoreError error) =>
            new(false, null, null, error);
    }

    private sealed record ActivePointerSnapshot(
        bool Success,
        ProtectedTransactionId? TransactionId,
        IProtectedFileSnapshotLease? Snapshot,
        ProtectedTransactionStoreError Error) : IDisposable
    {
        internal byte[]? Bytes => Snapshot?.Bytes;

        internal ProtectedFileIdentity128? Identity =>
            Snapshot?.Identity;

        internal bool Revalidate() =>
            Snapshot?.Revalidate()
                ?? TransactionId is null;

        internal static ActivePointerSnapshot Found(
            ProtectedTransactionId? transactionId,
            IProtectedFileSnapshotLease? snapshot) =>
            new(
                true,
                transactionId,
                snapshot,
                ProtectedTransactionStoreError.None);

        internal static ActivePointerSnapshot Failed(
            ProtectedTransactionStoreError error) =>
            new(false, null, null, error);

        public void Dispose() => Snapshot?.Dispose();
    }

    private bool ValidateRootDirectoryChain(
        ProtectedTransactionRootLayout root) =>
        _fileSystem.ValidateProtectedDirectory(
            root.ProductRoot)
        && _fileSystem.ValidateProtectedDirectory(
            root.TransactionsRoot);

    private static bool RecordsEqual(
        ProtectedTransactionRecord first,
        ProtectedTransactionRecord second)
    {
        var firstBytes = SerializeRecord(first);
        var secondBytes = SerializeRecord(second);
        return firstBytes is not null
            && secondBytes is not null
            && firstBytes.AsSpan().SequenceEqual(secondBytes);
    }

    private static bool HasExactProperties(
        JsonElement element,
        IReadOnlyCollection<string> expected)
    {
        var seen = new HashSet<string>(
            StringComparer.Ordinal);
        var count = 0;
        foreach (var property in element.EnumerateObject())
        {
            count++;
            if (!expected.Contains(
                    property.Name,
                    StringComparer.Ordinal)
                || !seen.Add(property.Name))
            {
                return false;
            }
        }

        return count == expected.Count;
    }

    private static bool TryParseCanonicalVersion(
        string? value,
        out SemanticVersion version) =>
        SemanticVersion.TryParseNormalized(
            value,
            out version)
        && string.Equals(
            value,
            version.ToString(),
            StringComparison.Ordinal);

    private static bool IsSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');

    private static bool IsCollectionFailure(
        Exception exception) =>
        exception is InvalidOperationException
            or ArgumentOutOfRangeException
            or IndexOutOfRangeException
            or NotSupportedException;

    private static bool IsExpectedFileException(
        Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException
            or ObjectDisposedException
            or InvalidOperationException
            or System.ComponentModel.Win32Exception
            or CryptographicException
            or System.Security.SecurityException;

    private sealed class WindowsProtectedInstalledReleaseVerifier
        : IProtectedInstalledReleaseVerifier
    {
        private readonly IExecutableProductVersionReader
            _productVersionReader;
        private readonly ProtectedDirectoryAcl _acl;

        internal WindowsProtectedInstalledReleaseVerifier(
            IExecutableProductVersionReader productVersionReader,
            ProtectedDirectoryAcl acl)
        {
            _productVersionReader = productVersionReader
                ?? throw new ArgumentNullException(
                    nameof(productVersionReader));
            _acl = acl
                ?? throw new ArgumentNullException(nameof(acl));
        }

        public bool Verify(
            ProtectedInstalledReleaseIdentity oldRelease,
            ProtectedInstalledReleaseIdentity newRelease,
            ProtectedInstalledReleaseVerification verification)
        {
            if (!Enum.IsDefined(verification)
                || !HaveSameRootIdentity(
                    oldRelease,
                    newRelease))
            {
                return false;
            }

            using var rootResult =
                _acl.InspectProtectedDirectory(
                    oldRelease.InstallRoot,
                    ProtectedDirectoryInspectionPolicy
                        .InstalledRelease);
            if (!rootResult.Success
                || rootResult.Lease is not { } root
                || !MatchesIdentity(root.Identity, oldRelease))
            {
                return false;
            }

            if (verification
                == ProtectedInstalledReleaseVerification
                    .NamespaceOnly)
            {
                return root.Revalidate();
            }

            var expected = verification
                == ProtectedInstalledReleaseVerification.FullNew
                    ? newRelease
                    : oldRelease;
            return VerifyExactRelease(
                    root,
                    expected)
                && root.Revalidate();
        }

        private bool VerifyExactRelease(
            ProtectedDirectoryInspectionLease root,
            ProtectedInstalledReleaseIdentity expected)
        {
            using var manifestResult =
                _acl.OpenProtectedFileForRead(
                    root,
                    UpdateReleaseContract.ReleaseManifestPath,
                    ProtectedDirectoryInspectionPolicy
                        .InstalledRelease);
            if (!manifestResult.Success
                || manifestResult.Lease is not { } manifestFile
                || !manifestFile.TryReadAllBytes(
                    UpdateNetworkLimits.MetadataBytes,
                    out var manifestBytes)
                || !string.Equals(
                    HashBytes(manifestBytes),
                    expected.CurrentManifestSha256,
                    StringComparison.Ordinal)
                || !TryParseReleaseManifest(
                    manifestBytes,
                    out var manifest)
                || !TryValidateManifest(
                    manifest!,
                    expected,
                    out var manifestFiles)
                || manifestFiles.Count
                    != expected.ManagedFiles.Count)
            {
                return false;
            }

            var expectedByPath =
                new Dictionary<
                    string,
                    ProtectedManagedFileIdentity>(
                    StringComparer.Ordinal);
            var insensitivePaths = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var expectedFile in expected.ManagedFiles)
            {
                if (!expectedByPath.TryAdd(
                        expectedFile.RelativePath,
                        expectedFile)
                    || !insensitivePaths.Add(
                        expectedFile.RelativePath))
                {
                    return false;
                }
            }

            foreach (var declared in manifestFiles)
            {
                if (!expectedByPath.TryGetValue(
                        declared.Path,
                        out var recorded)
                    || recorded.Length != declared.Length
                    || !string.Equals(
                        recorded.Sha256,
                        declared.Sha256,
                        StringComparison.Ordinal))
                {
                    return false;
                }

                using var openedResult =
                    _acl.OpenProtectedFileForRead(
                        root,
                        declared.Path,
                        ProtectedDirectoryInspectionPolicy
                            .InstalledRelease);
                if (!openedResult.Success
                    || openedResult.Lease is not { } opened
                    || !TryHashRetainedFile(
                        opened,
                        out var length,
                        out var sha256)
                    || length != declared.Length
                    || !string.Equals(
                        sha256,
                        declared.Sha256,
                        StringComparison.Ordinal))
                {
                    return false;
                }

                if ((string.Equals(
                            declared.Path,
                            expected.ApplicationRelativePath,
                            StringComparison.Ordinal)
                        || string.Equals(
                            declared.Path,
                            expected.UpdaterRelativePath,
                            StringComparison.Ordinal))
                    && !WindowsProtectedTransactionFileSystem
                        .HasExpectedProductVersion(
                            opened,
                            expected.CurrentVersion.ToString(),
                            _productVersionReader))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool TryHashRetainedFile(
            ProtectedFileReadLease file,
            out long length,
            out string? sha256)
        {
            length = 0;
            sha256 = null;
            try
            {
                var stream = file.Stream;
                length = stream.Length;
                if (length < 0
                    || length > UpdatePackageLimits.Default
                        .MaximumFileBytes)
                {
                    return false;
                }

                stream.Position = 0;
                sha256 = Convert.ToHexString(
                        SHA256.HashData(stream))
                    .ToLowerInvariant();
                return stream.Length == length
                    && file.Revalidate();
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                length = 0;
                sha256 = null;
                return false;
            }
        }

        private static bool HaveSameRootIdentity(
            ProtectedInstalledReleaseIdentity first,
            ProtectedInstalledReleaseIdentity second) =>
            string.Equals(
                first.InstallRoot,
                second.InstallRoot,
                StringComparison.OrdinalIgnoreCase)
            && first.VolumeSerialNumber
                == second.VolumeSerialNumber
            && first.RootFileIdLow == second.RootFileIdLow
            && first.RootFileIdHigh == second.RootFileIdHigh;

        private static bool TryValidateManifest(
            ReleaseManifest manifest,
            ProtectedInstalledReleaseIdentity expected,
            out IReadOnlyList<ReleasePayloadFile> files)
        {
            files = [];
            if (manifest.SchemaVersion != 1
                || manifest.RuntimeIdentifier
                    != UpdateReleaseContract
                        .WindowsRuntimeIdentifier
                || !TryParseCanonicalVersion(
                    manifest.Version,
                    out var currentVersion)
                || currentVersion != expected.CurrentVersion
                || !TryParseCanonicalVersion(
                    manifest.MinimumAutoUpdateVersion,
                    out var minimumVersion)
                || minimumVersion
                    != expected.MinimumAutoUpdateVersion
                || !TryParseCanonicalVersion(
                    manifest.RollbackCompatibleFromVersion,
                    out var rollbackVersion)
                || rollbackVersion
                    != expected.RollbackCompatibleFromVersion
                || manifest.StateSchemaVersion
                    != expected.StateSchemaVersion
                || !string.Equals(
                    manifest.EntryPoint,
                    expected.ApplicationRelativePath,
                    StringComparison.Ordinal)
                || !string.Equals(
                    manifest.UpdaterEntryPoint,
                    expected.UpdaterRelativePath,
                    StringComparison.Ordinal)
                || !HasExactLaunchers(
                    manifest.RequiredLaunchers)
                || manifest.Files is null
                || manifest.Files.Count is < 1
                    or >= WindowsReleasePathPolicy
                        .MaximumArchiveEntries)
            {
                return false;
            }

            var exactPaths = new HashSet<string>(
                StringComparer.Ordinal);
            var insensitivePaths = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            var snapshot =
                new List<ReleasePayloadFile>(
                    manifest.Files.Count);
            long total = 0;
            foreach (var file in manifest.Files)
            {
                var path = WindowsReleasePathPolicy.Validate(
                    file?.Path);
                if (file is null
                    || !path.Success
                    || path.CanonicalKey is null
                    || !string.Equals(
                        path.CanonicalKey,
                        file.Path,
                        StringComparison.Ordinal)
                    || ReleaseManagedPathPolicy
                        .IsProtectedPayloadPath(file.Path)
                    || file.Length < 0
                    || file.Length
                        > UpdatePackageLimits.Default
                            .MaximumFileBytes
                    || !IsSha256(file.Sha256)
                    || !exactPaths.Add(file.Path)
                    || !insensitivePaths.Add(file.Path))
                {
                    return false;
                }

                total = checked(total + file.Length);
                if (total > UpdatePackageLimits.Default
                    .MaximumExpandedBytes)
                {
                    return false;
                }

                snapshot.Add(file);
            }

            if (!exactPaths.Contains(
                    expected.ApplicationRelativePath)
                || !exactPaths.Contains(
                    expected.UpdaterRelativePath)
                || !UpdateReleaseContract.RequiredLauncherPaths
                    .All(exactPaths.Contains))
            {
                return false;
            }

            files = snapshot.AsReadOnly();
            return true;
        }

        private static bool HasExactLaunchers(
            IReadOnlyList<string>? launchers) =>
            launchers is not null
            && launchers.Count
                == UpdateReleaseContract
                    .RequiredLauncherPaths.Count
            && WindowsReleasePathPolicy
                .ValidateCollection(
                    launchers.Cast<string?>().ToArray())
                .Success
            && new HashSet<string>(
                    launchers,
                    StringComparer.Ordinal)
                .SetEquals(
                    UpdateReleaseContract
                        .RequiredLauncherPaths)
            && new HashSet<string>(
                    launchers,
                    StringComparer.OrdinalIgnoreCase)
                .Count == launchers.Count;

        private static bool MatchesIdentity(
            ProtectedFileIdentity128 actual,
            ProtectedInstalledReleaseIdentity expected) =>
            actual.VolumeSerialNumber
                == expected.VolumeSerialNumber
            && actual.FileIdLow == expected.RootFileIdLow
            && actual.FileIdHigh == expected.RootFileIdHigh;
    }
}

internal sealed class WindowsProtectedTransactionFileSystem
    : IProtectedTransactionFileSystem
{
    private readonly ProtectedDirectoryAcl _acl;

    public WindowsProtectedTransactionFileSystem()
        : this(new ProtectedDirectoryAcl())
    {
    }

    internal WindowsProtectedTransactionFileSystem(
        ProtectedDirectoryAcl acl)
    {
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
    }

    public bool ValidateProtectedDirectory(string path)
    {
        using var opened = _acl.InspectProtectedDirectory(
            path,
            ProtectedDirectoryInspectionPolicy.Transaction);
        return opened.Success
            && opened.Lease?.Revalidate() == true;
    }

    public ProtectedTransactionFileState InspectProtectedFile(
        string path)
    {
        using var opened = _acl.OpenProtectedFileForRead(path);
        if (opened.Success
            && opened.Lease?.Revalidate() == true)
        {
            return ProtectedTransactionFileState.Protected;
        }

        return opened.Error == ProtectedAclError.Missing
            ? ProtectedTransactionFileState.Missing
            : ProtectedTransactionFileState.Unsafe;
    }

    public byte[]? ReadProtectedFile(
        string path,
        long maximumBytes)
    {
        if (maximumBytes < 0
            || maximumBytes > int.MaxValue)
        {
            return null;
        }

        try
        {
            using var opened =
                _acl.OpenProtectedFileForRead(path);
            return opened.Success
                    && opened.Lease is { } file
                    && file.TryReadAllBytes(
                        maximumBytes,
                        out var bytes)
                ? bytes
                : null;
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return null;
        }
    }

    public IProtectedFileSnapshotLease?
        OpenProtectedFileSnapshot(
            string path,
            long maximumBytes)
    {
        if (maximumBytes < 0
            || maximumBytes > int.MaxValue)
        {
            return null;
        }

        ProtectedFileReadLease? lease = null;
        try
        {
            var opened = _acl.OpenProtectedFileForRead(path);
            if (!opened.Success
                || opened.Lease is not { } file)
            {
                return null;
            }

            lease = file;
            if (!file.TryReadAllBytes(
                    maximumBytes,
                    out var bytes))
            {
                return null;
            }

            var snapshot =
                new WindowsProtectedFileSnapshotLease(
                    _acl,
                    path,
                    file,
                    bytes);
            lease = null;
            return snapshot;
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return null;
        }
        finally
        {
            lease?.Dispose();
        }
    }

    public ProtectedAtomicCommitResult AtomicCreate(
        string destinationPath,
        byte[] replacementBytes)
    {
        var result = _acl.CreateProtectedFileIfAbsent(
            destinationPath,
            replacementBytes);
        return result.Outcome switch
        {
            ProtectedFileMutationOutcome.Committed =>
                ProtectedAtomicCommitResult.Committed,
            ProtectedFileMutationOutcome.Conflict =>
                ProtectedAtomicCommitResult.Conflict,
            _ => ProtectedAtomicCommitResult.Failed
        };
    }

    public ProtectedAtomicCommitResult AtomicCompareExchange(
        string destinationPath,
        byte[] expectedDestinationBytes,
        byte[] replacementBytes) =>
        AtomicCompareExchangeCore(
            destinationPath,
            expectedIdentity: null,
            expectedDestinationBytes,
            replacementBytes);

    public ProtectedAtomicCommitResult AtomicCompareExchange(
        string destinationPath,
        ProtectedFileIdentity128 expectedIdentity,
        byte[] expectedDestinationBytes,
        byte[] replacementBytes) =>
        expectedIdentity.IsValid
            ? AtomicCompareExchangeCore(
                destinationPath,
                expectedIdentity,
                expectedDestinationBytes,
                replacementBytes)
            : ProtectedAtomicCommitResult.Conflict;

    private ProtectedAtomicCommitResult
        AtomicCompareExchangeCore(
            string destinationPath,
            ProtectedFileIdentity128? expectedIdentity,
            byte[] expectedDestinationBytes,
            byte[] replacementBytes)
    {
        ProtectedFileIdentity128 identity;
        using (var observed =
            _acl.OpenProtectedFileForRead(destinationPath))
        {
            if (!observed.Success
                || observed.Lease is not { } file)
            {
                return observed.Error == ProtectedAclError.Missing
                    ? ProtectedAtomicCommitResult.Conflict
                    : ProtectedAtomicCommitResult.Failed;
            }

            if ((expectedIdentity is { } exactIdentity
                    && file.Identity != exactIdentity)
                || !file.TryReadAllBytes(
                    expectedDestinationBytes.LongLength,
                    out var actual)
                || !actual.AsSpan().SequenceEqual(
                    expectedDestinationBytes))
            {
                return ProtectedAtomicCommitResult.Conflict;
            }

            identity = file.Identity;
        }

        var result = _acl.CompareExchangeProtectedFile(
            destinationPath,
            identity,
            expectedDestinationBytes,
            replacementBytes);
        return result.Outcome switch
        {
            ProtectedFileCompareExchangeOutcome.Committed =>
                ProtectedAtomicCommitResult.Committed,
            ProtectedFileCompareExchangeOutcome.Conflict =>
                ProtectedAtomicCommitResult.Conflict,
            _ => ProtectedAtomicCommitResult.Failed
        };
    }

    public bool HasProtectedProductVersion(
        string path,
        string expectedVersion,
        IExecutableProductVersionReader versionReader)
    {
        using var opened = _acl.OpenProtectedFileForRead(path);
        if (!opened.Success
            || opened.Lease is not { } file)
        {
            return false;
        }

        return HasExpectedProductVersion(
            file,
            expectedVersion,
            versionReader);
    }

    internal static bool HasExpectedProductVersion(
        ProtectedFileReadLease file,
        string expectedVersion,
        IExecutableProductVersionReader versionReader)
    {
        var stream = file.Stream;
        var position = stream.Position;
        string? actualVersion;
        try
        {
            actualVersion =
                versionReader.ReadProductVersion(stream);
        }
        finally
        {
            stream.Position = position;
        }

        return string.Equals(
                actualVersion,
                expectedVersion,
                StringComparison.Ordinal)
            && file.Revalidate();
    }

    public string? ComputeProtectedSha256(
        string path,
        long maximumBytes)
    {
        if (maximumBytes < 0)
        {
            return null;
        }

        try
        {
            using var opened =
                _acl.OpenProtectedFileForRead(path);
            if (!opened.Success
                || opened.Lease is not { } file)
            {
                return null;
            }

            var stream = file.Stream;
            var length = stream.Length;
            if (length < 0 || length > maximumBytes)
            {
                return null;
            }

            stream.Position = 0;
            var hash = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Length == length
                    && file.Revalidate()
                ? hash
                : null;
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            return null;
        }
    }

    public IReadOnlyList<ProtectedCandidateFileSnapshot>?
        SnapshotProtectedFiles(
            string path,
            int maximumEntries,
            long maximumBytes)
    {
        if (maximumEntries < 0
            || maximumBytes < 0)
        {
            return null;
        }

        try
        {
            using var rootResult =
                _acl.InspectProtectedDirectory(
                    path,
                    ProtectedDirectoryInspectionPolicy
                        .Transaction);
            if (!rootResult.Success
                || rootResult.Lease is not { } root)
            {
                return null;
            }

            using var enumerationResult =
                _acl.EnumerateProtectedDirectory(
                    root,
                    ProtectedDirectoryInspectionPolicy
                        .Transaction,
                    maximumEntries);
            if (!enumerationResult.Success
                || enumerationResult.Lease
                    is not { } enumeration
                || enumeration.Files.Count > maximumEntries)
            {
                return null;
            }

            var files =
                new List<ProtectedCandidateFileSnapshot>();
            long total = 0;
            foreach (var file in enumeration.Files)
            {
                var pathValidation =
                    WindowsReleasePathPolicy.Validate(
                        file.RelativePath);
                if (!pathValidation.Success
                    || pathValidation.CanonicalKey is null
                    || !string.Equals(
                        pathValidation.CanonicalKey,
                        file.RelativePath,
                        StringComparison.Ordinal)
                    || !TrySnapshotRetainedFile(
                        file,
                        out var length,
                        out var hash))
                {
                    return null;
                }

                total = checked(total + length);
                if (total > maximumBytes)
                {
                    return null;
                }

                files.Add(
                    new ProtectedCandidateFileSnapshot(
                        file.RelativePath,
                        length,
                        hash!));
            }

            if (!enumeration.Revalidate()
                || !root.Revalidate())
            {
                return null;
            }

            files.Sort((left, right) =>
                StringComparer.Ordinal.Compare(
                    left.RelativePath,
                    right.RelativePath));
            return files.AsReadOnly();
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception)
            || exception is OverflowException)
        {
            return null;
        }
    }

    public long? MeasureProtectedDirectory(
        string path,
        long maximumBytes)
    {
        if (maximumBytes < 0)
        {
            return null;
        }

        try
        {
            using var rootResult =
                _acl.InspectProtectedDirectory(
                    path,
                    ProtectedDirectoryInspectionPolicy
                        .Transaction);
            if (!rootResult.Success
                || rootResult.Lease is not { } root)
            {
                return null;
            }

            using var enumerationResult =
                _acl.EnumerateProtectedDirectory(
                    root,
                    ProtectedDirectoryInspectionPolicy
                        .Transaction,
                    WindowsReleasePathPolicy
                        .MaximumArchiveEntries);
            if (!enumerationResult.Success
                || enumerationResult.Lease
                    is not { } enumeration)
            {
                return null;
            }

            long total = 0;
            foreach (var file in enumeration.Files)
            {
                var length = file.Stream.Length;
                if (length < 0
                    || length > UpdatePackageLimits.Default
                        .MaximumFileBytes)
                {
                    return null;
                }

                total = checked(total + length);
                if (total > maximumBytes
                    || !file.Revalidate())
                {
                    return null;
                }
            }

            return enumeration.Revalidate()
                    && root.Revalidate()
                ? total
                : null;
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception)
            || exception is OverflowException)
        {
            return null;
        }
    }

    private static bool TrySnapshotRetainedFile(
        ProtectedEnumeratedFileLease file,
        out long length,
        out string? sha256)
    {
        length = 0;
        sha256 = null;
        try
        {
            var stream = file.Stream;
            length = stream.Length;
            if (length < 0
                || length > UpdatePackageLimits.Default
                    .MaximumFileBytes)
            {
                return false;
            }

            stream.Position = 0;
            sha256 = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            return stream.Length == length
                && file.Revalidate();
        }
        catch (Exception exception) when (
            IsExpectedFileException(exception))
        {
            length = 0;
            sha256 = null;
            return false;
        }
    }

    private sealed class WindowsProtectedFileSnapshotLease
        : IProtectedFileSnapshotLease
    {
        private readonly ProtectedDirectoryAcl _acl;
        private readonly string _path;
        private ProtectedFileReadLease? _lease;
        private readonly byte[] _bytes;

        internal WindowsProtectedFileSnapshotLease(
            ProtectedDirectoryAcl acl,
            string path,
            ProtectedFileReadLease lease,
            byte[] bytes)
        {
            _acl = acl;
            _path = path;
            _lease = lease;
            _bytes = bytes.ToArray();
            Identity = lease.Identity;
        }

        public ProtectedFileIdentity128 Identity { get; }

        public byte[] Bytes => _bytes.ToArray();

        public bool Revalidate()
        {
            var lease = Volatile.Read(ref _lease);
            if (lease is null || !lease.Revalidate())
            {
                return false;
            }

            try
            {
                using var current =
                    _acl.OpenProtectedFileForRead(_path);
                return current.Success
                    && current.Lease is { } currentFile
                    && currentFile.Identity == Identity
                    && currentFile.TryReadAllBytes(
                        _bytes.LongLength,
                        out var actual)
                    && actual.AsSpan().SequenceEqual(_bytes)
                    && lease.Revalidate();
            }
            catch (Exception exception) when (
                IsExpectedFileException(exception))
            {
                return false;
            }
        }

        public void Dispose() =>
            Interlocked.Exchange(
                    ref _lease,
                    null)
                ?.Dispose();
    }

    private static bool IsExpectedFileException(
        Exception exception) =>
        exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException
            or ObjectDisposedException
            or InvalidOperationException
            or System.Security.SecurityException;
}
