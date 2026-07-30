using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

internal enum TransactionalUpdateExecutionOutcome
{
    AppliedAwaitingHealth,
    RetryableFailure,
    RecoveryBlocked,
    TerminalState
}

internal readonly record struct TransactionalUpdateExecutionResult(
    TransactionalUpdateExecutionOutcome Outcome,
    string? ErrorCode = null,
    bool NamespaceMutationPossible = false);

internal enum TransactionalUpdateGatewayFailure
{
    None,
    Retryable,
    Ambiguous
}

internal enum TransactionalUpdateJournalObservation
{
    AbsentInitial,
    Bound,
    PublishedUnbound,
    Unsafe
}

internal enum TransactionalUpdateFaultPoint
{
    BeforeJournalPublish,
    AfterJournalPublish,
    BeforePhaseCompareExchange,
    AfterPhaseCompareExchange,
    BeforeBackup,
    AfterBackup,
    BeforeTemporaryWrite,
    AfterTemporaryWrite,
    BeforeApply,
    AfterApply,
    BeforeRollback,
    AfterRollback
}

internal sealed record TransactionalUpdateFaultContext(
    TransactionalUpdateFaultPoint Point,
    ProtectedTransactionPhase Phase,
    long JournalGeneration,
    int? OperationOrdinal);

internal sealed record TransactionalUpdateSnapshot(
    ProtectedTransactionRecord Record,
    TransactionalUpdateJournalObservation JournalObservation,
    UpdateOperationJournal? Journal,
    string? JournalSha256,
    object? NativeToken);

internal readonly record struct TransactionalUpdateGatewayReadResult(
    TransactionalUpdateSnapshot? Snapshot,
    TransactionalUpdateGatewayFailure Failure)
{
    public bool Success =>
        Snapshot is not null
        && Failure == TransactionalUpdateGatewayFailure.None;
}

internal sealed record TransactionalUpdatePlanMaterial(
    ReleaseManifest CandidateManifest,
    long InstalledManifestLength,
    string InstalledManifestSha256,
    long CandidateManifestLength,
    string CandidateManifestSha256);

internal readonly record struct
    TransactionalUpdatePlanMaterialResult(
        TransactionalUpdatePlanMaterial? Material,
        TransactionalUpdateGatewayFailure Failure)
{
    public bool Success =>
        Material is not null
        && Failure == TransactionalUpdateGatewayFailure.None;
}

internal readonly record struct
    TransactionalUpdateFileSessionOpenResult(
        ITransactionalUpdateFileSession? Session,
        TransactionalUpdateGatewayFailure Failure) : IDisposable
{
    public bool Success =>
        Session is not null
        && Failure == TransactionalUpdateGatewayFailure.None;

    public void Dispose() => Session?.Dispose();
}

internal interface ITransactionalUpdateGateway
{
    TransactionalUpdateGatewayReadResult Read(
        ProtectedTransactionId transactionId);

    TransactionalUpdatePlanMaterialResult ReadPlanMaterial(
        TransactionalUpdateSnapshot expected);

    TransactionalUpdateGatewayReadResult PublishJournal(
        TransactionalUpdateSnapshot expected,
        ReadOnlyMemory<byte> canonicalJournal);

    TransactionalUpdateGatewayReadResult CompareExchange(
        TransactionalUpdateSnapshot expected,
        ProtectedTransactionRecord replacement);

    TransactionalUpdateFileSessionOpenResult OpenFileSession(
        TransactionalUpdateSnapshot expected);

    TransactionalUpdateGatewayReadResult EnterRecoveryBlocked(
        TransactionalUpdateSnapshot expected);
}

internal interface ITransactionalUpdateFileSession : IDisposable
{
    UpdateFileObservationResult Observe(
        UpdateOperation operation,
        UpdateFileLocation location);

    UpdateFileSystemResult CreateBackup(
        UpdateOperation operation);

    UpdateFileSystemResult StageReplacement(
        UpdateOperation operation);

    UpdateFileSystemResult Apply(
        UpdateOperation operation);

    UpdateFileSystemResult Rollback(
        UpdateOperation operation);
}

internal interface ITransactionalUpdateCoordinator
{
    TransactionalUpdateExecutionResult Resume(
        ProtectedTransactionId transactionId);
}

internal interface IProtectedTransactionalUpdateStore
{
    ProtectedJournalRecoveryReadResult ReadJournalForRecovery(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId);

    ProtectedJournalRecoveryReadResult PublishJournalCheckpoint(
        ProtectedUpdateMutexContext authority,
        ProtectedJournalRecoveryReadResult expected,
        ReadOnlyMemory<byte> canonicalJournal);

    ProtectedTransactionWriteResult CompareExchangeTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedJournalRecoveryReadResult expected,
        ProtectedTransactionRecord replacement);

    ProtectedTransactionWriteResult EnterRecoveryBlocked(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord expectedRecord);
}

internal sealed class ProtectedTransactionalUpdateStore
    : IProtectedTransactionalUpdateStore
{
    private readonly ProtectedTransactionStore _store;

    internal ProtectedTransactionalUpdateStore(
        ProtectedTransactionStore store)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
    }

    public ProtectedJournalRecoveryReadResult
        ReadJournalForRecovery(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId) =>
        _store.ReadJournalForRecovery(authority, transactionId);

    public ProtectedJournalRecoveryReadResult
        PublishJournalCheckpoint(
            ProtectedUpdateMutexContext authority,
            ProtectedJournalRecoveryReadResult expected,
            ReadOnlyMemory<byte> canonicalJournal) =>
        _store.PublishJournalCheckpoint(
            authority,
            expected,
            canonicalJournal);

    public ProtectedTransactionWriteResult
        CompareExchangeTransaction(
            ProtectedUpdateMutexContext authority,
            ProtectedJournalRecoveryReadResult expected,
            ProtectedTransactionRecord replacement) =>
        _store.CompareExchangeTransaction(
            authority,
            expected,
            replacement);

    public ProtectedTransactionWriteResult EnterRecoveryBlocked(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord expectedRecord) =>
        _store.EnterRecoveryBlocked(authority, expectedRecord);
}

internal sealed class ProtectedTransactionalUpdateGateway
    : ITransactionalUpdateGateway
{
    private static readonly JsonSerializerOptions ManifestJsonOptions =
        new()
        {
            AllowTrailingCommas = false,
            MaxDepth = 32,
            PropertyNameCaseInsensitive = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow
        };

    private readonly IProtectedTransactionalUpdateStore _store;
    private readonly ProtectedUpdateMutexContext _authority;
    private readonly ProtectedTransactionPaths _paths;
    private readonly ProtectedDirectoryAcl _acl;
    private readonly UpdateFileSystem _fileSystem;

    internal ProtectedTransactionalUpdateGateway(
        ProtectedTransactionStore store,
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPaths paths)
        : this(
            new ProtectedTransactionalUpdateStore(store),
            authority,
            paths,
            new ProtectedDirectoryAcl(),
            new UpdateFileSystem())
    {
    }

    internal ProtectedTransactionalUpdateGateway(
        IProtectedTransactionalUpdateStore store,
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPaths paths,
        ProtectedDirectoryAcl acl,
        UpdateFileSystem fileSystem)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _authority = authority
            ?? throw new ArgumentNullException(nameof(authority));
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
        _fileSystem = fileSystem
            ?? throw new ArgumentNullException(nameof(fileSystem));
    }

    public TransactionalUpdateGatewayReadResult Read(
        ProtectedTransactionId transactionId) =>
        transactionId.IsValid
            ? MapStoreRead(
                _store.ReadJournalForRecovery(
                    _authority,
                    transactionId))
            : new(
                Snapshot: null,
                TransactionalUpdateGatewayFailure.Retryable);

    public TransactionalUpdatePlanMaterialResult
        ReadPlanMaterial(
            TransactionalUpdateSnapshot expected)
    {
        if (!MatchesNativeSnapshot(expected)
            || expected.Record.Phase
                != ProtectedTransactionPhase.CloseAuthorized
            || expected.JournalObservation
                != TransactionalUpdateJournalObservation
                    .AbsentInitial)
        {
            return FailedMaterial(
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        var layoutResult = _paths.GetLayout(
            expected.Record.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is not { } layout)
        {
            return FailedMaterial(
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        using var candidateRootResult =
            _acl.InspectProtectedDirectory(
                layout.CandidateRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        using var installedRootResult =
            _acl.InspectProtectedDirectory(
                expected.Record.InstalledRelease.InstallRoot,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (!candidateRootResult.Success
            || candidateRootResult.Lease is not { } candidateRoot
            || !installedRootResult.Success
            || installedRootResult.Lease is not { } installedRoot
            || !MatchesInstalledRoot(
                installedRoot.Identity,
                expected.Record.InstalledRelease))
        {
            return FailedMaterial(
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        using var candidateManifestResult =
            _acl.OpenProtectedFileForRead(
                candidateRoot,
                UpdateReleaseContract.ReleaseManifestPath,
                ProtectedDirectoryInspectionPolicy.Transaction);
        using var installedManifestResult =
            _acl.OpenProtectedFileForRead(
                installedRoot,
                UpdateReleaseContract.ReleaseManifestPath,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (!candidateManifestResult.Success
            || candidateManifestResult.Lease is not { } candidateManifest
            || !installedManifestResult.Success
            || installedManifestResult.Lease is not { } installedManifest
            || !candidateManifest.TryReadAllBytes(
                UpdateNetworkLimits.MetadataBytes,
                out var candidateBytes)
            || !installedManifest.TryReadAllBytes(
                UpdateNetworkLimits.MetadataBytes,
                out var installedBytes)
            || !string.Equals(
                HashBytes(candidateBytes),
                expected.Record.Candidate.NewManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                HashBytes(installedBytes),
                expected.Record.InstalledRelease
                    .CurrentManifestSha256,
                StringComparison.Ordinal)
            || !TryParseManifest(
                candidateBytes,
                out var candidate)
            || !candidateManifest.Revalidate()
            || !installedManifest.Revalidate()
            || !candidateRoot.Revalidate()
            || !installedRoot.Revalidate())
        {
            return FailedMaterial(
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        return new(
            new TransactionalUpdatePlanMaterial(
                candidate!,
                installedBytes.LongLength,
                expected.Record.InstalledRelease
                    .CurrentManifestSha256,
                candidateBytes.LongLength,
                expected.Record.Candidate.NewManifestSha256),
            TransactionalUpdateGatewayFailure.None);
    }

    public TransactionalUpdateGatewayReadResult PublishJournal(
        TransactionalUpdateSnapshot expected,
        ReadOnlyMemory<byte> canonicalJournal)
    {
        if (!TryGetNative(
                expected,
                out var native))
        {
            return new(
                expected,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        return MapStoreRead(
            _store.PublishJournalCheckpoint(
                _authority,
                native,
                canonicalJournal));
    }

    public TransactionalUpdateGatewayReadResult CompareExchange(
        TransactionalUpdateSnapshot expected,
        ProtectedTransactionRecord replacement)
    {
        if (!TryGetNative(
                expected,
                out var native)
            || replacement is null
            || replacement.TransactionId
                != expected.Record.TransactionId)
        {
            return new(
                expected,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        if (expected.Record.Phase
                == ProtectedTransactionPhase.BackingUp
            && replacement.Phase
                == ProtectedTransactionPhase.Applying
            && !VerifyFullOld(expected.Record))
        {
            return new(
                expected,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        var exchanged = _store.CompareExchangeTransaction(
            _authority,
            native,
            replacement);
        if (!exchanged.Success
            || exchanged.Record is null)
        {
            return new(
                expected,
                MapStoreFailure(exchanged.Error));
        }

        var reread = Read(replacement.TransactionId);
        if (!reread.Success
            || reread.Snapshot is not { } snapshot
            || snapshot.Record.Phase != replacement.Phase
            || snapshot.Record.Journal
                != replacement.Journal)
        {
            return new(
                reread.Snapshot ?? expected,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        return reread;
    }

    public TransactionalUpdateFileSessionOpenResult
        OpenFileSession(
            TransactionalUpdateSnapshot expected)
    {
        if (!MatchesNativeSnapshot(expected)
            || expected.Record.Phase is not (
                ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.BackingUp
                or ProtectedTransactionPhase.Applying
                or ProtectedTransactionPhase.RollingBack)
            || expected.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || expected.Journal is null)
        {
            return new(
                Session: null,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        var layoutResult = _paths.GetLayout(
            expected.Record.TransactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is not { } layout)
        {
            return new(
                Session: null,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        var installedResult =
            _acl.InspectProtectedDirectory(
                expected.Record.InstalledRelease.InstallRoot,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        var backupResult =
            _acl.InspectProtectedDirectory(
                layout.BackupsRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        var candidateResult =
            _acl.InspectProtectedDirectory(
                layout.CandidateRoot,
                ProtectedDirectoryInspectionPolicy.Transaction);
        if (!installedResult.Success
            || installedResult.Lease is not { } installed
            || !backupResult.Success
            || backupResult.Lease is not { } backup
            || !candidateResult.Success
            || candidateResult.Lease is not { } candidate
            || !MatchesInstalledRoot(
                installed.Identity,
                expected.Record.InstalledRelease)
            || !installed.Revalidate()
            || !backup.Revalidate()
            || !candidate.Revalidate())
        {
            installedResult.Dispose();
            backupResult.Dispose();
            candidateResult.Dispose();
            return new(
                Session: null,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        var opened = _fileSystem.OpenSession(
            new UpdateFileSystemSessionRequest(
                installed.FinalPath,
                ToUpdateIdentity(installed.Identity),
                backup.FinalPath,
                ToUpdateIdentity(backup.Identity)));
        installedResult.Dispose();
        backupResult.Dispose();
        if (!opened.Success
            || opened.Session is null)
        {
            candidateResult.Dispose();
            opened.Dispose();
            return new(
                Session: null,
                TransactionalUpdateGatewayFailure.Ambiguous);
        }

        return new(
            new ProtectedTransactionalUpdateFileSession(
                opened.Session,
                _acl,
                candidate),
            TransactionalUpdateGatewayFailure.None);
    }

    public TransactionalUpdateGatewayReadResult
        EnterRecoveryBlocked(
            TransactionalUpdateSnapshot expected)
    {
        var blocked = _store.EnterRecoveryBlocked(
            _authority,
            expected.Record);
        if (!blocked.Success
            || blocked.Record is null)
        {
            return new(
                expected,
                MapStoreFailure(blocked.Error));
        }

        var reread = Read(expected.Record.TransactionId);
        if (reread.Success
            && reread.Snapshot?.Record.Phase
                == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return reread;
        }

        return new(
            expected with
            {
                Record = blocked.Record,
                NativeToken = null
            },
            TransactionalUpdateGatewayFailure.None);
    }

    internal static TransactionalUpdateGatewayReadResult
        MapStoreRead(
            ProtectedJournalRecoveryReadResult read)
    {
        if (!read.Success
            || read.Record is null)
        {
            return new(
                Snapshot: null,
                MapStoreFailure(read.Error));
        }

        UpdateOperationJournal? journal = null;
        var canonicalJournal =
            read.JournalBytes is not null
            && UpdateOperationJournalCodec.TryParseCanonical(
                read.JournalBytes,
                out journal)
            && journal is not null;
        var observation = read.Observation switch
        {
            ProtectedJournalObservation.AbsentInitial
                when read.Record.Journal.Generation == 0
                    && read.Record.Journal.Sha256 is null
                    && read.JournalBytes is null
                    && read.JournalSha256 is null =>
                TransactionalUpdateJournalObservation
                    .AbsentInitial,
            ProtectedJournalObservation.MatchesBoundHash
                when canonicalJournal
                    && journal!.TransactionId
                        == read.Record.TransactionId
                    && journal.Generation
                        == read.Record.Journal.Generation
                    && string.Equals(
                        read.JournalSha256,
                        read.Record.Journal.Sha256,
                        StringComparison.Ordinal) =>
                TransactionalUpdateJournalObservation.Bound,
            ProtectedJournalObservation.PresentButUnbound
                when canonicalJournal
                    && journal!.TransactionId
                        == read.Record.TransactionId
                    && read.Record.Journal.Generation
                        < long.MaxValue
                    && journal.Generation
                        == read.Record.Journal.Generation + 1 =>
                TransactionalUpdateJournalObservation
                    .PublishedUnbound,
            _ => TransactionalUpdateJournalObservation.Unsafe
        };
        var snapshot = new TransactionalUpdateSnapshot(
            read.Record,
            observation,
            canonicalJournal ? journal : null,
            read.JournalSha256,
            read);
        return observation
                == TransactionalUpdateJournalObservation.Unsafe
            ? new(
                snapshot,
                TransactionalUpdateGatewayFailure.Ambiguous)
            : new(
                snapshot,
                TransactionalUpdateGatewayFailure.None);
    }

    internal static TransactionalUpdateGatewayFailure
        MapStoreFailure(
            ProtectedTransactionStoreError error) =>
        error == ProtectedTransactionStoreError.Conflict
            ? TransactionalUpdateGatewayFailure.Retryable
            : TransactionalUpdateGatewayFailure.Ambiguous;

    private bool VerifyFullOld(
        ProtectedTransactionRecord record)
    {
        using var rootResult =
            _acl.InspectProtectedDirectory(
                record.InstalledRelease.InstallRoot,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        if (!rootResult.Success
            || rootResult.Lease is not { } root
            || !MatchesInstalledRoot(
                root.Identity,
                record.InstalledRelease)
            || !TryVerifyRetainedFile(
                root,
                UpdateReleaseContract.ReleaseManifestPath,
                expectedLength: null,
                record.InstalledRelease
                    .CurrentManifestSha256))
        {
            return false;
        }

        try
        {
            foreach (var file
                     in record.InstalledRelease.ManagedFiles)
            {
                if (!TryVerifyRetainedFile(
                        root,
                        file.RelativePath,
                        file.Length,
                        file.Sha256))
                {
                    return false;
                }
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or ArgumentOutOfRangeException
                or IndexOutOfRangeException
                or NotSupportedException)
        {
            return false;
        }

        return root.Revalidate();
    }

    private bool TryVerifyRetainedFile(
        ProtectedDirectoryInspectionLease root,
        string relativePath,
        long? expectedLength,
        string expectedSha256)
    {
        using var openedResult =
            _acl.OpenProtectedFileForRead(
                root,
                relativePath,
                ProtectedDirectoryInspectionPolicy
                    .InstalledRelease);
        return openedResult.Success
            && openedResult.Lease is { } opened
            && TryHashRetainedFile(
                opened,
                out var length,
                out var sha256)
            && (!expectedLength.HasValue
                || length == expectedLength.Value)
            && string.Equals(
                sha256,
                expectedSha256,
                StringComparison.Ordinal);
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
            var originalPosition = stream.Position;
            length = stream.Length;
            if (length < 0
                || length
                    > UpdatePackageLimits.Default.MaximumFileBytes)
            {
                return false;
            }

            stream.Position = 0;
            sha256 = Convert.ToHexString(
                    SHA256.HashData(stream))
                .ToLowerInvariant();
            stream.Position = originalPosition;
            return file.Revalidate();
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or ObjectDisposedException
                or CryptographicException
                or System.ComponentModel.Win32Exception
                or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool TryParseManifest(
        byte[] bytes,
        out ReleaseManifest? manifest)
    {
        manifest = null;
        if (bytes.LongLength
            > UpdateNetworkLimits.MetadataBytes)
        {
            return false;
        }

        try
        {
            manifest = JsonSerializer.Deserialize<ReleaseManifest>(
                bytes,
                ManifestJsonOptions);
            return manifest is not null;
        }
        catch (Exception exception) when (
            exception is JsonException
                or NotSupportedException)
        {
            return false;
        }
    }

    private static bool MatchesNativeSnapshot(
        TransactionalUpdateSnapshot expected) =>
        TryGetNative(expected, out var native)
        && native.Success
        && native.Record is not null
        && native.Record.TransactionId
            == expected.Record.TransactionId
        && native.Record.Phase == expected.Record.Phase
        && native.Record.Journal == expected.Record.Journal;

    private static bool TryGetNative(
        TransactionalUpdateSnapshot expected,
        out ProtectedJournalRecoveryReadResult native)
    {
        native = expected.NativeToken
            as ProtectedJournalRecoveryReadResult
            ?? null!;
        return native is not null;
    }

    private static bool MatchesInstalledRoot(
        ProtectedFileIdentity128 identity,
        ProtectedInstalledReleaseIdentity installed) =>
        identity.IsValid
        && identity.VolumeSerialNumber
            == installed.VolumeSerialNumber
        && identity.FileIdLow == installed.RootFileIdLow
        && identity.FileIdHigh == installed.RootFileIdHigh;

    private static UpdateFileIdentity128 ToUpdateIdentity(
        ProtectedFileIdentity128 identity) =>
        new(
            identity.VolumeSerialNumber,
            identity.FileIdLow,
            identity.FileIdHigh);

    private static string HashBytes(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

    private static TransactionalUpdatePlanMaterialResult
        FailedMaterial(
            TransactionalUpdateGatewayFailure failure) =>
        new(Material: null, failure);
}

internal sealed class ProtectedTransactionalUpdateFileSession
    : ITransactionalUpdateFileSession
{
    private readonly object _gate = new();
    private readonly ProtectedDirectoryAcl _acl;
    private UpdateFileSystemSession? _session;
    private ProtectedDirectoryInspectionLease? _candidateRoot;

    internal ProtectedTransactionalUpdateFileSession(
        UpdateFileSystemSession session,
        ProtectedDirectoryAcl acl,
        ProtectedDirectoryInspectionLease candidateRoot)
    {
        _session = session
            ?? throw new ArgumentNullException(nameof(session));
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
        _candidateRoot = candidateRoot
            ?? throw new ArgumentNullException(
                nameof(candidateRoot));
    }

    public UpdateFileObservationResult Observe(
        UpdateOperation operation,
        UpdateFileLocation location)
    {
        lock (_gate)
        {
            return _session is not null
                    && TryCreateOperationInput(
                        operation,
                        out var input)
                ? _session.Observe(input, location)
                : UpdateFileObservationResult.Failed(
                    UpdateFileSystemError.InvalidInput);
        }
    }

    public UpdateFileSystemResult CreateBackup(
        UpdateOperation operation)
    {
        lock (_gate)
        {
            return _session is not null
                    && TryCreateOperationInput(
                        operation,
                        out var input)
                ? _session.CreateBackup(input)
                : UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
        }
    }

    public UpdateFileSystemResult StageReplacement(
        UpdateOperation operation)
    {
        lock (_gate)
        {
            if (_session is null
                || _candidateRoot is not { } candidateRoot
                || !candidateRoot.Revalidate()
                || !TryCreateOperationInput(
                    operation,
                    out var input))
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafeRoot);
            }

            using var sourceResult =
                _acl.OpenProtectedFileForRead(
                    candidateRoot,
                    operation.TargetRelativePath,
                    ProtectedDirectoryInspectionPolicy.Transaction);
            if (!sourceResult.Success
                || sourceResult.Lease is not { } source
                || !source.Revalidate())
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafePath);
            }

            var staged = _session.StageReplacement(
                input,
                source.Stream);
            if (!source.Revalidate()
                || !candidateRoot.Revalidate())
            {
                return UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.UnsafePath,
                    staged.NamespaceChanged);
            }

            return staged;
        }
    }

    public UpdateFileSystemResult Apply(
        UpdateOperation operation)
    {
        lock (_gate)
        {
            return _session is not null
                    && TryCreateOperationInput(
                        operation,
                        out var input)
                ? _session.Apply(input)
                : UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
        }
    }

    public UpdateFileSystemResult Rollback(
        UpdateOperation operation)
    {
        lock (_gate)
        {
            return _session is not null
                    && TryCreateOperationInput(
                        operation,
                        out var input)
                ? _session.Rollback(input)
                : UpdateFileSystemResult.Failed(
                    UpdateFileSystemError.InvalidInput);
        }
    }

    public void Dispose()
    {
        UpdateFileSystemSession? session;
        ProtectedDirectoryInspectionLease? candidateRoot;
        lock (_gate)
        {
            session = _session;
            _session = null;
            candidateRoot = _candidateRoot;
            _candidateRoot = null;
        }

        session?.Dispose();
        candidateRoot?.Dispose();
    }

    internal static bool TryCreateOperationInput(
        UpdateOperation operation,
        out UpdateFileOperationInput? input)
    {
        input = null;
        if (operation is null
            || operation.Existed
                && (!operation.OldLength.HasValue
                    || operation.OldSha256 is null
                    || operation.BackupRelativePath is null
                    || !string.Equals(
                        operation.BackupRelativePath,
                        operation.TargetRelativePath,
                        StringComparison.Ordinal))
            || !operation.Existed
                && (operation.OldLength.HasValue
                    || operation.OldSha256 is not null
                    || operation.BackupRelativePath is not null))
        {
            return false;
        }

        input = new UpdateFileOperationInput(
            operation.TargetRelativePath,
            operation.Existed,
            operation.Existed
                ? new UpdateFileContentIdentity(
                    operation.OldLength!.Value,
                    operation.OldSha256!)
                : null,
            new UpdateFileContentIdentity(
                operation.NewLength,
                operation.NewSha256),
            operation.TargetRelativePath + ".bak",
            operation.TargetRelativePath + ".update-tmp");
        return true;
    }
}

internal sealed class TransactionalUpdateExecutor
    : ITransactionalUpdateCoordinator
{
    private readonly ITransactionalUpdateGateway _gateway;
    private readonly Action<TransactionalUpdateFaultContext>? _fault;

    internal TransactionalUpdateExecutor(
        ITransactionalUpdateGateway gateway,
        Action<TransactionalUpdateFaultContext>? fault = null)
    {
        _gateway = gateway
            ?? throw new ArgumentNullException(nameof(gateway));
        _fault = fault;
    }

    internal TransactionalUpdateExecutor(
        ProtectedTransactionStore store,
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPaths paths,
        Action<TransactionalUpdateFaultContext>? fault = null)
        : this(
            new ProtectedTransactionalUpdateGateway(
                store,
                authority,
                paths),
            fault)
    {
    }

    public TransactionalUpdateExecutionResult Resume(
        ProtectedTransactionId transactionId)
    {
        if (!transactionId.IsValid)
        {
            return Retryable("invalid_transaction");
        }

        var read = _gateway.Read(transactionId);
        if (read.Snapshot is not { } current
            || current.Record.TransactionId != transactionId)
        {
            return Retryable(
                "read",
                read.Snapshot,
                read.Failure);
        }

        if (current.Record.Phase
            == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return new(
                TransactionalUpdateExecutionOutcome
                    .RecoveryBlocked,
                ErrorCode: null,
                NamespaceMutationPossible: true);
        }

        if (!read.Success)
        {
            return read.Failure
                    == TransactionalUpdateGatewayFailure.Ambiguous
                && current.JournalObservation
                    == TransactionalUpdateJournalObservation.Unsafe
                    ? Block(current, "unsafe_journal")
                    : Retryable(
                        "read",
                        current,
                        read.Failure);
        }

        if (current.Record.Phase
            == ProtectedTransactionPhase.AppliedAwaitingHealth)
        {
            return new(
                TransactionalUpdateExecutionOutcome
                    .AppliedAwaitingHealth,
                ErrorCode: null,
                NamespaceMutationPossible: true);
        }

        if (current.Record.Phase is
            ProtectedTransactionPhase.Committed
                or ProtectedTransactionPhase.RolledBack)
        {
            return new(
                TransactionalUpdateExecutionOutcome.TerminalState);
        }

        if (current.JournalObservation
            == TransactionalUpdateJournalObservation
                .PublishedUnbound)
        {
            var phase = current.Record.Phase switch
            {
                ProtectedTransactionPhase.CloseAuthorized =>
                    ProtectedTransactionPhase.Prepared,
                ProtectedTransactionPhase.BackingUp =>
                    ProtectedTransactionPhase.BackingUp,
                ProtectedTransactionPhase.Applying =>
                    ProtectedTransactionPhase.Applying,
                ProtectedTransactionPhase.RollingBack =>
                    ProtectedTransactionPhase.RollingBack,
                _ => (ProtectedTransactionPhase?)null
            };
            if (phase is null)
            {
                return Retryable(
                    "unbound_phase",
                    current);
            }

            var bound = BindPublished(
                current,
                phase.Value,
                operationOrdinal: null);
            if (!bound.Success
                || bound.Snapshot is null)
            {
                return Retryable(
                    "bind",
                    current,
                    bound.Failure);
            }

            current = bound.Snapshot;
        }

        if (current.Record.Phase
            == ProtectedTransactionPhase.CloseAuthorized)
        {
            var prepared = Prepare(current);
            if (!prepared.Success
                || prepared.Snapshot is null)
            {
                return Retryable(
                    "prepare",
                    current,
                    prepared.Failure);
            }

            current = prepared.Snapshot;
        }

        if (current.Record.Phase is
            ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.BackingUp
                or ProtectedTransactionPhase.Applying
                or ProtectedTransactionPhase.RollingBack)
        {
            using var opened = _gateway.OpenFileSession(current);
            if (!opened.Success)
            {
                return current.Record.Phase
                        == ProtectedTransactionPhase.Prepared
                    && opened.Failure
                        == TransactionalUpdateGatewayFailure
                            .Retryable
                    ? Retryable(
                        "preflight",
                        current,
                        opened.Failure)
                    : Block(current, "mutation_session");
            }

            if (current.Record.Phase
                == ProtectedTransactionPhase.Prepared)
            {
                var backingUp = AdvancePhase(
                    current,
                    ProtectedTransactionPhase.BackingUp);
                if (!backingUp.Success
                    || backingUp.Snapshot is null)
                {
                    return Retryable(
                        "backing_up",
                        current,
                        backingUp.Failure);
                }

                current = backingUp.Snapshot;
            }

            if (current.Record.Phase
                == ProtectedTransactionPhase.BackingUp)
            {
                return ResumeBackingUp(
                    current,
                    opened.Session!);
            }

            if (current.Record.Phase
                == ProtectedTransactionPhase.RollingBack)
            {
                return ResumeRollingBack(
                    current,
                    opened.Session!);
            }

            return ResumeApplying(
                current,
                opened.Session!);
        }

        return Retryable(
            "resume_pending",
            current);
    }

    private TransactionalUpdateGatewayReadResult Prepare(
        TransactionalUpdateSnapshot current)
    {
        if (current.JournalObservation
            != TransactionalUpdateJournalObservation
                .AbsentInitial)
        {
            return FailedRead();
        }

        var material = _gateway.ReadPlanMaterial(current);
        if (!material.Success)
        {
            return FailedRead(material.Failure);
        }

        if (!TryBuildInitialJournal(
                current.Record,
                material.Material!,
                out var initial)
            || !UpdateOperationJournalCodec.TrySerialize(
                initial,
                out var canonical))
        {
            return FailedRead();
        }

        InvokeFault(
            TransactionalUpdateFaultPoint
                .BeforeJournalPublish,
            current,
            initial.Generation,
            operationOrdinal: null);
        var published = _gateway.PublishJournal(
            current,
            canonical);
        InvokeFault(
            TransactionalUpdateFaultPoint
                .AfterJournalPublish,
            published.Success
                ? published.Snapshot!
                : current,
            initial.Generation,
            operationOrdinal: null);
        if (!published.Success
            || published.Snapshot is null)
        {
            return published;
        }

        return BindPublished(
            published.Snapshot,
            ProtectedTransactionPhase.Prepared,
            operationOrdinal: null);
    }

    private TransactionalUpdateGatewayReadResult BindPublished(
        TransactionalUpdateSnapshot current,
        ProtectedTransactionPhase nextPhase,
        int? operationOrdinal)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation
                    .PublishedUnbound
            || current.Journal is not { } journal
            || !UpdateOperationJournalCodec.IsValid(journal)
            || journal.TransactionId
                != current.Record.TransactionId
            || journal.Generation
                != current.Record.Journal.Generation + 1
            || !IsSha256(current.JournalSha256)
            || current.Record.Phase
                    == ProtectedTransactionPhase.CloseAuthorized
                && (nextPhase
                        != ProtectedTransactionPhase.Prepared
                    || !UpdateOperationJournalCodec
                        .IsInitialPlan(journal))
            || current.Record.Phase
                    != ProtectedTransactionPhase.CloseAuthorized
                && nextPhase != current.Record.Phase)
        {
            return FailedRead();
        }

        var replacement = current.Record with
        {
            Phase = nextPhase,
            Journal = new ProtectedJournalMetadata(
                UpdateOperationJournalCodec.SchemaVersion,
                journal.Generation,
                current.JournalSha256)
        };
        InvokeFault(
            TransactionalUpdateFaultPoint
                .BeforePhaseCompareExchange,
            current,
            journal.Generation,
            operationOrdinal);
        var exchanged = _gateway.CompareExchange(
            current,
            replacement);
        InvokeFault(
            TransactionalUpdateFaultPoint
                .AfterPhaseCompareExchange,
            exchanged.Success
                ? exchanged.Snapshot!
                : current,
            journal.Generation,
            operationOrdinal);
        return exchanged.Success
                && exchanged.Snapshot is
                {
                    JournalObservation:
                        TransactionalUpdateJournalObservation.Bound
                }
                && exchanged.Snapshot.Record.Phase == nextPhase
            ? exchanged
            : FailedRead(exchanged.Failure);
    }

    private TransactionalUpdateExecutionResult ResumeBackingUp(
        TransactionalUpdateSnapshot current,
        ITransactionalUpdateFileSession session)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || current.Journal is not { } journal
            || journal.Mode != UpdateJournalMode.Applying
            || journal.TransactionId
                != current.Record.TransactionId)
        {
            return Block(current, "backup_journal");
        }

        for (var ordinal = 0;
             ordinal < journal.Operations.Count;
             ordinal++)
        {
            while (true)
            {
                journal = current.Journal!;
                var operation = journal.Operations[ordinal];
                if (operation.State
                    == UpdateOperationState.BackupComplete)
                {
                    break;
                }

                if (operation.State
                    == UpdateOperationState.Planned)
                {
                    var started = PublishAndBindCheckpoint(
                        current,
                        ordinal,
                        UpdateOperationState.BackupStarted);
                    if (!started.Success
                        || started.Snapshot is null)
                    {
                        return Retryable(
                            "backup_started",
                            current,
                            started.Failure);
                    }

                    current = started.Snapshot;
                    continue;
                }

                if (operation.State
                    != UpdateOperationState.BackupStarted)
                {
                    return Block(
                        current,
                        "backup_state");
                }

                if (!TryEnsureBackup(
                        current,
                        session,
                        operation,
                        out var failure))
                {
                    return failure;
                }

                var completed = PublishAndBindCheckpoint(
                    current,
                    ordinal,
                    UpdateOperationState.BackupComplete);
                if (!completed.Success
                    || completed.Snapshot is null)
                {
                    return operation.Kind
                            == UpdateOperationKind.Create
                        ? Retryable(
                            "backup_complete",
                            current,
                            completed.Failure)
                        : Block(
                            current,
                            "backup_complete");
                }

                current = completed.Snapshot;
            }
        }

        var applying = AdvancePhase(
            current,
            ProtectedTransactionPhase.Applying);
        if (!applying.Success
            || applying.Snapshot is null)
        {
            return Block(current, "applying");
        }

        return ResumeApplying(
            applying.Snapshot,
            session);
    }

    private TransactionalUpdateExecutionResult ResumeApplying(
        TransactionalUpdateSnapshot current,
        ITransactionalUpdateFileSession session)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || current.Journal is not { } journal
            || journal.Mode != UpdateJournalMode.Applying
            || journal.TransactionId
                != current.Record.TransactionId)
        {
            return Block(current, "apply_journal");
        }

        for (var ordinal = 0;
             ordinal < journal.Operations.Count;
             ordinal++)
        {
            while (true)
            {
                journal = current.Journal!;
                var operation = journal.Operations[ordinal];
                if (operation.State
                    == UpdateOperationState.WriteComplete)
                {
                    break;
                }

                if (operation.State
                    == UpdateOperationState.BackupComplete)
                {
                    var started = PublishAndBindCheckpoint(
                        current,
                        ordinal,
                        UpdateOperationState.WriteStarted);
                    if (!started.Success
                        || started.Snapshot is null)
                    {
                        return Retryable(
                            "write_started",
                            current,
                            started.Failure);
                    }

                    current = started.Snapshot;
                    continue;
                }

                if (operation.State
                    != UpdateOperationState.WriteStarted)
                {
                    return Block(current, "apply_state");
                }

                if (!TryEnsureApplied(
                        current,
                        session,
                        operation,
                        out var failure))
                {
                    return failure;
                }

                var completed = PublishAndBindCheckpoint(
                    current,
                    ordinal,
                    UpdateOperationState.WriteComplete);
                if (!completed.Success
                    || completed.Snapshot is null)
                {
                    return Block(
                        current,
                        "write_complete");
                }

                current = completed.Snapshot;
            }
        }

        var awaitingHealth = AdvancePhase(
            current,
            ProtectedTransactionPhase.AppliedAwaitingHealth);
        if (!awaitingHealth.Success
            || awaitingHealth.Snapshot is null)
        {
            return Block(current, "full_new");
        }

        return new(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth,
            ErrorCode: null,
            NamespaceMutationPossible: true);
    }

    private TransactionalUpdateExecutionResult ResumeRollingBack(
        TransactionalUpdateSnapshot current,
        ITransactionalUpdateFileSession session)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || current.Journal is not { } journal
            || journal.TransactionId
                != current.Record.TransactionId)
        {
            return Block(current, "rollback_journal");
        }

        if (journal.Mode == UpdateJournalMode.Applying)
        {
            var entry = journal with
            {
                Generation = journal.Generation + 1,
                Mode = UpdateJournalMode.RollingBack,
                RollbackCursor = FindHighestTouched(
                    journal.Operations),
                RollbackMutationStarted = false
            };
            var entered = PublishAndBindJournal(
                current,
                entry,
                operationOrdinal: null);
            if (!entered.Success
                || entered.Snapshot is null)
            {
                return Retryable(
                    "rollback_entry",
                    current,
                    entered.Failure);
            }

            current = entered.Snapshot;
            journal = current.Journal!;
        }

        if (journal.Mode != UpdateJournalMode.RollingBack)
        {
            return Block(current, "rollback_mode");
        }

        while (journal.RollbackCursor >= 0)
        {
            var cursor = journal.RollbackCursor;
            if (cursor >= journal.Operations.Count
                || !IsTouched(
                    journal.Operations[cursor].State))
            {
                return Block(current, "rollback_cursor");
            }

            if (!journal.RollbackMutationStarted)
            {
                var startedJournal = journal with
                {
                    Generation = journal.Generation + 1,
                    RollbackMutationStarted = true
                };
                var started = PublishAndBindJournal(
                    current,
                    startedJournal,
                    cursor);
                if (!started.Success
                    || started.Snapshot is null)
                {
                    return Retryable(
                        "rollback_started",
                        current,
                        started.Failure);
                }

                current = started.Snapshot;
                journal = current.Journal!;
            }

            var operation = journal.Operations[cursor];
            InvokeFault(
                TransactionalUpdateFaultPoint.BeforeRollback,
                current,
                journal.Generation,
                cursor);
            var rolledBack = session.Rollback(operation);
            InvokeFault(
                TransactionalUpdateFaultPoint.AfterRollback,
                current,
                journal.Generation,
                cursor);
            if (!rolledBack.Success)
            {
                return Block(
                    current,
                    "rollback_mutation");
            }

            var completedJournal = journal with
            {
                Generation = journal.Generation + 1,
                RollbackCursor = FindPreviousTouched(
                    journal.Operations,
                    cursor),
                RollbackMutationStarted = false
            };
            var completed = PublishAndBindJournal(
                current,
                completedJournal,
                cursor);
            if (!completed.Success
                || completed.Snapshot is null)
            {
                return Block(
                    current,
                    "rollback_complete");
            }

            current = completed.Snapshot;
            journal = current.Journal!;
        }

        if (journal.RollbackCursor != -1
            || journal.RollbackMutationStarted)
        {
            return Block(current, "rollback_terminal");
        }

        var terminal = AdvancePhase(
            current,
            ProtectedTransactionPhase.RolledBack);
        if (!terminal.Success
            || terminal.Snapshot is null)
        {
            return Block(current, "full_old");
        }

        return new(
            TransactionalUpdateExecutionOutcome.TerminalState,
            ErrorCode: null,
            NamespaceMutationPossible: true);
    }

    private bool TryEnsureApplied(
        TransactionalUpdateSnapshot current,
        ITransactionalUpdateFileSession session,
        UpdateOperation operation,
        out TransactionalUpdateExecutionResult failure)
    {
        failure = default;
        if (operation.Kind != UpdateOperationKind.Create)
        {
            var backup = session.Observe(
                operation,
                UpdateFileLocation.Backup);
            if (backup.Error != UpdateFileSystemError.None
                || backup.Observation
                    != UpdateFileObservation.ExactOld)
            {
                failure = Block(
                    current,
                    "apply_backup");
                return false;
            }
        }

        var target = session.Observe(
            operation,
            UpdateFileLocation.Target);
        var temporary = session.Observe(
            operation,
            UpdateFileLocation.Temporary);
        if (target.Error != UpdateFileSystemError.None
            || temporary.Error != UpdateFileSystemError.None)
        {
            failure = Block(
                current,
                "apply_observation");
            return false;
        }

        var expectedTarget = operation.Existed
            ? UpdateFileObservation.ExactOld
            : UpdateFileObservation.Missing;
        if (target.Observation
            == UpdateFileObservation.ExactNew)
        {
            if (temporary.Observation
                != UpdateFileObservation.Missing)
            {
                failure = Block(
                    current,
                    "applied_temp");
                return false;
            }
        }
        else if (target.Observation == expectedTarget)
        {
            if (temporary.Observation
                == UpdateFileObservation.Missing)
            {
                InvokeFault(
                    TransactionalUpdateFaultPoint
                        .BeforeTemporaryWrite,
                    current,
                    current.Journal!.Generation,
                    operation.Ordinal);
                var staged = session.StageReplacement(
                    operation);
                InvokeFault(
                    TransactionalUpdateFaultPoint
                        .AfterTemporaryWrite,
                    current,
                    current.Journal.Generation,
                    operation.Ordinal);
                if (!staged.Success)
                {
                    failure = ShouldBlock(staged)
                        ? Block(
                            current,
                            "temporary_mutation")
                        : Retryable(
                            "temporary_mutation",
                            current);
                    return false;
                }

                temporary = session.Observe(
                    operation,
                    UpdateFileLocation.Temporary);
            }

            if (temporary.Error
                    != UpdateFileSystemError.None
                || temporary.Observation
                    != UpdateFileObservation.ExactNew)
            {
                failure = Block(
                    current,
                    "temporary_unexpected");
                return false;
            }
        }
        else
        {
            failure = Block(
                current,
                "target_unexpected");
            return false;
        }

        InvokeFault(
            TransactionalUpdateFaultPoint.BeforeApply,
            current,
            current.Journal!.Generation,
            operation.Ordinal);
        var applied = session.Apply(operation);
        InvokeFault(
            TransactionalUpdateFaultPoint.AfterApply,
            current,
            current.Journal.Generation,
            operation.Ordinal);
        if (!applied.Success)
        {
            failure = ShouldBlock(applied)
                ? Block(current, "apply_mutation")
                : Retryable(
                    "apply_mutation",
                    current);
            return false;
        }

        var targetAfter = session.Observe(
            operation,
            UpdateFileLocation.Target);
        var temporaryAfter = session.Observe(
            operation,
            UpdateFileLocation.Temporary);
        if (targetAfter.Error
                != UpdateFileSystemError.None
            || targetAfter.Observation
                != UpdateFileObservation.ExactNew
            || temporaryAfter.Error
                != UpdateFileSystemError.None
            || temporaryAfter.Observation
                != UpdateFileObservation.Missing)
        {
            failure = Block(
                current,
                "apply_post_observation");
            return false;
        }

        return true;
    }

    private bool TryEnsureBackup(
        TransactionalUpdateSnapshot current,
        ITransactionalUpdateFileSession session,
        UpdateOperation operation,
        out TransactionalUpdateExecutionResult failure)
    {
        failure = default;
        if (operation.Kind == UpdateOperationKind.Create)
        {
            return true;
        }

        var observed = session.Observe(
            operation,
            UpdateFileLocation.Backup);
        if (observed.Error != UpdateFileSystemError.None)
        {
            failure = Block(
                current,
                "backup_observation");
            return false;
        }

        if (observed.Observation
            == UpdateFileObservation.ExactOld)
        {
            return true;
        }

        if (observed.Observation
            != UpdateFileObservation.Missing)
        {
            failure = Block(
                current,
                "backup_unexpected");
            return false;
        }

        InvokeFault(
            TransactionalUpdateFaultPoint.BeforeBackup,
            current,
            current.Journal!.Generation,
            operation.Ordinal);
        var created = session.CreateBackup(operation);
        InvokeFault(
            TransactionalUpdateFaultPoint.AfterBackup,
            current,
            current.Journal.Generation,
            operation.Ordinal);
        if (created.Success)
        {
            return true;
        }

        failure = ShouldBlock(created)
            ? Block(current, "backup_mutation")
            : Retryable(
                "backup_mutation",
                current);
        return false;
    }

    private TransactionalUpdateGatewayReadResult
        PublishAndBindCheckpoint(
            TransactionalUpdateSnapshot current,
            int ordinal,
            UpdateOperationState nextState)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || current.Journal is not { } journal
            || ordinal < 0
            || ordinal >= journal.Operations.Count)
        {
            return FailedRead();
        }

        var operations = journal.Operations
            .Select(operation => operation with { })
            .ToArray();
        operations[ordinal] = operations[ordinal] with
        {
            State = nextState
        };
        var next = journal with
        {
            Generation = journal.Generation + 1,
            Operations = operations
        };
        return PublishAndBindJournal(
            current,
            next,
            ordinal);
    }

    private TransactionalUpdateGatewayReadResult
        PublishAndBindJournal(
            TransactionalUpdateSnapshot current,
            UpdateOperationJournal next,
            int? operationOrdinal)
    {
        if (current.Journal is not { } journal
            || !UpdateOperationJournalCodec.IsLegalTransition(
                journal,
                next)
            || !UpdateOperationJournalCodec.TrySerialize(
                next,
                out var canonical))
        {
            return FailedRead();
        }

        InvokeFault(
            TransactionalUpdateFaultPoint
                .BeforeJournalPublish,
            current,
            next.Generation,
            operationOrdinal);
        var published = _gateway.PublishJournal(
            current,
            canonical);
        InvokeFault(
            TransactionalUpdateFaultPoint
                .AfterJournalPublish,
            published.Success
                ? published.Snapshot!
                : current,
            next.Generation,
            operationOrdinal);
        if (!published.Success
            || published.Snapshot is null)
        {
            return published;
        }

        return BindPublished(
            published.Snapshot,
            current.Record.Phase,
            operationOrdinal);
    }

    private TransactionalUpdateGatewayReadResult AdvancePhase(
        TransactionalUpdateSnapshot current,
        ProtectedTransactionPhase nextPhase)
    {
        if (current.JournalObservation
                != TransactionalUpdateJournalObservation.Bound
            || current.Journal is null)
        {
            return FailedRead();
        }

        var replacement = current.Record with
        {
            Phase = nextPhase
        };
        InvokeFault(
            TransactionalUpdateFaultPoint
                .BeforePhaseCompareExchange,
            current,
            current.Journal.Generation,
            operationOrdinal: null);
        var exchanged = _gateway.CompareExchange(
            current,
            replacement);
        InvokeFault(
            TransactionalUpdateFaultPoint
                .AfterPhaseCompareExchange,
            exchanged.Success
                ? exchanged.Snapshot!
                : current,
            current.Journal.Generation,
            operationOrdinal: null);
        return exchanged.Success
                && exchanged.Snapshot is
                {
                    JournalObservation:
                        TransactionalUpdateJournalObservation.Bound
                }
                && exchanged.Snapshot.Record.Phase == nextPhase
            ? exchanged
            : FailedRead(exchanged.Failure);
    }

    private TransactionalUpdateExecutionResult Block(
        TransactionalUpdateSnapshot current,
        string errorCode)
    {
        var blocked = _gateway.EnterRecoveryBlocked(current);
        return blocked.Success
                && blocked.Snapshot?.Record.Phase
                    == ProtectedTransactionPhase.RecoveryBlocked
            ? new(
                TransactionalUpdateExecutionOutcome
                    .RecoveryBlocked,
                errorCode,
                NamespaceMutationPossible: true)
            : Retryable(
                errorCode,
                current,
                blocked.Failure,
                namespaceMutationPossible: true);
    }

    private static bool ShouldBlock(
        UpdateFileSystemResult result) =>
        result.NamespaceChanged
        || result.Error is
            UpdateFileSystemError.UnsafeRoot
                or UpdateFileSystemError.UnsafePath
                or UpdateFileSystemError.UnexpectedTarget
                or UpdateFileSystemError.UnexpectedBackup
                or UpdateFileSystemError.UnexpectedTemporary
                or UpdateFileSystemError.BackupCollision
                or UpdateFileSystemError.TemporaryCollision
                or UpdateFileSystemError.RecoveryBlocked;

    private static int FindHighestTouched(
        IReadOnlyList<UpdateOperation> operations)
    {
        for (var index = operations.Count - 1;
             index >= 0;
             index--)
        {
            if (IsTouched(operations[index].State))
            {
                return index;
            }
        }

        return -1;
    }

    private static int FindPreviousTouched(
        IReadOnlyList<UpdateOperation> operations,
        int cursor)
    {
        for (var index = cursor - 1;
             index >= 0;
             index--)
        {
            if (IsTouched(operations[index].State))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool IsTouched(
        UpdateOperationState state) =>
        state is UpdateOperationState.WriteStarted
            or UpdateOperationState.WriteComplete;

    private void InvokeFault(
        TransactionalUpdateFaultPoint point,
        TransactionalUpdateSnapshot snapshot,
        long journalGeneration,
        int? operationOrdinal) =>
        _fault?.Invoke(
            new TransactionalUpdateFaultContext(
                point,
                snapshot.Record.Phase,
                journalGeneration,
                operationOrdinal));

    private static bool TryBuildInitialJournal(
        ProtectedTransactionRecord record,
        TransactionalUpdatePlanMaterial material,
        out UpdateOperationJournal journal)
    {
        journal = null!;
        if (!TryValidatePlanMaterial(
                record,
                material,
                out var candidateFiles,
                out var installedFiles)
            || record.Journal.Generation != 0
            || record.Journal.Sha256 is not null)
        {
            return false;
        }

        var installedByPath = installedFiles.ToDictionary(
            file => file.RelativePath,
            StringComparer.Ordinal);
        var operations = new List<UpdateOperation>(
            candidateFiles.Count + 1);
        foreach (var candidate in candidateFiles.OrderBy(
                     file => file.Path,
                     StringComparer.Ordinal))
        {
            installedByPath.TryGetValue(
                candidate.Path,
                out var installed);
            if (installed is not null
                && installed.Length == candidate.Length
                && string.Equals(
                    installed.Sha256,
                    candidate.Sha256,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var ordinal = operations.Count;
            operations.Add(
                installed is null
                    ? new UpdateOperation(
                        ordinal,
                        UpdateOperationKind.Create,
                        candidate.Path,
                        Existed: false,
                        OldLength: null,
                        OldSha256: null,
                        BackupRelativePath: null,
                        BackupSha256: null,
                        candidate.Length,
                        candidate.Sha256,
                        UpdateOperationState.Planned)
                    : new UpdateOperation(
                        ordinal,
                        UpdateOperationKind.Replace,
                        candidate.Path,
                        Existed: true,
                        installed.Length,
                        installed.Sha256,
                        BackupRelativePath: candidate.Path,
                        BackupSha256: installed.Sha256,
                        candidate.Length,
                        candidate.Sha256,
                        UpdateOperationState.Planned));
        }

        operations.Add(
            new UpdateOperation(
                operations.Count,
                UpdateOperationKind.ReplaceManifest,
                UpdateReleaseContract.ReleaseManifestPath,
                Existed: true,
                material.InstalledManifestLength,
                material.InstalledManifestSha256,
                BackupRelativePath:
                    UpdateReleaseContract.ReleaseManifestPath,
                BackupSha256:
                    material.InstalledManifestSha256,
                material.CandidateManifestLength,
                material.CandidateManifestSha256,
                UpdateOperationState.Planned));
        var candidateJournal = new UpdateOperationJournal(
            UpdateOperationJournalCodec.SchemaVersion,
            Generation: 1,
            record.TransactionId,
            UpdateJournalMode.Applying,
            RollbackCursor: -1,
            RollbackMutationStarted: false,
            operations.ToArray());
        if (!UpdateOperationJournalCodec.IsInitialPlan(
                candidateJournal))
        {
            return false;
        }

        journal = candidateJournal;
        return true;
    }

    private static bool TryValidatePlanMaterial(
        ProtectedTransactionRecord record,
        TransactionalUpdatePlanMaterial material,
        out IReadOnlyList<ReleasePayloadFile> candidateFiles,
        out IReadOnlyList<ProtectedManagedFileIdentity>
            installedFiles)
    {
        candidateFiles = [];
        installedFiles = [];
        if (material is null
            || material.InstalledManifestLength < 0
            || material.InstalledManifestLength
                > UpdatePackageLimits.Default.MaximumFileBytes
            || material.CandidateManifestLength < 0
            || material.CandidateManifestLength
                > UpdatePackageLimits.Default.MaximumFileBytes
            || !string.Equals(
                material.InstalledManifestSha256,
                record.InstalledRelease.CurrentManifestSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                material.CandidateManifestSha256,
                record.Candidate.NewManifestSha256,
                StringComparison.Ordinal)
            || !IsSha256(material.InstalledManifestSha256)
            || !IsSha256(material.CandidateManifestSha256)
            || string.Equals(
                material.InstalledManifestSha256,
                material.CandidateManifestSha256,
                StringComparison.Ordinal)
            || material.CandidateManifest.Files is null)
        {
            return false;
        }

        IReadOnlyList<string?> archivePaths;
        try
        {
            archivePaths = material.CandidateManifest.Files
                .Select(file => (string?)file.Path)
                .Append(
                    UpdateReleaseContract.ReleaseManifestPath)
                .ToArray();
        }
        catch (Exception exception) when (
            IsCollectionFailure(exception))
        {
            return false;
        }

        var validation = ReleaseManifestValidator.Validate(
            material.CandidateManifest,
            record.Version,
            record.InstalledRelease.CurrentVersion,
            record.InstalledRelease.StateSchemaVersion,
            archivePaths);
        if (!validation.IsValid
            || validation.Manifest?.Files is not { } validatedFiles
            || !TrySnapshotInstalled(
                record.InstalledRelease.ManagedFiles,
                out var installedSnapshot))
        {
            return false;
        }

        candidateFiles = validatedFiles.ToArray();
        installedFiles = installedSnapshot;
        return true;
    }

    private static bool TrySnapshotInstalled(
        IReadOnlyList<ProtectedManagedFileIdentity>? files,
        out IReadOnlyList<ProtectedManagedFileIdentity> snapshot)
    {
        snapshot = [];
        if (files is null
            || files.Count is < 1
                or > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return false;
        }

        var copy = new ProtectedManagedFileIdentity[files.Count];
        var paths = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase);
        string? previous = null;
        try
        {
            for (var index = 0; index < copy.Length; index++)
            {
                var file = files[index];
                var path = WindowsReleasePathPolicy.Validate(
                    file?.RelativePath);
                if (file is null
                    || !path.Success
                    || !string.Equals(
                        path.CanonicalKey,
                        file.RelativePath,
                        StringComparison.Ordinal)
                    || ReleaseManagedPathPolicy
                        .IsProtectedPayloadPath(
                            file.RelativePath)
                    || !paths.Add(file.RelativePath)
                    || previous is not null
                        && StringComparer.Ordinal.Compare(
                            previous,
                            file.RelativePath) >= 0
                    || file.Length < 0
                    || file.Length
                        > UpdatePackageLimits.Default
                            .MaximumFileBytes
                    || !IsSha256(file.Sha256))
                {
                    return false;
                }

                copy[index] = file with { };
                previous = file.RelativePath;
            }

            if (files.Count != copy.Length)
            {
                return false;
            }
        }
        catch (Exception exception) when (
            IsCollectionFailure(exception))
        {
            return false;
        }

        snapshot = copy;
        return true;
    }

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

    private static TransactionalUpdateGatewayReadResult
        FailedRead(
            TransactionalUpdateGatewayFailure failure =
                TransactionalUpdateGatewayFailure.Retryable) =>
        new(Snapshot: null, failure);

    private static TransactionalUpdateExecutionResult Retryable(
        string errorCode,
        TransactionalUpdateSnapshot? current = null,
        TransactionalUpdateGatewayFailure failure =
            TransactionalUpdateGatewayFailure.Retryable,
        bool namespaceMutationPossible = false) =>
        new(
            TransactionalUpdateExecutionOutcome.RetryableFailure,
            errorCode,
            NamespaceMutationPossible:
                namespaceMutationPossible
                || failure
                    == TransactionalUpdateGatewayFailure.Ambiguous
                || MutationMayHaveStarted(current));

    private static bool MutationMayHaveStarted(
        TransactionalUpdateSnapshot? current) =>
        current is not null
        && (current.Record.Phase is
                ProtectedTransactionPhase.BackingUp
                    or ProtectedTransactionPhase.Applying
                    or ProtectedTransactionPhase
                        .AppliedAwaitingHealth
                    or ProtectedTransactionPhase.RollingBack
                    or ProtectedTransactionPhase.RecoveryBlocked
            || current.JournalObservation
                == TransactionalUpdateJournalObservation.Unsafe
            || current.Journal?.Mode
                == UpdateJournalMode.RollingBack
            || current.Journal?.Operations.Any(
                operation => operation.State is
                    UpdateOperationState.BackupStarted
                        or UpdateOperationState.BackupComplete
                        or UpdateOperationState.WriteStarted
                        or UpdateOperationState.WriteComplete)
                == true);
}
