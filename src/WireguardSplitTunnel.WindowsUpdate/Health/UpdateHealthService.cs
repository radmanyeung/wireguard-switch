using System.Text;
using System.Text.Json;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Health;

public enum UpdateHealthMarkerState
{
    CandidateRunning,
    Healthy
}

public sealed record UpdateHealthMarker(
    int SchemaVersion,
    ProtectedTransactionId TransactionId,
    SemanticVersion Version,
    ProcessIdentity CandidateProcess,
    UpdateHealthMarkerState State);

public enum UpdateHealthError
{
    None,
    InvalidAuthority,
    InvalidRequest,
    NoActiveTransaction,
    TransactionMismatch,
    WrongPhase,
    VersionMismatch,
    ProcessUnavailable,
    CandidateMismatch,
    ExecutableVerificationFailed,
    MarkerMissing,
    MarkerConflict,
    CorruptMarker,
    PersistenceFailed
}

public sealed record UpdateHealthResult(
    bool Success,
    UpdateHealthMarker? Marker,
    UpdateHealthError Error)
{
    internal static UpdateHealthResult Completed(
        UpdateHealthMarker marker) =>
        new(true, marker, UpdateHealthError.None);

    internal static UpdateHealthResult Failed(
        UpdateHealthError error) =>
        new(false, null, error);
}

internal sealed record UpdateHealthMarkerReadResult(
    bool Success,
    UpdateHealthMarker? Marker,
    UpdateHealthError Error)
{
    internal static UpdateHealthMarkerReadResult Found(
        UpdateHealthMarker marker) =>
        new(true, marker, UpdateHealthError.None);

    internal static UpdateHealthMarkerReadResult Missing() =>
        new(false, null, UpdateHealthError.MarkerMissing);

    internal static UpdateHealthMarkerReadResult Failed(
        UpdateHealthError error) =>
        new(false, null, error);
}

internal sealed record UpdateHealthTransactionReadResult(
    bool Success,
    ProtectedTransactionRecord? Record,
    UpdateHealthError Error)
{
    internal static UpdateHealthTransactionReadResult Found(
        ProtectedTransactionRecord record) =>
        new(true, record, UpdateHealthError.None);

    internal static UpdateHealthTransactionReadResult Failed(
        UpdateHealthError error) =>
        new(false, null, error);
}

internal interface IUpdateHealthBoundary
{
    UpdateHealthTransactionReadResult ReadActiveTransaction(
        ProtectedUpdateMutexContext authority);

    bool VerifyCandidateExecutable(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord record,
        ProcessIdentity identity);

    UpdateHealthMarkerReadResult ReadMarker(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId);

    UpdateHealthMarkerReadResult CreateMarker(
        ProtectedUpdateMutexContext authority,
        UpdateHealthMarker marker);

    UpdateHealthMarkerReadResult ReplaceMarker(
        ProtectedUpdateMutexContext authority,
        UpdateHealthMarker expected,
        UpdateHealthMarker replacement);
}

internal interface IUpdateHealthTransactionStore
{
    ProtectedActiveTransactionReadResult ReadActive(
        ProtectedUpdateMutexContext authority);

    ProtectedTransactionReadResult ReadTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId);

    ProtectedJournalRecoveryReadResult ReadJournalForRecovery(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId);

    ProtectedTransactionWriteResult CompareExchangeTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedJournalRecoveryReadResult expected,
        ProtectedTransactionRecord replacement);
}

internal interface IUpdateHealthLayoutProvider
{
    bool TryGetValidatedLayout(
        ProtectedTransactionId transactionId,
        out ProtectedTransactionLayout? layout);
}

internal sealed record UpdateHealthProcessCaptureResult(
    ProcessIdentity? Identity,
    IDisposable? Lease,
    UpdateHealthError Error) : IDisposable
{
    public bool Success => Identity is not null && Lease is not null;

    public void Dispose() => Lease?.Dispose();

    internal static UpdateHealthProcessCaptureResult Captured(
        ProcessIdentity identity,
        IDisposable lease) =>
        new(identity, lease, UpdateHealthError.None);

    internal static UpdateHealthProcessCaptureResult Failed(
        UpdateHealthError error) =>
        new(null, null, error);
}

internal interface IUpdateHealthProcessCapture
{
    UpdateHealthProcessCaptureResult Capture(int processId);

    UpdateHealthProcessCaptureResult CaptureCurrent();
}

public sealed class UpdateHealthService
{
    public const int MarkerSchemaVersion = 1;

    private readonly IUpdateHealthBoundary _boundary;
    private readonly IUpdateHealthProcessCapture _processes;

    public UpdateHealthService(
        ProtectedTransactionPaths paths,
        ProtectedTransactionStore store)
        : this(
            new ProtectedUpdateHealthBoundary(
                paths,
                store,
                new WindowsProtectedTransactionFileSystem(),
                new ProtectedDirectoryAcl()),
            new WindowsUpdateHealthProcessCapture(
                new WindowsProcessIdentityService()))
    {
    }

    internal UpdateHealthService(
        IUpdateHealthBoundary boundary,
        IUpdateHealthProcessCapture processes)
    {
        _boundary = boundary
            ?? throw new ArgumentNullException(nameof(boundary));
        _processes = processes
            ?? throw new ArgumentNullException(nameof(processes));
    }

    public UpdateHealthResult RecordCandidate(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId,
        SemanticVersion? version,
        int processId) =>
        Mutate(
            authority,
            transactionId,
            version,
            () => _processes.Capture(processId),
            processId,
            markHealthy: false);

    public UpdateHealthResult ReportHealthy(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId,
        SemanticVersion? version) =>
        Mutate(
            authority,
            transactionId,
            version,
            _processes.CaptureCurrent,
            expectedProcessId: null,
            markHealthy: true);

    internal UpdateHealthResult Read(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId,
        SemanticVersion? version)
    {
        if (authority is null
            || !authority.TryAcquireLease(out var authorityLease))
        {
            return UpdateHealthResult.Failed(
                UpdateHealthError.InvalidAuthority);
        }

        using (authorityLease)
        {
            if (!TryValidateRequest(transactionId, version))
            {
                return UpdateHealthResult.Failed(
                    UpdateHealthError.InvalidRequest);
            }

            var requestedVersion = version.GetValueOrDefault();
            var transaction = ValidateActive(
                authority,
                transactionId,
                requestedVersion);
            if (!transaction.Success)
            {
                return UpdateHealthResult.Failed(transaction.Error);
            }

            var marker = _boundary.ReadMarker(
                authority,
                transactionId);
            if (!marker.Success
                || marker.Marker is null
                || !MatchesTransaction(
                    marker.Marker,
                    transactionId,
                    requestedVersion))
            {
                return UpdateHealthResult.Failed(
                    marker.Success
                        ? UpdateHealthError.MarkerConflict
                        : marker.Error);
            }

            var after = ValidateActive(
                authority,
                transactionId,
                requestedVersion);
            return after.Success
                ? UpdateHealthResult.Completed(marker.Marker)
                : UpdateHealthResult.Failed(after.Error);
        }
    }

    private UpdateHealthResult Mutate(
        ProtectedUpdateMutexContext? authority,
        ProtectedTransactionId transactionId,
        SemanticVersion? version,
        Func<UpdateHealthProcessCaptureResult> capture,
        int? expectedProcessId,
        bool markHealthy)
    {
        if (authority is null
            || !authority.TryAcquireLease(out var authorityLease))
        {
            return UpdateHealthResult.Failed(
                UpdateHealthError.InvalidAuthority);
        }

        using (authorityLease)
        {
            if (!TryValidateRequest(transactionId, version)
                || expectedProcessId is <= 0)
            {
                return UpdateHealthResult.Failed(
                    UpdateHealthError.InvalidRequest);
            }

            var requestedVersion = version.GetValueOrDefault();
            var transaction = ValidateActive(
                authority,
                transactionId,
                requestedVersion);
            if (!transaction.Success || transaction.Record is null)
            {
                return UpdateHealthResult.Failed(transaction.Error);
            }

            using var process = capture();
            if (!process.Success || process.Identity is null)
            {
                return UpdateHealthResult.Failed(
                    process.Error == UpdateHealthError.None
                        ? UpdateHealthError.ProcessUnavailable
                        : process.Error);
            }

            if (expectedProcessId.HasValue
                && process.Identity.ProcessId
                    != expectedProcessId.Value)
            {
                return UpdateHealthResult.Failed(
                    UpdateHealthError.CandidateMismatch);
            }

            if (!_boundary.VerifyCandidateExecutable(
                    authority,
                    transaction.Record,
                    process.Identity))
            {
                return UpdateHealthResult.Failed(
                    UpdateHealthError.ExecutableVerificationFailed);
            }

            var current = _boundary.ReadMarker(
                authority,
                transactionId);
            UpdateHealthMarkerReadResult persisted;
            if (markHealthy)
            {
                persisted = MarkHealthy(
                    authority,
                    transactionId,
                    requestedVersion,
                    process.Identity,
                    current);
            }
            else
            {
                persisted = RecordCandidate(
                    authority,
                    transactionId,
                    requestedVersion,
                    process.Identity,
                    current);
            }

            if (!persisted.Success || persisted.Marker is null)
            {
                return UpdateHealthResult.Failed(persisted.Error);
            }

            var after = ValidateActive(
                authority,
                transactionId,
                requestedVersion);
            return after.Success
                ? UpdateHealthResult.Completed(persisted.Marker)
                : UpdateHealthResult.Failed(after.Error);
        }
    }

    private UpdateHealthMarkerReadResult RecordCandidate(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId,
        SemanticVersion version,
        ProcessIdentity identity,
        UpdateHealthMarkerReadResult current)
    {
        var proposed = new UpdateHealthMarker(
            MarkerSchemaVersion,
            transactionId,
            version,
            identity,
            UpdateHealthMarkerState.CandidateRunning);
        if (!current.Success)
        {
            return current.Error == UpdateHealthError.MarkerMissing
                ? _boundary.CreateMarker(authority, proposed)
                : current;
        }

        if (current.Marker is null
            || !MatchesMarkerIdentity(current.Marker, proposed))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.MarkerConflict);
        }

        return current;
    }

    private UpdateHealthMarkerReadResult MarkHealthy(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId,
        SemanticVersion version,
        ProcessIdentity identity,
        UpdateHealthMarkerReadResult current)
    {
        if (!current.Success || current.Marker is null)
        {
            return UpdateHealthMarkerReadResult.Failed(
                current.Error == UpdateHealthError.None
                    ? UpdateHealthError.MarkerMissing
                    : current.Error);
        }

        var expected = current.Marker;
        if (!MatchesTransaction(expected, transactionId, version)
            || !SameIdentity(expected.CandidateProcess, identity))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.CandidateMismatch);
        }

        if (expected.State == UpdateHealthMarkerState.Healthy)
        {
            return current;
        }

        if (expected.State
            != UpdateHealthMarkerState.CandidateRunning)
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.CorruptMarker);
        }

        return _boundary.ReplaceMarker(
            authority,
            expected,
            expected with
            {
                State = UpdateHealthMarkerState.Healthy
            });
    }

    private UpdateHealthTransactionReadResult ValidateActive(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId,
        SemanticVersion version)
    {
        var transaction = _boundary.ReadActiveTransaction(
            authority);
        if (!transaction.Success || transaction.Record is null)
        {
            return transaction;
        }

        if (transaction.Record.TransactionId != transactionId)
        {
            return UpdateHealthTransactionReadResult.Failed(
                UpdateHealthError.TransactionMismatch);
        }

        if (transaction.Record.Phase
            != ProtectedTransactionPhase.AppliedAwaitingHealth)
        {
            return UpdateHealthTransactionReadResult.Failed(
                UpdateHealthError.WrongPhase);
        }

        return transaction.Record.Version == version
            ? transaction
            : UpdateHealthTransactionReadResult.Failed(
                UpdateHealthError.VersionMismatch);
    }

    private static bool TryValidateRequest(
        ProtectedTransactionId transactionId,
        SemanticVersion? version) =>
        transactionId.IsValid
        && version is { } value
        && SemanticVersion.TryParseNormalized(
            value.ToString(),
            out var parsed)
        && parsed == value;

    private static bool MatchesMarkerIdentity(
        UpdateHealthMarker current,
        UpdateHealthMarker proposed) =>
        MatchesTransaction(
            current,
            proposed.TransactionId,
            proposed.Version)
        && SameIdentity(
            current.CandidateProcess,
            proposed.CandidateProcess)
        && current.SchemaVersion == MarkerSchemaVersion;

    private static bool MatchesTransaction(
        UpdateHealthMarker marker,
        ProtectedTransactionId transactionId,
        SemanticVersion version) =>
        marker.SchemaVersion == MarkerSchemaVersion
        && marker.TransactionId == transactionId
        && marker.Version == version;

    private static bool SameIdentity(
        ProcessIdentity left,
        ProcessIdentity right) =>
        left.ProcessId == right.ProcessId
        && left.CreationTimeFileTimeUtc
            == right.CreationTimeFileTimeUtc
        && string.Equals(
            left.ImagePath,
            right.ImagePath,
            StringComparison.OrdinalIgnoreCase);
}

internal sealed class WindowsUpdateHealthProcessCapture
    : IUpdateHealthProcessCapture
{
    private readonly WindowsProcessIdentityService _processes;

    internal WindowsUpdateHealthProcessCapture(
        WindowsProcessIdentityService processes)
    {
        _processes = processes
            ?? throw new ArgumentNullException(nameof(processes));
    }

    public UpdateHealthProcessCaptureResult Capture(
        int processId) =>
        Convert(_processes.Capture(processId));

    public UpdateHealthProcessCaptureResult CaptureCurrent() =>
        Convert(_processes.CaptureCurrent());

    private static UpdateHealthProcessCaptureResult Convert(
        ProcessIdentityOpenResult result) =>
        result.Success
            && result.Identity is not null
            && result.Lease is not null
                ? UpdateHealthProcessCaptureResult.Captured(
                    result.Identity,
                    result.Lease)
                : UpdateHealthProcessCaptureResult.Failed(
                    UpdateHealthError.ProcessUnavailable);
}

internal sealed class ProtectedUpdateHealthTransactionStore
    : IUpdateHealthTransactionStore
{
    private readonly ProtectedTransactionStore _store;

    internal ProtectedUpdateHealthTransactionStore(
        ProtectedTransactionStore store)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
    }

    public ProtectedActiveTransactionReadResult ReadActive(
        ProtectedUpdateMutexContext authority) =>
        _store.ReadActive(authority);

    public ProtectedTransactionReadResult ReadTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId) =>
        _store.ReadTransaction(authority, transactionId);

    public ProtectedJournalRecoveryReadResult ReadJournalForRecovery(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId) =>
        _store.ReadJournalForRecovery(authority, transactionId);

    public ProtectedTransactionWriteResult CompareExchangeTransaction(
        ProtectedUpdateMutexContext authority,
        ProtectedJournalRecoveryReadResult expected,
        ProtectedTransactionRecord replacement) =>
        _store.CompareExchangeTransaction(
            authority,
            expected,
            replacement);
}

internal sealed class ProtectedUpdateHealthLayoutProvider
    : IUpdateHealthLayoutProvider
{
    private readonly ProtectedTransactionPaths _paths;
    private readonly ProtectedDirectoryAcl _acl;

    internal ProtectedUpdateHealthLayoutProvider(
        ProtectedTransactionPaths paths,
        ProtectedDirectoryAcl acl)
    {
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
    }

    public bool TryGetValidatedLayout(
        ProtectedTransactionId transactionId,
        out ProtectedTransactionLayout? layout)
    {
        layout = null;
        var result = _paths.GetLayout(transactionId);
        if (!result.Success
            || result.Layout is null
            || !_acl.ValidateProtectedDirectory(
                    result.Layout.TransactionRoot)
                .Success)
        {
            return false;
        }

        layout = result.Layout;
        return true;
    }
}

internal sealed class ProtectedUpdateHealthBoundary
    : IUpdateHealthBoundary
{
    private const long MaximumMarkerBytes = 64 * 1024;
    private const int MaximumJsonDepth = 16;

    private readonly IUpdateHealthTransactionStore _store;
    private readonly IProtectedTransactionFileSystem _fileSystem;
    private readonly IUpdateHealthLayoutProvider _layouts;

    internal ProtectedUpdateHealthBoundary(
        ProtectedTransactionPaths paths,
        ProtectedTransactionStore store,
        IProtectedTransactionFileSystem fileSystem,
        ProtectedDirectoryAcl acl)
        : this(
            new ProtectedUpdateHealthTransactionStore(store),
            fileSystem,
            new ProtectedUpdateHealthLayoutProvider(paths, acl))
    {
    }

    internal ProtectedUpdateHealthBoundary(
        IUpdateHealthTransactionStore store,
        IProtectedTransactionFileSystem fileSystem,
        IUpdateHealthLayoutProvider layouts)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _fileSystem = fileSystem
            ?? throw new ArgumentNullException(nameof(fileSystem));
        _layouts = layouts
            ?? throw new ArgumentNullException(nameof(layouts));
    }

    public UpdateHealthTransactionReadResult ReadActiveTransaction(
        ProtectedUpdateMutexContext authority)
    {
        using var mutationLease =
            authority.AcquireMutationLease();
        return ReadActiveTransactionCore(authority);
    }

    private UpdateHealthTransactionReadResult
        ReadActiveTransactionCore(
            ProtectedUpdateMutexContext authority)
    {
        var active = _store.ReadActive(authority);
        if (!active.Success)
        {
            return UpdateHealthTransactionReadResult.Failed(
                MapStoreError(active.Error));
        }

        if (active.TransactionId is not { } transactionId)
        {
            return UpdateHealthTransactionReadResult.Failed(
                UpdateHealthError.NoActiveTransaction);
        }

        var transaction = _store.ReadTransaction(
            authority,
            transactionId);
        if (!transaction.Success || transaction.Record is null)
        {
            return UpdateHealthTransactionReadResult.Failed(
                MapStoreError(transaction.Error));
        }

        var activeAfter = _store.ReadActive(authority);
        return activeAfter.Success
                && activeAfter.TransactionId == transactionId
            ? UpdateHealthTransactionReadResult.Found(
                transaction.Record)
            : UpdateHealthTransactionReadResult.Failed(
                activeAfter.Success
                    ? UpdateHealthError.TransactionMismatch
                    : MapStoreError(activeAfter.Error));
    }

    public bool VerifyCandidateExecutable(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionRecord record,
        ProcessIdentity identity)
    {
        if (!TryGetExpectedApplicationPath(
                record,
                out var expectedPath)
            || !string.Equals(
                expectedPath,
                identity.ImagePath,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var observed = _store.ReadJournalForRecovery(
            authority,
            record.TransactionId);
        return observed.Success
            && observed.Record is not null
            && observed.Observation
                == ProtectedJournalObservation.MatchesBoundHash
            && observed.Record.Phase
                == ProtectedTransactionPhase.AppliedAwaitingHealth
            && observed.Record.TransactionId
                == record.TransactionId
            && observed.Record.Version == record.Version
            && _store.CompareExchangeTransaction(
                    authority,
                    observed,
                    observed.Record)
                .Success;
    }

    public UpdateHealthMarkerReadResult ReadMarker(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionId transactionId)
    {
        if (!TryGetValidatedLayout(
                transactionId,
                out var layout))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.PersistenceFailed);
        }

        var state = _fileSystem.InspectProtectedFile(
            layout!.HealthPath);
        if (state == ProtectedTransactionFileState.Missing)
        {
            return UpdateHealthMarkerReadResult.Missing();
        }

        if (state != ProtectedTransactionFileState.Protected)
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.CorruptMarker);
        }

        var bytes = _fileSystem.ReadProtectedFile(
            layout.HealthPath,
            MaximumMarkerBytes);
        if (bytes is null
            || _fileSystem.InspectProtectedFile(layout.HealthPath)
                != ProtectedTransactionFileState.Protected
            || !TryParseCanonical(bytes, out var marker)
            || marker is null
            || marker.TransactionId != transactionId
            || !TryGetValidatedLayout(
                transactionId,
                out var after)
            || !string.Equals(
                after!.HealthPath,
                layout.HealthPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.CorruptMarker);
        }

        return UpdateHealthMarkerReadResult.Found(marker);
    }

    public UpdateHealthMarkerReadResult CreateMarker(
        ProtectedUpdateMutexContext authority,
        UpdateHealthMarker marker)
    {
        if (!TryGetValidatedLayout(
                marker.TransactionId,
                out var layout)
            || !TrySerialize(marker, out var bytes))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.PersistenceFailed);
        }

        var committed = _fileSystem.AtomicCreate(
            layout!.HealthPath,
            bytes);
        return CompleteWrite(
            authority,
            marker,
            committed,
            bytes);
    }

    public UpdateHealthMarkerReadResult ReplaceMarker(
        ProtectedUpdateMutexContext authority,
        UpdateHealthMarker expected,
        UpdateHealthMarker replacement)
    {
        if (expected.TransactionId != replacement.TransactionId
            || !TryGetValidatedLayout(
                replacement.TransactionId,
                out var layout)
            || !TrySerialize(expected, out var expectedBytes)
            || !TrySerialize(replacement, out var replacementBytes))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.PersistenceFailed);
        }

        var committed = _fileSystem.AtomicCompareExchange(
            layout!.HealthPath,
            expectedBytes,
            replacementBytes);
        return CompleteWrite(
            authority,
            replacement,
            committed,
            replacementBytes);
    }

    private UpdateHealthMarkerReadResult CompleteWrite(
        ProtectedUpdateMutexContext authority,
        UpdateHealthMarker expected,
        ProtectedAtomicCommitResult committed,
        byte[] expectedBytes)
    {
        if (committed is not
            (ProtectedAtomicCommitResult.Committed
                or ProtectedAtomicCommitResult.Conflict))
        {
            return UpdateHealthMarkerReadResult.Failed(
                UpdateHealthError.PersistenceFailed);
        }

        var read = ReadMarker(
            authority,
            expected.TransactionId);
        if (read.Success
            && read.Marker == expected
            && TrySerialize(read.Marker, out var actualBytes)
            && actualBytes.AsSpan().SequenceEqual(expectedBytes))
        {
            return read;
        }

        return UpdateHealthMarkerReadResult.Failed(
            committed == ProtectedAtomicCommitResult.Conflict
                ? UpdateHealthError.MarkerConflict
                : UpdateHealthError.PersistenceFailed);
    }

    private bool TryGetValidatedLayout(
        ProtectedTransactionId transactionId,
        out ProtectedTransactionLayout? layout) =>
        _layouts.TryGetValidatedLayout(
            transactionId,
            out layout);

    private static bool TryGetExpectedApplicationPath(
        ProtectedTransactionRecord record,
        out string path)
    {
        path = string.Empty;
        try
        {
            var relative = WindowsReleasePathPolicy.Validate(
                record.InstalledRelease.ApplicationRelativePath);
            if (!relative.Success
                || relative.CanonicalKey is null)
            {
                return false;
            }

            var root = Path.GetFullPath(
                record.InstalledRelease.InstallRoot);
            var candidate = Path.GetFullPath(
                Path.Combine(
                    root,
                    relative.CanonicalKey.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            if (!candidate.StartsWith(
                    root.TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            path = candidate;
            return true;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or NotSupportedException)
        {
            return false;
        }
    }

    private static UpdateHealthError MapStoreError(
        ProtectedTransactionStoreError error) =>
        UpdateHealthError.PersistenceFailed;

    internal static bool TrySerialize(
        UpdateHealthMarker marker,
        out byte[] bytes)
    {
        bytes = [];
        if (!IsValidMarker(marker))
        {
            return false;
        }

        try
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(
                stream,
                new JsonWriterOptions
                {
                    Indented = false,
                    SkipValidation = false
                }))
            {
                writer.WriteStartObject();
                writer.WriteNumber(
                    "schemaVersion",
                    marker.SchemaVersion);
                writer.WriteString(
                    "transactionId",
                    marker.TransactionId.DirectoryName);
                writer.WriteString(
                    "version",
                    marker.Version.ToString());
                writer.WriteStartObject("candidateProcess");
                writer.WriteNumber(
                    "processId",
                    marker.CandidateProcess.ProcessId);
                writer.WriteNumber(
                    "creationTimeFileTimeUtc",
                    marker.CandidateProcess
                        .CreationTimeFileTimeUtc);
                writer.WriteString(
                    "imagePath",
                    marker.CandidateProcess.ImagePath);
                writer.WriteEndObject();
                writer.WriteString("state", marker.State.ToString());
                writer.WriteEndObject();
                writer.Flush();
            }

            bytes = stream.ToArray();
            return bytes.LongLength is > 0 and <= MaximumMarkerBytes;
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or InvalidOperationException
                or IOException
                or NotSupportedException)
        {
            bytes = [];
            return false;
        }
    }

    internal static bool TryParseCanonical(
        byte[] bytes,
        out UpdateHealthMarker? marker)
    {
        marker = null;
        if (bytes.LongLength is <= 0 or > MaximumMarkerBytes)
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
                    MaxDepth = MaximumJsonDepth
                });
            var root = document.RootElement;
            if (!HasExactProperties(
                    root,
                    "schemaVersion",
                    "transactionId",
                    "version",
                    "candidateProcess",
                    "state")
                || root.GetProperty("schemaVersion")
                        .ValueKind != JsonValueKind.Number
                || !root.GetProperty("schemaVersion")
                    .TryGetInt32(out var schemaVersion)
                || schemaVersion
                    != UpdateHealthService.MarkerSchemaVersion
                || root.GetProperty("transactionId")
                        .ValueKind != JsonValueKind.String
                || !TryParseTransactionId(
                    root.GetProperty("transactionId").GetString(),
                    out var transactionId)
                || root.GetProperty("version")
                        .ValueKind != JsonValueKind.String
                || !SemanticVersion.TryParseNormalized(
                    root.GetProperty("version").GetString(),
                    out var version)
                || !string.Equals(
                    root.GetProperty("version").GetString(),
                    version.ToString(),
                    StringComparison.Ordinal)
                || !TryParseProcess(
                    root.GetProperty("candidateProcess"),
                    out var process)
                || root.GetProperty("state")
                        .ValueKind != JsonValueKind.String
                || !Enum.TryParse<UpdateHealthMarkerState>(
                    root.GetProperty("state").GetString(),
                    ignoreCase: false,
                    out var state)
                || !Enum.IsDefined(state))
            {
                return false;
            }

            var parsed = new UpdateHealthMarker(
                schemaVersion,
                transactionId,
                version,
                process!,
                state);
            if (!TrySerialize(parsed, out var canonical)
                || !bytes.AsSpan().SequenceEqual(canonical))
            {
                return false;
            }

            marker = parsed;
            return true;
        }
        catch (Exception exception) when (
            exception is JsonException
                or InvalidOperationException
                or FormatException)
        {
            return false;
        }
    }

    private static bool TryParseTransactionId(
        string? value,
        out ProtectedTransactionId transactionId)
    {
        transactionId = default;
        if (value is null
            || value.Length != 32
            || !Guid.TryParseExact(value, "N", out var guid))
        {
            return false;
        }

        transactionId = new ProtectedTransactionId(guid);
        return transactionId.IsValid
            && string.Equals(
                value,
                transactionId.DirectoryName,
                StringComparison.Ordinal);
    }

    private static bool TryParseProcess(
        JsonElement element,
        out ProcessIdentity? process)
    {
        process = null;
        if (!HasExactProperties(
                element,
                "processId",
                "creationTimeFileTimeUtc",
                "imagePath")
            || element.GetProperty("processId")
                    .ValueKind != JsonValueKind.Number
            || !element.GetProperty("processId")
                .TryGetInt32(out var processId)
            || element.GetProperty("creationTimeFileTimeUtc")
                    .ValueKind != JsonValueKind.Number
            || !element.GetProperty("creationTimeFileTimeUtc")
                .TryGetInt64(out var creationTime)
            || element.GetProperty("imagePath")
                    .ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var parsed = new ProcessIdentity(
            processId,
            creationTime,
            element.GetProperty("imagePath").GetString()!);
        if (!IsValidProcess(parsed))
        {
            return false;
        }

        process = parsed;
        return true;
    }

    private static bool HasExactProperties(
        JsonElement element,
        params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                return false;
            }
        }

        return names.Count == expected.Length
            && expected.All(names.Contains);
    }

    private static bool IsValidMarker(UpdateHealthMarker marker) =>
        marker is not null
        && marker.SchemaVersion
            == UpdateHealthService.MarkerSchemaVersion
        && marker.TransactionId.IsValid
        && SemanticVersion.TryParseNormalized(
            marker.Version.ToString(),
            out var parsedVersion)
        && parsedVersion == marker.Version
        && Enum.IsDefined(marker.State)
        && IsValidProcess(marker.CandidateProcess);

    private static bool IsValidProcess(ProcessIdentity process)
    {
        if (process is null
            || process.ProcessId <= 0
            || process.CreationTimeFileTimeUtc <= 0
            || !WindowsProcessIdentityService
                .TryCanonicalizeImagePath(
                    process.ImagePath,
                    out var canonical)
            || canonical.StartsWith(
                @"\\",
                StringComparison.Ordinal)
            || !string.Equals(
                canonical,
                process.ImagePath,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }
}
