using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Launcher;

public enum LauncherRecoveryAction
{
    ContinueNormalLaunch,
    CandidateLaunchHandled,
    ExistingCandidateStillRunning,
    OldVersionLaunchHandled,
    RecoveryBlocked
}

internal enum LauncherRecoveredKind
{
    ContinueCurrent,
    AwaitingHealth,
    Committed,
    RolledBack,
    ExistingAuthorizedProcess,
    Blocked
}

internal sealed record LauncherRecoveredTransaction(
    LauncherRecoveredKind Kind,
    ProtectedTransactionRecord? Record)
{
    internal static LauncherRecoveredTransaction ContinueCurrent() =>
        new(LauncherRecoveredKind.ContinueCurrent, Record: null);

    internal static LauncherRecoveredTransaction AwaitingHealth(
        ProtectedTransactionRecord record) =>
        new(LauncherRecoveredKind.AwaitingHealth, record);

    internal static LauncherRecoveredTransaction Committed(
        ProtectedTransactionRecord record) =>
        new(LauncherRecoveredKind.Committed, record);

    internal static LauncherRecoveredTransaction RolledBack(
        ProtectedTransactionRecord record) =>
        new(LauncherRecoveredKind.RolledBack, record);

    internal static LauncherRecoveredTransaction
        ExistingAuthorizedProcess(
            ProtectedTransactionRecord record) =>
        new(
            LauncherRecoveredKind.ExistingAuthorizedProcess,
            record);

    internal static LauncherRecoveredTransaction Blocked() =>
        new(LauncherRecoveredKind.Blocked, Record: null);
}

internal enum LauncherHealthKind
{
    Missing,
    CandidateRunning,
    Healthy,
    Invalid
}

internal sealed record LauncherHealthObservation(
    LauncherHealthKind Kind,
    UpdateHealthMarker? Marker)
{
    internal static LauncherHealthObservation Missing { get; } =
        new(LauncherHealthKind.Missing, Marker: null);

    internal static LauncherHealthObservation Invalid { get; } =
        new(LauncherHealthKind.Invalid, Marker: null);

    internal static LauncherHealthObservation CandidateRunning(
        UpdateHealthMarker marker) =>
        new(LauncherHealthKind.CandidateRunning, marker);

    internal static LauncherHealthObservation Healthy(
        UpdateHealthMarker marker) =>
        new(LauncherHealthKind.Healthy, marker);
}

internal enum LauncherProcessObservation
{
    Running,
    Exited,
    PidReused,
    Ambiguous
}

internal enum LauncherProcessStartStatus
{
    Created,
    CleanFailure,
    AmbiguousFailure
}

internal interface ILauncherFailSafeProcess : IDisposable
{
    int ProcessId { get; }
}

internal sealed record LauncherProcessStartResult(
    LauncherProcessStartStatus Status,
    ILauncherFailSafeProcess? Process)
{
    internal static LauncherProcessStartResult Created(
        ILauncherFailSafeProcess process) =>
        new(LauncherProcessStartStatus.Created, process);

    internal static LauncherProcessStartResult CleanFailure() =>
        new(
            LauncherProcessStartStatus.CleanFailure,
            Process: null);

    internal static LauncherProcessStartResult AmbiguousFailure() =>
        new(
            LauncherProcessStartStatus.AmbiguousFailure,
            Process: null);
}

internal enum LauncherCandidateRecordOutcome
{
    Recorded,
    CleanNotRecorded,
    Ambiguous
}

internal enum LauncherResumeOutcome
{
    Started,
    NeverRanAndDead,
    Ambiguous
}

internal sealed record LauncherTerminalResult(
    bool Success,
    ProtectedTransactionRecord? Record)
{
    internal static LauncherTerminalResult Completed(
        ProtectedTransactionRecord record) =>
        new(true, record);

    internal static LauncherTerminalResult Failed() =>
        new(false, Record: null);
}

internal interface ILauncherRecoveryBoundary
{
    LauncherRecoveredTransaction Recover();

    LauncherHealthObservation ReadHealth(
        ProtectedTransactionRecord record);

    LauncherProcessObservation ObserveProcess(
        ProcessIdentity identity);

    bool RevalidateCandidate(
        ProtectedTransactionRecord record);

    LauncherProcessStartResult StartCandidate(
        ProtectedTransactionRecord record,
        IReadOnlyList<string> arguments);

    LauncherCandidateRecordOutcome RecordCandidate(
        ProtectedTransactionRecord record,
        int processId);

    LauncherResumeOutcome ResumeAndRelease(
        ILauncherFailSafeProcess process);

    bool AbortBeforeResume(
        ILauncherFailSafeProcess process);

    LauncherTerminalResult Commit(
        ProtectedTransactionRecord record);

    LauncherTerminalResult Rollback(
        ProtectedTransactionRecord record);

    LauncherProcessStartResult StartOld(
        ProtectedTransactionRecord terminalRecord);

    bool Deactivate(
        ProtectedTransactionRecord terminalRecord);

    bool Cleanup(
        ProtectedTransactionRecord terminalRecord);

    bool EnterRecoveryBlocked(
        ProtectedTransactionRecord record);
}

public sealed class LauncherRecoveryService
{
    private readonly ILauncherRecoveryBoundary _boundary;

    internal LauncherRecoveryService(
        ILauncherRecoveryBoundary boundary)
    {
        _boundary = boundary
            ?? throw new ArgumentNullException(nameof(boundary));
    }

    internal LauncherRecoveryService(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionStore store,
        ProtectedTransactionPaths paths,
        TransactionRecoveryService recovery,
        UpdateHealthService health,
        WindowsProcessIdentityService processes)
        : this(
            new ProtectedLauncherRecoveryBoundary(
                authority,
                store,
                paths,
                recovery,
                health,
                processes))
    {
    }

    public LauncherRecoveryAction RecoverForUserLaunch()
    {
        LauncherRecoveredTransaction recovered;
        try
        {
            recovered = _boundary.Recover();
        }
        catch
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        return recovered.Kind switch
        {
            LauncherRecoveredKind.ContinueCurrent =>
                LauncherRecoveryAction.ContinueNormalLaunch,
            LauncherRecoveredKind.AwaitingHealth
                when recovered.Record is not null =>
                    HandleAwaitingHealth(recovered.Record),
            LauncherRecoveredKind.Committed
                when recovered.Record is not null =>
                    HandleCommitted(recovered.Record),
            LauncherRecoveredKind.RolledBack
                when recovered.Record is not null =>
                    StartOld(recovered.Record),
            LauncherRecoveredKind.ExistingAuthorizedProcess =>
                LauncherRecoveryAction
                    .ExistingCandidateStillRunning,
            _ => LauncherRecoveryAction.RecoveryBlocked
        };
    }

    internal static IReadOnlyList<string> CandidateArguments(
        ProtectedTransactionRecord record) =>
        [
            "--update-transaction",
            record.TransactionId.DirectoryName,
            "--update-version",
            record.Version.ToString()
        ];

    private LauncherRecoveryAction HandleAwaitingHealth(
        ProtectedTransactionRecord record)
    {
        LauncherHealthObservation health;
        try
        {
            health = _boundary.ReadHealth(record);
        }
        catch
        {
            return Block(record);
        }

        return health.Kind switch
        {
            LauncherHealthKind.Missing =>
                StartCandidate(record),
            LauncherHealthKind.CandidateRunning
                when IsExactMarker(record, health.Marker) =>
                    HandleCandidateRunning(
                        record,
                        health.Marker!),
            LauncherHealthKind.Healthy
                when IsExactMarker(record, health.Marker) =>
                    HandleHealthy(
                        record,
                        health.Marker!,
                        commitRequired: true),
            _ => Block(record)
        };
    }

    private LauncherRecoveryAction HandleCommitted(
        ProtectedTransactionRecord record)
    {
        LauncherHealthObservation health;
        try
        {
            health = _boundary.ReadHealth(record);
        }
        catch
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        return health.Kind == LauncherHealthKind.Healthy
                && IsExactMarker(record, health.Marker)
            ? HandleHealthy(
                record,
                health.Marker!,
                commitRequired: false)
            : LauncherRecoveryAction.RecoveryBlocked;
    }

    private LauncherRecoveryAction HandleCandidateRunning(
        ProtectedTransactionRecord record,
        UpdateHealthMarker marker)
    {
        var process = Observe(marker.CandidateProcess);
        return process switch
        {
            LauncherProcessObservation.Running =>
                LauncherRecoveryAction
                    .ExistingCandidateStillRunning,
            LauncherProcessObservation.Exited
                or LauncherProcessObservation.PidReused =>
                    RollbackAndStartOld(record),
            _ => Block(record)
        };
    }

    private LauncherRecoveryAction HandleHealthy(
        ProtectedTransactionRecord record,
        UpdateHealthMarker marker,
        bool commitRequired)
    {
        var process = Observe(marker.CandidateProcess);
        if (process == LauncherProcessObservation.Ambiguous)
        {
            return commitRequired
                ? Block(record)
                : LauncherRecoveryAction.RecoveryBlocked;
        }

        var terminal = record;
        if (commitRequired)
        {
            var committed = SafeCommit(record);
            if (!committed.Success
                || committed.Record is null)
            {
                return Block(record);
            }

            terminal = committed.Record;
        }

        if (!SafeDeactivate(terminal))
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        SafeCleanup(terminal);
        return process == LauncherProcessObservation.Running
            ? LauncherRecoveryAction
                .ExistingCandidateStillRunning
            : LauncherRecoveryAction.ContinueNormalLaunch;
    }

    private LauncherRecoveryAction StartCandidate(
        ProtectedTransactionRecord record)
    {
        bool revalidated;
        try
        {
            revalidated = _boundary.RevalidateCandidate(record);
        }
        catch
        {
            revalidated = false;
        }

        if (!revalidated)
        {
            return Block(record);
        }

        LauncherProcessStartResult started;
        try
        {
            started = _boundary.StartCandidate(
                record,
                CandidateArguments(record));
        }
        catch
        {
            return Block(record);
        }

        if (started.Status
                == LauncherProcessStartStatus.CleanFailure
            && started.Process is null)
        {
            return RollbackAndStartOld(record);
        }

        if (started.Status
                != LauncherProcessStartStatus.Created
            || started.Process is null)
        {
            return Block(record);
        }

        using var process = started.Process;
        LauncherCandidateRecordOutcome recorded;
        try
        {
            recorded = _boundary.RecordCandidate(
                record,
                process.ProcessId);
        }
        catch
        {
            recorded =
                LauncherCandidateRecordOutcome.Ambiguous;
        }

        if (recorded
            != LauncherCandidateRecordOutcome.Recorded)
        {
            var certified = SafeAbort(process);
            return recorded
                        == LauncherCandidateRecordOutcome
                            .CleanNotRecorded
                    && certified
                ? RollbackAndStartOld(record)
                : Block(record);
        }

        var resumed = SafeResume(process);
        return resumed switch
        {
            LauncherResumeOutcome.Started =>
                LauncherRecoveryAction.CandidateLaunchHandled,
            LauncherResumeOutcome.NeverRanAndDead =>
                RollbackAndStartOld(record),
            _ => Block(record)
        };
    }

    private LauncherRecoveryAction RollbackAndStartOld(
        ProtectedTransactionRecord record)
    {
        LauncherTerminalResult rolledBack;
        try
        {
            rolledBack = _boundary.Rollback(record);
        }
        catch
        {
            return Block(record);
        }

        return rolledBack.Success
                && rolledBack.Record is
                {
                    Phase: ProtectedTransactionPhase.RolledBack
                } terminal
            ? StartOld(terminal)
            : Block(record);
    }

    private LauncherRecoveryAction StartOld(
        ProtectedTransactionRecord terminal)
    {
        LauncherProcessStartResult started;
        try
        {
            started = _boundary.StartOld(terminal);
        }
        catch
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        if (started.Status
                != LauncherProcessStartStatus.Created
            || started.Process is null)
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        using var process = started.Process;
        if (!SafeDeactivate(terminal))
        {
            SafeAbort(process);
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        var resumed = SafeResume(process);
        if (resumed == LauncherResumeOutcome.Ambiguous)
        {
            return LauncherRecoveryAction.RecoveryBlocked;
        }

        SafeCleanup(terminal);
        return resumed == LauncherResumeOutcome.Started
            ? LauncherRecoveryAction.OldVersionLaunchHandled
            : LauncherRecoveryAction.ContinueNormalLaunch;
    }

    private LauncherProcessObservation Observe(
        ProcessIdentity identity)
    {
        try
        {
            return _boundary.ObserveProcess(identity);
        }
        catch
        {
            return LauncherProcessObservation.Ambiguous;
        }
    }

    private LauncherTerminalResult SafeCommit(
        ProtectedTransactionRecord record)
    {
        try
        {
            return _boundary.Commit(record);
        }
        catch
        {
            return LauncherTerminalResult.Failed();
        }
    }

    private bool SafeDeactivate(
        ProtectedTransactionRecord record)
    {
        try
        {
            return _boundary.Deactivate(record);
        }
        catch
        {
            return false;
        }
    }

    private void SafeCleanup(
        ProtectedTransactionRecord record)
    {
        try
        {
            _boundary.Cleanup(record);
        }
        catch
        {
            // Cleanup is post-terminal best effort. Once the active
            // pointer is cleared there is currently no durable automatic
            // retry reference; a failure must never change launch routing.
        }
    }

    private LauncherResumeOutcome SafeResume(
        ILauncherFailSafeProcess process)
    {
        try
        {
            return _boundary.ResumeAndRelease(process);
        }
        catch
        {
            return LauncherResumeOutcome.Ambiguous;
        }
    }

    private bool SafeAbort(
        ILauncherFailSafeProcess process)
    {
        try
        {
            return _boundary.AbortBeforeResume(process);
        }
        catch
        {
            return false;
        }
    }

    private LauncherRecoveryAction Block(
        ProtectedTransactionRecord record)
    {
        if (record.Phase is not (
                ProtectedTransactionPhase.Committed
                or ProtectedTransactionPhase.RolledBack
                or ProtectedTransactionPhase.RecoveryBlocked))
        {
            try
            {
                _boundary.EnterRecoveryBlocked(record);
            }
            catch
            {
                // The action remains fail-closed even when persistence
                // cannot be certified.
            }
        }

        return LauncherRecoveryAction.RecoveryBlocked;
    }

    private static bool IsExactMarker(
        ProtectedTransactionRecord record,
        UpdateHealthMarker? marker) =>
        marker is not null
        && marker.SchemaVersion
            == UpdateHealthService.MarkerSchemaVersion
        && marker.TransactionId == record.TransactionId
        && marker.Version == record.Version
        && marker.CandidateProcess is
        {
            ProcessId: > 0,
            CreationTimeFileTimeUtc: > 0
        }
        && !string.IsNullOrWhiteSpace(
            marker.CandidateProcess.ImagePath);
}

internal interface ILauncherProcessStarter
{
    LauncherProcessStartResult StartSuspended(
        string executablePath,
        IReadOnlyList<string> arguments);
}

internal sealed class ProtectedLauncherRecoveryBoundary
    : ILauncherRecoveryBoundary
{
    private readonly ProtectedUpdateMutexContext _authority;
    private readonly ProtectedTransactionStore _store;
    private readonly ProtectedTransactionPaths _paths;
    private readonly TransactionRecoveryService _recovery;
    private readonly UpdateHealthService _health;
    private readonly WindowsProcessIdentityService _processes;
    private readonly IUpdateHealthBoundary _markerBoundary;
    private readonly TransactionalUpdateExecutor _executor;
    private readonly ILauncherProcessStarter _processStarter;
    private readonly ProtectedTerminalTransactionCleaner _cleaner;

    internal ProtectedLauncherRecoveryBoundary(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionStore store,
        ProtectedTransactionPaths paths,
        TransactionRecoveryService recovery,
        UpdateHealthService health,
        WindowsProcessIdentityService processes)
        : this(
            authority,
            store,
            paths,
            recovery,
            health,
            processes,
            new ProtectedUpdateHealthBoundary(
                paths,
                store,
                new WindowsProtectedTransactionFileSystem(),
                new ProtectedDirectoryAcl()),
            new TransactionalUpdateExecutor(
                store,
                authority,
                paths),
            new WindowsFailSafeProcessLauncher(),
            new ProtectedTerminalTransactionCleaner(
                paths,
                new ProtectedDirectoryAcl()))
    {
    }

    internal ProtectedLauncherRecoveryBoundary(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionStore store,
        ProtectedTransactionPaths paths,
        TransactionRecoveryService recovery,
        UpdateHealthService health,
        WindowsProcessIdentityService processes,
        IUpdateHealthBoundary markerBoundary,
        TransactionalUpdateExecutor executor,
        ILauncherProcessStarter processStarter,
        ProtectedTerminalTransactionCleaner cleaner)
    {
        _authority = authority
            ?? throw new ArgumentNullException(nameof(authority));
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _recovery = recovery
            ?? throw new ArgumentNullException(nameof(recovery));
        _health = health
            ?? throw new ArgumentNullException(nameof(health));
        _processes = processes
            ?? throw new ArgumentNullException(nameof(processes));
        _markerBoundary = markerBoundary
            ?? throw new ArgumentNullException(
                nameof(markerBoundary));
        _executor = executor
            ?? throw new ArgumentNullException(nameof(executor));
        _processStarter = processStarter
            ?? throw new ArgumentNullException(
                nameof(processStarter));
        _cleaner = cleaner
            ?? throw new ArgumentNullException(nameof(cleaner));
    }

    public LauncherRecoveredTransaction Recover()
    {
        var oldProcessGuard = GuardAuthorizedOldProcess();
        if (oldProcessGuard is not null)
        {
            return oldProcessGuard;
        }

        var recovered = _recovery.Recover();
        if (recovered.Outcome
                == TransactionRecoveryOutcome.Blocked
            || recovered.Route == TransactionRecoveryRoute.Blocked)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        if (recovered.Route
                == TransactionRecoveryRoute.ContinueOld
            && !recovered.CleanupEligible)
        {
            return LauncherRecoveredTransaction.ContinueCurrent();
        }

        if (recovered.TransactionId is not
            { IsValid: true } transactionId
            || recovered.Phase is not { } expectedPhase)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        var read = _store.ReadTransaction(
            _authority,
            transactionId);
        if (!read.Success
            || read.Record is not { } record
            || record.TransactionId != transactionId
            || record.Phase != expectedPhase)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        return recovered.Route switch
        {
            TransactionRecoveryRoute.AwaitHealth
                when record.Phase
                    == ProtectedTransactionPhase
                        .AppliedAwaitingHealth =>
                    LauncherRecoveredTransaction
                        .AwaitingHealth(record),
            TransactionRecoveryRoute.CleanupCommitted
                when recovered.CleanupEligible
                    && record.Phase
                        == ProtectedTransactionPhase.Committed =>
                    LauncherRecoveredTransaction.Committed(record),
            TransactionRecoveryRoute.CleanupRolledBack
                when recovered.CleanupEligible
                    && record.Phase
                        == ProtectedTransactionPhase.RolledBack =>
                    LauncherRecoveredTransaction.RolledBack(record),
            _ => LauncherRecoveredTransaction.Blocked()
        };
    }

    private LauncherRecoveredTransaction?
        GuardAuthorizedOldProcess()
    {
        var active = _store.ReadActive(_authority);
        if (!active.Success)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        if (active.TransactionId is not
            { IsValid: true } transactionId)
        {
            return null;
        }

        var read = _store.ReadTransaction(
            _authority,
            transactionId);
        if (!read.Success || read.Record is not { } record)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        if (record.Phase
            != ProtectedTransactionPhase.CloseAuthorized)
        {
            return null;
        }

        if (record.AuthorizedProcess is null)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        return RouteAuthorizedOldProcess(
            record,
            ObserveProcess(record.AuthorizedProcess));
    }

    internal static LauncherRecoveredTransaction?
        RouteAuthorizedOldProcess(
            ProtectedTransactionRecord record,
            LauncherProcessObservation observation)
    {
        if (record.Phase
                != ProtectedTransactionPhase.CloseAuthorized
            || record.AuthorizedProcess is null)
        {
            return LauncherRecoveredTransaction.Blocked();
        }

        return observation switch
        {
            LauncherProcessObservation.Running =>
                LauncherRecoveredTransaction
                    .ExistingAuthorizedProcess(record),
            LauncherProcessObservation.Exited
                or LauncherProcessObservation.PidReused =>
                    null,
            _ => LauncherRecoveredTransaction.Blocked()
        };
    }

    public LauncherHealthObservation ReadHealth(
        ProtectedTransactionRecord record)
    {
        if (record.Phase
            == ProtectedTransactionPhase.AppliedAwaitingHealth)
        {
            return MapHealth(
                _health.Read(
                    _authority,
                    record.TransactionId,
                    record.Version));
        }

        if (record.Phase
            != ProtectedTransactionPhase.Committed
            || !_authority.TryAcquireLease(
                out var authorityLease))
        {
            return LauncherHealthObservation.Invalid;
        }

        using (authorityLease)
        {
            var marker = _markerBoundary.ReadMarker(
                _authority,
                record.TransactionId);
            return marker.Success && marker.Marker is not null
                ? MapMarker(record, marker.Marker)
                : marker.Error == UpdateHealthError.MarkerMissing
                    ? LauncherHealthObservation.Missing
                    : LauncherHealthObservation.Invalid;
        }
    }

    public LauncherProcessObservation ObserveProcess(
        ProcessIdentity identity)
    {
        var opened = _processes.ReopenValidated(identity);
        if (!opened.Success || opened.Lease is null)
        {
            return MapFailedProcessOpen(opened);
        }

        using var lease = opened.Lease;
        var waited = lease.WaitForExit(TimeSpan.Zero);
        return waited.Status switch
        {
            ProcessWaitStatus.StillRunning =>
                LauncherProcessObservation.Running,
            ProcessWaitStatus.Exited =>
                LauncherProcessObservation.Exited,
            _ => LauncherProcessObservation.Ambiguous
        };
    }

    internal static LauncherProcessObservation
        MapFailedProcessOpen(ProcessIdentityOpenResult opened)
    {
        const int ErrorInvalidParameter = 87;

        if (opened.Success || opened.Lease is not null)
        {
            return LauncherProcessObservation.Ambiguous;
        }

        return opened.Status switch
        {
            ProcessIdentityOpenStatus.ProcessUnavailable
                when opened.NativeErrorCode
                    == ErrorInvalidParameter =>
                LauncherProcessObservation.Exited,
            ProcessIdentityOpenStatus.ProcessIdMismatch
                or ProcessIdentityOpenStatus
                    .CreationTimeMismatch
                or ProcessIdentityOpenStatus.ImagePathMismatch =>
                    LauncherProcessObservation.PidReused,
            _ => LauncherProcessObservation.Ambiguous
        };
    }

    public bool RevalidateCandidate(
        ProtectedTransactionRecord record)
    {
        if (!TryReadBound(
                record,
                ProtectedTransactionPhase.AppliedAwaitingHealth,
                out var current)
            || !TryResolveInstalledApplication(
                current.Record!,
                out _))
        {
            return false;
        }

        var verified = _store.CompareExchangeTransaction(
            _authority,
            current,
            current.Record);
        return verified.Success
            && verified.Record is
            {
                Phase:
                    ProtectedTransactionPhase.AppliedAwaitingHealth
            } verifiedRecord
            && verifiedRecord.TransactionId
                == record.TransactionId
            && verifiedRecord.Version == record.Version;
    }

    public LauncherProcessStartResult StartCandidate(
        ProtectedTransactionRecord record,
        IReadOnlyList<string> arguments)
    {
        var expectedArguments =
            LauncherRecoveryService.CandidateArguments(record);
        if (arguments is null
            || !arguments.SequenceEqual(
                expectedArguments,
                StringComparer.Ordinal)
            || !RevalidateCandidate(record)
            || !TryResolveInstalledApplication(
                record,
                out var executablePath))
        {
            return LauncherProcessStartResult
                .AmbiguousFailure();
        }

        return _processStarter.StartSuspended(
            executablePath!,
            expectedArguments);
    }

    public LauncherCandidateRecordOutcome RecordCandidate(
        ProtectedTransactionRecord record,
        int processId)
    {
        var persisted = _health.RecordCandidate(
            _authority,
            record.TransactionId,
            record.Version,
            processId);
        if (IsExactCandidateMarker(
                persisted.Marker,
                record,
                processId))
        {
            return LauncherCandidateRecordOutcome.Recorded;
        }

        var reread = _health.Read(
            _authority,
            record.TransactionId,
            record.Version);
        if (IsExactCandidateMarker(
                reread.Marker,
                record,
                processId))
        {
            return LauncherCandidateRecordOutcome.Recorded;
        }

        return reread.Error == UpdateHealthError.MarkerMissing
                && persisted.Error is
                    UpdateHealthError.PersistenceFailed
                        or UpdateHealthError.ProcessUnavailable
            ? LauncherCandidateRecordOutcome.CleanNotRecorded
            : LauncherCandidateRecordOutcome.Ambiguous;
    }

    public LauncherResumeOutcome ResumeAndRelease(
        ILauncherFailSafeProcess process) =>
        process is WindowsFailSafeLaunchedProcess launched
            ? launched.ResumeAndRelease()
            : LauncherResumeOutcome.Ambiguous;

    public bool AbortBeforeResume(
        ILauncherFailSafeProcess process) =>
        process is WindowsFailSafeLaunchedProcess launched
        && launched.AbortBeforeResume();

    public LauncherTerminalResult Commit(
        ProtectedTransactionRecord record)
    {
        if (!TryReadBound(
                record,
                ProtectedTransactionPhase.AppliedAwaitingHealth,
                out var current))
        {
            return LauncherTerminalResult.Failed();
        }

        var committed = _store.CompareExchangeTransaction(
            _authority,
            current,
            current.Record! with
            {
                Phase = ProtectedTransactionPhase.Committed
            });
        return committed.Success
                && committed.Record is
                {
                    Phase: ProtectedTransactionPhase.Committed
                } terminal
            ? LauncherTerminalResult.Completed(terminal)
            : LauncherTerminalResult.Failed();
    }

    public LauncherTerminalResult Rollback(
        ProtectedTransactionRecord record)
    {
        if (!TryReadBound(
                record,
                ProtectedTransactionPhase.AppliedAwaitingHealth,
                out var current))
        {
            return LauncherTerminalResult.Failed();
        }

        var rolling = _store.CompareExchangeTransaction(
            _authority,
            current,
            current.Record! with
            {
                Phase = ProtectedTransactionPhase.RollingBack
            });
        if (!rolling.Success
            || rolling.Record?.Phase
                != ProtectedTransactionPhase.RollingBack)
        {
            return LauncherTerminalResult.Failed();
        }

        var execution = _executor.Resume(record.TransactionId);
        if (execution.Outcome
                != TransactionalUpdateExecutionOutcome.TerminalState)
        {
            return LauncherTerminalResult.Failed();
        }

        var terminal = _store.ReadJournalForRecovery(
            _authority,
            record.TransactionId);
        return terminal.Success
                && terminal.Observation
                    == ProtectedJournalObservation.MatchesBoundHash
                && terminal.Record is
                {
                    Phase: ProtectedTransactionPhase.RolledBack
                } rolledBack
            ? LauncherTerminalResult.Completed(rolledBack)
            : LauncherTerminalResult.Failed();
    }

    public LauncherProcessStartResult StartOld(
        ProtectedTransactionRecord terminalRecord)
    {
        if (!TryReadBound(
                terminalRecord,
                ProtectedTransactionPhase.RolledBack,
                out var current)
            || !_store.CompareExchangeTransaction(
                    _authority,
                    current,
                    current.Record)
                .Success
            || !TryResolveInstalledApplication(
                current.Record!,
                out var executablePath))
        {
            return LauncherProcessStartResult
                .AmbiguousFailure();
        }

        return _processStarter.StartSuspended(
            executablePath!,
            arguments: []);
    }

    public bool Deactivate(
        ProtectedTransactionRecord terminalRecord) =>
        _store.DeactivateTerminal(
                _authority,
                terminalRecord)
            .Success;

    public bool Cleanup(
        ProtectedTransactionRecord terminalRecord) =>
        _store.CleanupInactiveTerminalTransaction(
                _authority,
                terminalRecord,
                () => _cleaner.Cleanup(
                    terminalRecord.TransactionId))
            .Success;

    public bool EnterRecoveryBlocked(
        ProtectedTransactionRecord record)
    {
        var read = _store.ReadTransaction(
            _authority,
            record.TransactionId);
        if (!read.Success
            || read.Record is not { } current
            || current.TransactionId != record.TransactionId
            || current.Version != record.Version)
        {
            return false;
        }

        if (current.Phase
            == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return true;
        }

        var blocked = _store.EnterRecoveryBlocked(
            _authority,
            current);
        return blocked.Success
            && blocked.Record?.Phase
                == ProtectedTransactionPhase.RecoveryBlocked;
    }

    private bool TryReadBound(
        ProtectedTransactionRecord expected,
        ProtectedTransactionPhase phase,
        out ProtectedJournalRecoveryReadResult current)
    {
        current = _store.ReadJournalForRecovery(
            _authority,
            expected.TransactionId);
        return current.Success
            && current.Observation
                == ProtectedJournalObservation.MatchesBoundHash
            && current.Record is { } record
            && record.TransactionId == expected.TransactionId
            && record.Version == expected.Version
            && record.Phase == phase;
    }

    private bool TryResolveInstalledApplication(
        ProtectedTransactionRecord record,
        out string? executablePath) =>
        TryResolveInstalledPath(
            record.InstalledRelease.InstallRoot,
            record.InstalledRelease.ApplicationRelativePath,
            out executablePath);

    internal static bool TryResolveInstalledPath(
        string? installRoot,
        string? relativePath,
        out string? path)
    {
        path = null;
        var validated = WindowsReleasePathPolicy.Validate(
            relativePath);
        if (!validated.Success
            || validated.CanonicalKey is null
            || !string.Equals(
                validated.CanonicalKey,
                relativePath,
                StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var root = Path.GetFullPath(installRoot!);
            var candidate = Path.GetFullPath(
                Path.Combine(
                    root,
                    validated.CanonicalKey.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            var prefix = root.EndsWith(
                Path.DirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;
            if (!string.Equals(
                    root,
                    installRoot,
                    StringComparison.OrdinalIgnoreCase)
                || !candidate.StartsWith(
                    prefix,
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

    private static LauncherHealthObservation MapHealth(
        UpdateHealthResult result)
    {
        if (result.Success && result.Marker is not null)
        {
            return result.Marker.State switch
            {
                UpdateHealthMarkerState.CandidateRunning =>
                    LauncherHealthObservation.CandidateRunning(
                        result.Marker),
                UpdateHealthMarkerState.Healthy =>
                    LauncherHealthObservation.Healthy(
                        result.Marker),
                _ => LauncherHealthObservation.Invalid
            };
        }

        return result.Error == UpdateHealthError.MarkerMissing
            ? LauncherHealthObservation.Missing
            : LauncherHealthObservation.Invalid;
    }

    private static LauncherHealthObservation MapMarker(
        ProtectedTransactionRecord record,
        UpdateHealthMarker marker)
    {
        if (marker.TransactionId != record.TransactionId
            || marker.Version != record.Version)
        {
            return LauncherHealthObservation.Invalid;
        }

        return marker.State switch
        {
            UpdateHealthMarkerState.CandidateRunning =>
                LauncherHealthObservation.CandidateRunning(marker),
            UpdateHealthMarkerState.Healthy =>
                LauncherHealthObservation.Healthy(marker),
            _ => LauncherHealthObservation.Invalid
        };
    }

    private static bool IsExactCandidateMarker(
        UpdateHealthMarker? marker,
        ProtectedTransactionRecord record,
        int processId) =>
        marker is
        {
            SchemaVersion:
                UpdateHealthService.MarkerSchemaVersion,
            State: UpdateHealthMarkerState.CandidateRunning
        }
        && marker.TransactionId == record.TransactionId
        && marker.Version == record.Version
        && marker.CandidateProcess.ProcessId == processId;
}

internal sealed class ProtectedTerminalTransactionCleaner
{
    private const int MetadataEntryAllowance = 64;

    private readonly ProtectedTransactionPaths _paths;
    private readonly ProtectedDirectoryAcl _acl;

    internal ProtectedTerminalTransactionCleaner(
        ProtectedTransactionPaths paths,
        ProtectedDirectoryAcl acl)
    {
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _acl = acl
            ?? throw new ArgumentNullException(nameof(acl));
    }

    internal bool Cleanup(ProtectedTransactionId transactionId)
    {
        if (!transactionId.IsValid)
        {
            return false;
        }

        var layoutResult = _paths.GetLayout(transactionId);
        if (!layoutResult.Success
            || layoutResult.Layout is not { } layout)
        {
            return false;
        }

        try
        {
            using var rootResult =
                _acl.InspectProtectedDirectory(
                    layout.TransactionRoot,
                    ProtectedDirectoryInspectionPolicy.Transaction);
            if (!rootResult.Success
                || rootResult.Lease is not { } root
                || !string.Equals(
                    root.FinalPath,
                    layout.TransactionRoot,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var files =
                new List<(
                    string Path,
                    ProtectedFileIdentity128 Identity)>();
            var directories =
                new List<(
                    string Path,
                    ProtectedFileIdentity128 Identity)>();
            using (var enumerationResult =
                _acl.EnumerateProtectedDirectory(
                    root,
                    ProtectedDirectoryInspectionPolicy.Transaction,
                    checked(
                        WindowsReleasePathPolicy.MaximumArchiveEntries
                        * 2
                        + MetadataEntryAllowance)))
            {
                if (!enumerationResult.Success
                    || enumerationResult.Lease
                        is not { } enumeration)
                {
                    return false;
                }

                foreach (var file in enumeration.Files)
                {
                    if (!IsCanonicalDescendant(
                            layout.TransactionRoot,
                            file.FinalPath)
                        || !file.Identity.IsValid)
                    {
                        return false;
                    }

                    files.Add((file.FinalPath, file.Identity));
                }

                foreach (var directory
                    in enumeration.Directories)
                {
                    if (!IsCanonicalDescendant(
                            layout.TransactionRoot,
                            directory.FinalPath)
                        || !directory.Identity.IsValid)
                    {
                        return false;
                    }

                    directories.Add(
                        (directory.FinalPath,
                         directory.Identity));
                }

                if (!enumeration.Revalidate()
                    || !root.Revalidate())
                {
                    return false;
                }
            }

            foreach (var file in files
                .OrderBy(item =>
                    string.Equals(
                        item.Path,
                        layout.TransactionRecordPath,
                        StringComparison.OrdinalIgnoreCase)
                            ? 1
                            : 0)
                .ThenByDescending(item => item.Path.Length))
            {
                if (_acl.DeleteProtectedFile(
                            file.Path,
                            file.Identity)
                        .Outcome
                    != ProtectedFileMutationOutcome.Committed)
                {
                    return false;
                }
            }

            foreach (var directory in directories
                .OrderByDescending(item => item.Path.Length))
            {
                if (_acl.DeleteProtectedDirectory(
                            directory.Path,
                            directory.Identity)
                        .Outcome
                    != ProtectedFileMutationOutcome.Committed)
                {
                    return false;
                }
            }

            var rootIdentity = root.Identity;
            root.Dispose();
            return _acl.DeleteProtectedDirectory(
                        layout.TransactionRoot,
                        rootIdentity)
                    .Outcome
                == ProtectedFileMutationOutcome.Committed;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or InvalidOperationException
                or NotSupportedException
                or Win32Exception
                or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool IsCanonicalDescendant(
        string root,
        string path)
    {
        try
        {
            var canonicalRoot = Path.GetFullPath(root);
            var canonicalPath = Path.GetFullPath(path);
            var prefix = canonicalRoot.EndsWith(
                Path.DirectorySeparatorChar)
                ? canonicalRoot
                : canonicalRoot + Path.DirectorySeparatorChar;
            return string.Equals(
                    root,
                    canonicalRoot,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    path,
                    canonicalPath!,
                    StringComparison.OrdinalIgnoreCase)
                && canonicalPath.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or NotSupportedException)
        {
            return false;
        }
    }
}

internal sealed class WindowsFailSafeProcessLauncher
    : ILauncherProcessStarter
{
    private const uint CreateSuspended = 0x0000_0004;
    private const uint ExtendedStartupInfoPresent = 0x0008_0000;
    private const uint JobObjectLimitKillOnJobClose =
        0x0000_2000;
    private const int JobObjectExtendedLimitInformationClass = 9;
    private static readonly nuint ProcThreadAttributeJobList =
        0x0002_000D;
    private readonly Func<uint, int> _convertProcessId;

    public WindowsFailSafeProcessLauncher()
        : this(static processId =>
            checked((int)processId))
    {
    }

    internal WindowsFailSafeProcessLauncher(
        Func<uint, int> convertProcessId)
    {
        _convertProcessId = convertProcessId
            ?? throw new ArgumentNullException(
                nameof(convertProcessId));
    }

    public LauncherProcessStartResult StartSuspended(
        string executablePath,
        IReadOnlyList<string> arguments)
    {
        if (!TryValidateLaunch(
                executablePath,
                arguments,
                out var canonicalPath,
                out var commandLine))
        {
            return LauncherProcessStartResult.CleanFailure();
        }

        SafeLauncherKernelHandle? job = null;
        SafeLauncherKernelHandle? process = null;
        SafeLauncherKernelHandle? thread = null;
        var childCreated = false;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr jobList = IntPtr.Zero;
        try
        {
            job = NativeMethods.CreateJobObject(
                IntPtr.Zero,
                name: null);
            if (job.IsInvalid
                || !SetKillOnClose(job, enabled: true)
                || !TryCreateAttributeList(
                    job,
                    out attributeList,
                    out jobList))
            {
                job.Dispose();
                return LauncherProcessStartResult.CleanFailure();
            }

            var startup = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfoEx>()
                },
                AttributeList = attributeList
            };
            var mutableCommandLine =
                new StringBuilder(commandLine);
            if (!NativeMethods.CreateProcess(
                    canonicalPath!,
                    mutableCommandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: false,
                    CreateSuspended
                        | ExtendedStartupInfoPresent,
                    IntPtr.Zero,
                    currentDirectory:
                        Path.GetDirectoryName(canonicalPath!),
                    ref startup,
                    out var information))
            {
                job.Dispose();
                return LauncherProcessStartResult.CleanFailure();
            }

            process = new SafeLauncherKernelHandle(
                information.ProcessHandle,
                ownsHandle: true);
            thread = new SafeLauncherKernelHandle(
                information.ThreadHandle,
                ownsHandle: true);
            childCreated = true;
            var launched = new WindowsFailSafeLaunchedProcess(
                _convertProcessId(information.ProcessId),
                process,
                thread,
                job);
            process = null;
            thread = null;
            job = null;
            return LauncherProcessStartResult.Created(launched);
        }
        catch (Exception exception) when (
            exception is ArgumentException
                or IOException
                or InvalidOperationException
                or NotSupportedException
                or OverflowException
                or Win32Exception
                or System.Security.SecurityException)
        {
            if (childCreated
                && process is not null
                && thread is not null
                && job is not null)
            {
                var certified =
                    WindowsFailSafeLaunchedProcess
                        .AbortSuspendedHandles(
                            process,
                            thread,
                            job);
                process = null;
                thread = null;
                job = null;
                return certified
                    ? LauncherProcessStartResult.CleanFailure()
                    : LauncherProcessStartResult
                        .AmbiguousFailure();
            }

            return childCreated
                ? LauncherProcessStartResult.AmbiguousFailure()
                : LauncherProcessStartResult.CleanFailure();
        }
        finally
        {
            thread?.Dispose();
            process?.Dispose();
            job?.Dispose();
            if (attributeList != IntPtr.Zero)
            {
                NativeMethods.DeleteProcThreadAttributeList(
                    attributeList);
                Marshal.FreeHGlobal(attributeList);
            }

            if (jobList != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(jobList);
            }
        }
    }

    internal static bool TryBuildCommandLine(
        string executablePath,
        IReadOnlyList<string> arguments,
        out string commandLine)
    {
        commandLine = string.Empty;
        if (arguments is null
            || arguments.Any(argument => argument is null))
        {
            return false;
        }

        var builder = new StringBuilder();
        AppendQuotedArgument(builder, executablePath);
        foreach (var argument in arguments)
        {
            builder.Append(' ');
            AppendQuotedArgument(builder, argument);
        }

        commandLine = builder.ToString();
        return commandLine.Length is > 0 and < 32767;
    }

    private static bool TryValidateLaunch(
        string? executablePath,
        IReadOnlyList<string>? arguments,
        out string? canonicalPath,
        out string commandLine)
    {
        canonicalPath = null;
        commandLine = string.Empty;
        if (string.IsNullOrWhiteSpace(executablePath)
            || arguments is null
            || executablePath.IndexOf('\0') >= 0)
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(executablePath);
            if (!Path.IsPathFullyQualified(full)
                || !string.Equals(
                    full,
                    executablePath,
                    StringComparison.OrdinalIgnoreCase)
                || !TryBuildCommandLine(
                    full,
                    arguments,
                    out commandLine))
            {
                return false;
            }

            canonicalPath = full;
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

    private static void AppendQuotedArgument(
        StringBuilder builder,
        string value)
    {
        builder.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                builder.Append('\\', checked(backslashes * 2 + 1));
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            if (backslashes > 0)
            {
                builder.Append('\\', backslashes);
                backslashes = 0;
            }

            builder.Append(character);
        }

        if (backslashes > 0)
        {
            builder.Append('\\', checked(backslashes * 2));
        }

        builder.Append('"');
    }

    private static bool TryCreateAttributeList(
        SafeLauncherKernelHandle job,
        out IntPtr attributeList,
        out IntPtr jobList)
    {
        attributeList = IntPtr.Zero;
        jobList = IntPtr.Zero;
        nuint size = 0;
        NativeMethods.InitializeProcThreadAttributeList(
            IntPtr.Zero,
            attributeCount: 1,
            flags: 0,
            ref size);
        if (size == 0 || size > int.MaxValue)
        {
            return false;
        }

        attributeList = Marshal.AllocHGlobal(
            checked((int)size));
        if (!NativeMethods.InitializeProcThreadAttributeList(
                attributeList,
                attributeCount: 1,
                flags: 0,
                ref size))
        {
            Marshal.FreeHGlobal(attributeList);
            attributeList = IntPtr.Zero;
            return false;
        }

        jobList = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(
            jobList,
            job.DangerousGetHandle());
        return NativeMethods.UpdateProcThreadAttribute(
            attributeList,
            flags: 0,
            ProcThreadAttributeJobList,
            jobList,
            checked((nuint)IntPtr.Size),
            IntPtr.Zero,
            IntPtr.Zero);
    }

    internal static bool SetKillOnClose(
        SafeLauncherKernelHandle job,
        bool enabled)
    {
        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation =
                new JobObjectBasicLimitInformation
                {
                    LimitFlags = enabled
                        ? JobObjectLimitKillOnJobClose
                        : 0
                }
        };
        return NativeMethods.SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformationClass,
            ref limits,
            Marshal.SizeOf<JobObjectExtendedLimitInformation>());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved;
        internal IntPtr Desktop;
        internal IntPtr Title;
        internal int X;
        internal int Y;
        internal int XSize;
        internal int YSize;
        internal int XCountChars;
        internal int YCountChars;
        internal int FillAttribute;
        internal int Flags;
        internal short ShowWindow;
        internal short Reserved2;
        internal IntPtr Reserved2Pointer;
        internal IntPtr StandardInput;
        internal IntPtr StandardOutput;
        internal IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        internal StartupInfo StartupInfo;
        internal IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr ProcessHandle;
        internal IntPtr ThreadHandle;
        internal uint ProcessId;
        internal uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal nuint MinimumWorkingSetSize;
        internal nuint MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal nuint Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        internal JobObjectBasicLimitInformation
            BasicLimitInformation;
        internal IoCounters IoInfo;
        internal nuint ProcessMemoryLimit;
        internal nuint JobMemoryLimit;
        internal nuint PeakProcessMemoryUsed;
        internal nuint PeakJobMemoryUsed;
    }

    private static class NativeMethods
    {
        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateJobObjectW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        internal static extern SafeLauncherKernelHandle
            CreateJobObject(
                IntPtr securityAttributes,
                string? name);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            SafeLauncherKernelHandle job,
            int informationClass,
            ref JobObjectExtendedLimitInformation information,
            int informationLength);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool
            InitializeProcThreadAttributeList(
                IntPtr attributeList,
                int attributeCount,
                int flags,
                ref nuint size);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            nuint attribute,
            IntPtr value,
            nuint size,
            IntPtr previousValue,
            IntPtr returnSize);

        [DllImport("kernel32.dll")]
        internal static extern void
            DeleteProcThreadAttributeList(
                IntPtr attributeList);

        [DllImport(
            "kernel32.dll",
            EntryPoint = "CreateProcessW",
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string? currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation);
    }
}

internal sealed class WindowsFailSafeLaunchedProcess
    : ILauncherFailSafeProcess
{
    private const uint WaitObject0 = 0;
    private const uint ResumeFailed = uint.MaxValue;
    private const uint AbortExitCode = 0xFFFF_FFFE;
    private const uint AbortWaitMilliseconds = 10_000;

    private readonly object _gate = new();
    private SafeLauncherKernelHandle? _process;
    private SafeLauncherKernelHandle? _thread;
    private SafeLauncherKernelHandle? _job;
    private State _state = State.Suspended;

    internal WindowsFailSafeLaunchedProcess(
        int processId,
        SafeLauncherKernelHandle process,
        SafeLauncherKernelHandle thread,
        SafeLauncherKernelHandle job)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(processId));
        }

        ProcessId = processId;
        _process = process
            ?? throw new ArgumentNullException(nameof(process));
        _thread = thread
            ?? throw new ArgumentNullException(nameof(thread));
        _job = job
            ?? throw new ArgumentNullException(nameof(job));
    }

    public int ProcessId { get; }

    internal LauncherResumeOutcome ResumeAndRelease()
    {
        lock (_gate)
        {
            if (_state != State.Suspended
                || _thread is null
                || _job is null)
            {
                return LauncherResumeOutcome.Ambiguous;
            }

            var resumed = NativeMethods.ResumeThread(_thread);
            if (resumed == ResumeFailed || resumed > 1)
            {
                return AbortCore()
                    ? LauncherResumeOutcome.NeverRanAndDead
                    : LauncherResumeOutcome.Ambiguous;
            }

            if (resumed == 0)
            {
                _state = State.RunningArmed;
                KillRunningArmed();
                return LauncherResumeOutcome.Ambiguous;
            }

            _state = State.RunningArmed;
            if (!WindowsFailSafeProcessLauncher.SetKillOnClose(
                    _job,
                    enabled: false))
            {
                KillRunningArmed();
                return LauncherResumeOutcome.Ambiguous;
            }

            _job.Dispose();
            _job = null;
            _thread.Dispose();
            _thread = null;
            _process?.Dispose();
            _process = null;
            _state = State.Released;
            return LauncherResumeOutcome.Started;
        }
    }

    internal bool AbortBeforeResume()
    {
        lock (_gate)
        {
            return AbortCore();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_state == State.Suspended)
            {
                AbortCore();
            }
            else if (_state == State.RunningArmed)
            {
                KillRunningArmed();
            }

            DisposeHandles();
            _state = State.Disposed;
        }
    }

    private bool AbortCore()
    {
        if (_state != State.Suspended
            || _process is null
            || _thread is null
            || _job is null)
        {
            return false;
        }

        var process = _process;
        var thread = _thread;
        var job = _job;
        _process = null;
        _thread = null;
        _job = null;
        var certified = AbortSuspendedHandles(
            process,
            thread,
            job);
        _state = certified ? State.Aborted : State.Disposed;
        return certified;
    }

    internal static bool AbortSuspendedHandles(
        SafeLauncherKernelHandle process,
        SafeLauncherKernelHandle thread,
        SafeLauncherKernelHandle job)
    {
        try
        {
            NativeMethods.TerminateProcess(
                process,
                AbortExitCode);
            return NativeMethods.WaitForSingleObject(
                    process,
                    AbortWaitMilliseconds)
                == WaitObject0;
        }
        finally
        {
            thread.Dispose();
            process.Dispose();
            job.Dispose();
        }
    }

    private void KillRunningArmed()
    {
        if (_process is not null)
        {
            NativeMethods.TerminateProcess(
                _process,
                AbortExitCode);
            NativeMethods.WaitForSingleObject(
                _process,
                AbortWaitMilliseconds);
        }

        DisposeHandles();
        _state = State.Disposed;
    }

    private void DisposeHandles()
    {
        _thread?.Dispose();
        _thread = null;
        _process?.Dispose();
        _process = null;
        _job?.Dispose();
        _job = null;
    }

    private enum State
    {
        Suspended,
        RunningArmed,
        Released,
        Aborted,
        Disposed
    }

    private static class NativeMethods
    {
        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        internal static extern uint ResumeThread(
            SafeLauncherKernelHandle thread);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(
            SafeLauncherKernelHandle process,
            uint exitCode);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        internal static extern uint WaitForSingleObject(
            SafeLauncherKernelHandle handle,
            uint milliseconds);
    }
}

internal sealed class SafeLauncherKernelHandle
    : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeLauncherKernelHandle()
        : base(ownsHandle: true)
    {
    }

    internal SafeLauncherKernelHandle(
        IntPtr handle,
        bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle() =>
        CloseHandle(handle);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
