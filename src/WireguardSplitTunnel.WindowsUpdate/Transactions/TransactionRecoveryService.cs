namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

internal enum TransactionRecoveryAcquisitionStatus
{
    NoActive,
    Ready,
    Failed
}

internal readonly record struct TransactionRecoveryAcquisition(
    TransactionRecoveryAcquisitionStatus Status,
    ProtectedTransactionId? ActiveTransactionId,
    ProtectedJournalRecoveryReadResult? Snapshot,
    ProtectedTransactionStoreError Error)
{
    internal static TransactionRecoveryAcquisition NoActive() =>
        new(
            TransactionRecoveryAcquisitionStatus.NoActive,
            ActiveTransactionId: null,
            Snapshot: null,
            ProtectedTransactionStoreError.None);

    internal static TransactionRecoveryAcquisition Ready(
        ProtectedTransactionId transactionId,
        ProtectedJournalRecoveryReadResult snapshot) =>
        new(
            TransactionRecoveryAcquisitionStatus.Ready,
            transactionId,
            snapshot,
            ProtectedTransactionStoreError.None);

    internal static TransactionRecoveryAcquisition Failed(
        ProtectedTransactionStoreError error) =>
        new(
            TransactionRecoveryAcquisitionStatus.Failed,
            ActiveTransactionId: null,
            Snapshot: null,
            error);
}

internal interface ITransactionRecoveryGateway
{
    TransactionRecoveryAcquisition AcquireActive();

    ProtectedTransactionWriteResult EnterRecoveryBlocked(
        ProtectedTransactionRecord expectedRecord);
}

internal sealed class ProtectedTransactionRecoveryGateway
    : ITransactionRecoveryGateway
{
    private readonly ProtectedTransactionStore _store;
    private readonly ProtectedUpdateMutexContext _authority;

    internal ProtectedTransactionRecoveryGateway(
        ProtectedTransactionStore store,
        ProtectedUpdateMutexContext authority)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _authority = authority
            ?? throw new ArgumentNullException(nameof(authority));
    }

    public TransactionRecoveryAcquisition AcquireActive()
    {
        if (!_authority.TryAcquireLease(out var authorityLease))
        {
            return TransactionRecoveryAcquisition.Failed(
                ProtectedTransactionStoreError.InvalidAuthority);
        }

        using (authorityLease)
        using (_authority.AcquireMutationLease())
        {
            var before = _store.ReadActive(_authority);
            if (!before.Success)
            {
                return TransactionRecoveryAcquisition.Failed(
                    before.Error);
            }

            if (before.TransactionId is not { IsValid: true } id)
            {
                var absentAfter = _store.ReadActive(_authority);
                return absentAfter.Success
                        && absentAfter.TransactionId is null
                    ? TransactionRecoveryAcquisition.NoActive()
                    : TransactionRecoveryAcquisition.Failed(
                        absentAfter.Success
                            ? ProtectedTransactionStoreError.Conflict
                            : absentAfter.Error);
            }

            var snapshot = _store.ReadJournalForRecovery(
                _authority,
                id);
            if (!snapshot.Success)
            {
                return TransactionRecoveryAcquisition.Failed(
                    snapshot.Error);
            }

            var after = _store.ReadActive(_authority);
            if (!after.Success
                || after.TransactionId != id
                || snapshot.Record?.TransactionId != id)
            {
                return TransactionRecoveryAcquisition.Failed(
                    after.Success
                        ? ProtectedTransactionStoreError.Conflict
                        : after.Error);
            }

            return TransactionRecoveryAcquisition.Ready(
                id,
                snapshot);
        }
    }

    public ProtectedTransactionWriteResult EnterRecoveryBlocked(
        ProtectedTransactionRecord expectedRecord) =>
        _store.EnterRecoveryBlocked(
            _authority,
            expectedRecord);
}

internal enum TransactionRecoveryRoute
{
    ContinueOld,
    ResumeApply,
    AwaitHealth,
    ResumeRollback,
    AdoptOneAhead,
    CleanupCommitted,
    CleanupRolledBack,
    Blocked
}

internal enum TransactionRecoveryOutcome
{
    Old,
    New,
    AwaitHealth,
    Blocked
}

internal enum TransactionRecoveryFailure
{
    None,
    GatewayFailure,
    InvalidSnapshot,
    CorruptState,
    MissingBoundJournal,
    JournalHashMismatch,
    UnsafeOneAheadJournal,
    UnknownObservation,
    UnknownPhase,
    ExecutionFailed,
    ExecutionAmbiguous,
    RecoveryBlockFailed
}

internal readonly record struct TransactionRecoveryResult(
    TransactionRecoveryOutcome Outcome,
    TransactionRecoveryRoute Route,
    ProtectedTransactionId? TransactionId,
    ProtectedTransactionPhase? Phase,
    ProtectedJournalObservation? Observation,
    bool CleanupEligible,
    TransactionRecoveryFailure Failure,
    ProtectedTransactionStoreError StoreError);

internal sealed class TransactionRecoveryService
{
    private readonly ITransactionRecoveryGateway _gateway;
    private readonly ITransactionalUpdateCoordinator _coordinator;

    internal TransactionRecoveryService(
        ITransactionRecoveryGateway gateway,
        ITransactionalUpdateCoordinator coordinator)
    {
        _gateway = gateway
            ?? throw new ArgumentNullException(nameof(gateway));
        _coordinator = coordinator
            ?? throw new ArgumentNullException(nameof(coordinator));
    }

    internal TransactionRecoveryResult Recover()
    {
        TransactionRecoveryAcquisition acquisition;
        try
        {
            acquisition = _gateway.AcquireActive();
        }
        catch
        {
            return Blocked(
                TransactionRecoveryFailure.GatewayFailure,
                ProtectedTransactionStoreError.IoFailure);
        }

        if (acquisition.Status
            == TransactionRecoveryAcquisitionStatus.NoActive)
        {
            return acquisition.ActiveTransactionId is null
                    && acquisition.Snapshot is null
                    && acquisition.Error
                        == ProtectedTransactionStoreError.None
                ? Old()
                : Blocked(
                    TransactionRecoveryFailure.InvalidSnapshot,
                    acquisition.Error);
        }

        if (acquisition.Status
            == TransactionRecoveryAcquisitionStatus.Failed)
        {
            return Blocked(
                TransactionRecoveryFailure.GatewayFailure,
                acquisition.Error);
        }

        if (acquisition.Status
                != TransactionRecoveryAcquisitionStatus.Ready
            || !TryValidateReady(
                acquisition,
                out var snapshot,
                out var record))
        {
            return Blocked(
                TransactionRecoveryFailure.InvalidSnapshot,
                acquisition.Error);
        }

        var route = SelectRoute(
            record.Phase,
            snapshot.Observation);
        return route switch
        {
            TransactionRecoveryRoute.ContinueOld =>
                Result(
                    TransactionRecoveryOutcome.Old,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: false),
            TransactionRecoveryRoute.AwaitHealth =>
                Result(
                    TransactionRecoveryOutcome.AwaitHealth,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: false),
            TransactionRecoveryRoute.CleanupCommitted =>
                Result(
                    TransactionRecoveryOutcome.New,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: true),
            TransactionRecoveryRoute.CleanupRolledBack =>
                Result(
                    TransactionRecoveryOutcome.Old,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: true),
            TransactionRecoveryRoute.ResumeApply
                or TransactionRecoveryRoute.ResumeRollback
                or TransactionRecoveryRoute.AdoptOneAhead =>
                    Resume(record, snapshot),
            _ => EnterBlockedForInvalidRoute(record, snapshot)
        };
    }

    internal static TransactionRecoveryRoute SelectRoute(
        ProtectedTransactionPhase phase,
        ProtectedJournalObservation observation)
    {
        if (!Enum.IsDefined(phase)
            || !Enum.IsDefined(observation))
        {
            return TransactionRecoveryRoute.Blocked;
        }

        if (observation
            == ProtectedJournalObservation.PresentButUnbound)
        {
            return phase is
                ProtectedTransactionPhase.CloseAuthorized
                    or ProtectedTransactionPhase.Prepared
                    or ProtectedTransactionPhase.BackingUp
                    or ProtectedTransactionPhase.Applying
                    or ProtectedTransactionPhase.RollingBack
                ? TransactionRecoveryRoute.AdoptOneAhead
                : TransactionRecoveryRoute.Blocked;
        }

        if (observation is
            ProtectedJournalObservation.Unavailable
                or ProtectedJournalObservation.MissingButBound
                or ProtectedJournalObservation.HashMismatch)
        {
            return TransactionRecoveryRoute.Blocked;
        }

        if (observation
            == ProtectedJournalObservation.AbsentInitial)
        {
            return phase switch
            {
                ProtectedTransactionPhase.ProtectedStaged =>
                    TransactionRecoveryRoute.ContinueOld,
                ProtectedTransactionPhase.CloseAuthorized =>
                    TransactionRecoveryRoute.ResumeApply,
                _ => TransactionRecoveryRoute.Blocked
            };
        }

        if (observation
            != ProtectedJournalObservation.MatchesBoundHash)
        {
            return TransactionRecoveryRoute.Blocked;
        }

        return phase switch
        {
            ProtectedTransactionPhase.CloseAuthorized
                or ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.BackingUp
                or ProtectedTransactionPhase.Applying =>
                    TransactionRecoveryRoute.ResumeApply,
            ProtectedTransactionPhase.AppliedAwaitingHealth =>
                TransactionRecoveryRoute.AwaitHealth,
            ProtectedTransactionPhase.RollingBack =>
                TransactionRecoveryRoute.ResumeRollback,
            ProtectedTransactionPhase.Committed =>
                TransactionRecoveryRoute.CleanupCommitted,
            ProtectedTransactionPhase.RolledBack =>
                TransactionRecoveryRoute.CleanupRolledBack,
            _ => TransactionRecoveryRoute.Blocked
        };
    }

    private TransactionRecoveryResult Resume(
        ProtectedTransactionRecord record,
        ProtectedJournalRecoveryReadResult snapshot)
    {
        TransactionalUpdateExecutionResult execution;
        try
        {
            execution = _coordinator.Resume(
                record.TransactionId);
        }
        catch
        {
            return EnterBlockedOnce(
                record,
                snapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous);
        }

        return execution.Outcome switch
        {
            TransactionalUpdateExecutionOutcome.AppliedAwaitingHealth =>
                ResolveAwaitHealth(record, snapshot),
            TransactionalUpdateExecutionOutcome.RetryableFailure =>
                execution.NamespaceMutationPossible
                    ? EnterBlockedOnce(
                        record,
                        snapshot,
                        TransactionRecoveryFailure
                            .ExecutionAmbiguous)
                    : Result(
                        TransactionRecoveryOutcome.Old,
                        TransactionRecoveryRoute.ContinueOld,
                        record,
                        snapshot,
                        cleanupEligible: false,
                        TransactionRecoveryFailure.ExecutionFailed),
            TransactionalUpdateExecutionOutcome.RecoveryBlocked =>
                ResolveRecoveryBlocked(record, snapshot),
            TransactionalUpdateExecutionOutcome.TerminalState =>
                ResolveTerminal(record, snapshot),
            _ => EnterBlockedOnce(
                record,
                snapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous)
        };
    }

    private TransactionRecoveryResult ResolveAwaitHealth(
        ProtectedTransactionRecord originalRecord,
        ProtectedJournalRecoveryReadResult originalSnapshot)
    {
        if (!TryReacquire(
                originalRecord.TransactionId,
                out var snapshot,
                out var record))
        {
            return EnterBlockedOnce(
                originalRecord,
                originalSnapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous);
        }

        if (record.Phase
                == ProtectedTransactionPhase.AppliedAwaitingHealth
            && SelectRoute(
                    record.Phase,
                    snapshot.Observation)
                == TransactionRecoveryRoute.AwaitHealth)
        {
            return Result(
                TransactionRecoveryOutcome.AwaitHealth,
                TransactionRecoveryRoute.AwaitHealth,
                record,
                snapshot,
                cleanupEligible: false);
        }

        if (record.Phase
            == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return Result(
                TransactionRecoveryOutcome.Blocked,
                TransactionRecoveryRoute.Blocked,
                record,
                snapshot,
                cleanupEligible: false);
        }

        return EnterBlockedOnce(
            record,
            snapshot,
            TransactionRecoveryFailure.ExecutionAmbiguous);
    }

    private TransactionRecoveryResult ResolveRecoveryBlocked(
        ProtectedTransactionRecord originalRecord,
        ProtectedJournalRecoveryReadResult originalSnapshot)
    {
        if (!TryReacquire(
                originalRecord.TransactionId,
                out var snapshot,
                out var record))
        {
            return EnterBlockedOnce(
                originalRecord,
                originalSnapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous);
        }

        if (record.Phase
            == ProtectedTransactionPhase.RecoveryBlocked)
        {
            return Result(
                TransactionRecoveryOutcome.Blocked,
                TransactionRecoveryRoute.Blocked,
                record,
                snapshot,
                cleanupEligible: false);
        }

        return EnterBlockedOnce(
            record,
            snapshot,
            TransactionRecoveryFailure.ExecutionAmbiguous);
    }

    private bool TryReacquire(
        ProtectedTransactionId expectedTransactionId,
        out ProtectedJournalRecoveryReadResult snapshot,
        out ProtectedTransactionRecord record)
    {
        snapshot = null!;
        record = null!;

        TransactionRecoveryAcquisition acquisition;
        try
        {
            acquisition = _gateway.AcquireActive();
        }
        catch
        {
            return false;
        }

        return TryValidateReady(
                acquisition,
                out snapshot,
                out record)
            && record.TransactionId == expectedTransactionId;
    }

    private TransactionRecoveryResult ResolveTerminal(
        ProtectedTransactionRecord originalRecord,
        ProtectedJournalRecoveryReadResult originalSnapshot)
    {
        TransactionRecoveryAcquisition acquisition;
        try
        {
            acquisition = _gateway.AcquireActive();
        }
        catch
        {
            return EnterBlockedOnce(
                originalRecord,
                originalSnapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous);
        }

        if (!TryValidateReady(
                acquisition,
                out var snapshot,
                out var record)
            || record.TransactionId
                != originalRecord.TransactionId)
        {
            return EnterBlockedOnce(
                originalRecord,
                originalSnapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous);
        }

        var route = SelectRoute(
            record.Phase,
            snapshot.Observation);
        return route switch
        {
            TransactionRecoveryRoute.CleanupCommitted =>
                Result(
                    TransactionRecoveryOutcome.New,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: true),
            TransactionRecoveryRoute.CleanupRolledBack =>
                Result(
                    TransactionRecoveryOutcome.Old,
                    route,
                    record,
                    snapshot,
                    cleanupEligible: true),
            _ when record.Phase
                == ProtectedTransactionPhase.RecoveryBlocked =>
                    Result(
                        TransactionRecoveryOutcome.Blocked,
                        TransactionRecoveryRoute.Blocked,
                        record,
                        snapshot,
                        cleanupEligible: false),
            _ => EnterBlockedOnce(
                record,
                snapshot,
                TransactionRecoveryFailure.ExecutionAmbiguous)
        };
    }

    private TransactionRecoveryResult EnterBlockedForInvalidRoute(
        ProtectedTransactionRecord record,
        ProtectedJournalRecoveryReadResult snapshot)
    {
        var failure = FailureForInvalidRoute(
            record.Phase,
            snapshot.Observation);

        if (record.Phase
                == ProtectedTransactionPhase.RecoveryBlocked
            || !CanEnterRecoveryBlocked(record.Phase))
        {
            return Result(
                TransactionRecoveryOutcome.Blocked,
                TransactionRecoveryRoute.Blocked,
                record,
                snapshot,
                cleanupEligible: false,
                failure);
        }

        return EnterBlockedOnce(
            record,
            snapshot,
            failure);
    }

    private TransactionRecoveryResult EnterBlockedOnce(
        ProtectedTransactionRecord record,
        ProtectedJournalRecoveryReadResult snapshot,
        TransactionRecoveryFailure failure)
    {
        ProtectedTransactionWriteResult persisted;
        try
        {
            persisted = _gateway.EnterRecoveryBlocked(record);
        }
        catch
        {
            return Result(
                TransactionRecoveryOutcome.Blocked,
                TransactionRecoveryRoute.Blocked,
                record,
                snapshot,
                cleanupEligible: false,
                TransactionRecoveryFailure.RecoveryBlockFailed,
                ProtectedTransactionStoreError.IoFailure);
        }

        if (!persisted.Success
            || persisted.Record is not { } blocked
            || persisted.Error
                != ProtectedTransactionStoreError.None
            || blocked.TransactionId != record.TransactionId
            || blocked.Phase
                != ProtectedTransactionPhase.RecoveryBlocked)
        {
            return Result(
                TransactionRecoveryOutcome.Blocked,
                TransactionRecoveryRoute.Blocked,
                record,
                snapshot,
                cleanupEligible: false,
                TransactionRecoveryFailure.RecoveryBlockFailed,
                persisted.Success
                    ? ProtectedTransactionStoreError
                        .VerificationFailed
                    : persisted.Error);
        }

        return Result(
            TransactionRecoveryOutcome.Blocked,
            TransactionRecoveryRoute.Blocked,
            blocked,
            snapshot,
            cleanupEligible: false,
            failure);
    }

    private static bool TryValidateReady(
        TransactionRecoveryAcquisition acquisition,
        out ProtectedJournalRecoveryReadResult snapshot,
        out ProtectedTransactionRecord record)
    {
        snapshot = null!;
        record = null!;
        if (acquisition.Status
                != TransactionRecoveryAcquisitionStatus.Ready
            || acquisition.Error
                != ProtectedTransactionStoreError.None
            || acquisition.ActiveTransactionId is not
            { IsValid: true } active
            || acquisition.Snapshot is not
            {
                Success: true,
                Error: ProtectedTransactionStoreError.None,
                Record: not null,
                RecordBytes: { Length: > 0 }
            } candidate
            || candidate.Record.TransactionId != active)
        {
            return false;
        }

        snapshot = candidate;
        record = candidate.Record;
        return true;
    }

    private static bool CanEnterRecoveryBlocked(
        ProtectedTransactionPhase phase) =>
        phase is
            ProtectedTransactionPhase.CloseAuthorized
                or ProtectedTransactionPhase.Prepared
                or ProtectedTransactionPhase.BackingUp
                or ProtectedTransactionPhase.Applying
                or ProtectedTransactionPhase
                    .AppliedAwaitingHealth
                or ProtectedTransactionPhase.RollingBack;

    private static TransactionRecoveryFailure FailureForInvalidRoute(
        ProtectedTransactionPhase phase,
        ProtectedJournalObservation observation)
    {
        if (!Enum.IsDefined(phase))
        {
            return TransactionRecoveryFailure.UnknownPhase;
        }

        if (!Enum.IsDefined(observation))
        {
            return TransactionRecoveryFailure.UnknownObservation;
        }

        return observation switch
        {
            ProtectedJournalObservation.MissingButBound =>
                TransactionRecoveryFailure.MissingBoundJournal,
            ProtectedJournalObservation.HashMismatch =>
                TransactionRecoveryFailure.JournalHashMismatch,
            ProtectedJournalObservation.Unavailable =>
                TransactionRecoveryFailure.CorruptState,
            ProtectedJournalObservation.PresentButUnbound =>
                TransactionRecoveryFailure.UnsafeOneAheadJournal,
            _ when phase
                == ProtectedTransactionPhase.RecoveryBlocked =>
                    TransactionRecoveryFailure.None,
            _ => TransactionRecoveryFailure.CorruptState
        };
    }

    private static TransactionRecoveryResult Old() =>
        new(
            TransactionRecoveryOutcome.Old,
            TransactionRecoveryRoute.ContinueOld,
            TransactionId: null,
            Phase: null,
            Observation: null,
            CleanupEligible: false,
            TransactionRecoveryFailure.None,
            ProtectedTransactionStoreError.None);

    private static TransactionRecoveryResult Blocked(
        TransactionRecoveryFailure failure,
        ProtectedTransactionStoreError error) =>
        new(
            TransactionRecoveryOutcome.Blocked,
            TransactionRecoveryRoute.Blocked,
            TransactionId: null,
            Phase: null,
            Observation: null,
            CleanupEligible: false,
            failure,
            error);

    private static TransactionRecoveryResult Result(
        TransactionRecoveryOutcome outcome,
        TransactionRecoveryRoute route,
        ProtectedTransactionRecord record,
        ProtectedJournalRecoveryReadResult snapshot,
        bool cleanupEligible,
        TransactionRecoveryFailure failure =
            TransactionRecoveryFailure.None,
        ProtectedTransactionStoreError storeError =
            ProtectedTransactionStoreError.None) =>
        new(
            outcome,
            route,
            record.TransactionId,
            record.Phase,
            snapshot.Observation,
            cleanupEligible,
            failure,
            storeError);
}