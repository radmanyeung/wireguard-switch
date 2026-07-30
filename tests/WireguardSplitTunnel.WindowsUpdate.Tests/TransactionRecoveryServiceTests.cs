using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class TransactionRecoveryServiceTests
{
    private static readonly ProtectedTransactionId TransactionId =
        new(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"));

    public static IEnumerable<object[]> BoundRestartRoutes()
    {
        yield return RouteCase(ProtectedTransactionPhase.ProtectedStaged, ProtectedJournalObservation.AbsentInitial, TransactionRecoveryRoute.ContinueOld);
        yield return RouteCase(ProtectedTransactionPhase.CloseAuthorized, ProtectedJournalObservation.AbsentInitial, TransactionRecoveryRoute.ResumeApply);
        yield return RouteCase(ProtectedTransactionPhase.CloseAuthorized, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.ResumeApply);
        yield return RouteCase(ProtectedTransactionPhase.Prepared, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.ResumeApply);
        yield return RouteCase(ProtectedTransactionPhase.BackingUp, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.ResumeApply);
        yield return RouteCase(ProtectedTransactionPhase.Applying, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.ResumeApply);
        yield return RouteCase(ProtectedTransactionPhase.AppliedAwaitingHealth, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.AwaitHealth);
        yield return RouteCase(ProtectedTransactionPhase.RollingBack, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.ResumeRollback);
        yield return RouteCase(ProtectedTransactionPhase.Committed, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.CleanupCommitted);
        yield return RouteCase(ProtectedTransactionPhase.RolledBack, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.CleanupRolledBack);
        yield return RouteCase(ProtectedTransactionPhase.RecoveryBlocked, ProtectedJournalObservation.MatchesBoundHash, TransactionRecoveryRoute.Blocked);
    }

    public static IEnumerable<object[]> OneAheadRestartRoutes()
    {
        yield return RouteCase(ProtectedTransactionPhase.CloseAuthorized, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.AdoptOneAhead);
        yield return RouteCase(ProtectedTransactionPhase.Prepared, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.AdoptOneAhead);
        yield return RouteCase(ProtectedTransactionPhase.BackingUp, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.AdoptOneAhead);
        yield return RouteCase(ProtectedTransactionPhase.Applying, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.AdoptOneAhead);
        yield return RouteCase(ProtectedTransactionPhase.RollingBack, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.AdoptOneAhead);
        yield return RouteCase(ProtectedTransactionPhase.ProtectedStaged, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.Blocked);
        yield return RouteCase(ProtectedTransactionPhase.AppliedAwaitingHealth, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.Blocked);
        yield return RouteCase(ProtectedTransactionPhase.Committed, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.Blocked);
        yield return RouteCase(ProtectedTransactionPhase.RolledBack, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.Blocked);
        yield return RouteCase(ProtectedTransactionPhase.RecoveryBlocked, ProtectedJournalObservation.PresentButUnbound, TransactionRecoveryRoute.Blocked);
    }

    public static IEnumerable<object[]> UnsafeJournalObservations()
    {
        yield return [(int)ProtectedJournalObservation.Unavailable];
        yield return [(int)ProtectedJournalObservation.MissingButBound];
        yield return [(int)ProtectedJournalObservation.HashMismatch];
    }

    [Theory]
    [MemberData(nameof(BoundRestartRoutes))]
    public void Route_BoundRestartMatrix_IsDeterministic(
        ProtectedTransactionPhase phase,
        int observationValue,
        int expectedRouteValue)
    {
        TransactionRecoveryService.SelectRoute(
                phase,
                (ProtectedJournalObservation)observationValue)
            .Should()
            .Be((TransactionRecoveryRoute)expectedRouteValue);
    }

    [Theory]
    [MemberData(nameof(OneAheadRestartRoutes))]
    public void Route_OneAheadJournal_IsOnlyDelegatedForSafeAdoption(
        ProtectedTransactionPhase phase,
        int observationValue,
        int expectedRouteValue)
    {
        TransactionRecoveryService.SelectRoute(
                phase,
                (ProtectedJournalObservation)observationValue)
            .Should()
            .Be((TransactionRecoveryRoute)expectedRouteValue);
    }

    [Theory]
    [MemberData(nameof(UnsafeJournalObservations))]
    public void Route_UnsafeJournal_IsBlocked(int observationValue)
    {
        TransactionRecoveryService.SelectRoute(
                ProtectedTransactionPhase.Applying,
                (ProtectedJournalObservation)observationValue)
            .Should()
            .Be(TransactionRecoveryRoute.Blocked);
    }

    [Fact]
    public void Route_UnknownValues_AreBlocked()
    {
        TransactionRecoveryService.SelectRoute(
                (ProtectedTransactionPhase)int.MaxValue,
                ProtectedJournalObservation.MatchesBoundHash)
            .Should().Be(TransactionRecoveryRoute.Blocked);
        TransactionRecoveryService.SelectRoute(
                ProtectedTransactionPhase.Applying,
                (ProtectedJournalObservation)int.MaxValue)
            .Should().Be(TransactionRecoveryRoute.Blocked);
    }

    [Fact]
    public void Recover_NoActiveTransaction_ContinuesOldWithoutExecution()
    {
        var fixture = RecoveryFixture.NoActive();

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Old);
        result.Route.Should().Be(TransactionRecoveryRoute.ContinueOld);
        result.CleanupEligible.Should().BeFalse();
        result.Failure.Should().Be(TransactionRecoveryFailure.None);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_ProtectedStaged_ContinuesOldWithoutExecution()
    {
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.ProtectedStaged,
            ProtectedJournalObservation.AbsentInitial);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Old);
        result.Route.Should().Be(TransactionRecoveryRoute.ContinueOld);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_AppliedAwaitingHealth_ReturnsTypedAwaitHealth()
    {
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.AppliedAwaitingHealth);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.AwaitHealth);
        result.Route.Should().Be(TransactionRecoveryRoute.AwaitHealth);
        result.CleanupEligible.Should().BeFalse();
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Theory]
    [InlineData(ProtectedTransactionPhase.Applying, (int)ProtectedJournalObservation.MatchesBoundHash)]
    [InlineData(ProtectedTransactionPhase.AppliedAwaitingHealth, (int)ProtectedJournalObservation.HashMismatch)]
    public void Recover_AppliedOutcomeWithoutValidatedHealthState_BlocksOnce(
        ProtectedTransactionPhase observedPhase,
        int observationValue)
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.AppliedAwaitingHealth);
        fixture.Gateway.Enqueue(Ready(
            observedPhase,
            (ProtectedJournalObservation)observationValue));

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.ExecutionAmbiguous);
        fixture.Gateway.AcquireCount.Should().Be(2);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Theory]
    [InlineData(ProtectedTransactionPhase.Committed, (int)TransactionRecoveryOutcome.New, (int)TransactionRecoveryRoute.CleanupCommitted)]
    [InlineData(ProtectedTransactionPhase.RolledBack, (int)TransactionRecoveryOutcome.Old, (int)TransactionRecoveryRoute.CleanupRolledBack)]
    public void Recover_TerminalPhase_IsCleanupEligibleWithoutExecution(
        ProtectedTransactionPhase phase,
        int expectedOutcome,
        int expectedRoute)
    {
        var fixture = RecoveryFixture.For(phase);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be((TransactionRecoveryOutcome)expectedOutcome);
        result.Route.Should().Be((TransactionRecoveryRoute)expectedRoute);
        result.CleanupEligible.Should().BeTrue();
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Theory]
    [InlineData(ProtectedTransactionPhase.CloseAuthorized)]
    [InlineData(ProtectedTransactionPhase.Prepared)]
    [InlineData(ProtectedTransactionPhase.BackingUp)]
    [InlineData(ProtectedTransactionPhase.Applying)]
    [InlineData(ProtectedTransactionPhase.RollingBack)]
    public void Recover_ResumablePhase_DelegatesExactlyOnce(
        ProtectedTransactionPhase phase)
    {
        var fixture = RecoveryFixture.For(phase);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.AppliedAwaitingHealth);
        fixture.Gateway.Enqueue(Ready(
            ProtectedTransactionPhase.AppliedAwaitingHealth));

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.AwaitHealth);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Coordinator.LastTransactionId.Should().Be(TransactionId);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
    }

    [Theory]
    [InlineData(ProtectedTransactionPhase.CloseAuthorized)]
    [InlineData(ProtectedTransactionPhase.Prepared)]
    [InlineData(ProtectedTransactionPhase.BackingUp)]
    [InlineData(ProtectedTransactionPhase.Applying)]
    [InlineData(ProtectedTransactionPhase.RollingBack)]
    public void Recover_OneAheadJournal_DelegatesExactlyOnce(
        ProtectedTransactionPhase phase)
    {
        var fixture = RecoveryFixture.For(
            phase,
            ProtectedJournalObservation.PresentButUnbound);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.AppliedAwaitingHealth);
        fixture.Gateway.Enqueue(Ready(
            ProtectedTransactionPhase.AppliedAwaitingHealth));

        fixture.Subject.Recover();

        TransactionRecoveryService.SelectRoute(
                phase,
                ProtectedJournalObservation.PresentButUnbound)
            .Should().Be(TransactionRecoveryRoute.AdoptOneAhead);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Coordinator.LastTransactionId.Should().Be(TransactionId);
    }


    [Theory]
    [InlineData(ProtectedTransactionPhase.Committed, (int)TransactionRecoveryOutcome.New, (int)TransactionRecoveryRoute.CleanupCommitted)]
    [InlineData(ProtectedTransactionPhase.RolledBack, (int)TransactionRecoveryOutcome.Old, (int)TransactionRecoveryRoute.CleanupRolledBack)]
    public void Recover_TerminalExecution_ReacquiresValidatedFinalRecord(
        ProtectedTransactionPhase finalPhase,
        int expectedOutcome,
        int expectedRoute)
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.TerminalState);
        fixture.Gateway.Enqueue(Ready(finalPhase));

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be((TransactionRecoveryOutcome)expectedOutcome);
        result.Route.Should().Be((TransactionRecoveryRoute)expectedRoute);
        result.CleanupEligible.Should().BeTrue();
        fixture.Gateway.AcquireCount.Should().Be(2);
        fixture.Coordinator.ResumeCount.Should().Be(1);
    }

    [Fact]
    public void Recover_TerminalExecutionWithUnverifiableFinalState_BlocksOnce()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.TerminalState);
        fixture.Gateway.Enqueue(TransactionRecoveryAcquisition.Failed(
            ProtectedTransactionStoreError.CorruptData));

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.ExecutionAmbiguous);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
        fixture.Coordinator.ResumeCount.Should().Be(1);
    }

    [Fact]
    public void Recover_RetryableCertifiedBeforeMutation_ReturnsOldWithoutRetry()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Prepared);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.RetryableFailure,
            "preflight",
            NamespaceMutationPossible: false);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Old);
        result.Route.Should().Be(TransactionRecoveryRoute.ContinueOld);
        result.Failure.Should().Be(TransactionRecoveryFailure.ExecutionFailed);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
    }

    [Fact]
    public void Recover_RetryableAfterPossibleMutation_BlocksExactlyOnce()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.RetryableFailure,
            "ambiguous",
            NamespaceMutationPossible: true);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Route.Should().Be(TransactionRecoveryRoute.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.ExecutionAmbiguous);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Fact]
    public void Recover_ExecutorAlreadyBlocked_DoesNotPersistAgain()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.NextResult = new(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        fixture.Gateway.Enqueue(Ready(
            ProtectedTransactionPhase.RecoveryBlocked));

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
    }

    [Fact]
    public void Recover_CoordinatorThrows_EntersBlockedExactlyOnce()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.Exception = new InvalidOperationException("after mutation");

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.ExecutionAmbiguous);
        fixture.Coordinator.ResumeCount.Should().Be(1);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(UnsafeJournalObservations))]
    public void Recover_UnsafeJournal_BlocksAndPreservesEvidence(
        int observationValue)
    {
        var observation = (ProtectedJournalObservation)observationValue;
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.Applying,
            observation);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Route.Should().Be(TransactionRecoveryRoute.Blocked);
        result.Observation.Should().Be(observation);
        result.Failure.Should().Be(observation switch
        {
            ProtectedJournalObservation.MissingButBound =>
                TransactionRecoveryFailure.MissingBoundJournal,
            ProtectedJournalObservation.HashMismatch =>
                TransactionRecoveryFailure.JournalHashMismatch,
            _ => TransactionRecoveryFailure.CorruptState
        });
        fixture.Coordinator.ResumeCount.Should().Be(0);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Fact]
    public void Recover_UnsafeTerminalState_PreservesEvidenceWithoutIllegalMutation()
    {
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.Committed,
            ProtectedJournalObservation.HashMismatch);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Observation.Should().Be(ProtectedJournalObservation.HashMismatch);
        fixture.Coordinator.ResumeCount.Should().Be(0);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
    }

    [Fact]
    public void Recover_AlreadyBlocked_NeverRetries()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.RecoveryBlocked);

        fixture.Subject.Recover();
        fixture.Subject.Recover();

        fixture.Gateway.AcquireCount.Should().Be(2);
        fixture.Gateway.EnterBlockedCount.Should().Be(0);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_UnsafeOneAheadHealthState_NeverExecutes()
    {
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.AppliedAwaitingHealth,
            ProtectedJournalObservation.PresentButUnbound);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.UnsafeOneAheadJournal);
        fixture.Coordinator.ResumeCount.Should().Be(0);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Theory]
    [InlineData((int)TransactionRecoveryAcquisitionStatus.Failed, (int)TransactionRecoveryFailure.GatewayFailure)]
    [InlineData(int.MaxValue, (int)TransactionRecoveryFailure.InvalidSnapshot)]
    public void Recover_AcquisitionFailure_IsBlockedWithoutExecution(
        int statusValue,
        int expectedFailureValue)
    {
        var fixture = RecoveryFixture.NoActive();
        fixture.Gateway.NextAcquisition = new(
            (TransactionRecoveryAcquisitionStatus)statusValue,
            ActiveTransactionId: null,
            Snapshot: null,
            ProtectedTransactionStoreError.CorruptData);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be((TransactionRecoveryFailure)expectedFailureValue);
        result.StoreError.Should().Be(ProtectedTransactionStoreError.CorruptData);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_GatewayThrows_IsBlockedWithoutExecution()
    {
        var fixture = RecoveryFixture.NoActive();
        fixture.Gateway.AcquireException = new IOException("protected read failed");

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.GatewayFailure);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_MismatchedActiveAndRecord_IsBlockedWithoutExecution()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Gateway.NextAcquisition = fixture.Gateway.NextAcquisition with
        {
            ActiveTransactionId = new ProtectedTransactionId(Guid.NewGuid())
        };

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.InvalidSnapshot);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_MissingValidatedRecordBytes_IsBlockedWithoutExecution()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Gateway.NextAcquisition = fixture.Gateway.NextAcquisition with
        {
            Snapshot = fixture.Gateway.NextAcquisition.Snapshot! with
            {
                RecordBytes = null
            }
        };

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.InvalidSnapshot);
        fixture.Coordinator.ResumeCount.Should().Be(0);
    }

    [Fact]
    public void Recover_BlockPersistenceFailure_RemainsBlockedWithoutRetry()
    {
        var fixture = RecoveryFixture.For(
            ProtectedTransactionPhase.Applying,
            ProtectedJournalObservation.HashMismatch);
        fixture.Gateway.BlockResult = ProtectedTransactionWriteResult.Failed(
            ProtectedTransactionStoreError.Conflict);

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.RecoveryBlockFailed);
        result.StoreError.Should().Be(ProtectedTransactionStoreError.Conflict);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
    }

    [Fact]
    public void Recover_BlockPersistenceThrows_RemainsBlockedWithoutRetry()
    {
        var fixture = RecoveryFixture.For(ProtectedTransactionPhase.Applying);
        fixture.Coordinator.Exception = new InvalidOperationException("ambiguous");
        fixture.Gateway.BlockException = new IOException("blocked write failed");

        var result = fixture.Subject.Recover();

        result.Outcome.Should().Be(TransactionRecoveryOutcome.Blocked);
        result.Failure.Should().Be(TransactionRecoveryFailure.RecoveryBlockFailed);
        fixture.Gateway.EnterBlockedCount.Should().Be(1);
        fixture.Coordinator.ResumeCount.Should().Be(1);
    }

    [Fact]
    public void Recover_UnknownPhaseAndObservation_NeverExecute()
    {
        var unknownPhase = RecoveryFixture.For((ProtectedTransactionPhase)int.MaxValue);
        var unknownObservation = RecoveryFixture.For(
            ProtectedTransactionPhase.Applying,
            (ProtectedJournalObservation)int.MaxValue);

        var phaseResult = unknownPhase.Subject.Recover();
        var observationResult = unknownObservation.Subject.Recover();

        phaseResult.Failure.Should().Be(TransactionRecoveryFailure.UnknownPhase);
        observationResult.Failure.Should().Be(TransactionRecoveryFailure.UnknownObservation);
        unknownPhase.Coordinator.ResumeCount.Should().Be(0);
        unknownObservation.Coordinator.ResumeCount.Should().Be(0);
        unknownPhase.Gateway.EnterBlockedCount.Should().Be(0);
        unknownObservation.Gateway.EnterBlockedCount.Should().Be(1);
    }

    private static object[] RouteCase(
        ProtectedTransactionPhase phase,
        ProtectedJournalObservation observation,
        TransactionRecoveryRoute route) =>
        [phase, (int)observation, (int)route];

    private static TransactionRecoveryAcquisition Ready(
        ProtectedTransactionPhase phase,
        ProtectedJournalObservation observation =
            ProtectedJournalObservation.MatchesBoundHash)
    {
        var record = Record(phase);
        byte[]? journalBytes = observation is
            ProtectedJournalObservation.AbsentInitial
                or ProtectedJournalObservation.MissingButBound
            ? null
            : [7, 8, 9];
        var snapshot = ProtectedJournalRecoveryReadResult.Found(
            record,
            observation,
            recordBytes: [1, 2, 3],
            journalBytes,
            journalSha256: journalBytes is null
                ? null
                : new string('c', 64));
        return TransactionRecoveryAcquisition.Ready(TransactionId, snapshot);
    }

    private static ProtectedTransactionRecord Record(
        ProtectedTransactionPhase phase) =>
        new(
            SchemaVersion: 1,
            TransactionId,
            new SemanticVersion(1, 0, 0),
            PendingUpdateSource.Automatic,
            InstalledRelease: null!,
            Candidate: null!,
            HelperSha256: new string('a', 64),
            phase,
            AuthorizedProcess: null,
            new ProtectedJournalMetadata(
                SchemaVersion: 1,
                Generation: phase == ProtectedTransactionPhase.ProtectedStaged ? 0 : 1,
                Sha256: phase == ProtectedTransactionPhase.ProtectedStaged
                    ? null
                    : new string('b', 64)));

    private sealed class RecoveryFixture
    {
        private RecoveryFixture(
            FakeRecoveryGateway gateway,
            FakeCoordinator coordinator)
        {
            Gateway = gateway;
            Coordinator = coordinator;
            Subject = new TransactionRecoveryService(gateway, coordinator);
        }

        public FakeRecoveryGateway Gateway { get; }
        public FakeCoordinator Coordinator { get; }
        public TransactionRecoveryService Subject { get; }

        public static RecoveryFixture NoActive()
        {
            var gateway = new FakeRecoveryGateway
            {
                NextAcquisition = TransactionRecoveryAcquisition.NoActive()
            };
            return new(gateway, new FakeCoordinator());
        }

        public static RecoveryFixture For(
            ProtectedTransactionPhase phase,
            ProtectedJournalObservation observation =
                ProtectedJournalObservation.MatchesBoundHash)
        {
            var record = Record(phase);
            var gateway = new FakeRecoveryGateway
            {
                NextAcquisition = Ready(phase, observation),
                BlockResult = ProtectedTransactionWriteResult.Completed(
                    record with { Phase = ProtectedTransactionPhase.RecoveryBlocked })
            };
            return new(gateway, new FakeCoordinator());
        }
    }

    private sealed class FakeRecoveryGateway : ITransactionRecoveryGateway
    {
        private readonly Queue<TransactionRecoveryAcquisition> _queued = new();

        public TransactionRecoveryAcquisition NextAcquisition { get; set; } =
            TransactionRecoveryAcquisition.NoActive();
        public Exception? AcquireException { get; set; }
        public ProtectedTransactionWriteResult BlockResult { get; set; } =
            ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.IoFailure);
        public Exception? BlockException { get; set; }
        public int AcquireCount { get; private set; }
        public int EnterBlockedCount { get; private set; }

        public void Enqueue(TransactionRecoveryAcquisition acquisition) =>
            _queued.Enqueue(acquisition);

        public TransactionRecoveryAcquisition AcquireActive()
        {
            AcquireCount++;
            if (AcquireException is not null)
            {
                throw AcquireException;
            }

            return AcquireCount > 1 && _queued.Count > 0
                ? _queued.Dequeue()
                : NextAcquisition;
        }

        public ProtectedTransactionWriteResult EnterRecoveryBlocked(
            ProtectedTransactionRecord expectedRecord)
        {
            EnterBlockedCount++;
            if (BlockException is not null)
            {
                throw BlockException;
            }

            return BlockResult;
        }
    }

    private sealed class FakeCoordinator : ITransactionalUpdateCoordinator
    {
        public TransactionalUpdateExecutionResult NextResult { get; set; } =
            new(TransactionalUpdateExecutionOutcome.RetryableFailure, "default");
        public Exception? Exception { get; set; }
        public int ResumeCount { get; private set; }
        public ProtectedTransactionId? LastTransactionId { get; private set; }

        public TransactionalUpdateExecutionResult Resume(
            ProtectedTransactionId transactionId)
        {
            ResumeCount++;
            LastTransactionId = transactionId;
            if (Exception is not null)
            {
                throw Exception;
            }

            return NextResult;
        }
    }
}