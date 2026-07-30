using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class TransactionalUpdateExecutorTests
{
    private static readonly ProtectedTransactionId TransactionId =
        new(
            Guid.Parse(
                "00112233-4455-6677-8899-aabbccddeeff"));

    [Fact]
    public void CloseAuthorized_BuildsCanonicalChangedCreatePlanWithManifestLast()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        var executor = new TransactionalUpdateExecutor(
            fixture.Gateway);

        var result = executor.Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        result.NamespaceMutationPossible.Should().BeFalse();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Prepared);
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(1);
        fixture.Gateway.Snapshot.Journal.Should().NotBeNull();
        fixture.Gateway.Snapshot.Journal!.Generation.Should().Be(1);
        fixture.Gateway.Snapshot.Journal.Operations
            .Select(operation =>
                (operation.Kind, operation.TargetRelativePath))
            .Should()
            .Equal(
                (
                    UpdateOperationKind.Replace,
                    UpdateReleaseContract.WindowsApplicationPath),
                (
                    UpdateOperationKind.Create,
                    "assets/new.bin"),
                (
                    UpdateOperationKind.ReplaceManifest,
                    UpdateReleaseContract.ReleaseManifestPath));
        fixture.Gateway.Snapshot.Journal.Operations
            .Should()
            .OnlyContain(operation =>
                operation.State == UpdateOperationState.Planned);
        fixture.Gateway.Snapshot.Journal.Operations
            .Should()
            .NotContain(operation =>
                operation.TargetRelativePath
                    == "assets/unchanged.bin"
                || operation.TargetRelativePath
                    == "assets/obsolete.bin");
        UpdateOperationJournalCodec.TrySerialize(
                fixture.Gateway.Snapshot.Journal,
                out var canonical)
            .Should()
            .BeTrue();
        fixture.Gateway.LastPublishedBytes
            .Should()
            .Equal(canonical);
    }

    [Fact]
    public void Restart_AfterInitialJournalPublish_BindsPreparedWithoutRepublishing()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        var interrupted = false;
        var executor = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (!interrupted
                    && context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterJournalPublish)
                {
                    interrupted = true;
                    throw new InjectedInterruption();
                }
            });

        var first = () => executor.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.CloseAuthorized);
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation
                .PublishedUnbound);
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(0);

        var resumed = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        resumed.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Prepared);
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.Bound);
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(1);
    }

    [Fact]
    public void Restart_BeforeInitialJournalPublish_PublishesExactlyOnce()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .BeforeJournalPublish
                    && context.Phase
                        == ProtectedTransactionPhase.CloseAuthorized)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.PublishCount.Should().Be(0);
        fixture.Gateway.CompareExchangeCount.Should().Be(0);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.CloseAuthorized);
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.AbsentInitial);

        var resumed = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        resumed.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(1);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Prepared);
    }

    [Fact]
    public void Restart_BeforeInitialPhaseCas_BindsWithoutRepublishing()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .BeforePhaseCompareExchange
                    && context.Phase
                        == ProtectedTransactionPhase.CloseAuthorized)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(0);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.CloseAuthorized);
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.PublishedUnbound);

        var resumed = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        resumed.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        fixture.Gateway.PublishCount.Should().Be(1);
        fixture.Gateway.CompareExchangeCount.Should().Be(1);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Prepared);
    }

    [Fact]
    public void CloseAuthorized_InvalidCandidatePlanNeverPublishesOrMutates()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        fixture.Gateway.PlanMaterial =
            fixture.Gateway.PlanMaterial! with
            {
                CandidateManifest =
                    fixture.Gateway.PlanMaterial.CandidateManifest
                        with
                    {
                        Files =
                            [
                                .. fixture.Gateway.PlanMaterial
                                    .CandidateManifest.Files!,
                                new ReleasePayloadFile(
                                    "ASSETS/new.bin",
                                    3,
                                    Hash("case-collision"))
                            ]
                    }
            };
        var executor = new TransactionalUpdateExecutor(
            fixture.Gateway);

        var result = executor.Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        result.NamespaceMutationPossible.Should().BeFalse();
        fixture.Gateway.PublishCount.Should().Be(0);
        fixture.Gateway.CompareExchangeCount.Should().Be(0);
        fixture.Gateway.OpenSessionCount.Should().Be(0);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.CloseAuthorized);
        fixture.Gateway.Snapshot.Journal.Should().BeNull();
    }

    [Fact]
    public void BackupNamespaceChangeFailure_BlocksWithTypedMutationProvenance()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace)
        {
            BackupResult = UpdateFileSystemResult.Failed(
                UpdateFileSystemError.IoFailure,
                namespaceChanged: true)
        };
        fixture.Gateway.FileSession = files;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
        files.BackupCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
    }

    [Fact]
    public void AmbiguousBackupObservation_BlocksWithoutDestructiveRetry()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        files.SetBackupObservation(
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateFileObservation.Unknown);
        fixture.Gateway.FileSession = files;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
        files.BackupCalls.Should().BeEmpty();
    }

    [Fact]
    public void AmbiguousRead_ReturnsTypedPossibleMutationProvenance()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        fixture.Gateway.ReadFailure =
            TransactionalUpdateGatewayFailure.Ambiguous;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.PublishCount.Should().Be(0);
        fixture.Gateway.OpenSessionCount.Should().Be(0);
    }

    [Fact]
    public void Restart_UnsafeRetainedReadEntersRecoveryBlockedExactlyOnce()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        fixture.Gateway.SetUnsafeRetainedRead();
        var executor = new TransactionalUpdateExecutor(
            fixture.Gateway);

        var first = executor.Resume(TransactionId);
        var second = executor.Resume(TransactionId);

        first.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        first.NamespaceMutationPossible.Should().BeTrue();
        second.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        fixture.Gateway.EnterRecoveryBlockedCount.Should().Be(1);
        fixture.Gateway.PublishCount.Should().Be(0);
        fixture.Gateway.CompareExchangeCount.Should().Be(0);
        fixture.Gateway.OpenSessionCount.Should().Be(0);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
    }

    [Fact]
    public void BlockPersistenceFailure_AfterAppliedOperationReturnsRetryableWithPossibleMutation()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        fixture.Gateway.PublishFailureWhen = journal =>
            journal.Operations[0].State
                == UpdateOperationState.WriteComplete;
        fixture.Gateway.EnterRecoveryBlockedFailure =
            TransactionalUpdateGatewayFailure.Ambiguous;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Applying);
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.WriteStarted);
        files.ApplyCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
    }

    [Fact]
    public void RetryableApplyFailure_AfterEarlierWriteCompleteKeepsPossibleMutation()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        files.ApplyResults["assets/new.bin"] =
            UpdateFileSystemResult.Failed(
                UpdateFileSystemError.IoFailure,
                namespaceChanged: false);

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RetryableFailure);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.WriteComplete);
        fixture.Gateway.Snapshot.Journal.Operations[1]
            .State.Should().Be(
                UpdateOperationState.WriteStarted);
    }

    [Fact]
    public void Prepared_PreflightsThenCheckpointsEveryBackupBeforeApplying()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;
        var executor = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterPhaseCompareExchange
                    && context.Phase
                        == ProtectedTransactionPhase.Applying)
                {
                    throw new InjectedInterruption();
                }
            });

        var run = () => executor.Resume(TransactionId);

        run.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.Applying);
        fixture.Gateway.Snapshot.Journal!.Operations
            .Should()
            .OnlyContain(operation =>
                operation.State
                    == UpdateOperationState.BackupComplete);
        files.BackupCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.ReleaseManifestPath);
        files.BackupCalls.Should().NotContain(
            "assets/new.bin");
        fixture.Gateway.Trace.IndexOf("open-session")
            .Should()
            .BeLessThan(
                fixture.Gateway.Trace.IndexOf(
                    "cas:Prepared->BackingUp"));
        fixture.Gateway.Trace.IndexOf(
                "cas:Prepared->BackingUp")
            .Should()
            .BeLessThan(
                fixture.Gateway.Trace.IndexOf(
                "backup:0"));
    }

    [Fact]
    public void Prepared_AmbiguousProductionPreflightEntersRecoveryBlocked()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        fixture.Gateway.OpenSessionFailure =
            TransactionalUpdateGatewayFailure.Ambiguous;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
    }

    [Fact]
    public void BackupCompletePublishFailure_AfterBackupMutationEntersRecoveryBlocked()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;
        fixture.Gateway.PublishFailureWhen = journal =>
            journal.Operations[0].State
                == UpdateOperationState.BackupComplete;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RecoveryBlocked);
        files.BackupCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
    }

    [Fact]
    public void Restart_FromBackupStartedMissing_RetriesBackupExactlyOnce()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.BeforeBackup
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.BackupStarted);
        files.BackupCalls.Should().BeEmpty();

        var resumed = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterPhaseCompareExchange
                    && context.Phase
                        == ProtectedTransactionPhase.Applying)
                {
                    throw new InjectedInterruption();
                }
            });
        var second = () => resumed.Resume(TransactionId);

        second.Should().Throw<InjectedInterruption>();
        files.BackupCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
    }

    [Fact]
    public void Restart_AfterBackupMutation_ObservesExactBackupWithoutDuplicatingIt()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.AfterBackup
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.BackupStarted);
        files.BackupCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);

        var resumed = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterPhaseCompareExchange
                    && context.Phase
                        == ProtectedTransactionPhase.Applying)
                {
                    throw new InjectedInterruption();
                }
            });
        var second = () => resumed.Resume(TransactionId);

        second.Should().Throw<InjectedInterruption>();
        files.BackupCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
    }

    [Fact]
    public void Prepared_ContinuesThroughApplyManifestLastAndFullNewInOneResume()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.AppliedAwaitingHealth);
        fixture.Gateway.Snapshot.Journal!.Operations
            .Should()
            .OnlyContain(operation =>
                operation.State
                    == UpdateOperationState.WriteComplete);
        files.StageCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath,
            "assets/new.bin",
            UpdateReleaseContract.ReleaseManifestPath);
        files.ApplyCalls.Should().Equal(files.StageCalls);
        files.ApplyCalls.Last().Should().Be(
            UpdateReleaseContract.ReleaseManifestPath);
        fixture.Gateway.FullNewCompareExchangeCount
            .Should()
            .Be(1);
        fixture.Gateway.Trace.IndexOf("apply:2")
            .Should()
            .BeLessThan(
                fixture.Gateway.Trace.IndexOf(
                    "cas:Applying->AppliedAwaitingHealth"));
    }

    [Fact]
    public void Restart_FromWriteStartedMissingTemp_StagesAndAppliesOnce()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .BeforeTemporaryWrite
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.WriteStarted);
        files.StageCalls.Should().BeEmpty();
        files.ApplyCalls.Should().BeEmpty();

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        files.StageCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
        files.ApplyCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
    }

    [Fact]
    public void Restart_AfterTemporaryWrite_ReusesExactTempWithoutRestaging()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterTemporaryWrite
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        files.StageCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
        files.ApplyCalls.Should().BeEmpty();

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        files.StageCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
        files.ApplyCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
    }

    [Fact]
    public void Restart_BeforeApply_ReusesExactTempAndAppliesOnce()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.BeforeApply
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.WriteStarted);
        files.StageCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
        files.ApplyCalls.Should().BeEmpty();

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        files.StageCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
        files.ApplyCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
    }

    [Fact]
    public void Restart_AfterApplyBeforeCheckpoint_UsesIdempotentApplyThenCompletes()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.AfterApply
                    && context.OperationOrdinal == 0)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[0]
            .State.Should().Be(
                UpdateOperationState.WriteStarted);
        files.StageCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);
        files.ApplyCalls.Should().Equal(
            UpdateReleaseContract.WindowsApplicationPath);

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        files.StageCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(1);
        files.ApplyCalls.Count(path =>
                path == UpdateReleaseContract
                    .WindowsApplicationPath)
            .Should()
            .Be(2);
    }

    [Fact]
    public void Restart_AfterManifestApply_ConvergesBeforeFullNew()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var manifestOrdinal = fixture.Gateway.Snapshot.Journal!
            .Operations.Single(operation =>
                operation.TargetRelativePath
                    == UpdateReleaseContract.ReleaseManifestPath)
            .Ordinal;
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.AfterApply
                    && context.OperationOrdinal == manifestOrdinal)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Operations[
                manifestOrdinal]
            .State.Should().Be(UpdateOperationState.WriteStarted);
        files.ApplyCalls.Last().Should().Be(
            UpdateReleaseContract.ReleaseManifestPath);
        fixture.Gateway.FullNewCompareExchangeCount
            .Should()
            .Be(0);

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        files.StageCalls.Count(path =>
                path == UpdateReleaseContract.ReleaseManifestPath)
            .Should()
            .Be(1);
        files.ApplyCalls.Count(path =>
                path == UpdateReleaseContract.ReleaseManifestPath)
            .Should()
            .Be(2);
        fixture.Gateway.FullNewCompareExchangeCount
            .Should()
            .Be(1);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.AppliedAwaitingHealth);
    }

    [Fact]
    public void RollingBack_RestoresTouchedOperationsInReverseOrder()
    {
        var (fixture, files) =
            AppliedFixtureWithFiles();
        fixture.Gateway.SetPhase(
            ProtectedTransactionPhase.RollingBack);

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.TerminalState);
        result.NamespaceMutationPossible.Should().BeTrue();
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RolledBack);
        fixture.Gateway.Snapshot.Journal!.Mode.Should().Be(
            UpdateJournalMode.RollingBack);
        fixture.Gateway.Snapshot.Journal.RollbackCursor
            .Should()
            .Be(-1);
        fixture.Gateway.Snapshot.Journal.RollbackMutationStarted
            .Should()
            .BeFalse();
        files.RollbackCalls.Should().Equal(
            UpdateReleaseContract.ReleaseManifestPath,
            "assets/new.bin",
            UpdateReleaseContract.WindowsApplicationPath);
    }

    [Fact]
    public void Restart_AfterRollbackMutation_ReplaysIdempotentRollbackThenCompletes()
    {
        var (fixture, files) =
            AppliedFixtureWithFiles();
        fixture.Gateway.SetPhase(
            ProtectedTransactionPhase.RollingBack);
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterRollback
                    && context.OperationOrdinal == 2)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Mode.Should().Be(
            UpdateJournalMode.RollingBack);
        fixture.Gateway.Snapshot.Journal.RollbackCursor
            .Should()
            .Be(2);
        fixture.Gateway.Snapshot.Journal.RollbackMutationStarted
            .Should()
            .BeTrue();
        files.RollbackCalls.Should().Equal(
            UpdateReleaseContract.ReleaseManifestPath);

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.TerminalState);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RolledBack);
        files.RollbackCalls.Count(path =>
                path == UpdateReleaseContract
                    .ReleaseManifestPath)
            .Should()
            .Be(2);
    }

    [Fact]
    public void Restart_BeforeRollback_ExecutesMutationExactlyOnce()
    {
        var (fixture, files) =
            AppliedFixtureWithFiles();
        fixture.Gateway.SetPhase(
            ProtectedTransactionPhase.RollingBack);
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint.BeforeRollback
                    && context.OperationOrdinal == 2)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.Journal!.Mode.Should().Be(
            UpdateJournalMode.RollingBack);
        fixture.Gateway.Snapshot.Journal.RollbackCursor
            .Should()
            .Be(2);
        fixture.Gateway.Snapshot.Journal.RollbackMutationStarted
            .Should()
            .BeTrue();
        files.RollbackCalls.Should().BeEmpty();

        var result = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);

        result.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.TerminalState);
        files.RollbackCalls.Count(path =>
                path == UpdateReleaseContract.ReleaseManifestPath)
            .Should()
            .Be(1);
        fixture.Gateway.Snapshot.Record.Phase.Should().Be(
            ProtectedTransactionPhase.RolledBack);
    }

    [Fact]
    public void Restart_AfterRollbackEntryPublish_BindsWithoutRepublishingEntry()
    {
        var (fixture, _) =
            AppliedFixtureWithFiles();
        fixture.Gateway.SetPhase(
            ProtectedTransactionPhase.RollingBack);
        var interrupted = new TransactionalUpdateExecutor(
            fixture.Gateway,
            context =>
            {
                if (context.Point
                        == TransactionalUpdateFaultPoint
                            .AfterJournalPublish
                    && context.Phase
                        == ProtectedTransactionPhase.RollingBack)
                {
                    throw new InjectedInterruption();
                }
            });

        var first = () => interrupted.Resume(TransactionId);

        first.Should().Throw<InjectedInterruption>();
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation
                .PublishedUnbound);
        fixture.Gateway.Snapshot.Journal!.Mode.Should().Be(
            UpdateJournalMode.RollingBack);
        var publishCount = fixture.Gateway.PublishCount;
        var generation =
            fixture.Gateway.Snapshot.Journal.Generation;

        var bindingInterrupted =
            new TransactionalUpdateExecutor(
                fixture.Gateway,
                context =>
                {
                    if (context.Point
                            == TransactionalUpdateFaultPoint
                                .AfterPhaseCompareExchange
                        && context.Phase
                            == ProtectedTransactionPhase
                                .RollingBack
                        && context.OperationOrdinal is null)
                    {
                        throw new InjectedInterruption();
                    }
                });
        var second = () =>
            bindingInterrupted.Resume(TransactionId);

        second.Should().Throw<InjectedInterruption>();
        fixture.Gateway.PublishCount.Should().Be(
            publishCount);
        fixture.Gateway.Snapshot.Journal!.Generation
            .Should()
            .Be(generation);
        fixture.Gateway.Snapshot.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.Bound);
    }

    [Fact]
    public void ProductionGateway_MapsBoundStoreReadAndRetainsCasToken()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        UpdateOperationJournalCodec.TrySerialize(
                fixture.Gateway.Snapshot.Journal,
                out var bytes)
            .Should()
            .BeTrue();
        var native = ProtectedJournalRecoveryReadResult.Found(
            fixture.Gateway.Snapshot.Record,
            ProtectedJournalObservation.MatchesBoundHash,
            recordBytes: [1, 2, 3],
            journalBytes: bytes,
            journalSha256: HashBytes(bytes));

        var mapped =
            ProtectedTransactionalUpdateGateway.MapStoreRead(
                native);

        mapped.Success.Should().BeTrue();
        mapped.Failure.Should().Be(
            TransactionalUpdateGatewayFailure.None);
        mapped.Snapshot.Should().NotBeNull();
        mapped.Snapshot!.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.Bound);
        mapped.Snapshot.Journal.Should().BeEquivalentTo(
            fixture.Gateway.Snapshot.Journal);
        mapped.Snapshot.NativeToken.Should().BeSameAs(native);
    }

    [Fact]
    public void ProductionGateway_MapsUnsafeStoreObservationAsAmbiguous()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        UpdateOperationJournalCodec.TrySerialize(
                fixture.Gateway.Snapshot.Journal,
                out var bytes)
            .Should()
            .BeTrue();
        var native = ProtectedJournalRecoveryReadResult.Found(
            fixture.Gateway.Snapshot.Record,
            ProtectedJournalObservation.HashMismatch,
            recordBytes: [1, 2, 3],
            journalBytes: bytes,
            journalSha256: Hash("mismatch"));

        var mapped =
            ProtectedTransactionalUpdateGateway.MapStoreRead(
                native);

        mapped.Success.Should().BeFalse();
        mapped.Failure.Should().Be(
            TransactionalUpdateGatewayFailure.Ambiguous);
        mapped.Snapshot.Should().NotBeNull();
        mapped.Snapshot!.JournalObservation.Should().Be(
            TransactionalUpdateJournalObservation.Unsafe);
        mapped.Snapshot.NativeToken.Should().BeSameAs(native);
    }

    [Fact]
    public void ProductionGateway_UnsafeStoreReadBlocksExactlyOnceAcrossRestart()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        UpdateOperationJournalCodec.TrySerialize(
                fixture.Gateway.Snapshot.Journal,
                out var bytes)
            .Should()
            .BeTrue();
        var native = ProtectedJournalRecoveryReadResult.Found(
            fixture.Gateway.Snapshot.Record,
            ProtectedJournalObservation.HashMismatch,
            recordBytes: [1, 2, 3],
            journalBytes: bytes,
            journalSha256: Hash("mismatch"));
        var store = new FakeProtectedGatewayStore(native);
        var gateway = new ProtectedTransactionalUpdateGateway(
            store,
            new ProtectedUpdateMutexContext(wasAbandoned: false),
            new ProtectedTransactionPaths(),
            new ProtectedDirectoryAcl(),
            new UpdateFileSystem());
        var executor = new TransactionalUpdateExecutor(gateway);

        var first = executor.Resume(TransactionId);
        var second = executor.Resume(TransactionId);

        first.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        first.NamespaceMutationPossible.Should().BeTrue();
        second.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked);
        store.EnterRecoveryBlockedCount.Should().Be(1);
        store.PublishCount.Should().Be(0);
        store.CompareExchangeCount.Should().Be(0);
    }

    [Fact]
    public void ProductionFileSession_MapsJournalOperationToDeterministicMutationPaths()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var operation =
            fixture.Gateway.Snapshot.Journal!.Operations[0];

        var success =
            ProtectedTransactionalUpdateFileSession
                .TryCreateOperationInput(
                    operation,
                    out var input);

        success.Should().BeTrue();
        input.Should().NotBeNull();
        input!.TargetRelativePath.Should().Be(
            operation.TargetRelativePath);
        input.BackupRelativePath.Should().Be(
            operation.TargetRelativePath + ".bak");
        input.TemporaryRelativePath.Should().Be(
            operation.TargetRelativePath + ".update-tmp");
        input.OldContent.Should().Be(
            new UpdateFileContentIdentity(
                operation.OldLength!.Value,
                operation.OldSha256!));
        input.NewContent.Should().Be(
            new UpdateFileContentIdentity(
                operation.NewLength,
                operation.NewSha256));
    }

    private sealed class ExecutorFixture
    {
        private ExecutorFixture(FakeGateway gateway)
        {
            Gateway = gateway;
        }

        public FakeGateway Gateway { get; }

        public static ExecutorFixture CloseAuthorized()
        {
            var installed = InstalledFiles();
            var candidate = CandidateManifest(installed);
            var record = new ProtectedTransactionRecord(
                ProtectedTransactionStore
                    .TransactionSchemaVersion,
                TransactionId,
                new SemanticVersion(2, 0, 0),
                PendingUpdateSource.Automatic,
                new ProtectedInstalledReleaseIdentity(
                    @"C:\Program Files\WireguardSplitTunnel",
                    VolumeSerialNumber: 1,
                    RootFileIdLow: 2,
                    RootFileIdHigh: 3,
                    new SemanticVersion(1, 0, 0),
                    new SemanticVersion(1, 0, 0),
                    new SemanticVersion(1, 0, 0),
                    StateSchemaVersion: 1,
                    UpdateReleaseContract.WindowsApplicationPath,
                    UpdateReleaseContract.WindowsUpdaterPath,
                    CurrentManifestSha256:
                        Hash("old-manifest"),
                    installed),
                new ProtectedCandidateIdentity(
                    Hash("archive"),
                    Hash("new-manifest"),
                    ExpandedBytes: 4096),
                Hash("helper"),
                ProtectedTransactionPhase.CloseAuthorized,
                new ProcessIdentity(
                    ProcessId: 42,
                    CreationTimeFileTimeUtc: 1234,
                    ImagePath:
                        @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"),
                new ProtectedJournalMetadata(
                    ProtectedTransactionStore
                        .JournalSchemaVersion,
                    Generation: 0));
            var snapshot = new TransactionalUpdateSnapshot(
                record,
                TransactionalUpdateJournalObservation
                    .AbsentInitial,
                Journal: null,
                JournalSha256: null,
                NativeToken: null);
            var material = new TransactionalUpdatePlanMaterial(
                candidate,
                InstalledManifestLength: 101,
                InstalledManifestSha256:
                    record.InstalledRelease
                        .CurrentManifestSha256,
                CandidateManifestLength: 202,
                CandidateManifestSha256:
                    record.Candidate.NewManifestSha256);
            return new ExecutorFixture(
                new FakeGateway(snapshot, material));
        }
    }

    private sealed class FakeGateway
        : ITransactionalUpdateGateway
    {
        public FakeGateway(
            TransactionalUpdateSnapshot snapshot,
            TransactionalUpdatePlanMaterial planMaterial)
        {
            Snapshot = snapshot;
            PlanMaterial = planMaterial;
        }

        public TransactionalUpdateSnapshot Snapshot { get; private set; }
        public TransactionalUpdatePlanMaterial? PlanMaterial { get; set; }
        public int PublishCount { get; private set; }
        public int CompareExchangeCount { get; private set; }
        public int OpenSessionCount { get; private set; }
        public int FullNewCompareExchangeCount { get; private set; }
        public int EnterRecoveryBlockedCount { get; private set; }
        public byte[] LastPublishedBytes { get; private set; } = [];
        public FakeFileSession? FileSession { get; set; }
        public List<string> Trace { get; } = [];
        public TransactionalUpdateGatewayFailure ReadFailure
        { get; set; }
        public Func<UpdateOperationJournal, bool>?
            PublishFailureWhen
        { get; set; }
        public TransactionalUpdateGatewayFailure
            EnterRecoveryBlockedFailure
        { get; set; }
        public TransactionalUpdateGatewayFailure
            OpenSessionFailure
        { get; set; } =
                TransactionalUpdateGatewayFailure.Retryable;

        public void SetPhase(ProtectedTransactionPhase phase)
        {
            Snapshot = Snapshot with
            {
                Record = Snapshot.Record with
                {
                    Phase = phase
                }
            };
        }

        public void SetUnsafeRetainedRead()
        {
            Snapshot = Snapshot with
            {
                JournalObservation =
                    TransactionalUpdateJournalObservation.Unsafe
            };
            ReadFailure =
                TransactionalUpdateGatewayFailure.Ambiguous;
            RetainSnapshotOnReadFailure = true;
        }

        public bool RetainSnapshotOnReadFailure { get; private set; }

        public TransactionalUpdateGatewayReadResult Read(
            ProtectedTransactionId transactionId)
        {
            if (ReadFailure
                != TransactionalUpdateGatewayFailure.None)
            {
                return new(
                    Snapshot: RetainSnapshotOnReadFailure
                        ? Snapshot
                        : null,
                    ReadFailure);
            }

            return transactionId == Snapshot.Record.TransactionId
                ? new(
                    Snapshot,
                    TransactionalUpdateGatewayFailure.None)
                : new(
                    Snapshot: null,
                    TransactionalUpdateGatewayFailure.Retryable);
        }

        public TransactionalUpdatePlanMaterialResult
            ReadPlanMaterial(
                TransactionalUpdateSnapshot expected) =>
            PlanMaterial is null
                ? new(
                    Material: null,
                    TransactionalUpdateGatewayFailure.Retryable)
                : new(
                    PlanMaterial,
                    TransactionalUpdateGatewayFailure.None);

        public TransactionalUpdateGatewayReadResult
            PublishJournal(
                TransactionalUpdateSnapshot expected,
                ReadOnlyMemory<byte> canonicalJournal)
        {
            PublishCount++;
            Trace.Add("publish");
            LastPublishedBytes = canonicalJournal.ToArray();
            if (!UpdateOperationJournalCodec.TryParseCanonical(
                    LastPublishedBytes,
                    out var journal)
                || journal is null)
            {
                return new(
                    Snapshot: null,
                    TransactionalUpdateGatewayFailure
                        .Ambiguous);
            }

            if (PublishFailureWhen?.Invoke(journal) == true)
            {
                return new(
                    Snapshot: null,
                    TransactionalUpdateGatewayFailure
                        .Ambiguous);
            }

            Snapshot = Snapshot with
            {
                JournalObservation =
                    TransactionalUpdateJournalObservation
                        .PublishedUnbound,
                Journal = journal,
                JournalSha256 = HashBytes(
                    LastPublishedBytes)
            };
            return new(
                Snapshot,
                TransactionalUpdateGatewayFailure.None);
        }

        public TransactionalUpdateGatewayReadResult
            CompareExchange(
                TransactionalUpdateSnapshot expected,
                ProtectedTransactionRecord replacement)
        {
            CompareExchangeCount++;
            if (replacement.Phase
                == ProtectedTransactionPhase.AppliedAwaitingHealth)
            {
                FullNewCompareExchangeCount++;
            }
            Trace.Add(
                $"cas:{Snapshot.Record.Phase}->{replacement.Phase}");
            Snapshot = Snapshot with
            {
                Record = replacement,
                JournalObservation =
                    replacement.Journal.Generation == 0
                        ? TransactionalUpdateJournalObservation
                            .AbsentInitial
                        : TransactionalUpdateJournalObservation
                            .Bound
            };
            return new(
                Snapshot,
                TransactionalUpdateGatewayFailure.None);
        }

        public TransactionalUpdateFileSessionOpenResult
            OpenFileSession(
                TransactionalUpdateSnapshot expected)
        {
            OpenSessionCount++;
            Trace.Add("open-session");
            return FileSession is null
                ? new(
                    Session: null,
                    OpenSessionFailure)
                : new(
                    FileSession,
                    TransactionalUpdateGatewayFailure.None);
        }

        public TransactionalUpdateGatewayReadResult
            EnterRecoveryBlocked(
                TransactionalUpdateSnapshot expected)
        {
            EnterRecoveryBlockedCount++;
            if (EnterRecoveryBlockedFailure
                != TransactionalUpdateGatewayFailure.None)
            {
                return new(
                    Snapshot: null,
                    EnterRecoveryBlockedFailure);
            }

            Snapshot = Snapshot with
            {
                Record = Snapshot.Record with
                {
                    Phase =
                        ProtectedTransactionPhase
                            .RecoveryBlocked
                }
            };
            return new(
                Snapshot,
                TransactionalUpdateGatewayFailure.None);
        }
    }

    private sealed class FakeProtectedGatewayStore
        : IProtectedTransactionalUpdateStore
    {
        private ProtectedJournalRecoveryReadResult _read;

        public FakeProtectedGatewayStore(
            ProtectedJournalRecoveryReadResult read)
        {
            _read = read;
        }

        public int PublishCount { get; private set; }
        public int CompareExchangeCount { get; private set; }
        public int EnterRecoveryBlockedCount { get; private set; }

        public ProtectedJournalRecoveryReadResult
            ReadJournalForRecovery(
                ProtectedUpdateMutexContext authority,
                ProtectedTransactionId transactionId) =>
            transactionId == _read.Record?.TransactionId
                ? _read
                : ProtectedJournalRecoveryReadResult.Failed(
                    ProtectedTransactionStoreError.Missing);

        public ProtectedJournalRecoveryReadResult
            PublishJournalCheckpoint(
                ProtectedUpdateMutexContext authority,
                ProtectedJournalRecoveryReadResult expected,
                ReadOnlyMemory<byte> canonicalJournal)
        {
            PublishCount++;
            return ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        public ProtectedTransactionWriteResult
            CompareExchangeTransaction(
                ProtectedUpdateMutexContext authority,
                ProtectedJournalRecoveryReadResult expected,
                ProtectedTransactionRecord replacement)
        {
            CompareExchangeCount++;
            return ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.Conflict);
        }

        public ProtectedTransactionWriteResult
            EnterRecoveryBlocked(
                ProtectedUpdateMutexContext authority,
                ProtectedTransactionRecord expectedRecord)
        {
            EnterRecoveryBlockedCount++;
            var blocked = expectedRecord with
            {
                Phase = ProtectedTransactionPhase.RecoveryBlocked
            };
            _read = _read with
            {
                Record = blocked
            };
            return ProtectedTransactionWriteResult.Completed(blocked);
        }
    }

    private sealed class FakeFileSession
        : ITransactionalUpdateFileSession
    {
        private readonly Dictionary<string, UpdateFileObservation>
            _targets = new(StringComparer.Ordinal);
        private readonly Dictionary<string, UpdateFileObservation>
            _backups = new(StringComparer.Ordinal);
        private readonly Dictionary<string, UpdateFileObservation>
            _temporaries = new(StringComparer.Ordinal);

        public FakeFileSession(
            UpdateOperationJournal journal,
            List<string>? trace = null)
        {
            Trace = trace ?? [];
            foreach (var operation in journal.Operations)
            {
                _targets[operation.TargetRelativePath] =
                    operation.Existed
                        ? UpdateFileObservation.ExactOld
                        : UpdateFileObservation.Missing;
                _backups[operation.TargetRelativePath] =
                    UpdateFileObservation.Missing;
                _temporaries[operation.TargetRelativePath] =
                    UpdateFileObservation.Missing;
            }
        }

        public List<string> BackupCalls { get; } = [];
        public List<string> StageCalls { get; } = [];
        public List<string> ApplyCalls { get; } = [];
        public List<string> RollbackCalls { get; } = [];
        public UpdateFileSystemResult BackupResult { get; set; } =
            UpdateFileSystemResult.Committed();
        public UpdateFileSystemResult StageResult { get; set; } =
            UpdateFileSystemResult.Committed();
        public UpdateFileSystemResult ApplyResult { get; set; } =
            UpdateFileSystemResult.Committed();
        public Dictionary<string, UpdateFileSystemResult>
            ApplyResults
        { get; } =
                new(StringComparer.Ordinal);
        public Dictionary<string, UpdateFileSystemResult>
            RollbackResults
        { get; } =
                new(StringComparer.Ordinal);
        private List<string> Trace { get; }

        public void SetBackupObservation(
            string relativePath,
            UpdateFileObservation observation) =>
            _backups[relativePath] = observation;

        public UpdateFileObservationResult Observe(
            UpdateOperation operation,
            UpdateFileLocation location) =>
            UpdateFileObservationResult.Observed(
                location switch
                {
                    UpdateFileLocation.Target =>
                        _targets[operation.TargetRelativePath],
                    UpdateFileLocation.Backup =>
                        _backups[operation.TargetRelativePath],
                    UpdateFileLocation.Temporary =>
                        _temporaries[operation.TargetRelativePath],
                    _ => UpdateFileObservation.Unknown
                });

        public UpdateFileSystemResult CreateBackup(
            UpdateOperation operation)
        {
            BackupCalls.Add(operation.TargetRelativePath);
            Trace.Add($"backup:{operation.Ordinal}");
            if (!BackupResult.Success)
            {
                return BackupResult;
            }

            _backups[operation.TargetRelativePath] =
                UpdateFileObservation.ExactOld;
            return BackupResult;
        }

        public UpdateFileSystemResult StageReplacement(
            UpdateOperation operation)
        {
            StageCalls.Add(operation.TargetRelativePath);
            Trace.Add($"stage:{operation.Ordinal}");
            if (!StageResult.Success)
            {
                return StageResult;
            }

            _temporaries[operation.TargetRelativePath] =
                UpdateFileObservation.ExactNew;
            return StageResult;
        }

        public UpdateFileSystemResult Apply(
            UpdateOperation operation)
        {
            ApplyCalls.Add(operation.TargetRelativePath);
            Trace.Add($"apply:{operation.Ordinal}");
            var result = ApplyResults.TryGetValue(
                operation.TargetRelativePath,
                out var configured)
                ? configured
                : ApplyResult;
            if (!result.Success)
            {
                return result;
            }

            _targets[operation.TargetRelativePath] =
                UpdateFileObservation.ExactNew;
            _temporaries[operation.TargetRelativePath] =
                UpdateFileObservation.Missing;
            return result;
        }

        public UpdateFileSystemResult Rollback(
            UpdateOperation operation)
        {
            RollbackCalls.Add(operation.TargetRelativePath);
            Trace.Add($"rollback:{operation.Ordinal}");
            var result = RollbackResults.TryGetValue(
                operation.TargetRelativePath,
                out var configured)
                ? configured
                : UpdateFileSystemResult.Committed();
            if (!result.Success)
            {
                return result;
            }

            _targets[operation.TargetRelativePath] =
                operation.Existed
                    ? UpdateFileObservation.ExactOld
                    : UpdateFileObservation.Missing;
            _temporaries[operation.TargetRelativePath] =
                UpdateFileObservation.Missing;
            return result;
        }

        public void Dispose()
        {
        }
    }

    private static (
        ExecutorFixture Fixture,
        FakeFileSession Files)
        PreparedFixtureWithFiles()
    {
        var fixture = ExecutorFixture.CloseAuthorized();
        new TransactionalUpdateExecutor(fixture.Gateway)
            .Resume(TransactionId);
        var files = new FakeFileSession(
            fixture.Gateway.Snapshot.Journal!,
            fixture.Gateway.Trace);
        fixture.Gateway.FileSession = files;
        return (fixture, files);
    }

    private static (
        ExecutorFixture Fixture,
        FakeFileSession Files)
        AppliedFixtureWithFiles()
    {
        var (fixture, files) =
            PreparedFixtureWithFiles();
        var applied = new TransactionalUpdateExecutor(
                fixture.Gateway)
            .Resume(TransactionId);
        applied.Outcome.Should().Be(
            TransactionalUpdateExecutionOutcome
                .AppliedAwaitingHealth);
        return (fixture, files);
    }

    private sealed class InjectedInterruption : Exception;

    private static ReleaseManifest CandidateManifest(
        IReadOnlyList<ProtectedManagedFileIdentity> installed)
    {
        var installedByPath = installed.ToDictionary(
            file => file.RelativePath,
            StringComparer.Ordinal);
        var files = installed
            .Where(file =>
                file.RelativePath != "assets/obsolete.bin")
            .Select(file =>
                file.RelativePath
                    == UpdateReleaseContract
                        .WindowsApplicationPath
                    ? new ReleasePayloadFile(
                        file.RelativePath,
                        Length: 8,
                        Hash("new-app"))
                    : new ReleasePayloadFile(
                        file.RelativePath,
                        file.Length,
                        file.Sha256))
            .Append(
                new ReleasePayloadFile(
                    "assets/new.bin",
                    Length: 3,
                    Hash("new")))
            .OrderBy(file => file.Path, StringComparer.Ordinal)
            .ToArray();
        installedByPath.Should().ContainKey(
            UpdateReleaseContract.WindowsUpdaterPath);
        return new ReleaseManifest(
            schemaVersion: 1,
            version: "2.0.0",
            runtimeIdentifier:
                UpdateReleaseContract.WindowsRuntimeIdentifier,
            minimumAutoUpdateVersion: "1.0.0",
            rollbackCompatibleFromVersion: "1.0.0",
            stateSchemaVersion: 1,
            entryPoint:
                UpdateReleaseContract.WindowsApplicationPath,
            updaterEntryPoint:
                UpdateReleaseContract.WindowsUpdaterPath,
            requiredLaunchers:
                UpdateReleaseContract.RequiredLauncherPaths,
            files);
    }

    private static IReadOnlyList<ProtectedManagedFileIdentity>
        InstalledFiles()
    {
        var paths = new List<string>
        {
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.WindowsUpdaterPath
        };
        paths.AddRange(
            UpdateReleaseContract.RequiredLauncherPaths);
        paths.Add("assets/obsolete.bin");
        paths.Add("assets/unchanged.bin");
        return paths
            .Distinct(StringComparer.Ordinal)
            .Select(path =>
                new ProtectedManagedFileIdentity(
                    path,
                    path == UpdateReleaseContract
                        .WindowsApplicationPath
                        ? 7
                        : 5,
                    path == UpdateReleaseContract
                        .WindowsApplicationPath
                        ? Hash("old-app")
                        : Hash(path)))
            .OrderBy(
                file => file.RelativePath,
                StringComparer.Ordinal)
            .ToArray();
    }

    private static string Hash(string value) =>
        HashBytes(Encoding.UTF8.GetBytes(value));

    private static string HashBytes(byte[] value) =>
        Convert.ToHexString(
                SHA256.HashData(value))
            .ToLowerInvariant();
}
