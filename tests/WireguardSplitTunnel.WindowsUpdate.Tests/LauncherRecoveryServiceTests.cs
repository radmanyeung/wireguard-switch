using System.Diagnostics;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Launcher;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class LauncherRecoveryServiceTests
{
    private static readonly ProtectedTransactionId TransactionId =
        new(
            Guid.Parse(
                "00112233-4455-6677-8899-aabbccddeeff"));

    [Fact]
    public void PublicRecoveryActions_AreTheExactLauncherContract()
    {
        Enum.GetNames<LauncherRecoveryAction>()
            .Should()
            .Equal(
                "ContinueNormalLaunch",
                "CandidateLaunchHandled",
                "ExistingCandidateStillRunning",
                "OldVersionLaunchHandled",
                "RecoveryBlocked");
    }

    [Fact]
    public void CandidateCommandLine_ContainsOnlyCanonicalBoundArguments()
    {
        var record = FakeBoundary.Record(
            ProtectedTransactionPhase.AppliedAwaitingHealth);
        var executable = Path.GetFullPath(
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe");

        var built =
            WindowsFailSafeProcessLauncher.TryBuildCommandLine(
                executable,
                LauncherRecoveryService.CandidateArguments(record),
                out var commandLine);

        built.Should().BeTrue();
        commandLine.Should().Be(
            "\"C:\\Program Files\\WireguardSplitTunnel\\WireguardSplitTunnel.App.exe\""
            + " \"--update-transaction\""
            + " \"00112233445566778899aabbccddeeff\""
            + " \"--update-version\" \"2.0.0\"");
        commandLine.Should().NotContain("--mode");
        commandLine.Should().NotContain("--transaction ");
    }

    [Fact]
    public void SuspendedChild_AbortCertifiesItNeverRanAndIsDead()
    {
        var executable = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "WireguardSplitTunnel.TestProcess.exe"));
        var started = new WindowsFailSafeProcessLauncher()
            .StartSuspended(executable, ["wait"]);

        started.Status.Should().Be(
            LauncherProcessStartStatus.Created);
        started.Process.Should().BeOfType<
            WindowsFailSafeLaunchedProcess>();
        using var process = started.Process!;

        ((WindowsFailSafeLaunchedProcess)process)
            .AbortBeforeResume()
            .Should()
            .BeTrue();
    }

    [Fact]
    public void PostCreateFault_AbortsAndCertifiesChildDeathBeforeCleanFailure()
    {
        uint createdProcessId = 0;
        var launcher = new WindowsFailSafeProcessLauncher(
            processId =>
            {
                createdProcessId = processId;
                throw new InvalidOperationException(
                    "Injected after CreateProcess.");
            });
        var executable = Path.GetFullPath(
            Path.Combine(
                AppContext.BaseDirectory,
                "WireguardSplitTunnel.TestProcess.exe"));

        var started = launcher.StartSuspended(
            executable,
            ["wait"]);

        started.Status.Should().Be(
            LauncherProcessStartStatus.CleanFailure);
        createdProcessId.Should().BeGreaterThan(0);
        IsProcessDead(createdProcessId).Should().BeTrue();
    }

    [Fact]
    public void NoActiveTransaction_ContinuesNormalLaunch()
    {
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.ContinueCurrent()
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.ContinueNormalLaunch);
        boundary.Trace.Should().Equal("recover");
    }

    [Fact]
    public void MissingHealth_RevalidatesThenStartsOnlyBoundCandidateArguments()
    {
        var boundary = new FakeBoundary();

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.CandidateLaunchHandled);
        boundary.Trace.Should().Equal(
            "recover",
            "health",
            "revalidate-candidate",
            "start-candidate",
            "record-candidate",
            "resume:4321");
        boundary.CandidateArguments.Should().Equal(
            "--update-transaction",
            TransactionId.DirectoryName,
            "--update-version",
            "2.0.0");
    }

    [Fact]
    public void TamperBeforeCandidateLaunch_BlocksWithoutStartingProcess()
    {
        var boundary = new FakeBoundary
        {
            CandidateRevalidationSucceeds = false
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.Trace.Should().Equal(
            "recover",
            "health",
            "revalidate-candidate",
            "block");
        boundary.CandidateStartCount.Should().Be(0);
    }

    [Fact]
    public void LiveUnconfirmedCandidate_IsReusedWithoutKillOrSecondLaunch()
    {
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.CandidateRunning(),
            Process = LauncherProcessObservation.Running
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction
                .ExistingCandidateStillRunning);
        boundary.CandidateStartCount.Should().Be(0);
        boundary.AbortCount.Should().Be(0);
        boundary.RollbackCount.Should().Be(0);
        boundary.Trace.Should().Equal(
            "recover",
            "health",
            "observe");
    }

    [Theory]
    [InlineData("Exited")]
    [InlineData("PidReused")]
    public void DeadOrReusedCandidate_RollsBackClearsAndStartsOld(
        string observationName)
    {
        var observation =
            Enum.Parse<LauncherProcessObservation>(
                observationName);
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.CandidateRunning(),
            Process = observation
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.OldVersionLaunchHandled);
        boundary.Trace.Should().Equal(
            "recover",
            "health",
            "observe",
            "rollback",
            "start-old",
            "deactivate",
            "resume:7654",
            "cleanup");
        boundary.CandidateStartCount.Should().Be(0);
    }

    [Fact]
    public void AmbiguousCandidateIdentity_BlocksWithoutRollback()
    {
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.CandidateRunning(),
            Process = LauncherProcessObservation.Ambiguous
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.RollbackCount.Should().Be(0);
        boundary.OldStartCount.Should().Be(0);
        boundary.BlockCount.Should().Be(1);
    }

    [Theory]
    [InlineData(
        "Running",
        LauncherRecoveryAction.ExistingCandidateStillRunning)]
    [InlineData(
        "Exited",
        LauncherRecoveryAction.ContinueNormalLaunch)]
    [InlineData(
        "PidReused",
        LauncherRecoveryAction.ContinueNormalLaunch)]
    public void HealthyMarker_CommitsClearsAndCleansTerminal(
        string observationName,
        LauncherRecoveryAction expected)
    {
        var observation =
            Enum.Parse<LauncherProcessObservation>(
                observationName);
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.Healthy(),
            Process = observation
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(expected);
        boundary.Trace.Should().Equal(
            "recover",
            "health",
            "observe",
            "commit",
            "deactivate",
            "cleanup");
        boundary.CommitCount.Should().Be(1);
        boundary.CleanupCount.Should().Be(1);
    }

    [Fact]
    public void WrongOrCorruptHealthMarker_BlocksWithoutLaunchOrCleanup()
    {
        var boundary = new FakeBoundary
        {
            Health = LauncherHealthObservation.Invalid
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.CandidateStartCount.Should().Be(0);
        boundary.OldStartCount.Should().Be(0);
        boundary.CleanupCount.Should().Be(0);
        boundary.BlockCount.Should().Be(1);
    }

    [Fact]
    public void ExistingRecoveryBlockedState_PerformsNoRetryLaunchOrCleanup()
    {
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.Blocked()
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.Trace.Should().Equal("recover");
        boundary.BlockCount.Should().Be(0);
        boundary.CandidateStartCount.Should().Be(0);
        boundary.OldStartCount.Should().Be(0);
        boundary.CleanupCount.Should().Be(0);
    }

    [Fact]
    public void LiveAuthorizedOldProcess_SuppressesMutationAndSecondLaunch()
    {
        var closeAuthorized = FakeBoundary.Record(
            ProtectedTransactionPhase.CloseAuthorized);
        var boundary = new FakeBoundary
        {
            Recovered =
                LauncherRecoveredTransaction
                    .ExistingAuthorizedProcess(closeAuthorized)
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction
                .ExistingCandidateStillRunning);
        boundary.Trace.Should().Equal("recover");
        boundary.CandidateStartCount.Should().Be(0);
        boundary.OldStartCount.Should().Be(0);
        boundary.RollbackCount.Should().Be(0);
    }

    [Theory]
    [InlineData("Running", "ExistingAuthorizedProcess")]
    [InlineData("Exited", null)]
    [InlineData("PidReused", null)]
    [InlineData("Ambiguous", "Blocked")]
    public void CloseAuthorized_GatesRecoveryOnFreshOldProcessIdentity(
        string observationName,
        string? expectedKind)
    {
        var record = FakeBoundary.Record(
            ProtectedTransactionPhase.CloseAuthorized);
        var observation =
            Enum.Parse<LauncherProcessObservation>(
                observationName);

        var routed =
            ProtectedLauncherRecoveryBoundary
                .RouteAuthorizedOldProcess(
                    record,
                    observation);

        if (expectedKind is null)
        {
            routed.Should().BeNull();
        }
        else
        {
            routed.Should().NotBeNull();
            routed!.Kind.ToString().Should().Be(expectedKind);
        }
    }

    [Theory]
    [InlineData(5, "Ambiguous")]
    [InlineData(87, "Exited")]
    [InlineData(1234, "Ambiguous")]
    public void ProductionBoundary_OnlyDefinitiveMissingPidMapsToExited(
        int nativeErrorCode,
        string expectedName)
    {
        var opened = new ProcessIdentityOpenResult(
            Success: false,
            ProcessIdentityOpenStatus.ProcessUnavailable,
            Identity: null,
            Lease: null,
            NativeErrorCode: nativeErrorCode);

        var observation =
            ProtectedLauncherRecoveryBoundary
                .MapFailedProcessOpen(opened);

        observation.ToString().Should().Be(expectedName);
    }

    [Fact]
    public void CleanCreateProcessFailure_RollsBackAndStartsOld()
    {
        var boundary = new FakeBoundary
        {
            CandidateStart = LauncherProcessStartResult.CleanFailure()
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.OldVersionLaunchHandled);
        boundary.RollbackCount.Should().Be(1);
        boundary.OldStartCount.Should().Be(1);
        boundary.BlockCount.Should().Be(0);
    }

    [Fact]
    public void AmbiguousCreateProcessFailure_BlocksAndPreservesEvidence()
    {
        var boundary = new FakeBoundary
        {
            CandidateStart =
                LauncherProcessStartResult.AmbiguousFailure()
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.RollbackCount.Should().Be(0);
        boundary.OldStartCount.Should().Be(0);
        boundary.CleanupCount.Should().Be(0);
    }

    [Theory]
    [InlineData(
        "CleanNotRecorded",
        true,
        LauncherRecoveryAction.OldVersionLaunchHandled)]
    [InlineData(
        "CleanNotRecorded",
        false,
        LauncherRecoveryAction.RecoveryBlocked)]
    [InlineData(
        "Ambiguous",
        true,
        LauncherRecoveryAction.RecoveryBlocked)]
    public void MarkerFailure_RequiresCertifiedNeverRanDeadForRollback(
        string markerName,
        bool abortCertified,
        LauncherRecoveryAction expected)
    {
        var marker =
            Enum.Parse<LauncherCandidateRecordOutcome>(
                markerName);
        var boundary = new FakeBoundary
        {
            CandidateRecord = marker,
            AbortCertifiedNeverRanAndDead = abortCertified
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(expected);
        boundary.AbortCount.Should().Be(1);
        boundary.RollbackCount.Should().Be(
            marker
                    == LauncherCandidateRecordOutcome
                        .CleanNotRecorded
                && abortCertified
                    ? 1
                    : 0);
    }

    [Theory]
    [InlineData(
        "NeverRanAndDead",
        LauncherRecoveryAction.OldVersionLaunchHandled)]
    [InlineData(
        "Ambiguous",
        LauncherRecoveryAction.RecoveryBlocked)]
    public void CandidateResumeFailure_RollsBackOnlyWhenNeverRanDeadIsCertified(
        string resumeName,
        LauncherRecoveryAction expected)
    {
        var resume = Enum.Parse<LauncherResumeOutcome>(
            resumeName);
        var boundary = new FakeBoundary
        {
            CandidateResume = resume
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(expected);
        boundary.RollbackCount.Should().Be(
            resume == LauncherResumeOutcome.NeverRanAndDead
                ? 1
                : 0);
    }

    [Fact]
    public void HealthyClearConflict_BlocksWithoutCleanup()
    {
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.Healthy(),
            Process = LauncherProcessObservation.Exited,
            DeactivateSucceeds = false
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.CommitCount.Should().Be(1);
        boundary.CleanupCount.Should().Be(0);
        boundary.CandidateStartCount.Should().Be(0);
    }

    [Fact]
    public void TerminalCleanupFailure_DoesNotLaunchSecondHealthyInstance()
    {
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.Healthy(),
            Process = LauncherProcessObservation.Running,
            CleanupSucceeds = false
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction
                .ExistingCandidateStillRunning);
        boundary.CleanupCount.Should().Be(1);
        boundary.CandidateStartCount.Should().Be(0);
    }

    [Fact]
    public void OldLaunchClearConflict_AbortsSuspendedOldAndBlocks()
    {
        var boundary = new FakeBoundary
        {
            Health = FakeBoundary.CandidateRunning(),
            Process = LauncherProcessObservation.Exited,
            DeactivateSucceeds = false
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.AbortCount.Should().Be(1);
        boundary.CleanupCount.Should().Be(0);
    }

    [Fact]
    public void OldCreateFailure_PreservesRolledBackPointerForRetry()
    {
        var rolledBack = FakeBoundary.Record(
            ProtectedTransactionPhase.RolledBack);
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.RolledBack(
                rolledBack),
            OldStart = LauncherProcessStartResult.CleanFailure()
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(LauncherRecoveryAction.RecoveryBlocked);
        boundary.DeactivateCount.Should().Be(0);
        boundary.CleanupCount.Should().Be(0);
        boundary.AbortCount.Should().Be(0);
    }

    [Theory]
    [InlineData(
        "NeverRanAndDead",
        LauncherRecoveryAction.ContinueNormalLaunch,
        1)]
    [InlineData(
        "Ambiguous",
        LauncherRecoveryAction.RecoveryBlocked,
        0)]
    public void OldResumeFailure_AfterClearNeverStartsAnotherProcess(
        string resumeName,
        LauncherRecoveryAction expected,
        int expectedCleanup)
    {
        var rolledBack = FakeBoundary.Record(
            ProtectedTransactionPhase.RolledBack);
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.RolledBack(
                rolledBack),
            OldResume = Enum.Parse<LauncherResumeOutcome>(
                resumeName)
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(expected);
        boundary.DeactivateCount.Should().Be(1);
        boundary.CleanupCount.Should().Be(expectedCleanup);
        boundary.OldStartCount.Should().Be(1);
    }

    [Fact]
    public void RecoveredCommitted_UsesHealthyMarkerWithoutSecondCommit()
    {
        var committed = FakeBoundary.Record(
            ProtectedTransactionPhase.Committed);
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.Committed(
                committed),
            Health = FakeBoundary.Healthy(committed),
            Process = LauncherProcessObservation.Exited
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.ContinueNormalLaunch);
        boundary.CommitCount.Should().Be(0);
        boundary.DeactivateCount.Should().Be(1);
        boundary.CleanupCount.Should().Be(1);
    }

    [Fact]
    public void RecoveredRolledBack_StartsOldOnlyInUserLaunchFlow()
    {
        var rolledBack = FakeBoundary.Record(
            ProtectedTransactionPhase.RolledBack);
        var boundary = new FakeBoundary
        {
            Recovered = LauncherRecoveredTransaction.RolledBack(
                rolledBack)
        };

        var action = new LauncherRecoveryService(boundary)
            .RecoverForUserLaunch();

        action.Should().Be(
            LauncherRecoveryAction.OldVersionLaunchHandled);
        boundary.OldStartCount.Should().Be(1);
        boundary.DeactivateCount.Should().Be(1);
    }

    private static bool IsProcessDead(uint processId)
    {
        try
        {
            using var process =
                Process.GetProcessById(checked((int)processId));
            return process.HasExited;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private sealed class FakeBoundary : ILauncherRecoveryBoundary
    {
        private readonly FakeProcess _candidate = new(4321);
        private readonly FakeProcess _old = new(7654);

        public FakeBoundary()
        {
            var record = Record(
                ProtectedTransactionPhase.AppliedAwaitingHealth);
            Recovered =
                LauncherRecoveredTransaction.AwaitingHealth(record);
            Health = LauncherHealthObservation.Missing;
            CandidateStart =
                LauncherProcessStartResult.Created(_candidate);
            OldStart = LauncherProcessStartResult.Created(_old);
            CommitResult = LauncherTerminalResult.Completed(
                record with
                {
                    Phase = ProtectedTransactionPhase.Committed
                });
            RollbackResult = LauncherTerminalResult.Completed(
                record with
                {
                    Phase = ProtectedTransactionPhase.RolledBack
                });
        }

        public LauncherRecoveredTransaction Recovered { get; set; }
        public LauncherHealthObservation Health { get; set; }
        public LauncherProcessObservation Process { get; set; } =
            LauncherProcessObservation.Exited;
        public bool CandidateRevalidationSucceeds { get; set; } = true;
        public LauncherProcessStartResult CandidateStart { get; set; }
        public LauncherProcessStartResult OldStart { get; set; }
        public LauncherCandidateRecordOutcome CandidateRecord
        { get; set; } =
                LauncherCandidateRecordOutcome.Recorded;
        public LauncherResumeOutcome CandidateResume { get; set; } =
            LauncherResumeOutcome.Started;
        public LauncherResumeOutcome OldResume { get; set; } =
            LauncherResumeOutcome.Started;
        public bool AbortCertifiedNeverRanAndDead { get; set; } = true;
        public LauncherTerminalResult CommitResult { get; set; }
        public LauncherTerminalResult RollbackResult { get; set; }
        public bool DeactivateSucceeds { get; set; } = true;
        public bool CleanupSucceeds { get; set; } = true;
        public List<string> Trace { get; } = [];
        public IReadOnlyList<string> CandidateArguments
        { get; private set; } =
                [];
        public int CandidateStartCount { get; private set; }
        public int OldStartCount { get; private set; }
        public int AbortCount { get; private set; }
        public int RollbackCount { get; private set; }
        public int CommitCount { get; private set; }
        public int DeactivateCount { get; private set; }
        public int CleanupCount { get; private set; }
        public int BlockCount { get; private set; }

        public LauncherRecoveredTransaction Recover()
        {
            Trace.Add("recover");
            return Recovered;
        }

        public LauncherHealthObservation ReadHealth(
            ProtectedTransactionRecord record)
        {
            Trace.Add("health");
            return Health;
        }

        public LauncherProcessObservation ObserveProcess(
            ProcessIdentity identity)
        {
            Trace.Add("observe");
            return Process;
        }

        public bool RevalidateCandidate(
            ProtectedTransactionRecord record)
        {
            Trace.Add("revalidate-candidate");
            return CandidateRevalidationSucceeds;
        }

        public LauncherProcessStartResult StartCandidate(
            ProtectedTransactionRecord record,
            IReadOnlyList<string> arguments)
        {
            Trace.Add("start-candidate");
            CandidateStartCount++;
            CandidateArguments = arguments.ToArray();
            return CandidateStart;
        }

        public LauncherCandidateRecordOutcome RecordCandidate(
            ProtectedTransactionRecord record,
            int processId)
        {
            Trace.Add("record-candidate");
            return CandidateRecord;
        }

        public LauncherResumeOutcome ResumeAndRelease(
            ILauncherFailSafeProcess process)
        {
            Trace.Add($"resume:{process.ProcessId}");
            return process.ProcessId == _candidate.ProcessId
                ? CandidateResume
                : OldResume;
        }

        public bool AbortBeforeResume(
            ILauncherFailSafeProcess process)
        {
            Trace.Add($"abort:{process.ProcessId}");
            AbortCount++;
            return AbortCertifiedNeverRanAndDead;
        }

        public LauncherTerminalResult Commit(
            ProtectedTransactionRecord record)
        {
            Trace.Add("commit");
            CommitCount++;
            return CommitResult;
        }

        public LauncherTerminalResult Rollback(
            ProtectedTransactionRecord record)
        {
            Trace.Add("rollback");
            RollbackCount++;
            return RollbackResult;
        }

        public LauncherProcessStartResult StartOld(
            ProtectedTransactionRecord terminalRecord)
        {
            Trace.Add("start-old");
            OldStartCount++;
            return OldStart;
        }

        public bool Deactivate(
            ProtectedTransactionRecord terminalRecord)
        {
            Trace.Add("deactivate");
            DeactivateCount++;
            return DeactivateSucceeds;
        }

        public bool Cleanup(
            ProtectedTransactionRecord terminalRecord)
        {
            Trace.Add("cleanup");
            CleanupCount++;
            return CleanupSucceeds;
        }

        public bool EnterRecoveryBlocked(
            ProtectedTransactionRecord record)
        {
            Trace.Add("block");
            BlockCount++;
            return true;
        }

        public static LauncherHealthObservation CandidateRunning(
            ProtectedTransactionRecord? record = null) =>
            LauncherHealthObservation.CandidateRunning(
                Marker(
                    record ?? Record(
                        ProtectedTransactionPhase
                            .AppliedAwaitingHealth),
                    UpdateHealthMarkerState.CandidateRunning));

        public static LauncherHealthObservation Healthy(
            ProtectedTransactionRecord? record = null) =>
            LauncherHealthObservation.Healthy(
                Marker(
                    record ?? Record(
                        ProtectedTransactionPhase
                            .AppliedAwaitingHealth),
                    UpdateHealthMarkerState.Healthy));

        public static ProtectedTransactionRecord Record(
            ProtectedTransactionPhase phase) =>
            new(
                ProtectedTransactionStore.TransactionSchemaVersion,
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
                    new string('a', 64),
                    [
                        new ProtectedManagedFileIdentity(
                            UpdateReleaseContract
                                .WindowsApplicationPath,
                            1,
                            new string('b', 64))
                    ]),
                new ProtectedCandidateIdentity(
                    new string('c', 64),
                    new string('d', 64),
                    ExpandedBytes: 2),
                new string('e', 64),
                phase,
                new ProcessIdentity(
                    123,
                    456,
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"),
                new ProtectedJournalMetadata(
                    ProtectedTransactionStore.JournalSchemaVersion,
                    Generation: 1,
                    Sha256: new string('f', 64)));

        private static UpdateHealthMarker Marker(
            ProtectedTransactionRecord record,
            UpdateHealthMarkerState state) =>
            new(
                UpdateHealthService.MarkerSchemaVersion,
                record.TransactionId,
                record.Version,
                new ProcessIdentity(
                    4321,
                    987654321,
                    @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe"),
                state);
    }

    private sealed class FakeProcess(int processId)
        : ILauncherFailSafeProcess
    {
        public int ProcessId { get; } = processId;

        public void Dispose()
        {
        }
    }
}
