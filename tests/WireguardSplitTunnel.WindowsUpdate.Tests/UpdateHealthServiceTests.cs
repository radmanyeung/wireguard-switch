using FluentAssertions;
using System.Text;
using System.Text.Json.Nodes;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdateHealthServiceTests
{
    private static readonly SemanticVersion Version = new(2, 0, 0);
    private const string CandidatePath =
        @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.App.exe";

    [Fact]
    public void RecordCandidate_HoldsTheObservedProcessUntilTheRunningMarkerIsDurable()
    {
        var fixture = new HealthFixture();

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Success.Should().BeTrue();
        result.Marker.Should().Be(new UpdateHealthMarker(
            UpdateHealthService.MarkerSchemaVersion,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity,
            UpdateHealthMarkerState.CandidateRunning));
        fixture.Boundary.Created.Should().Be(1);
        fixture.Boundary.Replaced.Should().Be(0);
        fixture.Boundary.ActiveReads.Should().Be(2);
        fixture.Process.CapturedProcessIds.Should()
            .Equal(fixture.Process.Identity.ProcessId);
        fixture.Process.Lease.Disposed.Should().BeTrue();
    }

    [Fact]
    public void RecordCandidate_IsIdempotentForTheExactPersistedIdentityAndNeverDowngradesHealthy()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Marker = fixture.Marker(
            UpdateHealthMarkerState.Healthy);

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Success.Should().BeTrue();
        result.Marker!.State.Should().Be(
            UpdateHealthMarkerState.Healthy);
        fixture.Boundary.Created.Should().Be(0);
        fixture.Boundary.Replaced.Should().Be(0);
    }

    [Theory]
    [InlineData("transaction")]
    [InlineData("phase")]
    [InlineData("version")]
    public void RecordCandidate_RejectsAnyActiveTransactionMismatchBeforeOpeningTheProcess(
        string mismatch)
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Record = mismatch switch
        {
            "transaction" => fixture.Boundary.Record with
            {
                TransactionId = ProtectedTransactionId.New()
            },
            "phase" => fixture.Boundary.Record with
            {
                Phase = ProtectedTransactionPhase.Applying
            },
            _ => fixture.Boundary.Record with
            {
                Version = new SemanticVersion(2, 0, 1)
            }
        };

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(mismatch switch
        {
            "transaction" => UpdateHealthError.TransactionMismatch,
            "phase" => UpdateHealthError.WrongPhase,
            _ => UpdateHealthError.VersionMismatch
        });
        fixture.Process.CapturedProcessIds.Should().BeEmpty();
        fixture.Boundary.Created.Should().Be(0);
    }

    [Fact]
    public void RecordCandidate_RejectsUnavailableOrUnverifiedProcessesWithoutWriting()
    {
        var unavailable = new HealthFixture();
        unavailable.Process.Error = UpdateHealthError.ProcessUnavailable;

        unavailable.Subject.RecordCandidate(
                unavailable.Authority,
                unavailable.TransactionId,
                Version,
                unavailable.Process.Identity.ProcessId)
            .Error.Should().Be(UpdateHealthError.ProcessUnavailable);
        unavailable.Boundary.Created.Should().Be(0);

        var unverified = new HealthFixture();
        unverified.Boundary.ExecutableVerified = false;

        unverified.Subject.RecordCandidate(
                unverified.Authority,
                unverified.TransactionId,
                Version,
                unverified.Process.Identity.ProcessId)
            .Error.Should().Be(
                UpdateHealthError.ExecutableVerificationFailed);
        unverified.Boundary.Created.Should().Be(0);
        unverified.Process.Lease.Disposed.Should().BeTrue();
    }

    [Fact]
    public void RecordCandidate_RefusesAConflictingPersistedProcessIdentity()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Marker = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning) with
        {
            CandidateProcess = fixture.Process.Identity with
            {
                CreationTimeFileTimeUtc =
                    fixture.Process.Identity.CreationTimeFileTimeUtc + 1
            }
        };

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Error.Should().Be(UpdateHealthError.MarkerConflict);
        fixture.Boundary.Created.Should().Be(0);
        fixture.Boundary.Replaced.Should().Be(0);
    }

    [Fact]
    public void RecordCandidate_RejectsIfTheCapturedHandleBelongsToAnotherPid()
    {
        var fixture = new HealthFixture();

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId + 1);

        result.Error.Should().Be(UpdateHealthError.CandidateMismatch);
        fixture.Boundary.Created.Should().Be(0);
        fixture.Process.Lease.Disposed.Should().BeTrue();
    }

    [Theory]
    [InlineData(0, 2, 0, 0)]
    [InlineData(4321, -1, 0, 0)]
    public void RecordCandidate_RejectsInvalidPidOrVersionWithoutOpeningAProcess(
        int processId,
        int major,
        int minor,
        int patch)
    {
        var fixture = new HealthFixture();

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            new SemanticVersion(major, minor, patch),
            processId);

        result.Error.Should().Be(UpdateHealthError.InvalidRequest);
        fixture.Process.CapturedProcessIds.Should().BeEmpty();
        fixture.Boundary.Created.Should().Be(0);
    }

    [Fact]
    public void ReportHealthy_AtomicallyPromotesOnlyTheMatchingCurrentCandidate()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Marker = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning);

        var result = fixture.Subject.ReportHealthy(
            fixture.Authority,
            fixture.TransactionId,
            Version);

        result.Success.Should().BeTrue();
        result.Marker!.State.Should().Be(
            UpdateHealthMarkerState.Healthy);
        fixture.Process.CaptureCurrentCalls.Should().Be(1);
        fixture.Boundary.Created.Should().Be(0);
        fixture.Boundary.Replaced.Should().Be(1);
        fixture.Process.Lease.Disposed.Should().BeTrue();
    }

    [Fact]
    public void ReportHealthy_RejectsMissingOrMismatchedCandidateMarkersWithoutCreatingOne()
    {
        var missing = new HealthFixture();

        missing.Subject.ReportHealthy(
                missing.Authority,
                missing.TransactionId,
                Version)
            .Error.Should().Be(UpdateHealthError.MarkerMissing);
        missing.Boundary.Created.Should().Be(0);
        missing.Boundary.Replaced.Should().Be(0);

        var mismatch = new HealthFixture();
        mismatch.Boundary.Marker = mismatch.Marker(
            UpdateHealthMarkerState.CandidateRunning) with
        {
            CandidateProcess = mismatch.Process.Identity with
            {
                ProcessId = mismatch.Process.Identity.ProcessId + 1
            }
        };

        mismatch.Subject.ReportHealthy(
                mismatch.Authority,
                mismatch.TransactionId,
                Version)
            .Error.Should().Be(UpdateHealthError.CandidateMismatch);
        mismatch.Boundary.Replaced.Should().Be(0);
    }

    [Fact]
    public void Mutation_RechecksTheProtectedActiveRecordAfterTheMarkerWrite()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.RecordAfterWrite =
            fixture.Boundary.Record with
            {
                Phase = ProtectedTransactionPhase.RollingBack
            };

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Error.Should().Be(UpdateHealthError.WrongPhase);
        fixture.Boundary.Marker.Should().NotBeNull(
            "the durable observation is preserved for recovery");
    }

    [Fact]
    public void Read_RequiresAnExactActiveTransactionAndMatchingMarker()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Marker = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning);

        fixture.Subject.Read(
                fixture.Authority,
                fixture.TransactionId,
                Version)
            .Marker.Should().Be(fixture.Boundary.Marker);

        fixture.Boundary.Marker = fixture.Boundary.Marker with
        {
            Version = new SemanticVersion(9, 9, 9)
        };
        fixture.Subject.Read(
                fixture.Authority,
                fixture.TransactionId,
                Version)
            .Error.Should().Be(UpdateHealthError.MarkerConflict);
    }

    [Fact]
    public void Read_RechecksTheActivePhaseAfterReadingTheMarker()
    {
        var fixture = new HealthFixture();
        fixture.Boundary.Marker = fixture.Marker(
            UpdateHealthMarkerState.Healthy);
        fixture.Boundary.RecordAfterWrite =
            fixture.Boundary.Record with
            {
                Phase = ProtectedTransactionPhase.RollingBack
            };

        var result = fixture.Subject.Read(
            fixture.Authority,
            fixture.TransactionId,
            Version);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(UpdateHealthError.WrongPhase);
        fixture.Boundary.ActiveReads.Should().Be(2);
    }

    [Theory]
    [InlineData("create")]
    [InlineData("replace")]
    public void Boundary_AtomicFailureIsNeverUpgradedByAVisibleDesiredMarker(
        string operation)
    {
        var fixture = new ProductionBoundaryFixture();
        var candidate = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning);
        var expected = operation == "create"
            ? null
            : candidate;
        var replacement = operation == "create"
            ? candidate
            : candidate with
            {
                State = UpdateHealthMarkerState.Healthy
            };
        if (expected is not null)
        {
            fixture.FileSystem.PutMarker(expected);
        }

        fixture.FileSystem.PublishReplacementDespiteFailure = true;
        var result = operation == "create"
            ? fixture.Boundary.CreateMarker(
                fixture.Authority,
                replacement)
            : fixture.Boundary.ReplaceMarker(
                fixture.Authority,
                expected!,
                replacement);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(UpdateHealthError.PersistenceFailed);
        fixture.FileSystem.ReadMarker().Should().Be(replacement);
    }

    [Theory]
    [InlineData("create")]
    [InlineData("replace")]
    public void Boundary_AtomicConflictConvergesOnlyToTheExactDesiredMarker(
        string operation)
    {
        var fixture = new ProductionBoundaryFixture();
        var candidate = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning);
        var expected = operation == "create"
            ? null
            : candidate;
        var replacement = operation == "create"
            ? candidate
            : candidate with
            {
                State = UpdateHealthMarkerState.Healthy
            };
        if (expected is not null)
        {
            fixture.FileSystem.PutMarker(expected);
        }

        fixture.FileSystem.AtomicResult =
            ProtectedAtomicCommitResult.Conflict;
        fixture.FileSystem.PublishReplacementDespiteFailure = true;
        var result = operation == "create"
            ? fixture.Boundary.CreateMarker(
                fixture.Authority,
                replacement)
            : fixture.Boundary.ReplaceMarker(
                fixture.Authority,
                expected!,
                replacement);

        result.Success.Should().BeTrue();
        result.Marker.Should().Be(replacement);
    }

    [Fact]
    public async Task Boundary_CompositeActiveReadWaitsForTheMutationLease()
    {
        var fixture = new ProductionBoundaryFixture();
        using var mutation = fixture.Authority.AcquireMutationLease();
        using var callStarted = new ManualResetEventSlim();
        var read = Task.Run(() =>
        {
            callStarted.Set();
            return fixture.Boundary.ReadActiveTransaction(
                fixture.Authority);
        });
        callStarted.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();

        await Task.Delay(TimeSpan.FromMilliseconds(200));

        fixture.Store.ActiveReads.Should().Be(
            0,
            "the composite read must not enter the Store while another "
            + "transaction mutation is in progress");
        mutation.Dispose();
        var result = await read.WaitAsync(TimeSpan.FromSeconds(5));
        result.Success.Should().BeTrue();
        fixture.Store.ActiveReads.Should().Be(2);
    }

    [Fact]
    public void InvalidOrExpiredAuthorityFailsBeforeAnyBoundaryCall()
    {
        var fixture = new HealthFixture();
        fixture.Authority.Invalidate();

        var result = fixture.Subject.RecordCandidate(
            fixture.Authority,
            fixture.TransactionId,
            Version,
            fixture.Process.Identity.ProcessId);

        result.Error.Should().Be(UpdateHealthError.InvalidAuthority);
        fixture.Boundary.ActiveReads.Should().Be(0);
        fixture.Process.CapturedProcessIds.Should().BeEmpty();
    }

    [Fact]
    public void MarkerCodec_RoundTripsOnlyExactCanonicalProtectedData()
    {
        var fixture = new HealthFixture();
        var marker = fixture.Marker(
            UpdateHealthMarkerState.CandidateRunning);

        ProtectedUpdateHealthBoundary.TrySerialize(
                marker,
                out var first)
            .Should().BeTrue();
        ProtectedUpdateHealthBoundary.TrySerialize(
                marker,
                out var second)
            .Should().BeTrue();
        first.Should().Equal(second);
        ProtectedUpdateHealthBoundary.TryParseCanonical(
                first,
                out var parsed)
            .Should().BeTrue();
        parsed.Should().Be(marker);

        var nonCanonical = Encoding.UTF8.GetBytes(
            " " + Encoding.UTF8.GetString(first));
        ProtectedUpdateHealthBoundary.TryParseCanonical(
                nonCanonical,
                out _)
            .Should().BeFalse();

        var wrongTransaction = JsonNode.Parse(first)!.AsObject();
        wrongTransaction["transactionId"] =
            fixture.TransactionId.DirectoryName.ToUpperInvariant();
        ProtectedUpdateHealthBoundary.TryParseCanonical(
                Encoding.UTF8.GetBytes(
                    wrongTransaction.ToJsonString()),
                out _)
            .Should().BeFalse();

        var unsafeProcess = JsonNode.Parse(first)!.AsObject();
        unsafeProcess["candidateProcess"]!["imagePath"] =
            @"\\server\share\WireguardSplitTunnel.App.exe";
        ProtectedUpdateHealthBoundary.TryParseCanonical(
                Encoding.UTF8.GetBytes(
                    unsafeProcess.ToJsonString()),
                out _)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("state")]
    public void MarkerCodec_RejectsUnknownDuplicateAndWrongCaseFields(
        string mutation)
    {
        var fixture = new HealthFixture();
        ProtectedUpdateHealthBoundary.TrySerialize(
            fixture.Marker(
                UpdateHealthMarkerState.CandidateRunning),
            out var canonical);
        var json = Encoding.UTF8.GetString(canonical);
        var mutated = mutation switch
        {
            "unknown" => json.Replace(
                "{\"schemaVersion\":1,",
                "{\"schemaVersion\":1,\"extra\":true,",
                StringComparison.Ordinal),
            "duplicate" => json.Replace(
                "{\"schemaVersion\":1,",
                "{\"schemaVersion\":1,\"schemaVersion\":1,",
                StringComparison.Ordinal),
            _ => json.Replace(
                "\"CandidateRunning\"",
                "\"candidaterunning\"",
                StringComparison.Ordinal)
        };

        ProtectedUpdateHealthBoundary.TryParseCanonical(
                Encoding.UTF8.GetBytes(mutated),
                out _)
            .Should().BeFalse();
    }

    private sealed class HealthFixture
    {
        public HealthFixture()
        {
            TransactionId = ProtectedTransactionId.New();
            Authority = new ProtectedUpdateMutexContext(
                wasAbandoned: false);
            Process = new FakeProcessCapture(new ProcessIdentity(
                ProcessId: 4321,
                CreationTimeFileTimeUtc: 133_700_000,
                CandidatePath));
            Boundary = new FakeBoundary(
                CreateRecord(TransactionId));
            Subject = new UpdateHealthService(
                Boundary,
                Process);
        }

        public ProtectedTransactionId TransactionId { get; }
        public ProtectedUpdateMutexContext Authority { get; }
        public FakeProcessCapture Process { get; }
        public FakeBoundary Boundary { get; }
        public UpdateHealthService Subject { get; }

        public UpdateHealthMarker Marker(
            UpdateHealthMarkerState state) =>
            new(
                UpdateHealthService.MarkerSchemaVersion,
                TransactionId,
                Version,
                Process.Identity,
                state);
    }

    private sealed class ProductionBoundaryFixture
    {
        public ProductionBoundaryFixture()
        {
            TransactionId = ProtectedTransactionId.New();
            Authority = new ProtectedUpdateMutexContext(
                wasAbandoned: false);
            Record = CreateRecord(TransactionId);
            Store = new FakeHealthTransactionStore(Record);
            FileSystem = new FakeHealthFileSystem();
            Layouts = new FakeHealthLayoutProvider(
                TransactionId,
                CreateLayout(TransactionId));
            Boundary = new ProtectedUpdateHealthBoundary(
                Store,
                FileSystem,
                Layouts);
        }

        public ProtectedTransactionId TransactionId { get; }
        public ProtectedUpdateMutexContext Authority { get; }
        public ProtectedTransactionRecord Record { get; }
        public FakeHealthTransactionStore Store { get; }
        public FakeHealthFileSystem FileSystem { get; }
        public FakeHealthLayoutProvider Layouts { get; }
        public ProtectedUpdateHealthBoundary Boundary { get; }

        public UpdateHealthMarker Marker(
            UpdateHealthMarkerState state) =>
            new(
                UpdateHealthService.MarkerSchemaVersion,
                TransactionId,
                Version,
                new ProcessIdentity(
                    ProcessId: 4321,
                    CreationTimeFileTimeUtc: 133_700_000,
                    CandidatePath),
                state);
    }

    private sealed class FakeHealthTransactionStore
        : IUpdateHealthTransactionStore
    {
        public FakeHealthTransactionStore(
            ProtectedTransactionRecord record)
        {
            Record = record;
        }

        public ProtectedTransactionRecord Record { get; set; }
        public int ActiveReads { get; private set; }

        public ProtectedActiveTransactionReadResult ReadActive(
            ProtectedUpdateMutexContext authority)
        {
            ActiveReads++;
            return ProtectedActiveTransactionReadResult.Found(
                Record.TransactionId);
        }

        public ProtectedTransactionReadResult ReadTransaction(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId) =>
            ProtectedTransactionReadResult.Found(Record);

        public ProtectedJournalRecoveryReadResult
            ReadJournalForRecovery(
                ProtectedUpdateMutexContext authority,
                ProtectedTransactionId transactionId) =>
            ProtectedJournalRecoveryReadResult.Failed(
                ProtectedTransactionStoreError.InvalidData);

        public ProtectedTransactionWriteResult
            CompareExchangeTransaction(
                ProtectedUpdateMutexContext authority,
                ProtectedJournalRecoveryReadResult expected,
                ProtectedTransactionRecord replacement) =>
            ProtectedTransactionWriteResult.Failed(
                ProtectedTransactionStoreError.InvalidData);
    }

    private sealed class FakeHealthLayoutProvider
        : IUpdateHealthLayoutProvider
    {
        private readonly ProtectedTransactionId _transactionId;

        public FakeHealthLayoutProvider(
            ProtectedTransactionId transactionId,
            ProtectedTransactionLayout layout)
        {
            _transactionId = transactionId;
            Layout = layout;
        }

        public ProtectedTransactionLayout Layout { get; }

        public bool TryGetValidatedLayout(
            ProtectedTransactionId transactionId,
            out ProtectedTransactionLayout? layout)
        {
            layout = transactionId == _transactionId
                ? Layout
                : null;
            return layout is not null;
        }
    }

    private sealed class FakeHealthFileSystem
        : IProtectedTransactionFileSystem
    {
        private byte[]? _markerBytes;

        public bool PublishReplacementDespiteFailure { get; set; }

        public ProtectedAtomicCommitResult AtomicResult { get; set; } =
            ProtectedAtomicCommitResult.Failed;

        public bool ValidateProtectedDirectory(string path) => true;

        public ProtectedTransactionFileState InspectProtectedFile(
            string path) =>
            _markerBytes is null
                ? ProtectedTransactionFileState.Missing
                : ProtectedTransactionFileState.Protected;

        public byte[]? ReadProtectedFile(
            string path,
            long maximumBytes) =>
            _markerBytes is not null
                && _markerBytes.LongLength <= maximumBytes
                ? [.. _markerBytes]
                : null;

        public ProtectedAtomicCommitResult AtomicCreate(
            string destinationPath,
            byte[] replacementBytes)
        {
            if (PublishReplacementDespiteFailure)
            {
                _markerBytes = [.. replacementBytes];
            }

            return AtomicResult;
        }

        public ProtectedAtomicCommitResult AtomicCompareExchange(
            string destinationPath,
            byte[] expectedDestinationBytes,
            byte[] replacementBytes)
        {
            if (PublishReplacementDespiteFailure)
            {
                _markerBytes = [.. replacementBytes];
            }

            return AtomicResult;
        }

        public bool HasProtectedProductVersion(
            string path,
            string expectedVersion,
            IExecutableProductVersionReader versionReader) =>
            false;

        public string? ComputeProtectedSha256(
            string path,
            long maximumBytes) =>
            null;

        public IReadOnlyList<ProtectedCandidateFileSnapshot>?
            SnapshotProtectedFiles(
                string path,
                int maximumEntries,
                long maximumBytes) =>
            null;

        public long? MeasureProtectedDirectory(
            string path,
            long maximumBytes) =>
            null;

        public void PutMarker(UpdateHealthMarker marker)
        {
            ProtectedUpdateHealthBoundary.TrySerialize(
                    marker,
                    out _markerBytes)
                .Should()
                .BeTrue();
        }

        public UpdateHealthMarker? ReadMarker()
        {
            ProtectedUpdateHealthBoundary.TryParseCanonical(
                    _markerBytes!,
                    out var marker)
                .Should()
                .BeTrue();
            return marker;
        }
    }

    private sealed class FakeBoundary : IUpdateHealthBoundary
    {
        public FakeBoundary(ProtectedTransactionRecord record)
        {
            Record = record;
        }

        public ProtectedTransactionRecord Record { get; set; }
        public ProtectedTransactionRecord? RecordAfterWrite { get; set; }
        public UpdateHealthMarker? Marker { get; set; }
        public bool ExecutableVerified { get; set; } = true;
        public int ActiveReads { get; private set; }
        public int Created { get; private set; }
        public int Replaced { get; private set; }

        public UpdateHealthTransactionReadResult ReadActiveTransaction(
            ProtectedUpdateMutexContext authority)
        {
            ActiveReads++;
            return UpdateHealthTransactionReadResult.Found(
                ActiveReads > 1 && RecordAfterWrite is not null
                    ? RecordAfterWrite
                    : Record);
        }

        public bool VerifyCandidateExecutable(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionRecord record,
            ProcessIdentity identity) =>
            ExecutableVerified;

        public UpdateHealthMarkerReadResult ReadMarker(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId) =>
            Marker is null
                ? UpdateHealthMarkerReadResult.Missing()
                : UpdateHealthMarkerReadResult.Found(Marker);

        public UpdateHealthMarkerReadResult CreateMarker(
            ProtectedUpdateMutexContext authority,
            UpdateHealthMarker marker)
        {
            if (Marker is not null)
            {
                return UpdateHealthMarkerReadResult.Failed(
                    UpdateHealthError.MarkerConflict);
            }

            Created++;
            Marker = marker;
            return UpdateHealthMarkerReadResult.Found(marker);
        }

        public UpdateHealthMarkerReadResult ReplaceMarker(
            ProtectedUpdateMutexContext authority,
            UpdateHealthMarker expected,
            UpdateHealthMarker replacement)
        {
            if (Marker != expected)
            {
                return UpdateHealthMarkerReadResult.Failed(
                    UpdateHealthError.MarkerConflict);
            }

            Replaced++;
            Marker = replacement;
            return UpdateHealthMarkerReadResult.Found(replacement);
        }
    }

    private sealed class FakeProcessCapture : IUpdateHealthProcessCapture
    {
        public FakeProcessCapture(ProcessIdentity identity)
        {
            Identity = identity;
        }

        public ProcessIdentity Identity { get; }
        public UpdateHealthError Error { get; set; }
        public TrackingLease Lease { get; private set; } = new();
        public List<int> CapturedProcessIds { get; } = [];
        public int CaptureCurrentCalls { get; private set; }

        public UpdateHealthProcessCaptureResult Capture(
            int processId)
        {
            CapturedProcessIds.Add(processId);
            return CreateResult();
        }

        public UpdateHealthProcessCaptureResult CaptureCurrent()
        {
            CaptureCurrentCalls++;
            return CreateResult();
        }

        private UpdateHealthProcessCaptureResult CreateResult()
        {
            if (Error != UpdateHealthError.None)
            {
                return UpdateHealthProcessCaptureResult.Failed(Error);
            }

            Lease = new TrackingLease();
            return UpdateHealthProcessCaptureResult.Captured(
                Identity,
                Lease);
        }
    }

    private sealed class TrackingLease : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }

    private static ProtectedTransactionLayout CreateLayout(
        ProtectedTransactionId transactionId)
    {
        var productRoot = @"C:\ProgramData\WireguardSplitTunnel";
        var transactionsRoot = Path.Combine(
            productRoot,
            "UpdateTransactions");
        var transactionRoot = Path.Combine(
            transactionsRoot,
            transactionId.DirectoryName);
        var helperRoot = Path.Combine(transactionRoot, "helper");
        return new ProtectedTransactionLayout(
            productRoot,
            transactionsRoot,
            Path.Combine(productRoot, "active-transaction.json"),
            transactionRoot,
            Path.Combine(transactionRoot, "transaction.json"),
            Path.Combine(transactionRoot, "journal.json"),
            Path.Combine(transactionRoot, "health.json"),
            helperRoot,
            Path.Combine(
                helperRoot,
                "WireguardSplitTunnel.Updater.exe"),
            Path.Combine(transactionRoot, "candidate"),
            Path.Combine(transactionRoot, "backups"));
    }

    private static ProtectedTransactionRecord CreateRecord(
        ProtectedTransactionId transactionId) =>
        new(
            ProtectedTransactionStore.TransactionSchemaVersion,
            transactionId,
            Version,
            PendingUpdateSource.Manual,
            new ProtectedInstalledReleaseIdentity(
                @"C:\Program Files\WireguardSplitTunnel",
                VolumeSerialNumber: 1,
                RootFileIdLow: 2,
                RootFileIdHigh: 3,
                CurrentVersion: new SemanticVersion(1, 9, 0),
                MinimumAutoUpdateVersion:
                    new SemanticVersion(1, 9, 0),
                RollbackCompatibleFromVersion:
                    new SemanticVersion(1, 9, 0),
                StateSchemaVersion: 1,
                UpdateReleaseContract.WindowsApplicationPath,
                UpdateReleaseContract.WindowsUpdaterPath,
                CurrentManifestSha256: new string('a', 64),
                ManagedFiles: []),
            new ProtectedCandidateIdentity(
                ArchiveSha256: new string('b', 64),
                NewManifestSha256: new string('c', 64),
                ExpandedBytes: 1),
            HelperSha256: new string('d', 64),
            ProtectedTransactionPhase.AppliedAwaitingHealth,
            new ProcessIdentity(
                ProcessId: 1234,
                CreationTimeFileTimeUtc: 133_600_000,
                CandidatePath),
            new ProtectedJournalMetadata(
                ProtectedTransactionStore.JournalSchemaVersion,
                Generation: 1,
                Sha256: new string('e', 64)));
}
