using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdaterCommandLineTests : IDisposable
{
    private readonly string _root;
    private readonly ProtectedTransactionPaths _paths;
    private readonly UpdaterCommandLine _parser;

    public UpdaterCommandLineTests()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "wgst-updater-cli-" + Guid.NewGuid().ToString("N"));
        _paths = new ProtectedTransactionPaths(
            _root,
            new NeverReparse(),
            _ => DriveType.Fixed);
        _parser = new UpdaterCommandLine(
            _paths,
            _ => DriveType.Fixed);
    }

    [Theory]
    [InlineData("apply-after-exit", UpdaterMode.ApplyAfterExit)]
    [InlineData("recover-and-launch", UpdaterMode.RecoverAndLaunch)]
    public void Parse_AcceptsOnlyTheTwoExactModes(
        string value,
        UpdaterMode expected)
    {
        var transaction = ProtectedTransactionId.New();
        var path = RequiredRecordPath(transaction);

        var result = _parser.Parse(
        [
            "--mode",
            value,
            "--transaction",
            path
        ]);

        result.Success.Should().BeTrue();
        result.Error.Should().Be(UpdaterCommandLineError.None);
        result.Command.Should().Be(
            new UpdaterCommand(expected, transaction, path));
    }

    [Theory]
    [MemberData(nameof(InvalidArguments))]
    public void Parse_RejectsMalformedDuplicateMissingAndUnknownArguments(
        string[]? arguments)
    {
        var result = _parser.Parse(arguments);

        result.Success.Should().BeFalse();
        result.Command.Should().BeNull();
        result.Error.Should().Be(
            UpdaterCommandLineError.InvalidArguments);
    }

    [Fact]
    public void Parse_AllowsTheTwoNamedPairsInEitherOrder()
    {
        var transaction = ProtectedTransactionId.New();
        var path = RequiredRecordPath(transaction);

        var result = _parser.Parse(
        [
            "--transaction",
            path,
            "--mode",
            "recover-and-launch"
        ]);

        result.Success.Should().BeTrue();
        result.Command!.Mode.Should().Be(UpdaterMode.RecoverAndLaunch);
        result.Command.TransactionId.Should().Be(transaction);
    }

    [Theory]
    [MemberData(nameof(UnsafePaths))]
    public void Parse_RejectsRelativeUncNonCanonicalAndOutsidePaths(
        Func<UpdaterCommandLineTests, string> createPath)
    {
        var result = _parser.Parse(
        [
            "--mode",
            "recover-and-launch",
            "--transaction",
            createPath(this)
        ]);

        result.Success.Should().BeFalse();
        result.Command.Should().BeNull();
        result.Error.Should().Be(
            UpdaterCommandLineError.UnsafeTransactionPath);
    }

    [Fact]
    public void Parse_RejectsAPathThatNamesOneTransactionButResolvesAnother()
    {
        var first = ProtectedTransactionId.New();
        var second = ProtectedTransactionId.New();
        var firstLayout = _paths.GetLayout(first).Layout!;
        var mismatched = Path.Combine(
            firstLayout.TransactionRoot,
            "..",
            second.DirectoryName,
            "transaction.json");

        var result = _parser.Parse(
        [
            "--mode",
            "apply-after-exit",
            "--transaction",
            mismatched
        ]);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            UpdaterCommandLineError.UnsafeTransactionPath);
    }

    [Fact]
    public void ExitCodes_AreTheLockedProcessContract()
    {
        UpdaterExitCodes.Success.Should().Be(0);
        UpdaterExitCodes.LaunchHandled.Should().Be(10);
        UpdaterExitCodes.ExistingCandidate.Should().Be(20);
        UpdaterExitCodes.RecoveryBlocked.Should().Be(30);
        UpdaterExitCodes.InvalidArguments.Should().Be(64);
        UpdaterExitCodes.Failed.Should().Be(70);
    }

    public static IEnumerable<object?[]> InvalidArguments()
    {
        yield return [null];
        yield return [Array.Empty<string>()];
        yield return [new[] { "--mode", "recover-and-launch" }];
        yield return
        [
            new[]
            {
                "--mode",
                "RECOVER-AND-LAUNCH",
                "--transaction",
                @"C:\ProgramData\WireguardSplitTunnel\UpdateTransactions\0123456789abcdef0123456789abcdef\transaction.json"
            }
        ];
        yield return
        [
            new[]
            {
                "--mode",
                "recover-and-launch",
                "--mode",
                "apply-after-exit"
            }
        ];
        yield return
        [
            new[]
            {
                "--mode",
                "recover-and-launch",
                "--transaction",
                "value",
                "--unknown",
                "value"
            }
        ];
        yield return
        [
            new[]
            {
                "recover-and-launch",
                "--mode",
                "value",
                "--transaction"
            }
        ];
        yield return
        [
            new[]
            {
                "--mode",
                "recover-and-launch",
                "--transaction",
                ""
            }
        ];
    }

    public static IEnumerable<object[]> UnsafePaths()
    {
        yield return [new Func<UpdaterCommandLineTests, string>(_ => "transaction.json")];
        yield return [new Func<UpdaterCommandLineTests, string>(_ => @"\\server\share\transaction.json")];
        yield return
        [
            new Func<UpdaterCommandLineTests, string>(fixture =>
            {
                var id = ProtectedTransactionId.New();
                return fixture.RequiredRecordPath(id)
                    .Replace(id.DirectoryName, id.DirectoryName.ToUpperInvariant(), StringComparison.Ordinal);
            })
        ];
        yield return
        [
            new Func<UpdaterCommandLineTests, string>(fixture =>
                Path.Combine(
                    fixture._root,
                    "UpdateTransactions",
                    "not-a-guid",
                    "transaction.json"))
        ];
        yield return
        [
            new Func<UpdaterCommandLineTests, string>(fixture =>
                Path.Combine(
                    Path.GetDirectoryName(fixture._root)!,
                    "outside",
                    Guid.NewGuid().ToString("N"),
                    "transaction.json"))
        ];
        yield return
        [
            new Func<UpdaterCommandLineTests, string>(fixture =>
            {
                var id = ProtectedTransactionId.New();
                return Path.Combine(
                    fixture._paths.GetLayout(id).Layout!.TransactionRoot,
                    "other.json");
            })
        ];
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private string RequiredRecordPath(
        ProtectedTransactionId transactionId) =>
        _paths.GetLayout(transactionId).Layout!.TransactionRecordPath;

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }
}

public sealed class UpdaterApplyAfterExitTests
{
    [Fact]
    public void Run_HoldsTheValidatedOldProcessBeforeReadyAndAppliesOnlyAfterExit()
    {
        var fixture = new ApplyFixture();
        fixture.Lease.WaitResult = new(
            ProcessWaitStatus.Exited);

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.AppliedAwaitingHealth);
        fixture.Events.Should().Equal(
            "open",
            "ready",
            "wait:60000",
            "resume",
            "dispose");
        fixture.Writer.Lines.Should().Equal(
            $"READY {fixture.Transaction.DirectoryName}");
    }

    [Theory]
    [InlineData(ProcessWaitStatus.StillRunning, (int)ApplyAfterExitError.ProcessStillRunning)]
    [InlineData(ProcessWaitStatus.Failed, (int)ApplyAfterExitError.ProcessWaitFailed)]
    [InlineData(ProcessWaitStatus.Disposed, (int)ApplyAfterExitError.ProcessWaitFailed)]
    [InlineData(ProcessWaitStatus.InvalidTimeout, (int)ApplyAfterExitError.ProcessWaitFailed)]
    public void Run_WaitFailureOrTimeoutLeavesCloseAuthorizedRetryable(
        ProcessWaitStatus status,
        int expected)
    {
        var fixture = new ApplyFixture();
        fixture.Lease.WaitResult = new(status);

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.RetryableFailure);
        result.Error.Should().Be((ApplyAfterExitError)expected);
        fixture.Boundary.ResumeCalls.Should().Be(0);
        fixture.Events.Should().NotContain("resume");
        fixture.Lease.Disposed.Should().BeTrue();
    }

    [Fact]
    public void Run_OpenFailureWritesNoReadyAndPerformsNoMutation()
    {
        var fixture = new ApplyFixture();
        fixture.Boundary.OpenResult =
            UpdaterAuthorizedProcessOpenResult.Failed(
                ApplyAfterExitError.AuthorizedProcessMismatch);

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.RetryableFailure);
        result.Error.Should().Be(
            ApplyAfterExitError.AuthorizedProcessMismatch);
        fixture.Writer.Lines.Should().BeEmpty();
        fixture.Boundary.ResumeCalls.Should().Be(0);
        fixture.Lease.WaitCalls.Should().Be(0);
    }

    [Fact]
    public void Run_ReadyWriteFailurePerformsNoWaitOrMutation()
    {
        var fixture = new ApplyFixture();
        fixture.Writer.Success = false;

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.RetryableFailure);
        result.Error.Should().Be(
            ApplyAfterExitError.ReadyWriteFailed);
        fixture.Lease.WaitCalls.Should().Be(0);
        fixture.Boundary.ResumeCalls.Should().Be(0);
        fixture.Lease.Disposed.Should().BeTrue();
    }

    [Fact]
    public void Run_MapsAnExecutorRecoveryBlockWithoutLaunchingAnything()
    {
        var fixture = new ApplyFixture();
        fixture.Lease.WaitResult = new(ProcessWaitStatus.Exited);
        fixture.Boundary.ExecutionResult = new(
            TransactionalUpdateExecutionOutcome.RecoveryBlocked,
            NamespaceMutationPossible: true);

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.RecoveryBlocked);
        result.Error.Should().Be(ApplyAfterExitError.None);
    }

    [Fact]
    public void Run_MapsExecutorRetryableFailureAndPreservesItsMutationProvenance()
    {
        var fixture = new ApplyFixture();
        fixture.Lease.WaitResult = new(ProcessWaitStatus.Exited);
        fixture.Boundary.ExecutionResult = new(
            TransactionalUpdateExecutionOutcome.RetryableFailure,
            "phase_write",
            NamespaceMutationPossible: true);

        var result = fixture.Service.Run(fixture.Command);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.RetryableFailure);
        result.Error.Should().Be(
            ApplyAfterExitError.ApplyFailed);
        result.NamespaceMutationPossible.Should().BeTrue();
    }

    [Fact]
    public void Run_RejectsRecoverModeBeforeOpeningAProcess()
    {
        var fixture = new ApplyFixture();
        var wrongMode = fixture.Command with
        {
            Mode = UpdaterMode.RecoverAndLaunch
        };

        var result = fixture.Service.Run(wrongMode);

        result.Outcome.Should().Be(
            ApplyAfterExitOutcome.InvalidRequest);
        result.Error.Should().Be(
            ApplyAfterExitError.InvalidRequest);
        fixture.Events.Should().BeEmpty();
    }

    private sealed class ApplyFixture
    {
        public ApplyFixture()
        {
            Transaction = ProtectedTransactionId.New();
            Command = new UpdaterCommand(
                UpdaterMode.ApplyAfterExit,
                Transaction,
                Path.Combine(
                    @"C:\ProgramData\WireguardSplitTunnel\UpdateTransactions",
                    Transaction.DirectoryName,
                    "transaction.json"));
            Lease = new FakeLease(Events);
            Boundary = new FakeApplyBoundary(Events, Lease);
            Writer = new FakeReadyWriter(Events);
            Service = new UpdaterApplyAfterExitService(
                Boundary,
                Writer,
                TimeSpan.FromSeconds(60));
        }

        public List<string> Events { get; } = [];
        public ProtectedTransactionId Transaction { get; }
        public UpdaterCommand Command { get; }
        public FakeLease Lease { get; }
        public FakeApplyBoundary Boundary { get; }
        public FakeReadyWriter Writer { get; }
        public UpdaterApplyAfterExitService Service { get; }
    }

    private sealed class FakeApplyBoundary(
        List<string> events,
        FakeLease lease) : IUpdaterApplyAfterExitBoundary
    {
        public UpdaterAuthorizedProcessOpenResult OpenResult { get; set; } =
            UpdaterAuthorizedProcessOpenResult.Opened(lease);

        public TransactionalUpdateExecutionResult ExecutionResult { get; set; } =
            new(TransactionalUpdateExecutionOutcome.AppliedAwaitingHealth);

        public int ResumeCalls { get; private set; }

        public UpdaterAuthorizedProcessOpenResult OpenAuthorizedProcess(
            UpdaterCommand command)
        {
            events.Add("open");
            return OpenResult;
        }

        public TransactionalUpdateExecutionResult Resume(
            ProtectedTransactionId transactionId)
        {
            ResumeCalls++;
            events.Add("resume");
            return ExecutionResult;
        }
    }

    private sealed class FakeReadyWriter(List<string> events)
        : IUpdaterReadyWriter
    {
        public bool Success { get; set; } = true;
        public List<string> Lines { get; } = [];

        public bool WriteReady(ProtectedTransactionId transactionId)
        {
            events.Add("ready");
            Lines.Add($"READY {transactionId.DirectoryName}");
            return Success;
        }
    }

    private sealed class FakeLease(List<string> events)
        : IUpdaterAuthorizedProcessLease
    {
        public ProcessWaitResult WaitResult { get; set; } =
            new(ProcessWaitStatus.StillRunning);

        public int WaitCalls { get; private set; }
        public bool Disposed { get; private set; }

        public ProcessWaitResult WaitForExit(TimeSpan timeout)
        {
            WaitCalls++;
            events.Add($"wait:{timeout.TotalMilliseconds:0}");
            return WaitResult;
        }

        public void Dispose()
        {
            Disposed = true;
            events.Add("dispose");
        }
    }
}

[Collection(ProtectedUpdateMutexCollection.CollectionName)]
public sealed class ConsoleUpdaterReadyWriterTests
{
    [Fact]
    public void WriteReady_WritesAndFlushesTheExactProtocolLine()
    {
        var transaction = new ProtectedTransactionId(
            Guid.ParseExact(
                "0123456789abcdef0123456789abcdef",
                "N"));
        using var output = new StringWriter();
        var original = Console.Out;
        try
        {
            Console.SetOut(output);

            new ConsoleUpdaterReadyWriter()
                .WriteReady(transaction)
                .Should().BeTrue();
        }
        finally
        {
            Console.SetOut(original);
        }

        output.ToString().Should().Be(
            "READY 0123456789abcdef0123456789abcdef"
            + Environment.NewLine);
    }

    [Fact]
    public void WriteReady_InvalidTransactionWritesNothing()
    {
        using var output = new StringWriter();
        var original = Console.Out;
        try
        {
            Console.SetOut(output);

            new ConsoleUpdaterReadyWriter()
                .WriteReady(default)
                .Should().BeFalse();
        }
        finally
        {
            Console.SetOut(original);
        }

        output.ToString().Should().BeEmpty();
    }
}
