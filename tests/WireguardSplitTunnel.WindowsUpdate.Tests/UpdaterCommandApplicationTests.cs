using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Logging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdaterCommandApplicationTests : IDisposable
{
    private readonly string _root;
    private readonly ProtectedTransactionPaths _paths;
    private readonly UpdaterCommandLine _parser;

    public UpdaterCommandApplicationTests()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "wgst-updater-host-" + Guid.NewGuid().ToString("N"));
        _paths = new ProtectedTransactionPaths(
            _root,
            new NeverReparse(),
            _ => DriveType.Fixed);
        _parser = new UpdaterCommandLine(
            _paths,
            _ => DriveType.Fixed);
    }

    [Fact]
    public async Task RunAsync_InvalidArgumentsNeverEnterProtectedExecution()
    {
        var boundary = new FakeInvocationBoundary();
        var logger = new RecordingLogger();
        var application = new UpdaterCommandApplication(
            _parser,
            boundary,
            logger);

        var exitCode = await application.RunAsync(
            ["--mode", "recover-and-launch"],
            CancellationToken.None);

        exitCode.Should().Be(UpdaterExitCodes.InvalidArguments);
        boundary.Commands.Should().BeEmpty();
        logger.Events.Should().ContainSingle()
            .Which.Should().Be(("invalid_arguments", null, null));
    }

    [Theory]
    [InlineData(
        "AppliedAwaitingHealth",
        UpdaterExitCodes.Success)]
    [InlineData(
        "ContinueNormalLaunch",
        UpdaterExitCodes.Success)]
    [InlineData(
        "LaunchHandled",
        UpdaterExitCodes.LaunchHandled)]
    [InlineData(
        "ExistingCandidate",
        UpdaterExitCodes.ExistingCandidate)]
    [InlineData(
        "RecoveryBlocked",
        UpdaterExitCodes.RecoveryBlocked)]
    [InlineData(
        "Failed",
        UpdaterExitCodes.Failed)]
    public async Task RunAsync_MapsTypedOutcomeToLockedExitCode(
        string outcomeName,
        int expectedExitCode)
    {
        var outcome = Enum.Parse<UpdaterInvocationOutcome>(
            outcomeName);
        var boundary = new FakeInvocationBoundary
        {
            Outcome = outcome
        };
        var logger = new RecordingLogger();
        var application = new UpdaterCommandApplication(
            _parser,
            boundary,
            logger);

        var exitCode = await application.RunAsync(
            ValidArguments(UpdaterMode.RecoverAndLaunch),
            CancellationToken.None);

        exitCode.Should().Be(expectedExitCode);
        boundary.Commands.Should().ContainSingle();
        logger.Events.Should().ContainSingle();
        logger.Events[0].EventCode.Should().MatchRegex(
            "^[a-z0-9_]{1,64}$");
        logger.Events[0].DetailCode.Should().BeNull();
        logger.Events[0].Version.Should().BeNull();
    }

    [Fact]
    public async Task RunAsync_UnexpectedBoundaryFailureIsSanitizedAndFailsClosed()
    {
        var boundary = new FakeInvocationBoundary
        {
            Exception = new InvalidOperationException(
                "secret=C:\\Users\\person\\state.json")
        };
        var logger = new RecordingLogger();
        var application = new UpdaterCommandApplication(
            _parser,
            boundary,
            logger);

        var exitCode = await application.RunAsync(
            ValidArguments(UpdaterMode.ApplyAfterExit),
            CancellationToken.None);

        exitCode.Should().Be(UpdaterExitCodes.Failed);
        logger.Events.Should().ContainSingle()
            .Which.Should().Be(("helper_failed", "unexpected", null));
    }

    [Fact]
    public async Task RunAsync_LoggerFailureCannotChangeTheProtocolResult()
    {
        var boundary = new FakeInvocationBoundary
        {
            Outcome = UpdaterInvocationOutcome.LaunchHandled
        };
        var application = new UpdaterCommandApplication(
            _parser,
            boundary,
            new ThrowingLogger());

        var exitCode = await application.RunAsync(
            ValidArguments(UpdaterMode.RecoverAndLaunch),
            CancellationToken.None);

        exitCode.Should().Be(UpdaterExitCodes.LaunchHandled);
    }

    [Theory]
    [InlineData(
        UpdaterMode.ApplyAfterExit,
        ProtectedUpdateMutexStatus.Busy,
        "Failed")]
    [InlineData(
        UpdaterMode.RecoverAndLaunch,
        ProtectedUpdateMutexStatus.Busy,
        "ExistingCandidate")]
    [InlineData(
        UpdaterMode.RecoverAndLaunch,
        ProtectedUpdateMutexStatus.SecurityMismatch,
        "Failed")]
    [InlineData(
        UpdaterMode.RecoverAndLaunch,
        ProtectedUpdateMutexStatus.ActionFailed,
        "Failed")]
    public void MapMutexFailure_DistinguishesOnlyAConcurrentLauncher(
        UpdaterMode mode,
        ProtectedUpdateMutexStatus status,
        string expectedName)
    {
        var expected = Enum.Parse<UpdaterInvocationOutcome>(
            expectedName);
        ProtectedUpdaterInvocationBoundary
            .MapMutexFailure(mode, status)
            .Should().Be(expected);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private string[] ValidArguments(UpdaterMode mode)
    {
        var transaction = ProtectedTransactionId.New();
        var layout = _paths.GetLayout(transaction);
        layout.Success.Should().BeTrue();
        return
        [
            "--mode",
            mode == UpdaterMode.ApplyAfterExit
                ? "apply-after-exit"
                : "recover-and-launch",
            "--transaction",
            layout.Layout!.TransactionRecordPath
        ];
    }

    private sealed class FakeInvocationBoundary
        : IUpdaterInvocationBoundary
    {
        internal List<UpdaterCommand> Commands { get; } = [];

        internal UpdaterInvocationOutcome Outcome { get; init; } =
            UpdaterInvocationOutcome.ContinueNormalLaunch;

        internal Exception? Exception { get; init; }

        public Task<UpdaterInvocationOutcome> InvokeAsync(
            UpdaterCommand command,
            CancellationToken cancellationToken)
        {
            Commands.Add(command);
            if (Exception is not null)
            {
                throw Exception;
            }

            return Task.FromResult(Outcome);
        }
    }

    private sealed class RecordingLogger : IUpdaterEventLogger
    {
        internal List<(
            string EventCode,
            string? DetailCode,
            string? Version)> Events
        { get; } = [];

        public bool TryAppend(
            string eventCode,
            string? detailCode = null,
            string? version = null)
        {
            Events.Add((eventCode, detailCode, version));
            return true;
        }
    }

    private sealed class ThrowingLogger : IUpdaterEventLogger
    {
        public bool TryAppend(
            string eventCode,
            string? detailCode = null,
            string? version = null) =>
            throw new IOException("logger unavailable");
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }
}
