using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Launcher;
using WireguardSplitTunnel.WindowsUpdate.Logging;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate;

internal enum UpdaterInvocationOutcome
{
    AppliedAwaitingHealth,
    ContinueNormalLaunch,
    LaunchHandled,
    ExistingCandidate,
    RecoveryBlocked,
    Failed
}

internal interface IUpdaterInvocationBoundary
{
    Task<UpdaterInvocationOutcome> InvokeAsync(
        UpdaterCommand command,
        CancellationToken cancellationToken);
}

internal sealed class UpdaterCommandApplication
{
    private readonly UpdaterCommandLine _commandLine;
    private readonly IUpdaterInvocationBoundary _boundary;
    private readonly IUpdaterEventLogger _logger;

    internal UpdaterCommandApplication(
        UpdaterCommandLine commandLine,
        IUpdaterInvocationBoundary boundary,
        IUpdaterEventLogger logger)
    {
        _commandLine = commandLine
            ?? throw new ArgumentNullException(nameof(commandLine));
        _boundary = boundary
            ?? throw new ArgumentNullException(nameof(boundary));
        _logger = logger
            ?? throw new ArgumentNullException(nameof(logger));
    }

    internal async Task<int> RunAsync(
        string[]? arguments,
        CancellationToken cancellationToken)
    {
        var parsed = _commandLine.Parse(arguments);
        if (!parsed.Success || parsed.Command is null)
        {
            SafeLog("invalid_arguments");
            return UpdaterExitCodes.InvalidArguments;
        }

        UpdaterInvocationOutcome outcome;
        try
        {
            outcome = await _boundary.InvokeAsync(
                    parsed.Command,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            SafeLog("helper_failed", "cancelled");
            return UpdaterExitCodes.Failed;
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
            SafeLog("helper_failed", "unexpected");
            return UpdaterExitCodes.Failed;
        }

        SafeLog(EventCode(outcome));
        return ExitCode(outcome);
    }

    private void SafeLog(
        string eventCode,
        string? detailCode = null)
    {
        try
        {
            _logger.TryAppend(eventCode, detailCode);
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
        }
    }

    private static string EventCode(
        UpdaterInvocationOutcome outcome) =>
        outcome switch
        {
            UpdaterInvocationOutcome.AppliedAwaitingHealth =>
                "apply_completed",
            UpdaterInvocationOutcome.ContinueNormalLaunch =>
                "continue_launch",
            UpdaterInvocationOutcome.LaunchHandled =>
                "launch_handled",
            UpdaterInvocationOutcome.ExistingCandidate =>
                "existing_process",
            UpdaterInvocationOutcome.RecoveryBlocked =>
                "recovery_blocked",
            _ => "helper_failed"
        };

    private static int ExitCode(
        UpdaterInvocationOutcome outcome) =>
        outcome switch
        {
            UpdaterInvocationOutcome.AppliedAwaitingHealth
                or UpdaterInvocationOutcome.ContinueNormalLaunch =>
                    UpdaterExitCodes.Success,
            UpdaterInvocationOutcome.LaunchHandled =>
                UpdaterExitCodes.LaunchHandled,
            UpdaterInvocationOutcome.ExistingCandidate =>
                UpdaterExitCodes.ExistingCandidate,
            UpdaterInvocationOutcome.RecoveryBlocked =>
                UpdaterExitCodes.RecoveryBlocked,
            _ => UpdaterExitCodes.Failed
        };

    private static bool IsNonFatal(Exception exception) =>
        exception is not (
            OutOfMemoryException
                or StackOverflowException
                or AccessViolationException);
}

internal sealed class ProtectedUpdaterInvocationBoundary
    : IUpdaterInvocationBoundary
{
    private static readonly TimeSpan MutexTimeout = TimeSpan.Zero;

    private readonly ProtectedUpdateMutex _mutex;
    private readonly ProtectedTransactionPaths _paths;
    private readonly WindowsProcessIdentityService _processes;

    internal ProtectedUpdaterInvocationBoundary()
        : this(
            new ProtectedUpdateMutex(),
            new ProtectedTransactionPaths(),
            new WindowsProcessIdentityService())
    {
    }

    internal ProtectedUpdaterInvocationBoundary(
        ProtectedUpdateMutex mutex,
        ProtectedTransactionPaths paths,
        WindowsProcessIdentityService processes)
    {
        _mutex = mutex
            ?? throw new ArgumentNullException(nameof(mutex));
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _processes = processes
            ?? throw new ArgumentNullException(nameof(processes));
    }

    public async Task<UpdaterInvocationOutcome> InvokeAsync(
        UpdaterCommand command,
        CancellationToken cancellationToken)
    {
        if (command is null
            || !command.TransactionId.IsValid
            || string.IsNullOrWhiteSpace(command.TransactionPath)
            || !Enum.IsDefined(command.Mode))
        {
            return UpdaterInvocationOutcome.Failed;
        }

        var result = await _mutex.RunExclusiveAsync(
                (authority, _) =>
                    InvokeExclusive(authority, command),
                MutexTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        if (result.ActionInvoked
            && result.Status is
                ProtectedUpdateMutexStatus.Acquired
                    or ProtectedUpdateMutexStatus
                        .AbandonedAcquired)
        {
            return result.Value;
        }

        return MapMutexFailure(command.Mode, result.Status);
    }

    internal static UpdaterInvocationOutcome MapMutexFailure(
        UpdaterMode mode,
        ProtectedUpdateMutexStatus status) =>
        mode == UpdaterMode.RecoverAndLaunch
            && status is
                ProtectedUpdateMutexStatus.Busy
                    or ProtectedUpdateMutexStatus.TimedOut
            ? UpdaterInvocationOutcome.ExistingCandidate
            : UpdaterInvocationOutcome.Failed;

    private UpdaterInvocationOutcome InvokeExclusive(
        ProtectedUpdateMutexContext authority,
        UpdaterCommand command)
    {
        var store = new ProtectedTransactionStore(_paths);
        var self = _processes.CaptureCurrent();
        using var selfLease = self.Lease;
        if (!ValidateSelf(
                authority,
                command,
                store,
                self))
        {
            return UpdaterInvocationOutcome.Failed;
        }

        return command.Mode switch
        {
            UpdaterMode.ApplyAfterExit =>
                ApplyAfterExit(
                    authority,
                    command,
                    store),
            UpdaterMode.RecoverAndLaunch =>
                RecoverAndLaunch(authority, store),
            _ => UpdaterInvocationOutcome.Failed
        };
    }

    private bool ValidateSelf(
        ProtectedUpdateMutexContext authority,
        UpdaterCommand command,
        ProtectedTransactionStore store,
        ProcessIdentityOpenResult current)
    {
        var layout = _paths.GetLayout(command.TransactionId);
        if (!layout.Success
            || layout.Layout is null
            || !string.Equals(
                command.TransactionPath,
                layout.Layout.TransactionRecordPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!current.Success
            || current.Identity is null
            || current.Lease is null
            || !string.Equals(
                current.Identity.ImagePath,
                layout.Layout.HelperPath,
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var active = store.ReadActive(authority);
        var transaction = store.ReadTransaction(
            authority,
            command.TransactionId);
        if (!active.Success
            || active.TransactionId != command.TransactionId
            || !transaction.Success
            || transaction.Record is not { } record
            || record.TransactionId != command.TransactionId
            || !store.VerifyHelper(
                    authority,
                    command.TransactionId,
                    record.HelperSha256)
                .Success)
        {
            return false;
        }

        return true;
    }

    private UpdaterInvocationOutcome ApplyAfterExit(
        ProtectedUpdateMutexContext authority,
        UpdaterCommand command,
        ProtectedTransactionStore store)
    {
        var boundary = new ProtectedUpdaterApplyAfterExitBoundary(
            store,
            authority,
            _paths);
        var result = new UpdaterApplyAfterExitService(
                boundary,
                new ConsoleUpdaterReadyWriter())
            .Run(command);
        return result.Outcome switch
        {
            ApplyAfterExitOutcome.AppliedAwaitingHealth =>
                UpdaterInvocationOutcome.AppliedAwaitingHealth,
            ApplyAfterExitOutcome.RecoveryBlocked =>
                UpdaterInvocationOutcome.RecoveryBlocked,
            _ => UpdaterInvocationOutcome.Failed
        };
    }

    private UpdaterInvocationOutcome RecoverAndLaunch(
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionStore store)
    {
        var executor = new TransactionalUpdateExecutor(
            store,
            authority,
            _paths);
        var recovery = new TransactionRecoveryService(
            new ProtectedTransactionRecoveryGateway(
                store,
                authority),
            executor);
        var launcher = new LauncherRecoveryService(
            authority,
            store,
            _paths,
            recovery,
            new UpdateHealthService(_paths, store),
            _processes);
        return launcher.RecoverForUserLaunch() switch
        {
            LauncherRecoveryAction.ContinueNormalLaunch =>
                UpdaterInvocationOutcome.ContinueNormalLaunch,
            LauncherRecoveryAction.CandidateLaunchHandled
                or LauncherRecoveryAction.OldVersionLaunchHandled =>
                    UpdaterInvocationOutcome.LaunchHandled,
            LauncherRecoveryAction.ExistingCandidateStillRunning =>
                UpdaterInvocationOutcome.ExistingCandidate,
            _ => UpdaterInvocationOutcome.RecoveryBlocked
        };
    }
}
