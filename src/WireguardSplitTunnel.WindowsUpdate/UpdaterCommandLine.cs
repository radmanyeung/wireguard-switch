using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Processes;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate;

public enum UpdaterMode
{
    ApplyAfterExit,
    RecoverAndLaunch
}

public sealed record UpdaterCommand(
    UpdaterMode Mode,
    ProtectedTransactionId TransactionId,
    string TransactionPath);

public enum UpdaterCommandLineError
{
    None,
    InvalidArguments,
    UnsafeTransactionPath
}

public sealed record UpdaterCommandLineResult(
    bool Success,
    UpdaterCommand? Command,
    UpdaterCommandLineError Error)
{
    internal static UpdaterCommandLineResult Parsed(
        UpdaterCommand command) =>
        new(true, command, UpdaterCommandLineError.None);

    internal static UpdaterCommandLineResult Failed(
        UpdaterCommandLineError error) =>
        new(false, null, error);
}

public static class UpdaterExitCodes
{
    public const int Success = 0;
    public const int LaunchHandled = 10;
    public const int ExistingCandidate = 20;
    public const int RecoveryBlocked = 30;
    public const int InvalidArguments = 64;
    public const int Failed = 70;
}

public sealed class UpdaterCommandLine
{
    private const string ModeOption = "--mode";
    private const string TransactionOption = "--transaction";
    private const string TransactionFileName = "transaction.json";

    private readonly ProtectedTransactionPaths _paths;
    private readonly Func<string, DriveType> _getDriveType;

    public UpdaterCommandLine()
        : this(
            new ProtectedTransactionPaths(),
            root => new DriveInfo(root).DriveType)
    {
    }

    internal UpdaterCommandLine(
        ProtectedTransactionPaths paths,
        Func<string, DriveType> getDriveType)
    {
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _getDriveType = getDriveType
            ?? throw new ArgumentNullException(nameof(getDriveType));
    }

    public UpdaterCommandLineResult Parse(string[]? arguments)
    {
        if (!TryReadPairs(
                arguments,
                out var modeValue,
                out var transactionPath)
            || !TryParseMode(modeValue, out var mode))
        {
            return UpdaterCommandLineResult.Failed(
                UpdaterCommandLineError.InvalidArguments);
        }

        if (!TryResolveTransaction(
                transactionPath,
                out var transactionId,
                out var canonicalPath))
        {
            return UpdaterCommandLineResult.Failed(
                UpdaterCommandLineError.UnsafeTransactionPath);
        }

        return UpdaterCommandLineResult.Parsed(
            new UpdaterCommand(
                mode,
                transactionId,
                canonicalPath!));
    }

    private static bool TryReadPairs(
        string[]? arguments,
        out string? mode,
        out string? transaction)
    {
        mode = null;
        transaction = null;
        if (arguments is null || arguments.Length != 4)
        {
            return false;
        }

        for (var index = 0; index < arguments.Length; index += 2)
        {
            var option = arguments[index];
            var value = arguments[index + 1];
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            switch (option)
            {
                case ModeOption when mode is null:
                    mode = value;
                    break;
                case TransactionOption when transaction is null:
                    transaction = value;
                    break;
                default:
                    return false;
            }
        }

        return mode is not null && transaction is not null;
    }

    private static bool TryParseMode(
        string? value,
        out UpdaterMode mode)
    {
        switch (value)
        {
            case "apply-after-exit":
                mode = UpdaterMode.ApplyAfterExit;
                return true;
            case "recover-and-launch":
                mode = UpdaterMode.RecoverAndLaunch;
                return true;
            default:
                mode = default;
                return false;
        }
    }

    private bool TryResolveTransaction(
        string? suppliedPath,
        out ProtectedTransactionId transactionId,
        out string? canonicalPath)
    {
        transactionId = default;
        canonicalPath = null;
        if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(
                suppliedPath,
                _getDriveType,
                out var localPath)
            || localPath is null)
        {
            return false;
        }

        try
        {
            if (!string.Equals(
                    Path.GetFileName(localPath),
                    TransactionFileName,
                    StringComparison.Ordinal))
            {
                return false;
            }

            var transactionDirectory =
                Path.GetDirectoryName(localPath);
            var directoryName = transactionDirectory is null
                ? null
                : Path.GetFileName(transactionDirectory);
            if (directoryName is null
                || directoryName.Length != 32
                || !string.Equals(
                    directoryName,
                    directoryName.ToLowerInvariant(),
                    StringComparison.Ordinal)
                || !Guid.TryParseExact(
                    directoryName,
                    "N",
                    out var guid))
            {
                return false;
            }

            var parsedId = new ProtectedTransactionId(guid);
            var layout = _paths.GetLayout(parsedId);
            if (!parsedId.IsValid
                || !layout.Success
                || layout.Layout is null
                || !string.Equals(
                    localPath,
                    layout.Layout.TransactionRecordPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            transactionId = parsedId;
            canonicalPath = layout.Layout.TransactionRecordPath;
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
}

internal enum ApplyAfterExitOutcome
{
    AppliedAwaitingHealth,
    RetryableFailure,
    RecoveryBlocked,
    InvalidRequest
}

internal enum ApplyAfterExitError
{
    None,
    InvalidRequest,
    AuthorizedProcessMismatch,
    ReadyWriteFailed,
    ProcessStillRunning,
    ProcessWaitFailed,
    ApplyFailed
}

internal readonly record struct ApplyAfterExitResult(
    ApplyAfterExitOutcome Outcome,
    ApplyAfterExitError Error = ApplyAfterExitError.None,
    bool NamespaceMutationPossible = false);

internal interface IUpdaterAuthorizedProcessLease : IDisposable
{
    ProcessWaitResult WaitForExit(TimeSpan timeout);
}

internal readonly record struct UpdaterAuthorizedProcessOpenResult(
    IUpdaterAuthorizedProcessLease? Lease,
    ApplyAfterExitError Error)
{
    public bool Success =>
        Lease is not null && Error == ApplyAfterExitError.None;

    internal static UpdaterAuthorizedProcessOpenResult Opened(
        IUpdaterAuthorizedProcessLease lease) =>
        new(lease, ApplyAfterExitError.None);

    internal static UpdaterAuthorizedProcessOpenResult Failed(
        ApplyAfterExitError error) =>
        new(null, error);
}

internal interface IUpdaterApplyAfterExitBoundary
{
    UpdaterAuthorizedProcessOpenResult OpenAuthorizedProcess(
        UpdaterCommand command);

    TransactionalUpdateExecutionResult Resume(
        ProtectedTransactionId transactionId);
}

internal interface IUpdaterReadyWriter
{
    bool WriteReady(ProtectedTransactionId transactionId);
}

internal sealed class UpdaterApplyAfterExitService
{
    internal static readonly TimeSpan DefaultExitTimeout =
        TimeSpan.FromSeconds(60);

    private readonly IUpdaterApplyAfterExitBoundary _boundary;
    private readonly IUpdaterReadyWriter _readyWriter;
    private readonly TimeSpan _exitTimeout;

    internal UpdaterApplyAfterExitService(
        IUpdaterApplyAfterExitBoundary boundary,
        IUpdaterReadyWriter readyWriter,
        TimeSpan? exitTimeout = null)
    {
        _boundary = boundary
            ?? throw new ArgumentNullException(nameof(boundary));
        _readyWriter = readyWriter
            ?? throw new ArgumentNullException(nameof(readyWriter));
        _exitTimeout = exitTimeout ?? DefaultExitTimeout;
    }

    internal ApplyAfterExitResult Run(UpdaterCommand? command)
    {
        if (command is not
            {
                Mode: UpdaterMode.ApplyAfterExit,
                TransactionId.IsValid: true
            }
            || string.IsNullOrWhiteSpace(command.TransactionPath)
            || _exitTimeout <= TimeSpan.Zero
            || _exitTimeout.TotalMilliseconds > uint.MaxValue - 1)
        {
            return new(
                ApplyAfterExitOutcome.InvalidRequest,
                ApplyAfterExitError.InvalidRequest);
        }

        UpdaterAuthorizedProcessOpenResult opened;
        try
        {
            opened = _boundary.OpenAuthorizedProcess(command);
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
            return Retryable(
                ApplyAfterExitError.AuthorizedProcessMismatch);
        }

        if (!opened.Success || opened.Lease is null)
        {
            return Retryable(
                opened.Error == ApplyAfterExitError.None
                    ? ApplyAfterExitError.AuthorizedProcessMismatch
                    : opened.Error);
        }

        using (opened.Lease)
        {
            bool ready;
            try
            {
                ready = _readyWriter.WriteReady(
                    command.TransactionId);
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                ready = false;
            }

            if (!ready)
            {
                return Retryable(
                    ApplyAfterExitError.ReadyWriteFailed);
            }

            ProcessWaitResult wait;
            try
            {
                wait = opened.Lease.WaitForExit(_exitTimeout);
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return Retryable(
                    ApplyAfterExitError.ProcessWaitFailed);
            }

            if (wait.Status != ProcessWaitStatus.Exited)
            {
                return Retryable(
                    wait.Status == ProcessWaitStatus.StillRunning
                        ? ApplyAfterExitError.ProcessStillRunning
                        : ApplyAfterExitError.ProcessWaitFailed);
            }

            TransactionalUpdateExecutionResult execution;
            try
            {
                execution = _boundary.Resume(
                    command.TransactionId);
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return Retryable(
                    ApplyAfterExitError.ApplyFailed,
                    namespaceMutationPossible: true);
            }

            return execution.Outcome switch
            {
                TransactionalUpdateExecutionOutcome
                    .AppliedAwaitingHealth =>
                    new(
                        ApplyAfterExitOutcome
                            .AppliedAwaitingHealth,
                        NamespaceMutationPossible: true),
                TransactionalUpdateExecutionOutcome
                    .RecoveryBlocked =>
                    new(
                        ApplyAfterExitOutcome.RecoveryBlocked,
                        NamespaceMutationPossible: true),
                TransactionalUpdateExecutionOutcome
                    .RetryableFailure =>
                    Retryable(
                        ApplyAfterExitError.ApplyFailed,
                        execution.NamespaceMutationPossible),
                _ => Retryable(
                    ApplyAfterExitError.ApplyFailed,
                    namespaceMutationPossible: true)
            };
        }
    }

    private static ApplyAfterExitResult Retryable(
        ApplyAfterExitError error,
        bool namespaceMutationPossible = false) =>
        new(
            ApplyAfterExitOutcome.RetryableFailure,
            error,
            namespaceMutationPossible);

    private static bool IsNonFatal(Exception exception) =>
        exception is not (
            OutOfMemoryException
                or StackOverflowException
                or AccessViolationException);
}

internal sealed class ConsoleUpdaterReadyWriter : IUpdaterReadyWriter
{
    public bool WriteReady(ProtectedTransactionId transactionId)
    {
        if (!transactionId.IsValid)
        {
            return false;
        }

        try
        {
            Console.Out.WriteLine(
                $"READY {transactionId.DirectoryName}");
            Console.Out.Flush();
            return true;
        }
        catch (Exception exception) when (
            exception is IOException
                or ObjectDisposedException
                or InvalidOperationException)
        {
            return false;
        }
    }
}

internal sealed class WindowsUpdaterAuthorizedProcessLease(
    WindowsProcessIdentityLease inner)
    : IUpdaterAuthorizedProcessLease
{
    private WindowsProcessIdentityLease? _inner = inner
        ?? throw new ArgumentNullException(nameof(inner));

    public ProcessWaitResult WaitForExit(TimeSpan timeout) =>
        _inner?.WaitForExit(timeout)
        ?? new ProcessWaitResult(ProcessWaitStatus.Disposed);

    public void Dispose() =>
        Interlocked.Exchange(ref _inner, null)?.Dispose();
}

internal sealed class ProtectedUpdaterApplyAfterExitBoundary
    : IUpdaterApplyAfterExitBoundary
{
    private readonly ProtectedTransactionStore _store;
    private readonly ProtectedUpdateMutexContext _authority;
    private readonly ProtectedTransactionPaths _paths;
    private readonly WindowsProcessIdentityService _processes;
    private readonly TransactionalUpdateExecutor _executor;

    internal ProtectedUpdaterApplyAfterExitBoundary(
        ProtectedTransactionStore store,
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPaths paths)
        : this(
            store,
            authority,
            paths,
            new WindowsProcessIdentityService(),
            new TransactionalUpdateExecutor(
                store,
                authority,
                paths))
    {
    }

    internal ProtectedUpdaterApplyAfterExitBoundary(
        ProtectedTransactionStore store,
        ProtectedUpdateMutexContext authority,
        ProtectedTransactionPaths paths,
        WindowsProcessIdentityService processes,
        TransactionalUpdateExecutor executor)
    {
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _authority = authority
            ?? throw new ArgumentNullException(nameof(authority));
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _processes = processes
            ?? throw new ArgumentNullException(nameof(processes));
        _executor = executor
            ?? throw new ArgumentNullException(nameof(executor));
    }

    public UpdaterAuthorizedProcessOpenResult OpenAuthorizedProcess(
        UpdaterCommand command)
    {
        if (command is null
            || command.Mode != UpdaterMode.ApplyAfterExit
            || !command.TransactionId.IsValid
            || !_authority.TryAcquireLease(out var authorityLease))
        {
            return FailedOpen();
        }

        using (authorityLease)
        using (_authority.AcquireMutationLease())
        {
            var layout = _paths.GetLayout(command.TransactionId);
            if (!layout.Success
                || layout.Layout is null
                || !string.Equals(
                    command.TransactionPath,
                    layout.Layout.TransactionRecordPath,
                    StringComparison.OrdinalIgnoreCase))
            {
                return FailedOpen();
            }

            var active = _store.ReadActive(_authority);
            var transaction = _store.ReadJournalForRecovery(
                _authority,
                command.TransactionId);
            if (!active.Success
                || active.TransactionId != command.TransactionId
                || !IsRetryableCloseAuthorized(
                    transaction,
                    command.TransactionId,
                    out var record)
                || !HasExpectedAuthorizedImage(record!)
                || !_store.VerifyHelper(
                    _authority,
                    command.TransactionId,
                    record!.HelperSha256)
                    .Success)
            {
                return FailedOpen();
            }

            var opened = _processes.ReopenValidated(
                record.AuthorizedProcess!);
            if (!opened.Success
                || opened.Lease is null)
            {
                opened.Lease?.Dispose();
                return FailedOpen();
            }

            var activeAfter = _store.ReadActive(_authority);
            var transactionAfter =
                _store.ReadJournalForRecovery(
                    _authority,
                    command.TransactionId);
            if (!activeAfter.Success
                || activeAfter.TransactionId
                    != command.TransactionId
                || !IsSameRetryableSnapshot(
                    transaction,
                    transactionAfter))
            {
                opened.Lease.Dispose();
                return FailedOpen();
            }

            return UpdaterAuthorizedProcessOpenResult.Opened(
                new WindowsUpdaterAuthorizedProcessLease(
                    opened.Lease));
        }
    }

    public TransactionalUpdateExecutionResult Resume(
        ProtectedTransactionId transactionId) =>
        _executor.Resume(transactionId);

    private bool HasExpectedAuthorizedImage(
        ProtectedTransactionRecord record)
    {
        if (record.AuthorizedProcess is null)
        {
            return false;
        }

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
            var expected = Path.GetFullPath(
                Path.Combine(
                    root,
                    relative.CanonicalKey.Replace(
                        '/',
                        Path.DirectorySeparatorChar)));
            return expected.StartsWith(
                    root.TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    expected,
                    record.AuthorizedProcess.ImagePath,
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

    private static bool IsRetryableCloseAuthorized(
        ProtectedJournalRecoveryReadResult transaction,
        ProtectedTransactionId transactionId,
        out ProtectedTransactionRecord? record)
    {
        record = transaction.Record;
        return transaction.Success
            && record is not null
            && record.TransactionId == transactionId
            && record.Phase
                == ProtectedTransactionPhase.CloseAuthorized
            && record.AuthorizedProcess is not null
            && record.Journal.Generation == 0
            && record.Journal.Sha256 is null
            && transaction.Observation
                == ProtectedJournalObservation.AbsentInitial;
    }

    private static bool IsSameRetryableSnapshot(
        ProtectedJournalRecoveryReadResult before,
        ProtectedJournalRecoveryReadResult after) =>
        after.Success
        && before.RecordBytes is not null
        && after.RecordBytes is not null
        && before.RecordBytes.AsSpan().SequenceEqual(
            after.RecordBytes)
        && before.Observation == after.Observation
        && before.JournalBytes is null
        && after.JournalBytes is null;

    private static UpdaterAuthorizedProcessOpenResult FailedOpen() =>
        UpdaterAuthorizedProcessOpenResult.Failed(
            ApplyAfterExitError.AuthorizedProcessMismatch);
}
