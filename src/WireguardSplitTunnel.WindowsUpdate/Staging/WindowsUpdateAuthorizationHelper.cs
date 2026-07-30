using System.ComponentModel;
using System.Diagnostics;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Launcher;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

internal interface IWindowsUpdateAuthorizationMutex
{
    Task<ProtectedUpdateMutexResult<T>> RunExclusiveAsync<T>(
        Func<ProtectedUpdateMutexContext, T> action,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal sealed class WindowsUpdateAuthorizationMutex
    : IWindowsUpdateAuthorizationMutex
{
    private readonly ProtectedUpdateMutex _mutex;

    internal WindowsUpdateAuthorizationMutex(
        ProtectedUpdateMutex mutex)
    {
        _mutex = mutex
            ?? throw new ArgumentNullException(nameof(mutex));
    }

    public Task<ProtectedUpdateMutexResult<T>>
        RunExclusiveAsync<T>(
            Func<ProtectedUpdateMutexContext, T> action,
            TimeSpan timeout,
            CancellationToken cancellationToken) =>
        _mutex.RunExclusiveAsync(
            (context, _) => action(context),
            timeout,
            cancellationToken);
}

internal enum WindowsUpdateHelperLaunchOutcome
{
    Ready,
    LaunchFailed,
    OutputMismatch,
    TimedOut,
    ReadFailed
}

internal sealed record WindowsUpdateHelperLaunchResult(
    WindowsUpdateHelperLaunchOutcome Outcome)
{
    internal static WindowsUpdateHelperLaunchResult Ready() =>
        new(WindowsUpdateHelperLaunchOutcome.Ready);
}

internal sealed record WindowsUpdateHelperLaunchRequest(
    string HelperPath,
    string TransactionPath,
    ProtectedTransactionId TransactionId)
{
    internal string ExpectedReadyLine =>
        $"READY {TransactionId.DirectoryName}";
}

internal interface IWindowsUpdateHelperLauncher
{
    Task<WindowsUpdateHelperLaunchResult>
        LaunchAndWaitForReadyAsync(
            WindowsUpdateHelperLaunchRequest request,
            CancellationToken cancellationToken);
}

internal static class WindowsUpdateHelperReadyProtocol
{
    internal static bool Matches(
        string? line,
        ProtectedTransactionId transactionId) =>
        transactionId.IsValid
        && string.Equals(
            line,
            $"READY {transactionId.DirectoryName}",
            StringComparison.Ordinal);
}

internal sealed class WindowsUpdateHelperLauncher
    : IWindowsUpdateHelperLauncher
{
    internal static readonly TimeSpan DefaultReadyTimeout =
        TimeSpan.FromSeconds(15);

    private readonly TimeSpan _readyTimeout;

    internal WindowsUpdateHelperLauncher(
        TimeSpan? readyTimeout = null)
    {
        _readyTimeout = readyTimeout ?? DefaultReadyTimeout;
        if (_readyTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(readyTimeout));
        }
    }

    public async Task<WindowsUpdateHelperLaunchResult>
        LaunchAndWaitForReadyAsync(
            WindowsUpdateHelperLaunchRequest request,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!request.TransactionId.IsValid
            || string.IsNullOrWhiteSpace(request.HelperPath)
            || string.IsNullOrWhiteSpace(
                request.TransactionPath))
        {
            return new(
                WindowsUpdateHelperLaunchOutcome.LaunchFailed);
        }

        Process? process;
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = request.HelperPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = false,
                CreateNoWindow = true,
                WorkingDirectory =
                    Path.GetDirectoryName(request.HelperPath)
                    ?? string.Empty
            };
            start.ArgumentList.Add("--mode");
            start.ArgumentList.Add("apply-after-exit");
            start.ArgumentList.Add("--transaction");
            start.ArgumentList.Add(request.TransactionPath);
            process = Process.Start(start);
        }
        catch (Exception exception) when (
            IsExpectedProcessException(exception))
        {
            return new(
                WindowsUpdateHelperLaunchOutcome.LaunchFailed);
        }

        if (process is null)
        {
            return new(
                WindowsUpdateHelperLaunchOutcome.LaunchFailed);
        }

        using (process)
        using (var deadline =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken))
        {
            deadline.CancelAfter(_readyTimeout);
            string? line;
            try
            {
                line = await process.StandardOutput
                    .ReadLineAsync(deadline.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (!cancellationToken.IsCancellationRequested)
            {
                return new(
                    WindowsUpdateHelperLaunchOutcome.TimedOut);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException
                    or ObjectDisposedException
                    or InvalidOperationException)
            {
                return new(
                    WindowsUpdateHelperLaunchOutcome.ReadFailed);
            }

            return WindowsUpdateHelperReadyProtocol.Matches(
                    line,
                    request.TransactionId)
                ? WindowsUpdateHelperLaunchResult.Ready()
                : new(
                    WindowsUpdateHelperLaunchOutcome
                        .OutputMismatch);
        }
    }

    private static bool IsExpectedProcessException(
        Exception exception) =>
        exception is InvalidOperationException
            or Win32Exception
            or IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException;
}

internal interface IWindowsUpdateProtectedTransactionCleaner
{
    bool Cleanup(ProtectedTransactionId transactionId);
}

internal sealed class WindowsUpdateProtectedTransactionCleaner
    : IWindowsUpdateProtectedTransactionCleaner
{
    private readonly ProtectedTerminalTransactionCleaner _inner;

    internal WindowsUpdateProtectedTransactionCleaner(
        ProtectedTransactionPaths paths)
    {
        _inner = new ProtectedTerminalTransactionCleaner(
            paths,
            new ProtectedDirectoryAcl());
    }

    public bool Cleanup(
        ProtectedTransactionId transactionId) =>
        _inner.Cleanup(transactionId);
}

internal sealed class WindowsUpdateAuthorizationHelper
    : IWindowsUpdateAuthorizationHelper
{
    private static readonly TimeSpan MutexTimeout =
        TimeSpan.FromSeconds(5);

    private readonly IWindowsUpdateAuthorizationMutex _mutex;
    private readonly ProtectedTransactionStore _store;
    private readonly ProtectedTransactionPaths _paths;
    private readonly IWindowsUpdateHelperLauncher _launcher;
    private readonly IWindowsUpdateProtectedTransactionCleaner
        _cleaner;

    internal WindowsUpdateAuthorizationHelper(
        IWindowsUpdateAuthorizationMutex mutex,
        ProtectedTransactionStore store,
        ProtectedTransactionPaths paths,
        IWindowsUpdateHelperLauncher launcher,
        IWindowsUpdateProtectedTransactionCleaner cleaner)
    {
        _mutex = mutex
            ?? throw new ArgumentNullException(nameof(mutex));
        _store = store
            ?? throw new ArgumentNullException(nameof(store));
        _paths = paths
            ?? throw new ArgumentNullException(nameof(paths));
        _launcher = launcher
            ?? throw new ArgumentNullException(nameof(launcher));
        _cleaner = cleaner
            ?? throw new ArgumentNullException(nameof(cleaner));
    }

    public async Task<WindowsUpdateProtectedState>
        InspectAsync(CancellationToken cancellationToken)
    {
        var result = await _mutex.RunExclusiveAsync(
                InspectExclusive,
                MutexTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return IsAcquired(result)
            ? result.Value
                ?? WindowsUpdateProtectedState.Failed(
                    "protected_inspect")
            : WindowsUpdateProtectedState.Failed(
                "protected_mutex");
    }

    public async Task<WindowsUpdateProtectedCleanupResult>
        CleanupAutomaticProtectedStagedAsync(
            bool isElevated,
            CancellationToken cancellationToken)
    {
        if (!isElevated)
        {
            var state = await InspectAsync(cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!state.Success)
            {
                return WindowsUpdateProtectedCleanupResult
                    .Failed("protected_inspect");
            }

            return state is
            {
                Exists: true,
                Source: PendingUpdateSource.Automatic,
                Phase: ProtectedUpdatePhase.ProtectedStaged
            }
                ? WindowsUpdateProtectedCleanupResult
                    .PendingElevation()
                : state is
                {
                    Exists: true,
                    Source: PendingUpdateSource.Automatic
                }
                    ? WindowsUpdateProtectedCleanupResult
                        .LaterPhasePreserved()
                    : WindowsUpdateProtectedCleanupResult
                        .NothingToDo();
        }

        var result = await _mutex.RunExclusiveAsync(
                CleanupAutomaticExclusive,
                MutexTimeout,
                cancellationToken)
            .ConfigureAwait(false);
        return IsAcquired(result)
            ? result.Value
                ?? WindowsUpdateProtectedCleanupResult
                    .Failed("protected_cleanup")
            : WindowsUpdateProtectedCleanupResult.Failed(
                "protected_mutex");
    }

    public async Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            Func<PendingUpdateSource, bool>
                isAuthorizationAllowed,
            Func<PendingUpdateSource,
                IWindowsUpdateAuthorizationCommitLease?>
                tryAcquireAuthorizationCommitLease,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(
            isAuthorizationAllowed);
        ArgumentNullException.ThrowIfNull(
            tryAcquireAuthorizationCommitLease);
        if (!UpdateCloseEligibility.IsEligible(context))
        {
            return UpdateCloseAuthorizationResult
                .NoProtectedTransaction();
        }

        AuthorizationSnapshotResult inspected;
        try
        {
            var first = await _mutex.RunExclusiveAsync(
                    authority => InspectForAuthorization(
                        authority,
                        context,
                        isAuthorizationAllowed),
                    MutexTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!IsAcquired(first)
                || first.Value is null)
            {
                return UpdateCloseAuthorizationResult
                    .RecoverableFailure(
                        "authorization_mutex");
            }

            inspected = first.Value;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return UpdateCloseAuthorizationResult
                .RecoverableFailure(
                    "authorization_inspect");
        }

        if (inspected.Outcome
            == AuthorizationSnapshotOutcome.None)
        {
            return UpdateCloseAuthorizationResult
                .NoProtectedTransaction();
        }

        if (inspected.Outcome
                != AuthorizationSnapshotOutcome.Eligible
            || inspected.Snapshot is null)
        {
            return UpdateCloseAuthorizationResult
                .RecoverableFailure(
                    inspected.DetailCode
                    ?? "authorization_inspect");
        }

        AuthorizationTransitionResult transitioned;
        try
        {
            var second = await _mutex.RunExclusiveAsync(
                    authority => AuthorizeExclusive(
                        authority,
                        inspected.Snapshot,
                        context,
                        isAuthorizationAllowed,
                        tryAcquireAuthorizationCommitLease),
                    MutexTimeout,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!IsAcquired(second)
                || second.Value is null)
            {
                return UpdateCloseAuthorizationResult
                    .RecoverableFailure(
                        "authorization_mutex");
            }

            transitioned = second.Value;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return UpdateCloseAuthorizationResult
                .RecoverableFailure(
                    "authorization_failed");
        }

        if (!transitioned.Success
            || transitioned.Request is null)
        {
            return UpdateCloseAuthorizationResult
                .RecoverableFailure(
                    transitioned.DetailCode
                    ?? "authorization_conflict");
        }

        WindowsUpdateHelperLaunchResult launched;
        try
        {
            launched = await _launcher
                .LaunchAndWaitForReadyAsync(
                    transitioned.Request,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            launched = new(
                WindowsUpdateHelperLaunchOutcome.ReadFailed);
        }

        return launched.Outcome switch
        {
            WindowsUpdateHelperLaunchOutcome.Ready =>
                UpdateCloseAuthorizationResult.HelperReady(),
            WindowsUpdateHelperLaunchOutcome.LaunchFailed =>
                UpdateCloseAuthorizationResult
                    .RecoverableFailure("helper_launch"),
            WindowsUpdateHelperLaunchOutcome.TimedOut =>
                UpdateCloseAuthorizationResult
                    .RecoverableFailure("helper_timeout"),
            WindowsUpdateHelperLaunchOutcome.OutputMismatch =>
                UpdateCloseAuthorizationResult
                    .RecoverableFailure("helper_ready"),
            _ => UpdateCloseAuthorizationResult
                .RecoverableFailure("helper_read")
        };
    }

    private WindowsUpdateProtectedState InspectExclusive(
        ProtectedUpdateMutexContext authority)
    {
        var active = _store.ReadActive(authority);
        if (!active.Success)
        {
            return WindowsUpdateProtectedState.Failed(
                "protected_active");
        }

        if (active.TransactionId is null)
        {
            return WindowsUpdateProtectedState.None();
        }

        var transaction = _store.ReadTransaction(
            authority,
            active.TransactionId.Value);
        if (!transaction.Success
            || transaction.Record is not { } record
            || record.TransactionId
                != active.TransactionId.Value
            || !TryMapPhase(
                record.Phase,
                out var phase))
        {
            return WindowsUpdateProtectedState.Failed(
                "protected_record");
        }

        return WindowsUpdateProtectedState.Found(
            record.TransactionId,
            record.Version,
            record.Source,
            phase);
    }

    private WindowsUpdateProtectedCleanupResult
        CleanupAutomaticExclusive(
            ProtectedUpdateMutexContext authority)
    {
        var active = _store.ReadActive(authority);
        if (!active.Success)
        {
            return WindowsUpdateProtectedCleanupResult.Failed(
                "protected_active");
        }

        if (active.TransactionId is null)
        {
            return WindowsUpdateProtectedCleanupResult
                .NothingToDo();
        }

        var observed = _store.ReadJournalForRecovery(
            authority,
            active.TransactionId.Value);
        if (!observed.Success
            || observed.Record is not { } record
            || record.TransactionId
                != active.TransactionId.Value)
        {
            return WindowsUpdateProtectedCleanupResult.Failed(
                "protected_record");
        }

        if (record.Source != PendingUpdateSource.Automatic)
        {
            return WindowsUpdateProtectedCleanupResult
                .NothingToDo();
        }

        if (record.Phase
            != ProtectedTransactionPhase.ProtectedStaged)
        {
            return WindowsUpdateProtectedCleanupResult
                .LaterPhasePreserved();
        }

        var deactivated = _store
            .DeactivateProtectedStaged(
                authority,
                observed);
        if (!deactivated.Success)
        {
            return WindowsUpdateProtectedCleanupResult.Failed(
                deactivated.Error
                    == ProtectedTransactionStoreError.Conflict
                    ? "protected_conflict"
                    : "protected_cleanup");
        }

        // The exact active-pointer CAS is the security boundary. Physical
        // deletion is best effort so a crash or partial cleanup cannot leave
        // a permanently active automatic authorization or retry deadlock.
        _cleaner.Cleanup(record.TransactionId);
        return WindowsUpdateProtectedCleanupResult.Removed();
    }

    private AuthorizationSnapshotResult
        InspectForAuthorization(
            ProtectedUpdateMutexContext authority,
            UpdateCloseAuthorizationContext context,
            Func<PendingUpdateSource, bool>
                isAuthorizationAllowed)
    {
        var active = _store.ReadActive(authority);
        if (!active.Success)
        {
            return AuthorizationSnapshotResult.Failed(
                "authorization_active");
        }

        if (active.TransactionId is null)
        {
            return AuthorizationSnapshotResult.None();
        }

        var observed = _store.ReadJournalForRecovery(
            authority,
            active.TransactionId.Value);
        if (!observed.Success
            || observed.Record is not { } record
            || observed.RecordBytes is null)
        {
            return AuthorizationSnapshotResult.Failed(
                "authorization_record");
        }

        if (record.TransactionId
                != active.TransactionId.Value
            || record.Phase
                != ProtectedTransactionPhase.ProtectedStaged
            || record.AuthorizedProcess is not null)
        {
            return AuthorizationSnapshotResult.None();
        }

        if (!SafeAuthorizationAllowed(
                isAuthorizationAllowed,
                record.Source))
        {
            return AuthorizationSnapshotResult.None();
        }

        if (!HasExpectedApplicationPath(record, context))
        {
            return AuthorizationSnapshotResult.Failed(
                "authorization_process");
        }

        return AuthorizationSnapshotResult.Eligible(
            observed);
    }

    private AuthorizationTransitionResult AuthorizeExclusive(
        ProtectedUpdateMutexContext authority,
        ProtectedJournalRecoveryReadResult expected,
        UpdateCloseAuthorizationContext context,
        Func<PendingUpdateSource, bool>
            isAuthorizationAllowed,
        Func<PendingUpdateSource,
            IWindowsUpdateAuthorizationCommitLease?>
            tryAcquireAuthorizationCommitLease)
    {
        var expectedRecord = expected.Record;
        if (expectedRecord is null
            || expected.RecordBytes is null)
        {
            return AuthorizationTransitionResult.Failed(
                "authorization_conflict");
        }

        var active = _store.ReadActive(authority);
        if (!active.Success
            || active.TransactionId
                != expectedRecord.TransactionId)
        {
            return AuthorizationTransitionResult.Failed(
                "authorization_conflict");
        }

        var current = _store.ReadJournalForRecovery(
            authority,
            expectedRecord.TransactionId);
        if (!current.Success
            || current.Record is not { } currentRecord
            || current.RecordBytes is null
            || !current.RecordBytes.AsSpan().SequenceEqual(
                expected.RecordBytes)
            || currentRecord.Phase
                != ProtectedTransactionPhase.ProtectedStaged
            || currentRecord.AuthorizedProcess is not null
            || !SafeAuthorizationAllowed(
                isAuthorizationAllowed,
                currentRecord.Source)
            || !HasExpectedApplicationPath(
                currentRecord,
                context))
        {
            return AuthorizationTransitionResult.Failed(
                "authorization_conflict");
        }

        var replacement = currentRecord with
        {
            Phase = ProtectedTransactionPhase.CloseAuthorized,
            AuthorizedProcess = new ProcessIdentity(
                context.ProcessId,
                context.CreationTimeFileTimeUtc,
                context.ImagePath)
        };
        var commitLease =
            SafeAcquireAuthorizationCommitLease(
                tryAcquireAuthorizationCommitLease,
                currentRecord.Source);
        if (commitLease is null)
        {
            return AuthorizationTransitionResult.Failed(
                "authorization_conflict");
        }

        ProtectedTransactionWriteResult exchanged;
        using (commitLease)
        {
            exchanged = _store.CompareExchangeTransaction(
                authority,
                current,
                replacement);
        }
        if (!exchanged.Success
            || exchanged.Record is not
            {
                Phase:
                    ProtectedTransactionPhase.CloseAuthorized,
                AuthorizedProcess: not null
            })
        {
            return AuthorizationTransitionResult.Failed(
                exchanged.Error
                    == ProtectedTransactionStoreError.Conflict
                    ? "authorization_conflict"
                    : "authorization_store");
        }

        var layout = _paths.GetLayout(
            currentRecord.TransactionId);
        if (!layout.Success
            || layout.Layout is null)
        {
            return AuthorizationTransitionResult.Failed(
                "authorization_path");
        }

        return AuthorizationTransitionResult.Completed(
            new WindowsUpdateHelperLaunchRequest(
                layout.Layout.HelperPath,
                layout.Layout.TransactionRecordPath,
                currentRecord.TransactionId));
    }

    private static bool SafeAuthorizationAllowed(
        Func<PendingUpdateSource, bool> predicate,
        PendingUpdateSource source)
    {
        try
        {
            return Enum.IsDefined(source)
                && predicate(source);
        }
        catch (Exception exception) when (
            exception is not (
                OutOfMemoryException
                    or StackOverflowException
                    or AccessViolationException))
        {
            return false;
        }
    }

    private static IWindowsUpdateAuthorizationCommitLease?
        SafeAcquireAuthorizationCommitLease(
            Func<PendingUpdateSource,
                IWindowsUpdateAuthorizationCommitLease?> acquire,
            PendingUpdateSource source)
    {
        try
        {
            return Enum.IsDefined(source)
                ? acquire(source)
                : null;
        }
        catch (Exception exception) when (
            exception is not (
                OutOfMemoryException
                    or StackOverflowException
                    or AccessViolationException))
        {
            return null;
        }
    }

    private static bool HasExpectedApplicationPath(
        ProtectedTransactionRecord record,
        UpdateCloseAuthorizationContext context)
    {
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
            var prefix = root.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            return expected.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals(
                    expected,
                    Path.GetFullPath(context.ImagePath),
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

    private static bool TryMapPhase(
        ProtectedTransactionPhase phase,
        out ProtectedUpdatePhase mapped)
    {
        mapped = (ProtectedUpdatePhase)(int)phase;
        return Enum.IsDefined(phase)
            && Enum.IsDefined(mapped);
    }

    private static bool IsAcquired<T>(
        ProtectedUpdateMutexResult<T> result) =>
        result.ActionInvoked
        && result.Status is
            ProtectedUpdateMutexStatus.Acquired
                or ProtectedUpdateMutexStatus
                    .AbandonedAcquired;

    private enum AuthorizationSnapshotOutcome
    {
        None,
        Eligible,
        Failed
    }

    private sealed record AuthorizationSnapshotResult(
        AuthorizationSnapshotOutcome Outcome,
        ProtectedJournalRecoveryReadResult? Snapshot,
        string? DetailCode)
    {
        internal static AuthorizationSnapshotResult None() =>
            new(
                AuthorizationSnapshotOutcome.None,
                Snapshot: null,
                DetailCode: null);

        internal static AuthorizationSnapshotResult Eligible(
            ProtectedJournalRecoveryReadResult snapshot) =>
            new(
                AuthorizationSnapshotOutcome.Eligible,
                snapshot,
                DetailCode: null);

        internal static AuthorizationSnapshotResult Failed(
            string detailCode) =>
            new(
                AuthorizationSnapshotOutcome.Failed,
                Snapshot: null,
                detailCode);
    }

    private sealed record AuthorizationTransitionResult(
        bool Success,
        WindowsUpdateHelperLaunchRequest? Request,
        string? DetailCode)
    {
        internal static AuthorizationTransitionResult Completed(
            WindowsUpdateHelperLaunchRequest request) =>
            new(true, request, DetailCode: null);

        internal static AuthorizationTransitionResult Failed(
            string detailCode) =>
            new(false, Request: null, detailCode);
    }
}
