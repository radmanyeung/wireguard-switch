using System.Reflection;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Updates;

public enum CloseDisconnectFailureKind
{
    Journal,
    EnableWait,
    Enumeration,
    ElevatedHelperStart,
    Stop,
    Verification
}

/// <summary>
/// A sanitized close-disconnect failure. Adapter output and exception messages
/// deliberately never cross this contract.
/// </summary>
public sealed record CloseDisconnectFailure(
    CloseDisconnectFailureKind Kind,
    string Message);

public sealed record CloseDisconnectResult(
    bool Success,
    IReadOnlyList<CloseDisconnectFailure> Failures,
    IReadOnlyList<WindowsTunnelServiceIdentity> UnresolvedTargets)
{
    internal static CloseDisconnectResult Succeeded() => new(true, [], []);

    internal static CloseDisconnectResult Failed(
        IEnumerable<CloseDisconnectFailure> failures,
        IReadOnlyList<WindowsTunnelServiceIdentity>? unresolvedTargets = null) =>
        new(false, failures.ToArray(), unresolvedTargets ?? []);
}

public sealed record CloseDisconnectPreparation(
    Guid OperationId,
    CloseDisconnectFailure? Failure);

public interface IUserCloseDisconnectParticipant
{
    Task<CloseDisconnectPreparation> PrepareAsync(CancellationToken cancellationToken);

    Task<CloseDisconnectResult> DisconnectAsync(
        CloseDisconnectPreparation preparation,
        CancellationToken cancellationToken);
}

public interface IWindowsTunnelServiceStop
{
    Task StopAndUninstallAsync(
        IReadOnlyList<WindowsTunnelServiceIdentity> targets,
        CancellationToken cancellationToken);
}

/// <summary>
/// Durably records exact close targets, attempts one non-short-circuiting stop
/// batch, and verifies only the targets owned by that close operation.
/// </summary>
public sealed class CloseDisconnectCoordinator : IUserCloseDisconnectParticipant
{
    private static readonly TimeSpan VerificationRecheckDelay = TimeSpan.FromMilliseconds(200);
    private const int MaximumVerificationRechecks = 10;

    private readonly IWindowsTunnelServiceEnumerator enumerator;
    private readonly IWindowsTunnelServiceStop tunnelStop;
    private readonly ICloseDisconnectJournal journal;
    private readonly IEnableTunnelActivitySource enableActivitySource;
    private readonly Func<Guid> operationIdFactory;
    private readonly IEnableTunnelProcessSettlementProbe enableSettlementProbe;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;

    public CloseDisconnectCoordinator(
        IWindowsTunnelServiceEnumerator enumerator,
        IWindowsTunnelServiceStop tunnelStop,
        ICloseDisconnectJournal journal,
        IEnableTunnelActivitySource enableActivitySource,
        Func<Guid> operationIdFactory,
        IEnableTunnelProcessSettlementProbe enableSettlementProbe,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null)
    {
        this.enumerator = enumerator ?? throw new ArgumentNullException(nameof(enumerator));
        this.tunnelStop = tunnelStop ?? throw new ArgumentNullException(nameof(tunnelStop));
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        this.enableActivitySource = enableActivitySource
            ?? throw new ArgumentNullException(nameof(enableActivitySource));
        this.operationIdFactory = operationIdFactory
            ?? throw new ArgumentNullException(nameof(operationIdFactory));
        this.enableSettlementProbe = enableSettlementProbe
            ?? throw new ArgumentNullException(nameof(enableSettlementProbe));
        this.delayAsync = delayAsync ?? Task.Delay;
    }

    public async Task<CloseDisconnectPreparation> PrepareAsync(
        CancellationToken cancellationToken)
    {
        CloseDisconnectJournalEntry? existing;
        try
        {
            existing = journal.Load();
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return PreparationFailure(CloseDisconnectFailureKind.Journal);
        }

        EnableTunnelActivity activity;
        try
        {
            // Capture exactly once: the task and its selected identity must describe
            // the same operation even if Enable Now completes immediately afterward.
            activity = enableActivitySource.CaptureActivity();
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return PreparationFailure(CloseDisconnectFailureKind.EnableWait);
        }

        var operationId = existing?.OperationId ?? operationIdFactory();
        var pendingEnable = activity.PendingTunnel ?? existing?.PendingEnable;
        var pendingProcess = activity.ProcessIdentity
            ?? (activity.PendingTunnel is null ? existing?.PendingEnableProcess : null);
        var hasPendingEnable = activity.PendingTunnel is not null
            || activity.ProcessIdentity is not null
            || !activity.Completion.IsCompleted;
        CloseDisconnectJournalEntry? waitingEntry = null;

        if (existing is not null || hasPendingEnable)
        {
            waitingEntry = new CloseDisconnectJournalEntry(
                operationId,
                CloseDisconnectJournalPhase.WaitingForEnable,
                existing?.Targets ?? [],
                pendingEnable,
                pendingProcess);
            try
            {
                // This write must happen before observing completion so a forced
                // process exit during the wait leaves a startup recovery debt.
                journal.Save(waitingEntry);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                return PreparationFailure(CloseDisconnectFailureKind.Journal, operationId);
            }
        }

        if (waitingEntry is not null
            && activity.ProcessIdentity is null
            && !activity.ProcessIdentityAvailable.IsCompleted)
        {
            // The captured activity publishes its exact identity immediately after
            // the elevated process starts. Waiting for either signal never abandons
            // the noncancelable process completion itself.
            await Task.WhenAny(activity.Completion, activity.ProcessIdentityAvailable)
                .ConfigureAwait(false);
        }

        if (waitingEntry is not null
            && activity.ProcessIdentity is not null
            && !ProcessIdentitiesEqual(
                waitingEntry.PendingEnableProcess,
                activity.ProcessIdentity))
        {
            waitingEntry = waitingEntry with { PendingEnableProcess = activity.ProcessIdentity };
            try
            {
                journal.Save(waitingEntry);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                return PreparationFailure(CloseDisconnectFailureKind.Journal, operationId);
            }
        }

        try
        {
            // The elevated process is noncancelable. Close cancellation may cancel
            // its follow-on work, but must never abandon the captured activity wait.
            await activity.Completion.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Enable follow-on cancellation is expected once user close owns the
            // routing pipeline. The journaled pending identity is cleaned up below.
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return PreparationFailure(CloseDisconnectFailureKind.EnableWait, operationId);
        }

        return new CloseDisconnectPreparation(operationId, null);
    }

    public async Task<CloseDisconnectResult> DisconnectAsync(
        CloseDisconnectPreparation preparation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(preparation);
        var failures = new List<CloseDisconnectFailure>();
        if (preparation.Failure is not null)
        {
            if (preparation.Failure.Kind != CloseDisconnectFailureKind.EnableWait)
            {
                return CloseDisconnectResult.Failed([preparation.Failure]);
            }

            // A faulted Enable may already have installed its selected service.
            // Preserve the actual failure while still attempting recorded cleanup.
            failures.Add(preparation.Failure);
        }

        CloseDisconnectJournalEntry? existing;
        try
        {
            existing = journal.Load();
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures.Add(CreateFailure(CloseDisconnectFailureKind.Journal));
            return CloseDisconnectResult.Failed(failures);
        }

        if (existing is not null && existing.OperationId != preparation.OperationId)
        {
            // Never adopt, overwrite, stop, or complete another close operation.
            failures.Add(CreateFailure(CloseDisconnectFailureKind.Journal));
            return CloseDisconnectResult.Failed(failures);
        }

        IReadOnlyList<WindowsTunnelServiceIdentity> installed;
        try
        {
            installed = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures.Add(CreateFailure(CloseDisconnectFailureKind.Enumeration));
            return CloseDisconnectResult.Failed(failures);
        }

        var targets = MergeTargets(existing?.Targets, installed, existing?.PendingEnable);
        var operationId = existing?.OperationId ?? preparation.OperationId;
        if (targets.Count == 0)
        {
            if (failures.Count > 0)
            {
                return CloseDisconnectResult.Failed(failures);
            }

            return existing is null
                ? CloseDisconnectResult.Succeeded()
                : CompleteWithoutFailures(operationId);
        }

        var recordedEntry = new CloseDisconnectJournalEntry(
            operationId,
            CloseDisconnectJournalPhase.TargetsRecorded,
            targets,
            existing?.PendingEnable,
            existing?.PendingEnableProcess);
        if (existing is null || !JournalAlreadyRecords(existing, recordedEntry))
        {
            try
            {
                journal.Save(recordedEntry);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                failures.Add(CreateFailure(CloseDisconnectFailureKind.Journal));
                return CloseDisconnectResult.Failed(failures);
            }
        }

        var installedTargets = IntersectTargets(targets, installed);
        if (installedTargets.Count > 0)
        {
            try
            {
                // The adapter receives the whole batch. Its command builder uses &
                // so a failure for one service does not skip the remaining targets.
                await tunnelStop.StopAndUninstallAsync(installedTargets, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                failures.Add(CreateFailure(MapStopFailureKind(exception)));
            }
        }

        IReadOnlyList<WindowsTunnelServiceIdentity> remaining;
        try
        {
            // Always verify, including after a helper/start/stop exception. A later
            // verification result must not erase the primary stop failure.
            remaining = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures.Add(CreateFailure(CloseDisconnectFailureKind.Verification));
            return CloseDisconnectResult.Failed(failures);
        }

        var unresolved = IntersectTargets(targets, remaining);
        for (var attempt = 0;
            failures.Count == 0
            && unresolved.Count > 0
            && attempt < MaximumVerificationRechecks;
            attempt++)
        {
            try
            {
                await delayAsync(VerificationRecheckDelay, cancellationToken).ConfigureAwait(false);
                remaining = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
                unresolved = IntersectTargets(targets, remaining);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                failures.Add(CreateFailure(CloseDisconnectFailureKind.Verification));
                return CloseDisconnectResult.Failed(failures, unresolved);
            }
        }

        if (failures.Count == 0 && unresolved.Count == 0)
        {
            return CompleteWithoutFailures(operationId);
        }

        return CloseDisconnectResult.Failed(failures, unresolved);
    }

    public async Task<CloseDisconnectResult> ReconcileAsync(CancellationToken cancellationToken)
    {
        CloseDisconnectJournalEntry? existing;
        try
        {
            existing = journal.Load();
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return Failure(CloseDisconnectFailureKind.Journal);
        }

        if (existing is null)
        {
            return CloseDisconnectResult.Succeeded();
        }

        if (existing.Phase == CloseDisconnectJournalPhase.WaitingForEnable
            && existing.PendingEnable is not null)
        {
            if (existing.PendingEnableProcess is null)
            {
                // This includes the pre-process-start/UAC window and legacy entries.
                // Service absence cannot prove that the old elevated Enable settled.
                return Failure(CloseDisconnectFailureKind.EnableWait);
            }

            EnableTunnelProcessSettlement settlement;
            try
            {
                settlement = enableSettlementProbe.Probe(existing.PendingEnableProcess);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                return Failure(CloseDisconnectFailureKind.EnableWait);
            }

            if (settlement != EnableTunnelProcessSettlement.Settled)
            {
                return Failure(CloseDisconnectFailureKind.EnableWait);
            }
        }

        // Startup recovery deliberately has a closed target set. In particular,
        // do not capture Enable Now or adopt unrelated services discovered now.
        var targets = MergeTargets(existing.Targets, existing.PendingEnable);
        if (targets.Count == 0)
        {
            return CompleteWithoutFailures(existing.OperationId);
        }

        IReadOnlyList<WindowsTunnelServiceIdentity> installed;
        try
        {
            installed = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return Failure(CloseDisconnectFailureKind.Enumeration);
        }

        var installedTargets = IntersectTargets(targets, installed);
        if (installedTargets.Count == 0)
        {
            return CompleteWithoutFailures(existing.OperationId);
        }

        var recordedEntry = existing with
        {
            Phase = CloseDisconnectJournalPhase.TargetsRecorded,
            Targets = targets
        };
        if (!JournalAlreadyRecords(existing, recordedEntry))
        {
            try
            {
                journal.Save(recordedEntry);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                return Failure(CloseDisconnectFailureKind.Journal);
            }
        }

        var failures = new List<CloseDisconnectFailure>();
        try
        {
            await tunnelStop.StopAndUninstallAsync(installedTargets, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures.Add(CreateFailure(MapStopFailureKind(exception)));
        }

        IReadOnlyList<WindowsTunnelServiceIdentity> remaining;
        try
        {
            remaining = await enumerator.ListInstalledAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures.Add(CreateFailure(CloseDisconnectFailureKind.Verification));
            return CloseDisconnectResult.Failed(failures);
        }

        var unresolved = IntersectTargets(targets, remaining);
        if (failures.Count == 0 && unresolved.Count == 0)
        {
            return CompleteWithoutFailures(existing.OperationId);
        }

        return CloseDisconnectResult.Failed(failures, unresolved);
    }

    private CloseDisconnectResult CompleteWithoutFailures(Guid operationId)
    {
        try
        {
            journal.Complete(operationId);

            // Complete deliberately preserves a mismatched replacement as a no-op.
            // Confirm the final state instead of mistaking that preservation for
            // successful finalization of this operation.
            return journal.Load() is null
                ? CloseDisconnectResult.Succeeded()
                : Failure(CloseDisconnectFailureKind.Journal);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return Failure(CloseDisconnectFailureKind.Journal);
        }
    }

    private static CloseDisconnectPreparation PreparationFailure(
        CloseDisconnectFailureKind kind,
        Guid operationId = default) =>
        new(operationId, CreateFailure(kind));

    private static CloseDisconnectResult Failure(CloseDisconnectFailureKind kind) =>
        CloseDisconnectResult.Failed([CreateFailure(kind)]);

    private static CloseDisconnectFailure CreateFailure(CloseDisconnectFailureKind kind) =>
        new(kind, kind switch
        {
            CloseDisconnectFailureKind.Journal =>
                "The close-disconnect journal operation failed; cleanup remains pending.",
            CloseDisconnectFailureKind.EnableWait =>
                "The in-flight tunnel enable operation did not complete successfully; cleanup remains pending.",
            CloseDisconnectFailureKind.Enumeration =>
                "Installed WireGuard tunnel services could not be enumerated; cleanup remains pending.",
            CloseDisconnectFailureKind.ElevatedHelperStart =>
                "The elevated tunnel-stop helper could not be started; cleanup remains pending.",
            CloseDisconnectFailureKind.Stop =>
                "One or more WireGuard tunnel services could not be stopped; cleanup remains pending.",
            CloseDisconnectFailureKind.Verification =>
                "WireGuard tunnel service removal could not be verified; cleanup remains pending.",
            _ => "WireGuard tunnel cleanup failed; cleanup remains pending."
        });

    private static CloseDisconnectFailureKind MapStopFailureKind(Exception exception)
    {
        try
        {
            // Task 6's Windows adapter exposes a typed Kind property. Reflection
            // keeps this Core coordinator independent of that platform adapter and
            // avoids carrying its raw process output into the result.
            var value = exception.GetType()
                .GetProperty("Kind", BindingFlags.Public | BindingFlags.Instance)
                ?.GetValue(exception);
            return value is CloseDisconnectFailureKind.ElevatedHelperStart
                ? CloseDisconnectFailureKind.ElevatedHelperStart
                : CloseDisconnectFailureKind.Stop;
        }
        catch (Exception exceptionFromKind) when (IsOperationalFailure(exceptionFromKind))
        {
            return CloseDisconnectFailureKind.Stop;
        }
    }

    private static IReadOnlyList<WindowsTunnelServiceIdentity> MergeTargets(
        params object?[] targetGroups)
    {
        var targets = new List<WindowsTunnelServiceIdentity>();
        foreach (var group in targetGroups)
        {
            switch (group)
            {
                case WindowsTunnelServiceIdentity identity:
                    targets.Add(identity);
                    break;
                case IEnumerable<WindowsTunnelServiceIdentity> identities:
                    targets.AddRange(identities);
                    break;
            }
        }

        return targets
            .DistinctBy(target => target.TunnelName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(target => target.TunnelName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(target => target.ServiceName, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<WindowsTunnelServiceIdentity> IntersectTargets(
        IEnumerable<WindowsTunnelServiceIdentity> recordedTargets,
        IEnumerable<WindowsTunnelServiceIdentity> installedTargets)
    {
        var installedNames = installedTargets
            .Select(target => target.TunnelName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return recordedTargets
            .Where(target => installedNames.Contains(target.TunnelName))
            .ToArray();
    }

    private static bool JournalAlreadyRecords(
        CloseDisconnectJournalEntry existing,
        CloseDisconnectJournalEntry required) =>
        existing.OperationId == required.OperationId
        && existing.Phase == CloseDisconnectJournalPhase.TargetsRecorded
        && TargetsEqual(existing.Targets, required.Targets)
        && IdentitiesEqual(existing.PendingEnable, required.PendingEnable)
        && ProcessIdentitiesEqual(existing.PendingEnableProcess, required.PendingEnableProcess);

    private static bool TargetsEqual(
        IEnumerable<WindowsTunnelServiceIdentity> left,
        IEnumerable<WindowsTunnelServiceIdentity> right)
    {
        var leftNames = left.Select(target => target.TunnelName)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var rightNames = right.Select(target => target.TunnelName)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return leftNames.SequenceEqual(rightNames, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IdentitiesEqual(
        WindowsTunnelServiceIdentity? left,
        WindowsTunnelServiceIdentity? right) =>
        left is null || right is null
            ? left is null && right is null
            : string.Equals(left.TunnelName, right.TunnelName, StringComparison.OrdinalIgnoreCase);

    private static bool ProcessIdentitiesEqual(
        EnableTunnelProcessIdentity? left,
        EnableTunnelProcessIdentity? right) =>
        left is null || right is null
            ? left is null && right is null
            : left.ProcessId == right.ProcessId
                && left.CreationTimeFileTimeUtc == right.CreationTimeFileTimeUtc;

    private static bool IsOperationalFailure(Exception exception) =>
        exception is not (
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException);
}
