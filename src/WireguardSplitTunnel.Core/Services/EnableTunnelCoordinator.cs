using System.Diagnostics;

namespace WireguardSplitTunnel.Core.Services;

public sealed record EnableTunnelProcessIdentity(
    int ProcessId,
    long CreationTimeFileTimeUtc);

public interface IEnableTunnelProcess : IDisposable
{
    EnableTunnelProcessIdentity? Identity => null;
    int ExitCode { get; }
    Task WaitForExitAsync(CancellationToken cancellationToken);
}

public interface IEnableTunnelProcessFactory
{
    IEnableTunnelProcess Start(ProcessStartInfo startInfo);
}

public sealed record EnableTunnelActivity(
    WindowsTunnelServiceIdentity? PendingTunnel,
    Task Completion)
{
    public EnableTunnelProcessIdentity? ProcessIdentity { get; internal set; }

    public Task ProcessIdentityAvailable { get; internal init; } = Task.CompletedTask;
}

public interface IEnableTunnelActivitySource
{
    EnableTunnelActivity CaptureActivity();
}

/// <summary>
/// Serializes elevated tunnel installation and its follow-on renewal with all
/// other routing mutations. Once started, the process is tracked through exit
/// even when application close cancels the remaining renewal work.
/// </summary>
public sealed class EnableTunnelCoordinator : IEnableTunnelActivitySource
{
    private static readonly EnableTunnelActivity IdleActivity = new(null, Task.CompletedTask);
    private readonly SemaphoreSlim routingGate;
    private readonly IEnableTunnelProcessFactory processFactory;
    private readonly object activitySync = new();
    private TrackedEnableTunnelActivity? currentActivity;

    public EnableTunnelCoordinator(
        SemaphoreSlim routingGate,
        IEnableTunnelProcessFactory processFactory)
    {
        this.routingGate = routingGate ?? throw new ArgumentNullException(nameof(routingGate));
        this.processFactory = processFactory ?? throw new ArgumentNullException(nameof(processFactory));
    }

    public EnableTunnelActivity CaptureActivity()
    {
        lock (activitySync)
        {
            return currentActivity?.Activity ?? IdleActivity;
        }
    }

    public async Task RunAsync(
        Func<ProcessStartInfo> startInfoFactory,
        Func<bool> mayStart,
        Action processStarted,
        Func<CancellationToken, Task> followOnAsync,
        CancellationToken cancellationToken = default,
        WindowsTunnelServiceIdentity? selectedTunnel = null)
    {
        ArgumentNullException.ThrowIfNull(startInfoFactory);
        ArgumentNullException.ThrowIfNull(mayStart);
        ArgumentNullException.ThrowIfNull(processStarted);
        ArgumentNullException.ThrowIfNull(followOnAsync);
        if (!mayStart()) return;

        await routingGate.WaitAsync(cancellationToken).ConfigureAwait(true);
        TrackedEnableTunnelActivity? activity = null;
        Exception? failure = null;
        try
        {
            // A config check may have acquired the gate while this enable was
            // queued. Never start the elevated service-mutating command late.
            if (!mayStart()) return;

            activity = RegisterActivity(selectedTunnel);
            try
            {
                using var process = processFactory.Start(startInfoFactory());
                PublishProcessIdentity(activity, process.Identity);
                processStarted();
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(true);
                await followOnAsync(cancellationToken).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                failure = ex;
                throw;
            }
        }
        finally
        {
            if (activity is not null)
            {
                ClearActivity(activity);
            }

            routingGate.Release();
            activity?.Complete(failure);
        }
    }

    private TrackedEnableTunnelActivity RegisterActivity(
        WindowsTunnelServiceIdentity? selectedTunnel)
    {
        var activity = new TrackedEnableTunnelActivity(selectedTunnel);
        lock (activitySync)
        {
            currentActivity = activity;
        }

        return activity;
    }

    private void PublishProcessIdentity(
        TrackedEnableTunnelActivity activity,
        EnableTunnelProcessIdentity? processIdentity)
    {
        lock (activitySync)
        {
            activity.PublishProcessIdentity(processIdentity);
        }
    }

    private void ClearActivity(TrackedEnableTunnelActivity activity)
    {
        lock (activitySync)
        {
            if (ReferenceEquals(currentActivity, activity))
            {
                currentActivity = null;
            }
        }
    }

    private sealed class TrackedEnableTunnelActivity
    {
        private readonly TaskCompletionSource completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource processIdentityAvailable =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TrackedEnableTunnelActivity(WindowsTunnelServiceIdentity? selectedTunnel)
        {
            Activity = new EnableTunnelActivity(selectedTunnel, completion.Task)
            {
                ProcessIdentityAvailable = processIdentityAvailable.Task
            };
        }

        public EnableTunnelActivity Activity { get; }

        public void PublishProcessIdentity(EnableTunnelProcessIdentity? processIdentity)
        {
            Activity.ProcessIdentity = processIdentity;
            processIdentityAvailable.TrySetResult();
        }

        public void Complete(Exception? failure)
        {
            processIdentityAvailable.TrySetResult();
            if (failure is null)
            {
                completion.TrySetResult();
            }
            else
            {
                completion.TrySetException(failure);
            }
        }
    }
}
