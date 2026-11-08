namespace WireguardSplitTunnel.Core.ConfigCheck;

public interface IConfigCheckRecoveryAdapter
{
    Task<IReadOnlyList<ConfigCheckRecoveredTunnel>> RecoverAllAsync(
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task> reconcileDerivedConfigAsync,
        Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null);
}

/// <summary>
/// Serializes all startup journal recovery and its applicable follow-on route
/// renewal with every other service and routing mutation.
/// </summary>
public sealed class ConfigCheckStartupRecoveryCoordinator
{
    private readonly SemaphoreSlim softwareGate;
    private readonly SemaphoreSlim routingGate;
    private readonly Action resumeClose;
    private readonly object sync = new();
    private bool active = true;
    private bool failed;
    private bool running;
    private bool closeDeferred;
    private bool closeResumePending;
    private bool closeRequested;

    public ConfigCheckStartupRecoveryCoordinator(
        SemaphoreSlim softwareGate,
        SemaphoreSlim routingGate,
        Action? resumeClose = null)
    {
        this.softwareGate = softwareGate ?? throw new ArgumentNullException(nameof(softwareGate));
        this.routingGate = routingGate ?? throw new ArgumentNullException(nameof(routingGate));
        this.resumeClose = resumeClose ?? (() => { });
    }

    public bool IsActive
    {
        get
        {
            lock (sync) return active;
        }
    }

    public bool IsTunnelEnableBlocked
    {
        get
        {
            lock (sync) return active || failed;
        }
    }

    public bool CloseWasRequested
    {
        get
        {
            lock (sync) return closeRequested;
        }
    }

    public bool TryDeferClose()
    {
        lock (sync)
        {
            if (!active) return false;
            closeRequested = true;
            closeDeferred = true;
            return true;
        }
    }

    public void CompletePending()
    {
        var shouldResumeClose = false;
        lock (sync)
        {
            if (running || !active) return;
            failed = true;
            active = false;
            if (closeDeferred)
            {
                closeDeferred = false;
                closeResumePending = true;
                shouldResumeClose = true;
            }
        }

        if (!shouldResumeClose) return;
        try
        {
            resumeClose();
        }
        finally
        {
            lock (sync) closeResumePending = false;
        }
    }

    public async Task RunAsync(
        IConfigCheckRecoveryAdapter adapter,
        Func<ConfigCheckRestoreContext, CancellationToken, Task> reconcileDerivedConfigAsync,
        Func<ConfigCheckRecoveredService, bool> shouldRestoreRoutes,
        Func<CancellationToken, Task> restoreRoutesAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(reconcileDerivedConfigAsync);
        ArgumentNullException.ThrowIfNull(shouldRestoreRoutes);
        ArgumentNullException.ThrowIfNull(restoreRoutesAsync);
        lock (sync)
        {
            if (running || closeResumePending)
                throw new InvalidOperationException("Startup recovery is already running or handing off close.");
            running = true;
            active = true;
        }

        var softwareGateAcquired = false;
        var routingGateAcquired = false;
        var succeeded = false;
        try
        {
            // Close cancellation stops unrelated startup work, but must never
            // abandon journal, service, or route restoration.
            await softwareGate.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            softwareGateAcquired = true;
            await routingGate.WaitAsync(CancellationToken.None).ConfigureAwait(true);
            routingGateAcquired = true;

            var routesRestored = false;
            await adapter.RecoverAllAsync(
                CancellationToken.None,
                reconcileDerivedConfigAsync,
                async (service, _) =>
                {
                    if (routesRestored || !shouldRestoreRoutes(service)) return;
                    await restoreRoutesAsync(CancellationToken.None).ConfigureAwait(true);
                    routesRestored = true;
                }).ConfigureAwait(true);
            succeeded = true;
        }
        finally
        {
            if (routingGateAcquired) routingGate.Release();
            if (softwareGateAcquired) softwareGate.Release();

            var shouldResumeClose = false;
            lock (sync)
            {
                running = false;
                failed = !succeeded;
                active = false;
                if (closeDeferred)
                {
                    closeDeferred = false;
                    closeResumePending = true;
                    shouldResumeClose = true;
                }
            }

            if (shouldResumeClose)
            {
                try
                {
                    resumeClose();
                }
                finally
                {
                    lock (sync) closeResumePending = false;
                }
            }
        }
    }
}
