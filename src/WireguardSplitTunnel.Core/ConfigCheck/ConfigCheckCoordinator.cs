namespace WireguardSplitTunnel.Core.ConfigCheck;

/// <summary>
/// Owns the UI-independent config-check lifecycle. The caller's workflow includes
/// its restoration work; the shared software and routing gates remain held until
/// that work, any completion callback, and cleanup have finished.
/// </summary>
public sealed class ConfigCheckCoordinator
{
    private readonly SemaphoreSlim softwareGate;
    private readonly SemaphoreSlim routingGate;
    private readonly Action resumeClose;
    private readonly object sync = new();
    private bool active;
    private bool closeDeferred;
    private bool closeResumePending;

    public ConfigCheckCoordinator(
        SemaphoreSlim softwareGate,
        SemaphoreSlim routingGate,
        Action resumeClose)
    {
        this.softwareGate = softwareGate ?? throw new ArgumentNullException(nameof(softwareGate));
        this.routingGate = routingGate ?? throw new ArgumentNullException(nameof(routingGate));
        this.resumeClose = resumeClose ?? throw new ArgumentNullException(nameof(resumeClose));
    }

    public bool IsActive
    {
        get
        {
            lock (sync) return active;
        }
    }

    public bool TryDeferClose()
    {
        lock (sync)
        {
            if (active)
            {
                closeDeferred = true;
                return true;
            }

            // The resume callback re-enters normal window closing. Cleanup has
            // finished, so that close must proceed instead of deferring again.
            return false;
        }
    }

    public async Task<bool> RunAsync(
        Func<CancellationToken, Task<bool>> confirmInterruptionAsync,
        Func<CancellationToken, Task> runWorkflowAsync,
        Func<CancellationToken, Task> completeAsync,
        Action<bool> setControlsEnabled,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(confirmInterruptionAsync);
        ArgumentNullException.ThrowIfNull(runWorkflowAsync);
        ArgumentNullException.ThrowIfNull(completeAsync);
        ArgumentNullException.ThrowIfNull(setControlsEnabled);
        if (!TryBegin()) return false;

        var softwareGateAcquired = false;
        var routingGateAcquired = false;
        var controlsDisabled = false;
        try
        {
            if (!await confirmInterruptionAsync(cancellationToken).ConfigureAwait(true)
                || CloseIsDeferred())
            {
                return false;
            }

            setControlsEnabled(false);
            controlsDisabled = true;
            try
            {
                // All paths that need both gates acquire software before routing.
                // Keep both through service restoration, route renewal, and recycle.
                await softwareGate.WaitAsync(cancellationToken).ConfigureAwait(true);
                softwareGateAcquired = true;
                await routingGate.WaitAsync(cancellationToken).ConfigureAwait(true);
                routingGateAcquired = true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return false;
            }

            if (CloseIsDeferred()) return false;
            await runWorkflowAsync(cancellationToken).ConfigureAwait(true);
            if (CloseIsDeferred()) return false;
            await completeAsync(cancellationToken).ConfigureAwait(true);
            return !CloseIsDeferred();
        }
        finally
        {
            if (routingGateAcquired) routingGate.Release();
            if (softwareGateAcquired) softwareGate.Release();
            if (controlsDisabled && !CloseIsDeferred()) setControlsEnabled(true);

            var shouldResumeClose = false;
            lock (sync)
            {
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

    private bool TryBegin()
    {
        lock (sync)
        {
            if (active || closeResumePending) return false;
            active = true;
            closeDeferred = false;
            return true;
        }
    }

    private bool CloseIsDeferred()
    {
        lock (sync) return closeDeferred;
    }
}
