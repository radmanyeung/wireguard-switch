namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Serializes software-policy mutations and prevents an apply that was queued
/// before a config check or startup recovery from running late.
/// </summary>
public sealed class SoftwareApplyCoordinator
{
    private readonly SemaphoreSlim softwareGate;

    public SoftwareApplyCoordinator(SemaphoreSlim softwareGate)
    {
        this.softwareGate = softwareGate ?? throw new ArgumentNullException(nameof(softwareGate));
    }

    public async Task<bool> RunAsync(
        Func<bool> mayApply,
        Func<CancellationToken, Task> applyAsync,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mayApply);
        ArgumentNullException.ThrowIfNull(applyAsync);
        if (!mayApply()) return false;

        await softwareGate.WaitAsync(cancellationToken).ConfigureAwait(true);
        try
        {
            // Config checking or startup recovery may have started while this
            // apply was queued. Recheck under the gate before changing anything.
            if (!mayApply()) return false;
            await applyAsync(cancellationToken).ConfigureAwait(true);
            return true;
        }
        finally
        {
            softwareGate.Release();
        }
    }
}
