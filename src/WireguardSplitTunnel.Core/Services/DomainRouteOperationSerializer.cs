namespace WireguardSplitTunnel.Core.Services;

public static class DomainRouteOperationSerializer
{
    public static async Task RunAsync(
        SemaphoreSlim gate,
        Action mutation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(mutation);

        await gate.WaitAsync(cancellationToken);
        try
        {
            mutation();
        }
        finally
        {
            gate.Release();
        }
    }

    public static async Task RunAsync(
        SemaphoreSlim gate,
        Func<Task> operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(operation);

        await gate.WaitAsync(cancellationToken);
        try
        {
            await operation();
        }
        finally
        {
            gate.Release();
        }
    }
}