using System.Diagnostics;

namespace WireguardSplitTunnel.Core.Services;

public enum EnableTunnelProcessSettlement
{
    Settled,
    Running,
    Unknown
}

public interface IEnableTunnelProcessSettlementProbe
{
    EnableTunnelProcessSettlement Probe(EnableTunnelProcessIdentity processIdentity);
}

/// <summary>
/// Reopens only the recorded PID and validates its exact creation time. A reused
/// PID with another creation time proves the original process is gone; it never
/// proves that the replacement process belongs to the old Enable operation.
/// </summary>
public sealed class WindowsEnableTunnelProcessSettlementProbe : IEnableTunnelProcessSettlementProbe
{
    private readonly Func<int, EnableTunnelProcessIdentity?> inspectProcess;

    public WindowsEnableTunnelProcessSettlementProbe()
        : this(InspectProcess)
    {
    }

    internal WindowsEnableTunnelProcessSettlementProbe(
        Func<int, EnableTunnelProcessIdentity?> inspectProcess)
    {
        this.inspectProcess = inspectProcess ?? throw new ArgumentNullException(nameof(inspectProcess));
    }

    public EnableTunnelProcessSettlement Probe(EnableTunnelProcessIdentity processIdentity)
    {
        if (processIdentity is null
            || processIdentity.ProcessId <= 0
            || processIdentity.CreationTimeFileTimeUtc <= 0)
        {
            return EnableTunnelProcessSettlement.Unknown;
        }

        try
        {
            var observed = inspectProcess(processIdentity.ProcessId);
            if (observed is null)
            {
                return EnableTunnelProcessSettlement.Settled;
            }

            if (observed.ProcessId != processIdentity.ProcessId)
            {
                return EnableTunnelProcessSettlement.Unknown;
            }

            return observed.CreationTimeFileTimeUtc == processIdentity.CreationTimeFileTimeUtc
                ? EnableTunnelProcessSettlement.Running
                : EnableTunnelProcessSettlement.Settled;
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return EnableTunnelProcessSettlement.Unknown;
        }
    }

    private static EnableTunnelProcessIdentity? InspectProcess(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return null;
            }

            return new EnableTunnelProcessIdentity(
                process.Id,
                process.StartTime.ToUniversalTime().ToFileTimeUtc());
        }
        catch (ArgumentException)
        {
            // Windows reports an unknown/already-exited PID as an argument error.
            return null;
        }
    }

    private static bool IsOperationalFailure(Exception exception) =>
        exception is not (
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException);
}
