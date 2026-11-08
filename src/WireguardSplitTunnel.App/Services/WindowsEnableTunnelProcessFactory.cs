using System.Diagnostics;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.App.Services;

internal sealed class WindowsEnableTunnelProcessFactory : IEnableTunnelProcessFactory
{
    public IEnableTunnelProcess Start(ProcessStartInfo startInfo)
    {
        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The WireGuard enable process could not be started.");
        return new WindowsEnableTunnelProcess(process);
    }

    private sealed class WindowsEnableTunnelProcess(Process process) : IEnableTunnelProcess
    {
        public EnableTunnelProcessIdentity? Identity { get; } = CaptureIdentity(process);

        public int ExitCode => process.ExitCode;

        public Task WaitForExitAsync(CancellationToken cancellationToken) =>
            process.WaitForExitAsync(cancellationToken);

        public void Dispose() => process.Dispose();

        private static EnableTunnelProcessIdentity? CaptureIdentity(Process process)
        {
            try
            {
                var processId = process.Id;
                var creationTime = process.StartTime.ToUniversalTime().ToFileTimeUtc();
                return processId > 0 && creationTime > 0
                    ? new EnableTunnelProcessIdentity(processId, creationTime)
                    : null;
            }
            catch (Exception exception) when (exception is
                InvalidOperationException or
                ArgumentException or
                NotSupportedException or
                System.ComponentModel.Win32Exception)
            {
                // Missing exact identity is fail-closed during startup recovery.
                return null;
            }
        }
    }
}
