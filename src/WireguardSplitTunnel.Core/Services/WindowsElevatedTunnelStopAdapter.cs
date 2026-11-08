using System.Diagnostics;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Services;

public sealed class WindowsTunnelStopException : Exception
{
    internal WindowsTunnelStopException(CloseDisconnectFailureKind kind)
        : base(CreateSafeMessage(kind))
    {
        Kind = kind;
    }

    public CloseDisconnectFailureKind Kind { get; }

    private static string CreateSafeMessage(CloseDisconnectFailureKind kind) => kind switch
    {
        CloseDisconnectFailureKind.ElevatedHelperStart =>
            "The elevated tunnel-stop helper could not be started; cleanup remains pending.",
        CloseDisconnectFailureKind.Stop =>
            "One or more WireGuard tunnel services could not be stopped; cleanup remains pending.",
        _ => "WireGuard tunnel cleanup failed; cleanup remains pending."
    };
}

public sealed class WindowsElevatedTunnelStopAdapter : IWindowsTunnelServiceStop
{
    private readonly IEnableTunnelProcessFactory processFactory;
    private readonly Func<string?> resolveWireguardExecutablePath;

    public WindowsElevatedTunnelStopAdapter(
        IEnableTunnelProcessFactory processFactory,
        Func<string?> resolveWireguardExecutablePath)
    {
        this.processFactory = processFactory ?? throw new ArgumentNullException(nameof(processFactory));
        this.resolveWireguardExecutablePath = resolveWireguardExecutablePath
            ?? throw new ArgumentNullException(nameof(resolveWireguardExecutablePath));
    }

    public async Task StopAndUninstallAsync(
        IReadOnlyList<WindowsTunnelServiceIdentity> targets,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targets);
        if (targets.Count == 0) return;

        IEnableTunnelProcess process;
        try
        {
            var wireguardExePath = resolveWireguardExecutablePath();
            if (string.IsNullOrWhiteSpace(wireguardExePath))
            {
                throw new WindowsTunnelStopException(CloseDisconnectFailureKind.ElevatedHelperStart);
            }

            var arguments = WindowsCloseDisconnectCommandBuilder.BuildArguments(
                wireguardExePath,
                targets);
            process = processFactory.Start(new ProcessStartInfo
            {
                FileName = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "cmd.exe"),
                // Preserve every inner quote when cmd strips its sacrificial pair.
                Arguments = "/c \"" + arguments + "\"",
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            });
        }
        catch (WindowsTunnelStopException)
        {
            throw;
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            throw new WindowsTunnelStopException(CloseDisconnectFailureKind.ElevatedHelperStart);
        }

        using (process)
        {
            try
            {
                // The elevated stop cannot be abandoned after it has started.
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                throw new WindowsTunnelStopException(CloseDisconnectFailureKind.Stop);
            }

            if (process.ExitCode != 0)
            {
                throw new WindowsTunnelStopException(CloseDisconnectFailureKind.Stop);
            }
        }
    }

    private static bool IsOperationalFailure(Exception exception) =>
        exception is not (
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException);
}
