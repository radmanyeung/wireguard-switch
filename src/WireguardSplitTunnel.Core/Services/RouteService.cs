using System.Diagnostics;
using System.Net.NetworkInformation;

namespace WireguardSplitTunnel.Core.Services;

public interface IRouteService
{
    Task ApplyAsync(string interfaceName, IEnumerable<string> toAdd, IEnumerable<string> toRemove, CancellationToken cancellationToken);
}

public sealed class RouteService : IRouteService
{
    public async Task ApplyAsync(
        string interfaceName,
        IEnumerable<string> toAdd,
        IEnumerable<string> toRemove,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            throw new ArgumentException("Interface name is required.", nameof(interfaceName));
        }

        var interfaceIndex = ResolveInterfaceIndex(interfaceName);

        foreach (var ip in toRemove.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            await RunRouteCommandAsync($"delete {ip} mask 255.255.255.255", cancellationToken, allowNotFound: true);
            await RunRouteCommandAsync($"delete {ip} mask 255.255.255.255 if {interfaceIndex}", cancellationToken, allowNotFound: true);
        }

        foreach (var ip in toAdd.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // Force-rebind host route to WireGuard interface: remove any stale route first.
            await RunRouteCommandAsync($"delete {ip} mask 255.255.255.255", cancellationToken, allowNotFound: true);
            await RunRouteCommandAsync($"add {ip} mask 255.255.255.255 0.0.0.0 if {interfaceIndex}", cancellationToken, allowNotFound: false);
        }
    }

    private static int ResolveInterfaceIndex(string interfaceName)
    {
        var networkInterface = NetworkInterface
            .GetAllNetworkInterfaces()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, interfaceName, StringComparison.OrdinalIgnoreCase));

        if (networkInterface is null)
        {
            throw new InvalidOperationException($"Network interface '{interfaceName}' was not found.");
        }

        var ipv4 = networkInterface.GetIPProperties().GetIPv4Properties();
        if (ipv4 is null)
        {
            throw new InvalidOperationException($"Network interface '{interfaceName}' does not expose an IPv4 interface index.");
        }

        return ipv4.Index;
    }

    private static async Task RunRouteCommandAsync(string arguments, CancellationToken cancellationToken, bool allowNotFound)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "route",
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Unable to start route command process.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var combined = (stdout + "\n" + stderr).Trim();

        var hasFailureWord = combined.Contains("failed", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("failure", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("失敗", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("找不到", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("元素找不到", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("The route specified was not found", StringComparison.OrdinalIgnoreCase);

        if (allowNotFound && hasFailureWord)
        {
            return;
        }

        if (process.ExitCode != 0 || hasFailureWord)
        {
            throw new InvalidOperationException($"route {arguments} failed (exit {process.ExitCode}): {combined}");
        }
    }
}
