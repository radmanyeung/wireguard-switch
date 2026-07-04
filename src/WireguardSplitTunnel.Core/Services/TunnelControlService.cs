using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public interface ITunnelControlService
{
    Task InstallAndStartAsync(string configPath, CancellationToken cancellationToken);
    Task StopAndUninstallAsync(string tunnelName, CancellationToken cancellationToken);
}

public sealed class TunnelControlService : ITunnelControlService
{
    private readonly ITunnelControlService inner;

    public TunnelControlService()
    {
        if (OperatingSystem.IsWindows())
        {
            inner = new WindowsTunnelControlService();
        }
        else if (OperatingSystem.IsMacOS())
        {
            inner = new MacTunnelControlService();
        }
        else
        {
            throw new PlatformNotSupportedException(
                $"TunnelControlService is not supported on platform '{PlatformRuntime.CurrentName}'.");
        }
    }

    public Task InstallAndStartAsync(string configPath, CancellationToken cancellationToken)
        => inner.InstallAndStartAsync(configPath, cancellationToken);

    public Task StopAndUninstallAsync(string tunnelName, CancellationToken cancellationToken)
        => inner.StopAndUninstallAsync(tunnelName, cancellationToken);
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsTunnelControlService : ITunnelControlService
{
    public Task InstallAndStartAsync(string configPath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath))
        {
            throw new FileNotFoundException("WireGuard config path not found.", configPath);
        }

        var wireguardExe = ResolveWireguardExecutablePath()
            ?? throw new FileNotFoundException("wireguard.exe not found. Please install WireGuard first.");

        return RunAsync(wireguardExe, WireguardConfigCatalog.BuildInstallTunnelArgs(configPath), cancellationToken);
    }

    public Task StopAndUninstallAsync(string tunnelName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tunnelName))
        {
            throw new ArgumentException("Tunnel name is required.", nameof(tunnelName));
        }

        var wireguardExe = ResolveWireguardExecutablePath()
            ?? throw new FileNotFoundException("wireguard.exe not found.");

        return RunAsync(wireguardExe, WireguardConfigCatalog.BuildUninstallTunnelArgs(tunnelName), cancellationToken);
    }

    private static string? ResolveWireguardExecutablePath()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wireguard.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WireGuard", "wireguard.exe")
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static async Task RunAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = true,
            Verb = "runas",
            CreateNoWindow = true
        };

        using var process = Process.Start(info)
            ?? throw new InvalidOperationException("Unable to launch wireguard.exe.");

        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"wireguard.exe {arguments} failed (exit {process.ExitCode}).");
        }
    }
}

[SupportedOSPlatform("macos")]
internal sealed class MacTunnelControlService : ITunnelControlService
{
    private static readonly string[] WgQuickCandidates =
    [
        "/opt/homebrew/bin/wg-quick",
        "/usr/local/bin/wg-quick"
    ];

    public Task InstallAndStartAsync(string configPath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath))
        {
            throw new FileNotFoundException("WireGuard config path not found.", configPath);
        }

        var wgQuick = ResolveWgQuick();
        var script = BuildInstallAndStartScript(wgQuick, configPath, DiscoverActiveTunnelNames());

        return RunBatchAsync(script.ToString(), "WireGuard split tunnel needs to start the tunnel", cancellationToken);
    }

    public Task StopAndUninstallAsync(string tunnelName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tunnelName))
        {
            throw new ArgumentException("Tunnel name is required.", nameof(tunnelName));
        }

        var wgQuick = ResolveWgQuick();
        var script = $"{wgQuick} down \"{tunnelName}\"";
        return RunBatchAsync(script, "WireGuard split tunnel needs to stop the tunnel", cancellationToken);
    }

    private static async Task RunBatchAsync(string scriptBody, string promptReason, CancellationToken cancellationToken)
    {
        var result = await MacAdminShell.RunAsAdminAsync(scriptBody, promptReason, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"wg-quick failed (exit {result.ExitCode}): {result.Combined}");
        }
    }

    private static string ResolveWgQuick()
    {
        foreach (var candidate in WgQuickCandidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(
            "wg-quick not found. Install WireGuard tools via 'brew install wireguard-tools'.");
    }

    internal static string BuildInstallAndStartScript(
        string wgQuick,
        string configPath,
        IEnumerable<string> activeTunnelNames)
    {
        var script = new StringBuilder();
        _ = activeTunnelNames;

        // Bring down only the selected config first so re-applies are idempotent.
        // Do not stop unrelated active tunnels: users may already have the official
        // WireGuard app connected, and Start AI VPN should not break that tunnel.
        script.AppendLine($"{wgQuick} down {ShellQuote(configPath)} >/dev/null 2>&1 || true");
        script.AppendLine($"{wgQuick} up {ShellQuote(configPath)}");
        return script.ToString();
    }

    internal static IReadOnlyList<string> DiscoverActiveTunnelNamesFromRunEntries(IEnumerable<string> runEntries)
    {
        return runEntries
            .Select(TryGetTunnelNameFromNameFile)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList()!;
    }

    private static IReadOnlyList<string> DiscoverActiveTunnelNames()
    {
        const string wgRunDir = "/var/run/wireguard";
        try
        {
            return Directory.Exists(wgRunDir)
                ? DiscoverActiveTunnelNamesFromRunEntries(Directory.EnumerateFiles(wgRunDir, "*.name"))
                : [];
        }
        catch
        {
            return [];
        }
    }

    private static string? TryGetTunnelNameFromNameFile(string path)
    {
        var fileName = Path.GetFileName(path);
        if (!fileName.EndsWith(".name", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var tunnelName = fileName[..^".name".Length];
        return string.IsNullOrWhiteSpace(tunnelName) ? null : tunnelName;
    }

    private static string ShellQuote(string value) =>
        "\"" + value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("$", "\\$", StringComparison.Ordinal)
            .Replace("`", "\\`", StringComparison.Ordinal) + "\"";
}
