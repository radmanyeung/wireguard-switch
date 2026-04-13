using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public interface ISoftwarePolicyService
{
    Task ApplyAsync(string wireguardInterfaceName, IEnumerable<SoftwareRule> rules, DomainRouteMode globalDefaultMode, CancellationToken cancellationToken);
}

public sealed class SoftwareFirewallPolicyService : ISoftwarePolicyService
{
    private const string RulePrefix = "WGST-Software";

    public async Task ApplyAsync(string wireguardInterfaceName, IEnumerable<SoftwareRule> rules, DomainRouteMode globalDefaultMode, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var enabled = rules
            .Where(rule => rule.Enabled && !string.IsNullOrWhiteSpace(rule.ExecutablePath) && File.Exists(rule.ExecutablePath))
            .ToList();

        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
            .Select(nic => nic.Name)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var nonWireguardInterfaces = interfaces
            .Where(name => !string.Equals(name, wireguardInterfaceName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var scriptPath = Path.Combine(Path.GetTempPath(), $"wgst-sw-{Guid.NewGuid():N}.ps1");
        try
        {
            var script = BuildScript(wireguardInterfaceName, nonWireguardInterfaces, enabled, globalDefaultMode);
            await File.WriteAllTextAsync(scriptPath, script, Encoding.UTF8, cancellationToken);
            await RunPowerShellAsAdminAsync(scriptPath, cancellationToken);
        }
        finally
        {
            if (File.Exists(scriptPath))
            {
                File.Delete(scriptPath);
            }
        }
    }

    private static string BuildScript(
        string wireguardInterfaceName,
        List<string> nonWireguardInterfaces,
        List<SoftwareRule> enabledRules,
        DomainRouteMode globalDefaultMode)
    {
        var sb = new StringBuilder();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine($"Get-NetFirewallRule -DisplayName '{RulePrefix}-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue");

        foreach (var rule in enabledRules)
        {
            var path = Ps(rule.ExecutablePath!);
            var key = MakeKey(rule.ExecutablePath!);

            if (globalDefaultMode == DomainRouteMode.BypassWireGuard)
            {
                foreach (var iface in nonWireguardInterfaces)
                {
                    sb.AppendLine($"New-NetFirewallRule -DisplayName '{RulePrefix}-{key}-BLK-{MakeKey(iface)}' -Direction Outbound -Action Block -Program '{path}' -InterfaceAlias '{Ps(iface)}' -Profile Any | Out-Null");
                }
            }
            else
            {
                sb.AppendLine($"New-NetFirewallRule -DisplayName '{RulePrefix}-{key}-BLK-WG' -Direction Outbound -Action Block -Program '{path}' -InterfaceAlias '{Ps(wireguardInterfaceName)}' -Profile Any | Out-Null");
            }
        }

        return sb.ToString();
    }

    private static async Task RunPowerShellAsAdminAsync(string scriptPath, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\"",
            UseShellExecute = true,
            Verb = "runas",
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Unable to launch PowerShell for software policy apply.");

        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Software policy apply failed with exit code {process.ExitCode}.");
        }
    }

    private static string Ps(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static string MakeKey(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes)[..10];
    }
}
