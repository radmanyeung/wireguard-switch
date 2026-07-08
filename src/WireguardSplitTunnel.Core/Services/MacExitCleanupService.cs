using System.Runtime.Versioning;
using System.Text;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Tears down everything this app may have changed on the system — tunnels,
/// managed host routes, DNS overrides — in a single elevated script so the
/// user sees at most one admin prompt.
/// </summary>
public static class MacExitCleanupService
{
    internal static string BuildCleanupScript(
        string? wgQuickPath,
        string? splitConfigPath,
        string? rawTunnelName,
        IReadOnlyList<string> managedIpsToRemove,
        IReadOnlyList<string> dnsResetServices)
    {
        var script = new StringBuilder();

        if (!string.IsNullOrWhiteSpace(wgQuickPath))
        {
            foreach (var target in new[] { splitConfigPath, rawTunnelName })
            {
                if (!string.IsNullOrWhiteSpace(target))
                {
                    script.AppendLine($"{wgQuickPath} down {ShellQuoting.Quote(target)} >/dev/null 2>&1 || true");
                }
            }
        }

        foreach (var ip in managedIpsToRemove.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            script.AppendLine($"/sbin/route -n delete -host {ip} >/dev/null 2>&1 || true");
        }

        script.Append(MacDnsRepairService.BuildResetScript(dnsResetServices));

        return script.ToString();
    }

    /// <summary>
    /// Runs the batched cleanup. Returns false without prompting when there is
    /// nothing to clean up.
    /// </summary>
    [SupportedOSPlatform("macos")]
    public static async Task<bool> RunAsync(
        string? splitConfigPath,
        string? rawTunnelName,
        IReadOnlyList<string> managedIpsToRemove,
        IReadOnlyList<string> dnsResetServices,
        string promptReason,
        CancellationToken cancellationToken)
    {
        var script = BuildCleanupScript(
            MacTunnelControlService.TryResolveWgQuick(),
            splitConfigPath,
            rawTunnelName,
            managedIpsToRemove,
            dnsResetServices);
        if (script.Length == 0)
        {
            return false;
        }

        var result = await MacAdminShell.RunAsAdminAsync(script, promptReason, cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"cleanup failed (exit {result.ExitCode}): {result.Combined}");
        }

        return true;
    }
}
