using System.Net;
using System.Runtime.Versioning;
using System.Text;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public sealed record MacCleanupRequest
{
    public string? SplitConfigPath { get; init; }
    public string? RawTunnelName { get; init; }
    public IReadOnlyList<string> AdditionalTunnelTargets { get; init; } = [];
    public IReadOnlyList<string> ManagedIpsToRemove { get; init; } = [];
    public MacDnsRestorePlan DnsRestorePlan { get; init; } = new();
}

public sealed record MacCleanupResult
{
    public bool Prompted { get; init; }
    public bool Cancelled { get; init; }
    public bool SplitTunnelStopped { get; init; }
    public bool RawTunnelStopped { get; init; }
    public IReadOnlyList<string> AdditionalTunnelTargetsStopped { get; init; } = [];
    public IReadOnlyList<string> RemovedManagedIps { get; init; } = [];
    public IReadOnlyList<string> RestoredDnsServices { get; init; } = [];
    public bool BatchCompleted { get; init; } = true;
}

internal enum MacCleanupOperationKind
{
    SplitTunnel,
    RawTunnel,
    AdditionalTunnel,
    ManagedRoute,
    DnsService
}

internal sealed record MacCleanupOperation(
    int Id,
    MacCleanupOperationKind Kind,
    string Target)
{
    internal string SuccessMarker => $"__WGST_CLEANUP_OK_{Id}__";
}

internal sealed record MacCleanupBatch(
    string Script,
    IReadOnlyList<MacCleanupOperation> Operations);

/// <summary>
/// Executes app-owned macOS cleanup in one elevated batch while reporting each
/// exact component separately. Failed or unavailable commands never look like
/// successful cleanup to the state reducer.
/// </summary>
public static class MacExitCleanupService
{
    internal static MacCleanupBatch BuildCleanupBatch(
        string? wgQuickPath,
        MacCleanupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var commands = new List<(MacCleanupOperationKind Kind, string Target, string Command)>();
        if (!string.IsNullOrWhiteSpace(wgQuickPath))
        {
            AddTunnelCommand(MacCleanupOperationKind.SplitTunnel, request.SplitConfigPath);
            AddTunnelCommand(MacCleanupOperationKind.RawTunnel, request.RawTunnelName);
            foreach (var target in request.AdditionalTunnelTargets
                         .Where(target => !string.IsNullOrWhiteSpace(target))
                         .Distinct(StringComparer.OrdinalIgnoreCase))
            {
                AddTunnelCommand(MacCleanupOperationKind.AdditionalTunnel, target);
            }
        }

        foreach (var ip in request.ManagedIpsToRemove
                     .Where(ip => !string.IsNullOrWhiteSpace(ip))
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (IPAddress.TryParse(ip, out _))
            {
                commands.Add((
                    MacCleanupOperationKind.ManagedRoute,
                    ip,
                    $"/sbin/route -n delete -host {ShellQuoting.Quote(ip)}"));
            }
        }

        foreach (var snapshot in request.DnsRestorePlan.ServicesToRestore
                     .DistinctBy(service => service.ServiceName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(snapshot.ServiceName))
            {
                commands.Add((
                    MacCleanupOperationKind.DnsService,
                    snapshot.ServiceName,
                    BuildDnsRestoreCommand(snapshot)));
            }
        }

        var operations = new List<MacCleanupOperation>();
        var script = new StringBuilder();
        foreach (var command in commands)
        {
            var operation = new MacCleanupOperation(
                operations.Count,
                command.Kind,
                command.Target);
            operations.Add(operation);
            script.AppendLine($"if {command.Command} >/dev/null 2>&1; then");
            script.AppendLine($"  /usr/bin/printf '%s\\n' '{operation.SuccessMarker}'");
            script.AppendLine("fi");
        }

        return new MacCleanupBatch(script.ToString(), operations);

        void AddTunnelCommand(MacCleanupOperationKind kind, string? target)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                return;
            }

            try
            {
                commands.Add((
                    kind,
                    target,
                    MacTunnelStopScript.Build(wgQuickPath!, target)));
            }
            catch (ArgumentException)
            {
                // Invalid persisted/bare targets are deliberately left as debt.
                // They must never be copied into an elevated script.
            }
        }
    }

    internal static MacCleanupResult ParseCleanupResult(
        MacCleanupRequest request,
        MacCleanupBatch batch,
        MacShellResult shellResult)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(batch);

        var successful = batch.Operations
            .Where(operation => shellResult.Combined.Contains(
                operation.SuccessMarker,
                StringComparison.Ordinal))
            .ToList();

        return new MacCleanupResult
        {
            Prompted = batch.Script.Length > 0,
            SplitTunnelStopped = successful.Any(operation =>
                operation.Kind == MacCleanupOperationKind.SplitTunnel),
            RawTunnelStopped = successful.Any(operation =>
                operation.Kind == MacCleanupOperationKind.RawTunnel),
            AdditionalTunnelTargetsStopped = successful
                .Where(operation => operation.Kind == MacCleanupOperationKind.AdditionalTunnel)
                .Select(operation => operation.Target)
                .ToList(),
            RemovedManagedIps = successful
                .Where(operation => operation.Kind == MacCleanupOperationKind.ManagedRoute)
                .Select(operation => operation.Target)
                .ToList(),
            RestoredDnsServices = successful
                .Where(operation => operation.Kind == MacCleanupOperationKind.DnsService)
                .Select(operation => operation.Target)
                .ToList(),
            BatchCompleted = shellResult.ExitCode == 0
        };
    }

    [SupportedOSPlatform("macos")]
    public static async Task<MacCleanupResult> RunAsync(
        MacCleanupRequest request,
        string promptReason,
        CancellationToken cancellationToken)
    {
        var batch = BuildCleanupBatch(MacTunnelControlService.TryResolveWgQuick(), request);
        if (batch.Script.Length == 0)
        {
            return new MacCleanupResult { Prompted = false };
        }

        try
        {
            var shellResult = await MacAdminShell.RunAsAdminAsync(
                batch.Script,
                promptReason,
                cancellationToken);
            return ParseCleanupResult(request, batch, shellResult);
        }
        catch (OperationCanceledException)
        {
            return new MacCleanupResult
            {
                Prompted = true,
                Cancelled = true,
                BatchCompleted = false
            };
        }
    }

    private static string BuildDnsRestoreCommand(MacDnsServiceSnapshot snapshot)
    {
        var dnsArguments = snapshot.DnsServers.Count == 0
            ? "Empty"
            : string.Join(' ', snapshot.DnsServers.Select(ShellQuoting.Quote));
        var searchArguments = snapshot.SearchDomains.Count == 0
            ? "Empty"
            : string.Join(' ', snapshot.SearchDomains.Select(ShellQuoting.Quote));
        var service = ShellQuoting.Quote(snapshot.ServiceName);

        return $"/usr/sbin/networksetup -setdnsservers {service} {dnsArguments} >/dev/null 2>&1"
            + $" && /usr/sbin/networksetup -setsearchdomains {service} {searchArguments}";
    }
}
