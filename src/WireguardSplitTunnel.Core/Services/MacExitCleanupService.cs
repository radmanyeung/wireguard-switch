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
    public IReadOnlyList<ManagedRouteEntry> ManagedRoutesToRemove { get; init; } = [];
    public MacDnsRestorePlan DnsRestorePlan { get; init; } = new();
}

public sealed record MacCleanupResult
{
    public bool Prompted { get; init; }
    public bool Cancelled { get; init; }
    public bool SplitTunnelStopped { get; init; }
    public bool RawTunnelStopped { get; init; }
    public IReadOnlyList<string> AdditionalTunnelTargetsStopped { get; init; } = [];
    public IReadOnlyList<ManagedRouteEntry> DeletedManagedRoutes { get; init; } = [];
    public IReadOnlyList<ManagedRouteEntry> AlreadyAbsentManagedRoutes { get; init; } = [];
    public IReadOnlyList<ManagedRouteEntry> ReplacedManagedRoutes { get; init; } = [];
    public IReadOnlyList<string> RestoredDnsServerServices { get; init; } = [];
    public IReadOnlyList<string> RestoredSearchDomainServices { get; init; } = [];
    public IReadOnlyList<string> RestoredDnsServices => RestoredDnsServerServices
        .Concat(RestoredSearchDomainServices)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
    public bool BatchCompleted { get; init; } = true;
}

internal enum MacCleanupOperationKind
{
    SplitTunnel,
    RawTunnel,
    AdditionalTunnel,
    ManagedRoute,
    DnsServers,
    SearchDomains
}

internal sealed record MacCleanupOperation(
    int Id,
    MacCleanupOperationKind Kind,
    string Target,
    ManagedRouteEntry? ManagedRoute = null)
{
    internal string SuccessMarker => $"__WGST_CLEANUP_OK_{Id}__";

    internal string OutcomeMarker(MacManagedRouteCleanupDisposition disposition) =>
        $"__WGST_CLEANUP_ROUTE_{Id}_{disposition}__";
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

        var operations = new List<MacCleanupOperation>();
        var script = new StringBuilder();

        foreach (var route in request.ManagedRoutesToRemove
                     .DistinctBy(
                         route => (route.IpAddress, route.InterfaceName),
                         ManagedRouteOwnershipComparer.Instance))
        {
            if (!IPAddress.TryParse(route.IpAddress, out _)
                || MacTunnelNameResolver.ParseUtunName(route.InterfaceName ?? string.Empty) is null)
            {
                continue;
            }

            var operation = AddOperation(
                MacCleanupOperationKind.ManagedRoute,
                route.IpAddress,
                route);
            MacManagedRouteCleanupPlanner.AppendReconciliationScript(
                script,
                route,
                operation.OutcomeMarker(MacManagedRouteCleanupDisposition.ExactOwnedRoute),
                operation.OutcomeMarker(MacManagedRouteCleanupDisposition.AlreadyAbsent),
                operation.OutcomeMarker(MacManagedRouteCleanupDisposition.ReplacedByOtherInterface));
        }

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

        foreach (var snapshot in request.DnsRestorePlan.DnsServersToRestore
                     .DistinctBy(service => service.ServiceName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(snapshot.ServiceName))
            {
                AddSimpleOperation(
                    MacCleanupOperationKind.DnsServers,
                    snapshot.ServiceName,
                    BuildDnsServersRestoreCommand(snapshot));
            }
        }

        foreach (var snapshot in request.DnsRestorePlan.SearchDomainsToRestore
                     .DistinctBy(service => service.ServiceName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(snapshot.ServiceName))
            {
                AddSimpleOperation(
                    MacCleanupOperationKind.SearchDomains,
                    snapshot.ServiceName,
                    BuildSearchDomainsRestoreCommand(snapshot));
            }
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
                AddSimpleOperation(
                    kind,
                    target,
                    MacTunnelStopScript.Build(wgQuickPath!, target));
            }
            catch (ArgumentException)
            {
                // Invalid persisted/bare targets are deliberately left as debt.
                // They must never be copied into an elevated script.
            }
        }

        MacCleanupOperation AddOperation(
            MacCleanupOperationKind kind,
            string target,
            ManagedRouteEntry? managedRoute = null)
        {
            var operation = new MacCleanupOperation(
                operations.Count,
                kind,
                target,
                managedRoute);
            operations.Add(operation);
            return operation;
        }

        void AddSimpleOperation(MacCleanupOperationKind kind, string target, string command)
        {
            var operation = AddOperation(kind, target);
            script.AppendLine($"if {command} >/dev/null 2>&1; then");
            script.AppendLine($"  /usr/bin/printf '%s\\n' '{operation.SuccessMarker}'");
            script.AppendLine("fi");
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

        var routeOperations = batch.Operations
            .Where(operation => operation.Kind == MacCleanupOperationKind.ManagedRoute)
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
            DeletedManagedRoutes = RoutesWithOutcome(
                routeOperations,
                MacManagedRouteCleanupDisposition.ExactOwnedRoute),
            AlreadyAbsentManagedRoutes = RoutesWithOutcome(
                routeOperations,
                MacManagedRouteCleanupDisposition.AlreadyAbsent),
            ReplacedManagedRoutes = RoutesWithOutcome(
                routeOperations,
                MacManagedRouteCleanupDisposition.ReplacedByOtherInterface),
            RestoredDnsServerServices = successful
                .Where(operation => operation.Kind == MacCleanupOperationKind.DnsServers)
                .Select(operation => operation.Target)
                .ToList(),
            RestoredSearchDomainServices = successful
                .Where(operation => operation.Kind == MacCleanupOperationKind.SearchDomains)
                .Select(operation => operation.Target)
                .ToList(),
            BatchCompleted = shellResult.ExitCode == 0
        };

        IReadOnlyList<ManagedRouteEntry> RoutesWithOutcome(
            IEnumerable<MacCleanupOperation> routeOps,
            MacManagedRouteCleanupDisposition disposition)
        {
            return routeOps
                .Where(operation => shellResult.Combined.Contains(
                    operation.OutcomeMarker(disposition),
                    StringComparison.Ordinal))
                .Select(operation => operation.ManagedRoute)
                .Where(route => route is not null)
                .Cast<ManagedRouteEntry>()
                .ToList();
        }
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

    private static string BuildDnsServersRestoreCommand(MacDnsServiceSnapshot snapshot)
    {
        var dnsArguments = snapshot.DnsServers.Count == 0
            ? "Empty"
            : string.Join(' ', snapshot.DnsServers.Select(ShellQuoting.Quote));
        var service = ShellQuoting.Quote(snapshot.ServiceName);

        return $"/usr/sbin/networksetup -setdnsservers {service} {dnsArguments}";
    }

    private static string BuildSearchDomainsRestoreCommand(MacDnsServiceSnapshot snapshot)
    {
        var searchArguments = snapshot.SearchDomains.Count == 0
            ? "Empty"
            : string.Join(' ', snapshot.SearchDomains.Select(ShellQuoting.Quote));
        return $"/usr/sbin/networksetup -setsearchdomains {ShellQuoting.Quote(snapshot.ServiceName)} {searchArguments}";
    }

    private sealed class ManagedRouteOwnershipComparer
        : IEqualityComparer<(string IpAddress, string? InterfaceName)>
    {
        internal static ManagedRouteOwnershipComparer Instance { get; } = new();

        public bool Equals(
            (string IpAddress, string? InterfaceName) x,
            (string IpAddress, string? InterfaceName) y) =>
            string.Equals(x.IpAddress, y.IpAddress, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.InterfaceName, y.InterfaceName, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string IpAddress, string? InterfaceName) obj) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.IpAddress),
                obj.InterfaceName is null
                    ? 0
                    : StringComparer.OrdinalIgnoreCase.GetHashCode(obj.InterfaceName));
    }
}
