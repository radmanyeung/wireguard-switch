namespace WireguardSplitTunnel.Core.Models;

public sealed record AppState(
    List<DomainRule> DomainRules,
    Dictionary<string, List<string>> LastKnownResolvedIps,
    List<ManagedRouteEntry> ManagedRouteSnapshot,
    string? SelectedTunnelConfigPath = null,
    bool AutoEnableTunnel = false,
    List<SoftwareRule>? SoftwareRules = null,
    DomainRouteMode DomainGlobalDefaultMode = DomainRouteMode.BypassWireGuard,
    DomainRouteMode SoftwareGlobalDefaultMode = DomainRouteMode.BypassWireGuard,
    bool RestoreNormalRoutingOnExit = false,
    Dictionary<string, List<ResolvedIpDetail>>? LastKnownResolvedIpDetails = null)
{
    public Dictionary<string, List<ResolvedIpDetail>> LastKnownResolvedIpDetails { get; init; } =
        LastKnownResolvedIpDetails ?? new Dictionary<string, List<ResolvedIpDetail>>(StringComparer.OrdinalIgnoreCase);
}

public sealed record ManagedRouteEntry(string Domain, string IpAddress);

public enum ResolvedIpSourceKind
{
    Direct = 1,
    Learned = 2
}

public sealed record ResolvedIpDetail(string IpAddress, string SourceHost, ResolvedIpSourceKind SourceKind);
