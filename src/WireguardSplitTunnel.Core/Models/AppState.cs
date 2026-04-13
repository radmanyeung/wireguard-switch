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
    bool RestoreNormalRoutingOnExit = false);

public sealed record ManagedRouteEntry(string Domain, string IpAddress);

