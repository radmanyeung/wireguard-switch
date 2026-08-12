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
    Dictionary<string, List<ResolvedIpDetail>>? LastKnownResolvedIpDetails = null,
    List<MacTunnelProfile>? MacTunnelProfiles = null,
    List<MacSoftwareRule>? MacSoftwareRules = null,
    List<MacDomainProfileAssignment>? MacDomainProfileAssignments = null,
    // wg-quick tunnel started via the raw "Enable Tunnel" path (full tunnel:
    // default route + DNS override). Persisted so a restart still knows a
    // teardown is owed even after a crash.
    string? ActiveRawTunnelName = null,
    // Exact generated config path whose split tunnel still needs a proven
    // wg-quick down before ownership can be forgotten.
    string? ActiveSplitTunnelConfigPath = null,
    // Exact pre-raw-tunnel DNS/search-domain state. This stores only resolver
    // values and config identity, never WireGuard config text or private keys.
    MacRawTunnelDnsCleanupDebt? RawTunnelDnsCleanupDebt = null,
    bool AutoUpdateEnabled = true,
    // Extra user-added folders scanned for .conf / .conf.dpapi files, on top
    // of the platform defaults in WireguardConfigCatalog.
    List<string>? CustomConfigDirectories = null)
{
    public Dictionary<string, List<ResolvedIpDetail>> LastKnownResolvedIpDetails { get; init; } =
        LastKnownResolvedIpDetails ?? new Dictionary<string, List<ResolvedIpDetail>>(StringComparer.OrdinalIgnoreCase);

    public List<MacTunnelProfile> MacTunnelProfiles { get; init; } = MacTunnelProfiles ?? [];

    public List<MacSoftwareRule> MacSoftwareRules { get; init; } = MacSoftwareRules ?? [];

    public List<MacDomainProfileAssignment> MacDomainProfileAssignments { get; init; } =
        MacDomainProfileAssignments ?? [];

    public List<string> CustomConfigDirectories { get; init; } = CustomConfigDirectories ?? [];
}

public sealed record ManagedRouteEntry(
    string Domain,
    string IpAddress,
    string? InterfaceName = null);

public sealed record MacDnsServiceSnapshot(
    string ServiceName,
    List<string>? DnsServers = null,
    List<string>? SearchDomains = null,
    bool RestoreDnsServersPending = true,
    bool RestoreSearchDomainsPending = true)
{
    public List<string> DnsServers { get; init; } = DnsServers ?? [];
    public List<string> SearchDomains { get; init; } = SearchDomains ?? [];
}

public sealed record MacRawTunnelDnsCleanupDebt(
    string TunnelName,
    string ConfigPath,
    List<string>? TunnelDnsServers = null,
    List<string>? TunnelSearchDomains = null,
    List<MacDnsServiceSnapshot>? Services = null,
    string? JournalPath = null)
{
    public List<string> TunnelDnsServers { get; init; } = TunnelDnsServers ?? [];
    public List<string> TunnelSearchDomains { get; init; } = TunnelSearchDomains ?? [];
    public List<MacDnsServiceSnapshot> Services { get; init; } = Services ?? [];
}

public enum ResolvedIpSourceKind
{
    Direct = 1,
    Learned = 2
}

public sealed record ResolvedIpDetail(string IpAddress, string SourceHost, ResolvedIpSourceKind SourceKind);

public sealed record MacTunnelProfile(
    string Id,
    string DisplayName,
    string ConfigPath,
    bool Enabled = true,
    string TunnelName = "");

public sealed record MacSoftwareRule(
    string BundleIdentifier,
    string DisplayName,
    string? BundlePath,
    string ProfileId,
    bool Enabled = true);

public sealed record MacDomainProfileAssignment(
    string Domain,
    string ProfileId,
    bool Enabled = true);
