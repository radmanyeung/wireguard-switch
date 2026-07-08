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
    string? ActiveRawTunnelName = null)
{
    public Dictionary<string, List<ResolvedIpDetail>> LastKnownResolvedIpDetails { get; init; } =
        LastKnownResolvedIpDetails ?? new Dictionary<string, List<ResolvedIpDetail>>(StringComparer.OrdinalIgnoreCase);

    public List<MacTunnelProfile> MacTunnelProfiles { get; init; } = MacTunnelProfiles ?? [];

    public List<MacSoftwareRule> MacSoftwareRules { get; init; } = MacSoftwareRules ?? [];

    public List<MacDomainProfileAssignment> MacDomainProfileAssignments { get; init; } =
        MacDomainProfileAssignments ?? [];
}

public sealed record ManagedRouteEntry(string Domain, string IpAddress);

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
