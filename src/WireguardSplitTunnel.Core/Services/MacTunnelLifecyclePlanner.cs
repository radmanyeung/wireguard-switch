namespace WireguardSplitTunnel.Core.Services;

public static class MacTunnelLifecyclePlanner
{
    public static bool ShouldPreserveUnresolvedRawTunnel(
        MacTunnelMappingPresence presence) =>
        presence != MacTunnelMappingPresence.Absent;

    public static bool ShouldAttemptCleanup(MacTunnelMappingPresence presence) =>
        presence != MacTunnelMappingPresence.Absent;
}
