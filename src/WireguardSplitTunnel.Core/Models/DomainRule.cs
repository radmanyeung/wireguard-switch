namespace WireguardSplitTunnel.Core.Models;

public enum DomainRouteMode
{
    UseWireGuard = 1,
    BypassWireGuard = 2
}

public sealed record DomainRule(
    string Domain,
    bool Enabled = true,
    DomainRouteMode Mode = DomainRouteMode.UseWireGuard);

public sealed record SoftwareRule(
    string ProcessName,
    bool Enabled = true,
    DomainRouteMode Mode = DomainRouteMode.UseWireGuard,
    bool IncludeSubprocesses = true,
    string? ExecutablePath = null);
