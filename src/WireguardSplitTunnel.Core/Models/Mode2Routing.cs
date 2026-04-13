namespace WireguardSplitTunnel.Core.Models;

public enum Mode2EffectiveProfile
{
    DomainPriority = 1,
    SoftwarePriority = 2
}

public enum RoutingStatus
{
    Pass = 1,
    Warning = 2,
    Fail = 3
}

public sealed record RoutingCompatibility(
    Mode2EffectiveProfile Profile,
    RoutingStatus Status,
    string Reason);
