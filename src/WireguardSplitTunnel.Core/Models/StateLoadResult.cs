namespace WireguardSplitTunnel.Core.Models;

public sealed record StateLoadResult(
    AppState State,
    IReadOnlySet<string> PresentPropertyNames);
