namespace WireguardSplitTunnel.Core.Models;

public enum NetworkPathKind
{
    Vpn = 1,
    Normal = 2,
    Unknown = 3
}

public sealed record NetworkTrafficSummary(
    string InterfaceName,
    string InterfaceDescription,
    bool IsAvailable,
    long BytesReceived,
    long BytesSent,
    double DownloadBytesPerSecond,
    double UploadBytesPerSecond);

public sealed record NetworkLatencySummary(
    string Name,
    string Target,
    bool IsAvailable,
    double? PingMs,
    double? JitterMs,
    double PacketLossPercent,
    DateTimeOffset? LastUpdated,
    string Status);

public sealed record NetworkQualitySnapshot(
    NetworkLatencySummary VpnLatency,
    NetworkLatencySummary NormalLatency);

public sealed record NetworkActivityRow(
    string ProcessName,
    int ProcessId,
    string? ExecutablePath,
    string DomainOrAddress,
    string RemoteEndpoint,
    NetworkPathKind Route,
    int Connections,
    DateTimeOffset LastSeen);

public sealed record NetworkMonitorSnapshot(
    DateTimeOffset CapturedAt,
    string WireGuardInterfaceName,
    bool WireGuardFound,
    NetworkTrafficSummary VpnTraffic,
    NetworkTrafficSummary NormalTraffic,
    NetworkQualitySnapshot Quality,
    IReadOnlyList<NetworkActivityRow> Activities,
    IReadOnlyList<string> Warnings);
