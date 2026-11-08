namespace WireguardSplitTunnel.Core.ConfigCheck;

public enum ConfigCheckStatus { Healthy, Repaired, Unrepaired }
public sealed record ConfigCheckServer(string HostName, string PublicKey, string Country);
public sealed record ConfigCheckProbe(bool Success, string Reason, string ObservedCountry);
public sealed record ConfigCheckResult(ConfigCheckStatus Status, string ConfigPath, string Endpoint, string Reason)
{
    private string observedCountry = string.Empty;
    public string ObservedCountry
    {
        get => observedCountry;
        init => observedCountry = value is { Length: 2 } &&
            value.All(character => character is >= 'A' and <= 'Z') ? value : string.Empty;
    }
}
public sealed record ConfigCheckRestoreContext(string SourcePath, string DerivedConfigPath, string SourceFingerprint);
public sealed record ConfigCheckRecoveredTunnel(string SourcePath, bool OriginalServiceWasRunning);
public sealed record ConfigCheckRecoveredService(string SourcePath, string ServiceName);

public static class ConfigCheckDeletePolicy
{
    public static bool MayOffer(ConfigCheckStatus status) => status == ConfigCheckStatus.Unrepaired;
}

public interface IConfigCheckSession { string PrivateRoot { get; } }

public interface IConfigCheckAdapter
{
    Task<IReadOnlyList<ConfigCheckServer>> GetCandidatesAsync(string country, int limit, CancellationToken token);
    Task<IConfigCheckSession> BeginAsync(CheckedConfig config, CancellationToken token, string? derivedConfigPath = null);
    Task StopOriginalAsync(IConfigCheckSession session, CancellationToken token);
    Task<ConfigCheckProbe> TestAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token);
    Task CommitAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token);
    Task RestoreAsync(
        IConfigCheckSession session,
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null,
        Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null);
    Task RecycleUnrepairedAsync(CheckedConfig config, CancellationToken token);
}
