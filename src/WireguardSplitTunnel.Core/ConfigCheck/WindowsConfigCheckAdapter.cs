using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public sealed record ConfigCheckNativeResult(int ExitCode, string Output);

public enum ConfigCheckServiceStatus
{
    Stopped,
    StartPending,
    StopPending,
    Running
}

public sealed record ConfigCheckServiceState(
    string Name,
    string Identity,
    bool IsRunning,
    ConfigCheckServiceStatus? Status = null)
{
    [JsonIgnore]
    public ConfigCheckServiceStatus EffectiveStatus => Status ?? (IsRunning ? ConfigCheckServiceStatus.Running : ConfigCheckServiceStatus.Stopped);

    [JsonIgnore]
    public bool IsTransitional => EffectiveStatus is ConfigCheckServiceStatus.StartPending or ConfigCheckServiceStatus.StopPending;
}

public readonly record struct ConfigCheckFileIdentity(uint VolumeSerialNumber, ulong FileIndex);

public enum ConfigCheckReplacementPhase
{
    Prepared,
    Replaced,
    RollbackRequired,
    RollbackReplaced,
    RolledBack,
    Cleaned
}

public enum ConfigCheckReplacementOutcome
{
    OriginalRetained,
    ReplacementApplied,
    NewerSourceRetained,
    SourceMissing
}

public sealed record ConfigCheckReplacementTransaction(
    string StagedPath,
    string SourcePath,
    string ReplacementBackupPath,
    string RestoreBackupPath,
    ConfigCheckFileIdentity SourceIdentity,
    ConfigCheckFileIdentity ReplacementIdentity,
    string SourceFingerprint,
    string ReplacementFingerprint);

public sealed record ConfigCheckReplacementProgress(
    ConfigCheckReplacementPhase Phase,
    ConfigCheckFileIdentity? DisplacedSourceIdentity = null);

public enum ConfigCheckRecyclePhase
{
    Prepared,
    Quarantined,
    Recycled,
    Completed
}

public sealed record ConfigCheckRecycleTransaction(
    string SourcePath,
    string OriginalBackupPath,
    string QuarantineDirectory,
    string QuarantinePath,
    ConfigCheckFileIdentity SourceIdentity,
    string SourceFingerprint);

public sealed record ConfigCheckRecycleProgress(ConfigCheckRecyclePhase Phase);

public sealed record ConfigCheckSourceFile(string FullPath, byte[] Bytes, ConfigCheckFileIdentity Identity)
{
    private byte[] bytes = (byte[])Bytes.Clone();
    public byte[] Bytes { get => (byte[])bytes.Clone(); init => bytes = (byte[])value.Clone(); }
}

/// <summary>The only boundary through which the Windows config checker touches external state.</summary>
public interface IConfigCheckNative
{
    Task<string> GetJsonAsync(Uri uri, CancellationToken token);
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string hostName, CancellationToken token);
    Task<ConfigCheckNativeResult> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken token);
    Task<IReadOnlyList<ConfigCheckServiceState>> GetTunnelServicesAsync(CancellationToken token);
    Task StopServiceAsync(ConfigCheckServiceState service, CancellationToken token);
    Task StartServiceAsync(ConfigCheckServiceState service, CancellationToken token);
    Task DeleteTunnelServiceAsync(string tunnelName, CancellationToken token);
    Task AddProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token);
    Task DeleteProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token);
    Task VerifyProbeRouteAbsentAsync(string tunnelName, IPAddress probeAddress, CancellationToken token);
    Task CreatePrivateDirectoryAsync(string path, CancellationToken token);
    Task WritePrivateFileAsync(string path, byte[] bytes, CancellationToken token);
    Task<byte[]> ReadPrivateFileAsync(string path, CancellationToken token);
    Task DeletePrivateFileAsync(string path, CancellationToken token);
    void EnsureNoReparsePoints(string path);
    Task<bool> SourceFileExistsAsync(string path, CancellationToken token);
    Task<ConfigCheckSourceFile> ReadSourceFileAsync(string path, CancellationToken token);
    Task<ConfigCheckFileIdentity> StageReplacementAsync(string sourcePath, string stagedPath, byte[] bytes, CancellationToken token);
    Task DeleteStagedFileAsync(string path, CancellationToken token);
    Task VerifyStagedFileAbsentAsync(string path, CancellationToken token);
    Task AtomicReplaceAsync(
        ConfigCheckReplacementTransaction transaction,
        Func<ConfigCheckReplacementProgress, Task> progressAsync,
        CancellationToken token);
    Task MoveStagedFileToMissingSourceAsync(string stagedPath, string sourcePath, CancellationToken token);
    Task<ConfigCheckReplacementOutcome> RecoverReplacementAsync(
        ConfigCheckReplacementTransaction transaction,
        ConfigCheckFileIdentity? displacedSourceIdentity,
        Func<ConfigCheckReplacementProgress, Task> progressAsync,
        CancellationToken token);
    Task<string?> ReadJournalAsync(string privateRoot, string journalName, CancellationToken token);
    Task WriteJournalAsync(string privateRoot, string journalName, string json, CancellationToken token);
    Task ClearAttemptJournalAsync(string privateRoot, CancellationToken token);
    Task<IReadOnlyList<string>> FindJournalRootsAsync(string dataRoot, CancellationToken token);
    Task VerifyTunnelInactiveAsync(string tunnelName, CancellationToken token);
    Task RecycleFileAsync(
        ConfigCheckRecycleTransaction transaction,
        Func<ConfigCheckRecycleProgress, Task> progressAsync,
        CancellationToken token);
    Task RecoverRecycleAsync(
        ConfigCheckRecycleTransaction transaction,
        ConfigCheckRecyclePhase phase,
        Func<ConfigCheckRecycleProgress, Task> progressAsync,
        CancellationToken token);
    Task DelayAsync(TimeSpan delay, CancellationToken token);
}

public sealed class WindowsConfigCheckAdapter : IConfigCheckAdapter, IConfigCheckRecoveryAdapter
{
    public const string SessionJournalName = "journal.json";
    public const string AttemptJournalName = "attempt.json";
    public const string RecycleJournalName = "recycle.json";

    private const string CountriesUrl = "https://api.nordvpn.com/v1/servers/countries";
    private const string RecommendationsUrl = "https://api.nordvpn.com/v1/servers/recommendations";
    private const string ProbeHost = "www.cloudflare.com";
    private static readonly JsonSerializerOptions JournalJsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IConfigCheckNative native;
    private readonly string dataRoot;

    public WindowsConfigCheckAdapter(string appDataRoot)
        : this(new WindowsConfigCheckNative(), appDataRoot)
    {
    }

    public WindowsConfigCheckAdapter(IConfigCheckNative native, string appDataRoot)
    {
        this.native = native ?? throw new ArgumentNullException(nameof(native));
        dataRoot = Path.GetFullPath(appDataRoot ?? throw new ArgumentNullException(nameof(appDataRoot)));
    }

    public async Task<IReadOnlyList<ConfigCheckServer>> GetCandidatesAsync(string country, int limit, CancellationToken token)
    {
        if (limit is < 1 or > 5) throw new InvalidDataException("Candidate limit must be between one and five.");
        var countriesJson = await native.GetJsonAsync(new Uri(CountriesUrl), token).ConfigureAwait(false);
        var countryId = FindCountryId(countriesJson, country);
        var uri = new Uri(RecommendationsUrl + "?filters%5Bcountry_id%5D=" +
            countryId.ToString(CultureInfo.InvariantCulture) + "&limit=" + limit.ToString(CultureInfo.InvariantCulture));
        var recommendationsJson = await native.GetJsonAsync(uri, token).ConfigureAwait(false);
        using var recommendations = JsonDocument.Parse(recommendationsJson);
        return NordVpnMetadata.SelectCandidates(recommendations.RootElement, country, limit);
    }

    public async Task<IConfigCheckSession> BeginAsync(
        CheckedConfig config,
        CancellationToken token,
        string? derivedConfigPath = null)
    {
        await EnsureNoIncompleteJournal(token).ConfigureAwait(false);
        var privateRoot = Path.Combine(dataRoot, "config-check", Guid.NewGuid().ToString("N"));
        await native.CreatePrivateDirectoryAsync(privateRoot, token).ConfigureAwait(false);

        var backupPath = Path.Combine(privateRoot, "original.bin");
        await native.WritePrivateFileAsync(backupPath, config.Bytes, token).ConfigureAwait(false);
        var journal = new SessionJournal
        {
            SourcePath = Path.GetFullPath(config.Path),
            SourceFingerprint = config.Fingerprint,
            OriginalBackupPath = backupPath,
            DisplacedPath = Path.Combine(privateRoot, "displaced.bin"),
            DerivedConfigPath = derivedConfigPath,
            State = SessionState.Begun
        };
        ValidateSessionJournal(privateRoot, journal);
        await WriteSessionJournal(privateRoot, journal, token).ConfigureAwait(false);
        return new WindowsConfigCheckSession(privateRoot, Path.GetFullPath(config.Path), config.Fingerprint);
    }

    public async Task StopOriginalAsync(IConfigCheckSession session, CancellationToken token)
    {
        var privateRoot = RequirePrivateRoot(session);
        var journal = await ReadSessionJournal(privateRoot, token).ConfigureAwait(false);
        if (journal.State == SessionState.Completed) throw new IOException("The config-check session is already completed.");

        var snapshot = await native.GetTunnelServicesAsync(token).ConfigureAwait(false);
        EnsureNoTransitionalServices(snapshot);
        journal.Services = snapshot
            .Where(service => service.IsRunning && service.Name.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase))
            .ToList();
        journal.State = SessionState.StopRequested;
        // Validate the complete snapshot before persisting stop intent or mutating any service.
        ValidateSessionJournal(privateRoot, journal);
        // Persist requested identities before the first stop so a crash cannot lose restoration ownership.
        await WriteSessionJournal(privateRoot, journal, token).ConfigureAwait(false);
        foreach (var service in journal.Services)
            await native.StopServiceAsync(service, token).ConfigureAwait(false);
    }

    public async Task<ConfigCheckProbe> TestAsync(
        IConfigCheckSession session,
        CheckedConfig config,
        ConfigCheckServer server,
        CancellationToken token)
    {
        var privateRoot = RequirePrivateRoot(session);
        var journal = await ReadSessionJournal(privateRoot, token).ConfigureAwait(false);
        EnsureMatchingSession(config, journal);
        // Reuse the parser's endpoint, country, and key validation before creating an owned config.
        _ = config.WithPeerServer(server);
        _ = await ResolveIpv4(server.HostName, token).ConfigureAwait(false);
        var probeAddress = await ResolveIpv4(ProbeHost, token).ConfigureAwait(false);

        var tunnelName = WindowsConfigCheckPrimitives.NewOwnedTunnelName();
        var tempConfigPath = Path.Combine(privateRoot, tunnelName + ".conf");
        var attempt = new AttemptJournal
        {
            TunnelName = tunnelName,
            TempConfigPath = tempConfigPath,
            InstallRequested = true
        };
        journal.OwnedTunnelName = tunnelName;
        journal.OwnedTempConfigPath = tempConfigPath;
        journal.OwnedRouteAddress = null;
        journal.OwnedCleanupCompleted = false;
        // Persist a trusted fallback before creating any artifact, including a partial temp file.
        await WriteSessionJournal(privateRoot, journal, token).ConfigureAwait(false);
        var probeBytes = new UTF8Encoding(false).GetBytes(WindowsConfigCheckPrimitives.NewProbeConfig(config, server));

        Exception? primaryFailure = null;
        try
        {
            await native.WritePrivateFileAsync(tempConfigPath, probeBytes, token).ConfigureAwait(false);
            await WriteAttemptJournal(privateRoot, attempt, token).ConfigureAwait(false);
            var started = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var install = await native.RunAsync(
                "wireguard.exe",
                ["/installtunnelservice", tempConfigPath],
                token).ConfigureAwait(false);
            if (install.ExitCode != 0) return new ConfigCheckProbe(false, "TunnelInstallFailed", string.Empty);

            var handshake = false;
            for (var attemptNumber = 0; attemptNumber < 15 && !handshake; attemptNumber++)
            {
                var result = await native.RunAsync(
                    "wg.exe",
                    ["show", tunnelName, "latest-handshakes"],
                    token).ConfigureAwait(false);
                handshake = result.ExitCode == 0 &&
                    WindowsConfigCheckPrimitives.HasFreshHandshake(result.Output, server.PublicKey, started);
                if (!handshake && attemptNumber < 14)
                    await native.DelayAsync(TimeSpan.FromSeconds(1), token).ConfigureAwait(false);
            }
            if (!handshake) return new ConfigCheckProbe(false, "HandshakeFailed", string.Empty);

            attempt.RouteAddress = probeAddress.ToString();
            journal.OwnedRouteAddress = attempt.RouteAddress;
            // Journal the exact route in both records before adding it.
            await WriteSessionJournal(privateRoot, journal, token).ConfigureAwait(false);
            await WriteAttemptJournal(privateRoot, attempt, token).ConfigureAwait(false);
            await native.AddProbeRouteAsync(tunnelName, probeAddress, token).ConfigureAwait(false);

            var curl = await native.RunAsync(
                "curl.exe",
                WindowsConfigCheckPrimitives.BuildCurlArguments(attempt.RouteAddress, config.SourceAddress),
                token).ConfigureAwait(false);
            if (curl.ExitCode != 0) return new ConfigCheckProbe(false, "HttpsFailed", string.Empty);

            var observedCountry = ParseTraceCountry(curl.Output);
            if (observedCountry is null) return new ConfigCheckProbe(false, "CountryUnavailable", string.Empty);
            if (observedCountry != config.Country)
                return new ConfigCheckProbe(false, "ExitCountryMismatch", observedCountry);
            return new ConfigCheckProbe(true, "OK", observedCountry);
        }
        catch (Exception exception)
        {
            primaryFailure = exception;
            throw;
        }
        finally
        {
            try
            {
                await CleanupAttempt(privateRoot, journal).ConfigureAwait(false);
            }
            catch (Exception cleanupFailure)
            {
                if (primaryFailure is not null) throw new AggregateException(primaryFailure, cleanupFailure);
                throw;
            }
        }
    }

    public async Task CommitAsync(
        IConfigCheckSession session,
        CheckedConfig config,
        ConfigCheckServer server,
        CancellationToken token)
    {
        // A persistent replacement is deliberately non-cancelable, regardless of the supplied token.
        var privateRoot = RequirePrivateRoot(session);
        var journal = await ReadSessionJournal(privateRoot, CancellationToken.None).ConfigureAwait(false);
        EnsureMatchingSession(config, journal);
        var source = await ReadExpectedSource(config, journal).ConfigureAwait(false);
        var replacementBytes = config.WithPeerServer(server);
        var replacementFingerprint = CheckedConfig.FingerprintBytes(replacementBytes);

        await native.WritePrivateFileAsync(journal.DisplacedPath, source.Bytes, CancellationToken.None).ConfigureAwait(false);
        var stagedPath = Path.Combine(
            Path.GetDirectoryName(source.FullPath) ?? throw new IOException("Configuration directory is unavailable."),
            "." + Path.GetFileName(source.FullPath) + "." + Path.GetFileName(privateRoot) + ".wgst.tmp");
        journal.State = SessionState.Replacing;
        journal.StagedPath = stagedPath;
        journal.ReplacementFingerprint = replacementFingerprint;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
        var replacementIdentity = await native.StageReplacementAsync(
            source.FullPath, stagedPath, replacementBytes, CancellationToken.None).ConfigureAwait(false);
        journal.SourceIdentity = source.Identity;
        journal.ReplacementIdentity = replacementIdentity;
        journal.ReplacementBackupPath = stagedPath + ".replace-backup";
        journal.RestoreBackupPath = stagedPath + ".restore-backup";
        journal.ReplacementPhase = ConfigCheckReplacementPhase.Prepared;
        // Every artifact and both identities are durable before the first source mutation.
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
        await native.AtomicReplaceAsync(
            CreateReplacementTransaction(journal),
            progress => RecordReplacementProgress(privateRoot, journal, progress),
            CancellationToken.None).ConfigureAwait(false);

        if (!await SourceHasFingerprint(source.FullPath, replacementFingerprint).ConfigureAwait(false))
            throw new IOException("Configuration replacement could not be verified; newer content was retained.");
        journal.State = SessionState.Repaired;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
    }

    public async Task RestoreAsync(
        IConfigCheckSession session,
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null,
        Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null)
    {
        // Restoration is always non-cancelable. Read the persisted state so a new adapter can recover it.
        if (session is not WindowsConfigCheckSession expected)
            throw new IOException("Recovery requires the independently expected original configuration identity.");
        var privateRoot = RequirePrivateRoot(expected);
        var journal = await ReadSessionJournal(privateRoot, CancellationToken.None).ConfigureAwait(false);
        EnsureMatchingSession(expected.SourcePath, expected.SourceFingerprint, journal);
        if (journal.State == SessionState.Completed) return;

        await VerifyOriginalBackup(journal).ConfigureAwait(false);
        await CleanupAttempt(privateRoot, journal).ConfigureAwait(false);
        await RecoverReplacement(privateRoot, journal).ConfigureAwait(false);
        await CleanupOwnedStaging(privateRoot, journal).ConfigureAwait(false);
        if (RequiresDerivedConfigReconciliation(journal))
        {
            if (reconcileDerivedConfigAsync is null)
                throw new IOException("The repaired session requires derived config reconciliation before its original service can restart.");
            await reconcileDerivedConfigAsync(
                new ConfigCheckRestoreContext(
                    journal.SourcePath,
                    journal.DerivedConfigPath!,
                    journal.ReplacementFingerprint!),
                CancellationToken.None).ConfigureAwait(false);
        }
        await RestoreOriginalServices(journal, serviceRestoredAsync).ConfigureAwait(false);
        journal.State = SessionState.Completed;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
    }

    private static bool RequiresDerivedConfigReconciliation(SessionJournal journal) =>
        journal.State == SessionState.Repaired &&
        journal.DerivedConfigPath is not null &&
        OriginalServiceWasRunning(journal);

    private static bool OriginalServiceWasRunning(SessionJournal journal)
    {
        var originalServiceName = "WireGuardTunnel$" +
            global::WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(journal.SourcePath);
        return journal.Services.Any(service =>
            string.Equals(service.Name, originalServiceName, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<IReadOnlyList<ConfigCheckRecoveredTunnel>> RecoverAllAsync(
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null,
        Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null)
    {
        // Discover identity exclusively from protected journals. In particular, do
        // not parse a missing, partial, repaired, or otherwise mutated source file.
        var roots = await native.FindJournalRootsAsync(dataRoot, token).ConfigureAwait(false);
        var sessions = new List<(string PrivateRoot, SessionJournal Journal)>();
        var recycles = new List<(string PrivateRoot, RecycleJournal Journal)>();
        foreach (var privateRoot in roots)
        {
            var sessionJson = await native.ReadJournalAsync(privateRoot, SessionJournalName, token).ConfigureAwait(false);
            var recycleJson = await native.ReadJournalAsync(privateRoot, RecycleJournalName, token).ConfigureAwait(false);
            if ((sessionJson is null) == (recycleJson is null))
                throw new InvalidDataException("A config-check recovery root must contain exactly one transaction journal.");
            if (sessionJson is not null)
            {
                var journal = await ReadSessionJournal(privateRoot, token).ConfigureAwait(false);
                if (journal.State != SessionState.Completed) sessions.Add((privateRoot, journal));
            }
            else
            {
                var journal = await ReadRecycleJournal(privateRoot, token).ConfigureAwait(false);
                if (journal.Phase != ConfigCheckRecyclePhase.Completed) recycles.Add((privateRoot, journal));
            }
        }

        var sourcePaths = new List<string>();
        foreach (var sourcePath in sessions.Select(item => item.Journal.SourcePath)
                     .Concat(recycles.Select(item => item.Journal.SourcePath)))
        {
            if (sourcePaths.Any(existing => PathsEqual(existing, sourcePath)))
                throw new IOException("Multiple incomplete config-check journals match a source path; manual review is required.");
            sourcePaths.Add(sourcePath);
        }

        var recovered = new List<ConfigCheckRecoveredTunnel>();
        foreach (var (privateRoot, journal) in sessions)
        {
            var originalServiceWasRunning = OriginalServiceWasRunning(journal);
            await RestoreAsync(
                new WindowsConfigCheckSession(privateRoot, journal.SourcePath, journal.SourceFingerprint),
                CancellationToken.None,
                reconcileDerivedConfigAsync,
                serviceRestoredAsync).ConfigureAwait(false);
            recovered.Add(new ConfigCheckRecoveredTunnel(journal.SourcePath, originalServiceWasRunning));
        }
        foreach (var (privateRoot, journal) in recycles)
        {
            await VerifyRecycleOriginalBackup(journal).ConfigureAwait(false);
            await native.RecoverRecycleAsync(
                CreateRecycleTransaction(journal),
                journal.Phase,
                progress => RecordRecycleProgress(privateRoot, journal, progress),
                CancellationToken.None).ConfigureAwait(false);
        }
        return recovered;
    }

    public Task RecoverAsync(
        CheckedConfig config,
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null) =>
        RecoverAsync(config.Path, token, reconcileDerivedConfigAsync);

    public async Task RecoverAsync(
        string sourcePath,
        CancellationToken token,
        Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null)
    {
        var fullPath = ValidateConfigPath(sourcePath);
        var roots = await native.FindJournalRootsAsync(dataRoot, token).ConfigureAwait(false);
        var sessions = new List<(string PrivateRoot, SessionJournal Journal)>();
        var recycles = new List<(string PrivateRoot, RecycleJournal Journal)>();
        foreach (var privateRoot in roots)
        {
            var sessionJson = await native.ReadJournalAsync(privateRoot, SessionJournalName, token).ConfigureAwait(false);
            var recycleJson = await native.ReadJournalAsync(privateRoot, RecycleJournalName, token).ConfigureAwait(false);
            if ((sessionJson is null) == (recycleJson is null))
                throw new InvalidDataException("A config-check recovery root must contain exactly one transaction journal.");
            if (sessionJson is not null)
            {
                var journal = await ReadSessionJournal(privateRoot, token).ConfigureAwait(false);
                if (journal.State != SessionState.Completed && PathsEqual(fullPath, journal.SourcePath))
                    sessions.Add((privateRoot, journal));
            }
            else
            {
                var journal = await ReadRecycleJournal(privateRoot, token).ConfigureAwait(false);
                if (journal.Phase != ConfigCheckRecyclePhase.Completed && PathsEqual(fullPath, journal.SourcePath))
                    recycles.Add((privateRoot, journal));
            }
        }
        if (sessions.Count + recycles.Count > 1)
            throw new IOException("Multiple incomplete config-check journals match the source path; manual review is required.");

        if (sessions.Count == 1)
        {
            var (privateRoot, journal) = sessions[0];
            // Authenticate recovery from the protected journal and original backup, not a
            // reparsed source fingerprint (which may be replacement content or unavailable).
            await RestoreAsync(
                new WindowsConfigCheckSession(privateRoot, journal.SourcePath, journal.SourceFingerprint),
                CancellationToken.None,
                reconcileDerivedConfigAsync).ConfigureAwait(false);
        }
        else if (recycles.Count == 1)
        {
            var (privateRoot, journal) = recycles[0];
            await VerifyRecycleOriginalBackup(journal).ConfigureAwait(false);
            await native.RecoverRecycleAsync(
                CreateRecycleTransaction(journal),
                journal.Phase,
                progress => RecordRecycleProgress(privateRoot, journal, progress),
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    public async Task RecycleUnrepairedAsync(CheckedConfig config, CancellationToken token)
    {
        var fullPath = ValidateConfigPath(config.Path);
        var source = await native.ReadSourceFileAsync(fullPath, token).ConfigureAwait(false);
        EnsureSamePath(fullPath, source.FullPath);
        if (!string.Equals(CheckedConfig.FingerprintBytes(source.Bytes), config.Fingerprint, StringComparison.Ordinal))
            throw new IOException("Configuration changed after testing; it was not recycled.");

        var privateRoot = Path.Combine(dataRoot, "config-check", Guid.NewGuid().ToString("N"));
        await native.CreatePrivateDirectoryAsync(privateRoot, token).ConfigureAwait(false);
        var quarantineDirectory = Path.Combine(
            Path.GetDirectoryName(fullPath) ?? throw new IOException("Configuration directory is unavailable."),
            "." + Path.GetFileName(fullPath) + "." + Path.GetFileName(privateRoot) + ".wgst-recycle");
        var journal = new RecycleJournal
        {
            SourcePath = fullPath,
            SourceFingerprint = config.Fingerprint,
            SourceIdentity = source.Identity,
            OriginalBackupPath = Path.Combine(privateRoot, "original.bin"),
            QuarantineDirectory = quarantineDirectory,
            QuarantinePath = Path.Combine(quarantineDirectory, Path.GetFileName(fullPath)),
            Phase = ConfigCheckRecyclePhase.Prepared
        };
        await native.WritePrivateFileAsync(journal.OriginalBackupPath, source.Bytes, token).ConfigureAwait(false);
        await VerifyRecycleOriginalBackup(journal).ConfigureAwait(false);
        // The original, exact quarantine paths, expected identity, and phase are durable before File.Move.
        await WriteRecycleJournal(privateRoot, journal, token).ConfigureAwait(false);
        await native.RecycleFileAsync(
            CreateRecycleTransaction(journal),
            progress => RecordRecycleProgress(privateRoot, journal, progress),
            token).ConfigureAwait(false);
        if (journal.Phase != ConfigCheckRecyclePhase.Completed)
            throw new IOException("Configuration recycling did not reconcile its durable transaction.");
    }

    private static int FindCountryId(string json, string country)
    {
        using var countries = JsonDocument.Parse(json);
        if (countries.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Invalid country metadata.");
        foreach (var entry in countries.RootElement.EnumerateArray())
        {
            try
            {
                if (entry.GetProperty("code").GetString() == country &&
                    entry.GetProperty("id").TryGetInt32(out var id) && id > 0)
                    return id;
            }
            catch (Exception exception) when (exception is InvalidOperationException or KeyNotFoundException)
            {
                // Ignore unrelated malformed country records; never infer a country identifier.
            }
        }
        throw new InvalidDataException("The requested country is absent from NordVPN metadata.");
    }

    private async Task<IPAddress> ResolveIpv4(string hostName, CancellationToken token)
    {
        var addresses = await native.ResolveAsync(hostName, token).ConfigureAwait(false);
        var address = addresses.FirstOrDefault(candidate =>
            candidate.AddressFamily == AddressFamily.InterNetwork && !IPAddress.Any.Equals(candidate));
        return address ?? throw new IOException("A required IPv4 address could not be resolved.");
    }

    private async Task EnsureNoIncompleteJournal(CancellationToken token)
    {
        var roots = await native.FindJournalRootsAsync(dataRoot, token).ConfigureAwait(false);
        foreach (var root in roots)
        {
            var sessionJson = await native.ReadJournalAsync(root, SessionJournalName, token).ConfigureAwait(false);
            var recycleJson = await native.ReadJournalAsync(root, RecycleJournalName, token).ConfigureAwait(false);
            if ((sessionJson is null) == (recycleJson is null))
                throw new InvalidDataException("A config-check recovery root must contain exactly one transaction journal.");
            var incomplete = sessionJson is not null
                ? (await ReadSessionJournal(root, token).ConfigureAwait(false)).State != SessionState.Completed
                : (await ReadRecycleJournal(root, token).ConfigureAwait(false)).Phase != ConfigCheckRecyclePhase.Completed;
            if (incomplete)
                throw new IOException("An incomplete config-check recovery journal requires recovery before another check.");
        }
    }

    private string RequirePrivateRoot(IConfigCheckSession session)
    {
        ArgumentNullException.ThrowIfNull(session);
        var privateRoot = Path.GetFullPath(session.PrivateRoot);
        if (!IsExpectedPrivateRoot(privateRoot))
            throw new IOException("Config-check session path is outside the private recovery root.");
        native.EnsureNoReparsePoints(privateRoot);
        return privateRoot;
    }

    private bool IsExpectedPrivateRoot(string privateRoot)
    {
        if (!IsCanonicalFile(privateRoot)) return false;
        var expectedParent = Path.Combine(dataRoot, "config-check");
        var name = Path.GetFileName(privateRoot);
        return PathsEqual(Path.GetDirectoryName(privateRoot) ?? string.Empty, expectedParent) &&
            Guid.TryParseExact(name, "N", out _) && name.All(character =>
                (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));
    }

    private async Task<SessionJournal> ReadSessionJournal(string privateRoot, CancellationToken token)
    {
        var json = await native.ReadJournalAsync(privateRoot, SessionJournalName, token).ConfigureAwait(false);
        if (json is null) throw new IOException("The config-check recovery journal is missing.");
        SessionJournal? journal;
        try
        {
            journal = JsonSerializer.Deserialize<SessionJournal>(json, JournalJsonOptions);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            throw new InvalidDataException("The config-check recovery journal is invalid.");
        }
        if (journal is null) throw new InvalidDataException("The config-check recovery journal is invalid.");
        ValidateSessionJournal(privateRoot, journal);
        return journal;
    }

    private async Task<RecycleJournal> ReadRecycleJournal(string privateRoot, CancellationToken token)
    {
        var json = await native.ReadJournalAsync(privateRoot, RecycleJournalName, token).ConfigureAwait(false);
        if (json is null) throw new IOException("The config-check recycle journal is missing.");
        RecycleJournal? journal;
        try
        {
            journal = JsonSerializer.Deserialize<RecycleJournal>(json, JournalJsonOptions);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            throw new InvalidDataException("The config-check recycle journal is invalid.");
        }
        if (journal is null) throw new InvalidDataException("The config-check recycle journal is invalid.");
        ValidateRecycleJournal(privateRoot, journal);
        return journal;
    }

    private void ValidateRecycleJournal(string privateRoot, RecycleJournal journal)
    {
        if (!IsExpectedPrivateRoot(privateRoot) || journal.Version != 1 || !Enum.IsDefined(journal.Phase) ||
            !IsCanonicalFile(journal.SourcePath) ||
            !string.Equals(Path.GetExtension(journal.SourcePath), ".conf", StringComparison.OrdinalIgnoreCase) ||
            WindowsConfigCheckPrimitives.IsPathWithinRoot(Path.Combine(dataRoot, "config-check"), journal.SourcePath) ||
            !IsFingerprint(journal.SourceFingerprint))
            throw new InvalidDataException("The config-check recycle journal is invalid.");
        RequireOwnedPath(journal.OriginalBackupPath, Path.Combine(privateRoot, "original.bin"));
        var sourceDirectory = Path.GetDirectoryName(journal.SourcePath) ??
            throw new InvalidDataException("The config-check recycle journal is invalid.");
        var expectedDirectory = Path.Combine(
            sourceDirectory,
            "." + Path.GetFileName(journal.SourcePath) + "." + Path.GetFileName(privateRoot) + ".wgst-recycle");
        RequireOwnedPath(journal.QuarantineDirectory, expectedDirectory);
        RequireOwnedPath(journal.QuarantinePath, Path.Combine(expectedDirectory, Path.GetFileName(journal.SourcePath)));
        native.EnsureNoReparsePoints(journal.SourcePath);
        native.EnsureNoReparsePoints(journal.OriginalBackupPath);
        native.EnsureNoReparsePoints(journal.QuarantineDirectory);
        native.EnsureNoReparsePoints(journal.QuarantinePath);
    }

    private void ValidateSessionJournal(string privateRoot, SessionJournal journal)
    {
        if (!IsExpectedPrivateRoot(privateRoot) || journal.Version != 1 || !Enum.IsDefined(journal.State) ||
            !IsCanonicalFile(journal.SourcePath) ||
            !string.Equals(Path.GetExtension(journal.SourcePath), ".conf", StringComparison.OrdinalIgnoreCase) ||
            WindowsConfigCheckPrimitives.IsPathWithinRoot(Path.Combine(dataRoot, "config-check"), journal.SourcePath) ||
            !IsFingerprint(journal.SourceFingerprint) || journal.Services is null)
            throw new InvalidDataException("The config-check recovery journal is invalid.");

        RequireOwnedPath(journal.OriginalBackupPath, Path.Combine(privateRoot, "original.bin"));
        RequireOwnedPath(journal.DisplacedPath, Path.Combine(privateRoot, "displaced.bin"));
        if (journal.DerivedConfigPath is not null)
        {
            RequireOwnedPath(
                journal.DerivedConfigPath,
                Path.Combine(dataRoot, "derived-confs", Path.GetFileName(journal.SourcePath)));
            native.EnsureNoReparsePoints(journal.DerivedConfigPath);
        }
        var sourceDirectory = Path.GetDirectoryName(journal.SourcePath) ??
            throw new InvalidDataException("The config-check recovery journal is invalid.");
        var stagePrefix = "." + Path.GetFileName(journal.SourcePath) + "." + Path.GetFileName(privateRoot);
        var originalStage = Path.Combine(sourceDirectory, stagePrefix + ".wgst.tmp");
        var recoveryStage = Path.Combine(sourceDirectory, stagePrefix + ".recovery.tmp");
        if (journal.StagedPath is not null) RequireOwnedPath(journal.StagedPath, originalStage);
        if (journal.RecoveryStagedPath is not null) RequireOwnedPath(journal.RecoveryStagedPath, recoveryStage);
        if (journal.ReplacementFingerprint is not null && !IsFingerprint(journal.ReplacementFingerprint))
            throw new InvalidDataException("The config-check recovery journal is invalid.");
        if (journal.State is SessionState.Replacing or SessionState.Repaired or SessionState.Recovered)
        {
            if (journal.StagedPath is null || !IsFingerprint(journal.ReplacementFingerprint))
                throw new InvalidDataException("The replacement recovery journal is incomplete.");
        }
        else if (journal.State is SessionState.Begun or SessionState.StopRequested &&
            (journal.StagedPath is not null || journal.RecoveryStagedPath is not null || journal.ReplacementFingerprint is not null))
            throw new InvalidDataException("An early recovery journal contains replacement state.");
        if (journal.RecoveryStagedPath is not null && journal.StagedPath is null)
            throw new InvalidDataException("The recovery stage has no original replacement identity.");
        var hasTransaction = HasReplacementTransaction(journal);
        var hasAnyTransactionState = hasTransaction || journal.SourceIdentity is not null ||
            journal.ReplacementIdentity is not null || journal.ReplacementBackupPath is not null ||
            journal.RestoreBackupPath is not null || journal.ReplacementPhase is not null ||
            journal.DisplacedSourceIdentity is not null;
        if (!hasTransaction && hasAnyTransactionState)
            throw new InvalidDataException("The replacement transaction journal is incomplete.");
        if (hasTransaction)
        {
            RequireOwnedPath(journal.ReplacementBackupPath, originalStage + ".replace-backup");
            RequireOwnedPath(journal.RestoreBackupPath, originalStage + ".restore-backup");
            if (!Enum.IsDefined(journal.ReplacementPhase!.Value))
                throw new InvalidDataException("The replacement transaction phase is invalid.");
        }
        if (journal.State == SessionState.Repaired && !hasTransaction)
            throw new InvalidDataException("A repaired session requires its complete replacement transaction.");
        if (journal.State is SessionState.Begun or SessionState.StopRequested && hasAnyTransactionState)
            throw new InvalidDataException("An early recovery journal contains replacement transaction state.");

        var hasTunnel = journal.OwnedTunnelName is not null;
        var hasTemp = journal.OwnedTempConfigPath is not null;
        if (hasTunnel != hasTemp || (journal.OwnedRouteAddress is not null && !hasTunnel) ||
            (journal.OwnedCleanupCompleted && (hasTunnel || hasTemp || journal.OwnedRouteAddress is not null)))
            throw new InvalidDataException("The owned-probe recovery state is inconsistent.");
        if (hasTunnel) EnsureOwnedProbePaths(privateRoot, journal.OwnedTunnelName!, journal.OwnedTempConfigPath!);
        if (journal.OwnedRouteAddress is not null &&
            (!IPAddress.TryParse(journal.OwnedRouteAddress, out var route) || route.AddressFamily != AddressFamily.InterNetwork))
            throw new InvalidDataException("The owned-probe route journal is invalid.");
        foreach (var service in journal.Services)
        {
            if (service is null || !service.IsRunning ||
                !IsSavedTunnelServiceName(service.Name) || !IsFingerprint(service.Identity))
                throw new InvalidDataException("The saved tunnel service journal is invalid.");
            if (service.Status is not null &&
                (!Enum.IsDefined(service.Status.Value) ||
                 service.IsRunning != (service.Status.Value == ConfigCheckServiceStatus.Running)))
                throw new InvalidDataException("The saved tunnel service status is inconsistent.");
        }

        native.EnsureNoReparsePoints(journal.SourcePath);
        native.EnsureNoReparsePoints(journal.OriginalBackupPath);
        native.EnsureNoReparsePoints(journal.DisplacedPath);
        if (journal.StagedPath is not null) native.EnsureNoReparsePoints(journal.StagedPath);
        if (journal.RecoveryStagedPath is not null) native.EnsureNoReparsePoints(journal.RecoveryStagedPath);
        if (journal.ReplacementBackupPath is not null) native.EnsureNoReparsePoints(journal.ReplacementBackupPath);
        if (journal.RestoreBackupPath is not null) native.EnsureNoReparsePoints(journal.RestoreBackupPath);
        if (journal.OwnedTempConfigPath is not null) native.EnsureNoReparsePoints(journal.OwnedTempConfigPath);
    }

    private static bool IsSavedTunnelServiceName(string? serviceName)
    {
        const string prefix = "WireGuardTunnel$";
        if (string.IsNullOrWhiteSpace(serviceName) ||
            !serviceName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        var tunnelName = serviceName[prefix.Length..];
        if (string.IsNullOrWhiteSpace(tunnelName) || tunnelName is "." or ".." ||
            tunnelName.EndsWith(' ') || tunnelName.EndsWith('.') || tunnelName.Any(char.IsControl) ||
            tunnelName.IndexOfAny(['<', '>', ':', '"', '/', '\\', '|', '?', '*']) >= 0) return false;
        return string.Equals(
            global::WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(tunnelName + ".conf"),
            tunnelName,
            StringComparison.Ordinal);
    }

    private static bool IsCanonicalFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || Path.EndsInDirectorySeparator(path)) return false;
        try
        {
            return string.Equals(path, Path.GetFullPath(path), PathComparison);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsFingerprint(string? value) => value is not null && value.Length == 64 && value.All(character =>
        (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));

    private static void RequireOwnedPath(string? actual, string expected)
    {
        if (!IsCanonicalFile(actual) || !PathsEqual(actual!, expected))
            throw new InvalidDataException("A recovery path failed exact ownership validation.");
    }

    private async Task VerifyOriginalBackup(SessionJournal journal)
    {
        var original = await native.ReadPrivateFileAsync(journal.OriginalBackupPath, CancellationToken.None).ConfigureAwait(false);
        if (!string.Equals(CheckedConfig.FingerprintBytes(original), journal.SourceFingerprint, StringComparison.Ordinal))
            throw new InvalidDataException("The original configuration backup failed fingerprint verification.");
    }

    private async Task VerifyRecycleOriginalBackup(RecycleJournal journal)
    {
        var original = await native.ReadPrivateFileAsync(journal.OriginalBackupPath, CancellationToken.None).ConfigureAwait(false);
        if (!string.Equals(CheckedConfig.FingerprintBytes(original), journal.SourceFingerprint, StringComparison.Ordinal))
            throw new InvalidDataException("The original recycle backup failed fingerprint verification.");
    }

    private Task WriteRecycleJournal(string privateRoot, RecycleJournal journal, CancellationToken token) =>
        native.WriteJournalAsync(privateRoot, RecycleJournalName,
            JsonSerializer.Serialize(journal, JournalJsonOptions), token);

    private static ConfigCheckRecycleTransaction CreateRecycleTransaction(RecycleJournal journal) =>
        new(journal.SourcePath, journal.OriginalBackupPath, journal.QuarantineDirectory, journal.QuarantinePath,
            journal.SourceIdentity, journal.SourceFingerprint);

    private Task RecordRecycleProgress(
        string privateRoot,
        RecycleJournal journal,
        ConfigCheckRecycleProgress progress)
    {
        if (!Enum.IsDefined(progress.Phase) || progress.Phase < journal.Phase)
            throw new IOException("The recycle progress state is invalid.");
        journal.Phase = progress.Phase;
        return WriteRecycleJournal(privateRoot, journal, CancellationToken.None);
    }

    private Task WriteSessionJournal(string privateRoot, SessionJournal journal, CancellationToken token) =>
        native.WriteJournalAsync(privateRoot, SessionJournalName,
            JsonSerializer.Serialize(journal, JournalJsonOptions), token);

    private Task WriteAttemptJournal(string privateRoot, AttemptJournal journal, CancellationToken token) =>
        native.WriteJournalAsync(privateRoot, AttemptJournalName,
            JsonSerializer.Serialize(journal, JournalJsonOptions), token);

    private async Task CleanupAttempt(string privateRoot, SessionJournal journal)
    {
        var json = await native.ReadJournalAsync(privateRoot, AttemptJournalName, CancellationToken.None).ConfigureAwait(false);
        if (journal.OwnedCleanupCompleted)
        {
            // Cleanup was fully verified before this flag was persisted; only a crash-left attempt record remains.
            if (json is not null)
                await native.ClearAttemptJournalAsync(privateRoot, CancellationToken.None).ConfigureAwait(false);
            return;
        }

        AttemptJournal? attempt = null;
        if (json is not null)
        {
            try
            {
                attempt = JsonSerializer.Deserialize<AttemptJournal>(json, JournalJsonOptions);
                if (attempt is null || attempt.Version != 1 || string.IsNullOrEmpty(attempt.TunnelName) ||
                    string.IsNullOrEmpty(attempt.TempConfigPath))
                    attempt = null;
            }
            catch (Exception exception) when (exception is JsonException or NotSupportedException)
            {
                // The session journal below is the trusted fallback for an incomplete attempt record.
            }
        }

        if (attempt is not null &&
            ((journal.OwnedTunnelName is not null && journal.OwnedTunnelName != attempt.TunnelName) ||
             (journal.OwnedTempConfigPath is not null && !PathsEqual(journal.OwnedTempConfigPath, attempt.TempConfigPath))))
            throw new InvalidDataException("Owned-probe journal identities do not match.");

        var tunnelName = journal.OwnedTunnelName ?? attempt?.TunnelName;
        var tempConfigPath = journal.OwnedTempConfigPath ?? attempt?.TempConfigPath;
        if (tunnelName is null || tempConfigPath is null)
        {
            if (json is not null || tunnelName is not null || tempConfigPath is not null)
                throw new InvalidDataException("The owned-probe recovery journal is incomplete.");
            return;
        }
        EnsureOwnedProbePaths(privateRoot, tunnelName, tempConfigPath);

        var routeText = journal.OwnedRouteAddress ?? attempt?.RouteAddress;
        if (routeText is not null)
        {
            if (!IPAddress.TryParse(routeText, out var routeAddress) || routeAddress.AddressFamily != AddressFamily.InterNetwork)
                throw new InvalidDataException("The owned-probe route journal is invalid.");
            await DeleteOwnedProbeRoute(tunnelName, routeAddress).ConfigureAwait(false);
        }
        if (journal.OwnedTunnelName is not null || attempt?.InstallRequested == true)
            await native.DeleteTunnelServiceAsync(tunnelName, CancellationToken.None).ConfigureAwait(false);
        await native.VerifyTunnelInactiveAsync(tunnelName, CancellationToken.None).ConfigureAwait(false);
        native.EnsureNoReparsePoints(tempConfigPath);
        await native.DeletePrivateFileAsync(tempConfigPath, CancellationToken.None).ConfigureAwait(false);
        journal.OwnedTunnelName = null;
        journal.OwnedTempConfigPath = null;
        journal.OwnedRouteAddress = null;
        journal.OwnedCleanupCompleted = true;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
        await native.ClearAttemptJournalAsync(privateRoot, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task DeleteOwnedProbeRoute(string tunnelName, IPAddress routeAddress)
    {
        try
        {
            await native.DeleteProbeRouteAsync(tunnelName, routeAddress, CancellationToken.None).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // A failed delete is safe only when independent verification proves the owned route is absent.
            await native.VerifyProbeRouteAbsentAsync(tunnelName, routeAddress, CancellationToken.None).ConfigureAwait(false);
            return;
        }
        await native.VerifyProbeRouteAbsentAsync(tunnelName, routeAddress, CancellationToken.None).ConfigureAwait(false);
    }

    private static void EnsureOwnedProbePaths(string privateRoot, string tunnelName, string tempConfigPath)
    {
        var validName = tunnelName.Length == 22 && tunnelName.StartsWith("WGSTCheck-", StringComparison.Ordinal) &&
            tunnelName[10..].All(character =>
                (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'));
        var expectedPath = Path.Combine(Path.GetFullPath(privateRoot), tunnelName + ".conf");
        if (!validName || !WindowsConfigCheckPrimitives.IsPathWithinRoot(privateRoot, tempConfigPath) ||
            !PathsEqual(expectedPath, tempConfigPath))
            throw new InvalidDataException("The owned-probe artifact path failed ownership validation.");
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), PathComparison);

    private async Task RecoverReplacement(string privateRoot, SessionJournal journal)
    {
        if (journal.State is not (SessionState.Replacing or SessionState.Repaired)) return;
        if (!HasReplacementTransaction(journal))
        {
            // A crash before the prepared-transaction journal cannot own any replacement backups.
            // Never infer a healthy repair merely from content at the source path.
            if (await SourceHasFingerprint(journal.SourcePath, journal.SourceFingerprint).ConfigureAwait(false))
            {
                journal.State = SessionState.Recovered;
                await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
                return;
            }
            if (await native.SourceFileExistsAsync(journal.SourcePath, CancellationToken.None).ConfigureAwait(false))
                throw new IOException("An unprepared replacement has an ambiguous source and requires manual review.");
            await RestoreMissingSource(privateRoot, journal).ConfigureAwait(false);
            return;
        }

        var outcome = await native.RecoverReplacementAsync(
            CreateReplacementTransaction(journal),
            journal.DisplacedSourceIdentity,
            progress => RecordReplacementProgress(privateRoot, journal, progress),
            CancellationToken.None).ConfigureAwait(false);
        switch (outcome)
        {
            case ConfigCheckReplacementOutcome.ReplacementApplied:
                if (!await SourceHasFingerprint(journal.SourcePath, journal.ReplacementFingerprint!).ConfigureAwait(false))
                    throw new IOException("Recovered replacement content could not be verified.");
                journal.State = SessionState.Repaired;
                await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
                break;
            case ConfigCheckReplacementOutcome.OriginalRetained:
                if (journal.State == SessionState.Repaired ||
                    !await SourceHasFingerprint(journal.SourcePath, journal.SourceFingerprint).ConfigureAwait(false))
                    throw new IOException("Recovery contradicted the journaled replacement result.");
                journal.State = SessionState.Recovered;
                await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
                break;
            case ConfigCheckReplacementOutcome.SourceMissing:
                if (journal.State == SessionState.Repaired)
                    throw new IOException("The repaired source is missing; manual review is required.");
                await RestoreMissingSource(privateRoot, journal).ConfigureAwait(false);
                break;
            case ConfigCheckReplacementOutcome.NewerSourceRetained:
                throw new IOException("A newer configuration was restored after a replacement race; manual review is required.");
            default:
                throw new IOException("The replacement recovery outcome is invalid.");
        }
        await VerifyReplacementArtifactsAbsent(journal).ConfigureAwait(false);
    }

    private async Task RestoreMissingSource(string privateRoot, SessionJournal journal)
    {
        var displaced = await native.ReadPrivateFileAsync(journal.DisplacedPath, CancellationToken.None).ConfigureAwait(false);
        if (CheckedConfig.FingerprintBytes(displaced) != journal.SourceFingerprint)
            throw new IOException("The displaced configuration backup failed verification.");
        var recoveryStage = Path.Combine(
            Path.GetDirectoryName(journal.SourcePath) ?? throw new IOException("Configuration directory is unavailable."),
            "." + Path.GetFileName(journal.SourcePath) + "." + Path.GetFileName(privateRoot) + ".recovery.tmp");
        journal.RecoveryStagedPath = recoveryStage;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
        await DeleteOwnedStagingFile(privateRoot, journal, recoveryStage).ConfigureAwait(false);
        await native.StageReplacementAsync(journal.SourcePath, recoveryStage, displaced, CancellationToken.None).ConfigureAwait(false);
        await native.MoveStagedFileToMissingSourceAsync(
            recoveryStage, journal.SourcePath, CancellationToken.None).ConfigureAwait(false);
        if (!await SourceHasFingerprint(journal.SourcePath, journal.SourceFingerprint).ConfigureAwait(false))
            throw new IOException("Displaced configuration recovery could not be verified.");
        journal.State = SessionState.Recovered;
        await WriteSessionJournal(privateRoot, journal, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task CleanupOwnedStaging(string privateRoot, SessionJournal journal)
    {
        foreach (var path in new[] { journal.StagedPath, journal.RecoveryStagedPath })
        {
            if (path is not null)
                await DeleteOwnedStagingFile(privateRoot, journal, path).ConfigureAwait(false);
        }
        if (HasReplacementTransaction(journal))
            await VerifyReplacementArtifactsAbsent(journal).ConfigureAwait(false);
    }

    private async Task VerifyReplacementArtifactsAbsent(SessionJournal journal)
    {
        await native.VerifyStagedFileAbsentAsync(journal.ReplacementBackupPath!, CancellationToken.None).ConfigureAwait(false);
        await native.VerifyStagedFileAbsentAsync(journal.RestoreBackupPath!, CancellationToken.None).ConfigureAwait(false);
    }

    private Task RecordReplacementProgress(
        string privateRoot,
        SessionJournal journal,
        ConfigCheckReplacementProgress progress)
    {
        if (!Enum.IsDefined(progress.Phase)) throw new IOException("The replacement progress state is invalid.");
        journal.ReplacementPhase = progress.Phase;
        if (progress.DisplacedSourceIdentity is { } identity)
            journal.DisplacedSourceIdentity = identity;
        return WriteSessionJournal(privateRoot, journal, CancellationToken.None);
    }

    private static bool HasReplacementTransaction(SessionJournal journal) =>
        journal.SourceIdentity is not null && journal.ReplacementIdentity is not null &&
        journal.ReplacementBackupPath is not null && journal.RestoreBackupPath is not null &&
        journal.ReplacementPhase is not null;

    private static ConfigCheckReplacementTransaction CreateReplacementTransaction(SessionJournal journal)
    {
        if (!HasReplacementTransaction(journal))
            throw new InvalidDataException("The journaled replacement transaction is incomplete.");
        return new ConfigCheckReplacementTransaction(
            journal.StagedPath!,
            journal.SourcePath,
            journal.ReplacementBackupPath!,
            journal.RestoreBackupPath!,
            journal.SourceIdentity!.Value,
            journal.ReplacementIdentity!.Value,
            journal.SourceFingerprint,
            journal.ReplacementFingerprint!);
    }

    private async Task DeleteOwnedStagingFile(string privateRoot, SessionJournal journal, string path)
    {
        var directory = Path.GetDirectoryName(journal.SourcePath) ??
            throw new IOException("Configuration directory is unavailable.");
        var prefix = "." + Path.GetFileName(journal.SourcePath) + "." + Path.GetFileName(privateRoot);
        var originalStage = Path.Combine(directory, prefix + ".wgst.tmp");
        var recoveryStage = Path.Combine(directory, prefix + ".recovery.tmp");
        if (!PathsEqual(path, originalStage) && !PathsEqual(path, recoveryStage))
            throw new InvalidDataException("A replacement staging path failed ownership validation.");
        native.EnsureNoReparsePoints(path);
        await native.DeleteStagedFileAsync(path, CancellationToken.None).ConfigureAwait(false);
        await native.VerifyStagedFileAbsentAsync(path, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task RestoreOriginalServices(
        SessionJournal journal,
        Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync)
    {
        var snapshot = await native.GetTunnelServicesAsync(CancellationToken.None).ConfigureAwait(false);
        EnsureNoDifferentRunningTunnel(snapshot, journal.Services);
        // Validate the complete set before restarting even the first original service.
        foreach (var saved in journal.Services)
        {
            var current = snapshot.SingleOrDefault(service => service.Name == saved.Name);
            if (current is null || current.Identity != saved.Identity)
                throw new IOException("An original tunnel service identity changed; manual review is required.");
        }

        Exception? routeFailure = null;
        foreach (var saved in journal.Services)
        {
            try
            {
                var current = snapshot.Single(service => service.Name == saved.Name);
                if (!current.IsRunning)
                    await native.StartServiceAsync(saved, CancellationToken.None).ConfigureAwait(false);

                // Verify each service independently before reporting it as restored.
                var verification = await native.GetTunnelServicesAsync(CancellationToken.None).ConfigureAwait(false);
                EnsureNoDifferentRunningTunnel(verification, journal.Services);
                current = verification.SingleOrDefault(service => service.Name == saved.Name);
                if (current is null || current.Identity != saved.Identity || !current.IsRunning)
                    throw new IOException("An original tunnel service did not return to its recorded running state.");
                snapshot = verification;
            }
            catch (Exception serviceFailure)
            {
                if (routeFailure is not null)
                    throw new AggregateException(serviceFailure, routeFailure);
                throw;
            }

            if (serviceRestoredAsync is null || routeFailure is not null) continue;
            try
            {
                await serviceRestoredAsync(
                    new ConfigCheckRecoveredService(journal.SourcePath, saved.Name),
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                // Keep restoring the remaining journaled services, but never report
                // this transaction as completed when follow-on route renewal failed.
                routeFailure = exception;
            }
        }

        if (routeFailure is not null) throw routeFailure;
    }

    private static void EnsureNoDifferentRunningTunnel(
        IReadOnlyList<ConfigCheckServiceState> snapshot,
        IReadOnlyList<ConfigCheckServiceState> savedServices)
    {
        EnsureNoTransitionalServices(snapshot);
        var savedNames = savedServices.Select(service => service.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (snapshot.Any(service => service.IsRunning && !savedNames.Contains(service.Name)))
            throw new IOException("A different running WireGuard tunnel requires manual review.");
    }

    private static void EnsureNoTransitionalServices(IReadOnlyList<ConfigCheckServiceState> snapshot)
    {
        if (snapshot.Any(service => service.IsTransitional))
            throw new IOException("A WireGuard tunnel is in a transitional state; manual review is required.");
    }

    private async Task<ConfigCheckSourceFile> ReadExpectedSource(CheckedConfig config, SessionJournal journal)
    {
        var source = await native.ReadSourceFileAsync(config.Path, CancellationToken.None).ConfigureAwait(false);
        EnsureSamePath(config.Path, source.FullPath);
        var currentFingerprint = CheckedConfig.FingerprintBytes(source.Bytes);
        if (currentFingerprint != config.Fingerprint || currentFingerprint != journal.SourceFingerprint)
            throw new IOException("Configuration changed after testing; replacement was blocked.");
        return source;
    }

    private async Task<bool> SourceHasFingerprint(string path, string expectedFingerprint)
    {
        try
        {
            var source = await native.ReadSourceFileAsync(path, CancellationToken.None).ConfigureAwait(false);
            EnsureSamePath(path, source.FullPath);
            return CheckedConfig.FingerprintBytes(source.Bytes) == expectedFingerprint;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void EnsureMatchingSession(CheckedConfig config, SessionJournal journal) =>
        EnsureMatchingSession(config.Path, config.Fingerprint, journal);

    private static void EnsureMatchingSession(string sourcePath, string sourceFingerprint, SessionJournal journal)
    {
        EnsureSamePath(sourcePath, journal.SourcePath);
        if (!string.Equals(sourceFingerprint, journal.SourceFingerprint, StringComparison.Ordinal))
            throw new IOException("Configuration identity does not match the recovery session.");
    }

    private string ValidateConfigPath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetExtension(fullPath), ".conf", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Only the exact plaintext .conf source can be recycled.");
        native.EnsureNoReparsePoints(fullPath);
        return fullPath;
    }

    private static void EnsureSamePath(string expected, string actual)
    {
        if (!string.Equals(Path.GetFullPath(expected), Path.GetFullPath(actual), PathComparison))
            throw new IOException("Configuration path identity changed; the operation was blocked.");
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    private static string? ParseTraceCountry(string output)
    {
        foreach (var rawLine in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var line = rawLine.TrimEnd('\r');
            if (!line.StartsWith("loc=", StringComparison.Ordinal)) continue;
            var country = line.Substring(4);
            return country.Length == 2 && country.All(character => character >= 'A' && character <= 'Z') ? country : null;
        }
        return null;
    }

    private sealed record WindowsConfigCheckSession(
        string PrivateRoot,
        string SourcePath,
        string SourceFingerprint) : IConfigCheckSession;

    private enum SessionState { Begun, StopRequested, Replacing, Repaired, Recovered, Completed }

    private sealed class SessionJournal
    {
        public int Version { get; set; } = 1;
        public string SourcePath { get; set; } = string.Empty;
        public string SourceFingerprint { get; set; } = string.Empty;
        public string OriginalBackupPath { get; set; } = string.Empty;
        public string DisplacedPath { get; set; } = string.Empty;
        public string? DerivedConfigPath { get; set; }
        public string? StagedPath { get; set; }
        public string? RecoveryStagedPath { get; set; }
        public string? ReplacementFingerprint { get; set; }
        public string? ReplacementBackupPath { get; set; }
        public string? RestoreBackupPath { get; set; }
        public ConfigCheckFileIdentity? SourceIdentity { get; set; }
        public ConfigCheckFileIdentity? ReplacementIdentity { get; set; }
        public ConfigCheckFileIdentity? DisplacedSourceIdentity { get; set; }
        public ConfigCheckReplacementPhase? ReplacementPhase { get; set; }
        public string? OwnedTunnelName { get; set; }
        public string? OwnedTempConfigPath { get; set; }
        public string? OwnedRouteAddress { get; set; }
        public bool OwnedCleanupCompleted { get; set; }
        public SessionState State { get; set; }
        public List<ConfigCheckServiceState> Services { get; set; } = [];
    }

    private sealed class RecycleJournal
    {
        public int Version { get; set; } = 1;
        public string SourcePath { get; set; } = string.Empty;
        public string SourceFingerprint { get; set; } = string.Empty;
        public ConfigCheckFileIdentity SourceIdentity { get; set; }
        public string OriginalBackupPath { get; set; } = string.Empty;
        public string QuarantineDirectory { get; set; } = string.Empty;
        public string QuarantinePath { get; set; } = string.Empty;
        public ConfigCheckRecyclePhase Phase { get; set; }
    }

    private sealed class AttemptJournal
    {
        public int Version { get; set; } = 1;
        public string TunnelName { get; set; } = string.Empty;
        public string TempConfigPath { get; set; } = string.Empty;
        public string? RouteAddress { get; set; }
        public bool InstallRequested { get; set; }
    }
}
