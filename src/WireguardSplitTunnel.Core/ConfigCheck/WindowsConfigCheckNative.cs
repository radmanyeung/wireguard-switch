using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.VisualBasic.FileIO;
using Microsoft.Win32.SafeHandles;

namespace WireguardSplitTunnel.Core.ConfigCheck;

/// <summary>Production Windows operations. Offline tests always replace this class with a fake.</summary>
public sealed class WindowsConfigCheckNative : IConfigCheckNative
{
    private const int MaxJsonBytes = 1_048_576;
    private const int MaxSourceBytes = 1_048_576;
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(30);
    private static readonly HttpClient MetadataClient = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    })
    {
        Timeout = TimeSpan.FromSeconds(20)
    };
    private readonly string programFilesRoot;
    private readonly string system32Root;
    private readonly IConfigCheckProcessFactory processFactory;
    private readonly TimeSpan processTimeout;
    private readonly Func<TimeSpan, CancellationToken, Task> delayAsync;
    private readonly Action<string>? afterSourceIdentityVerification;
    private readonly Action<string>? afterQuarantineIdentityVerification;
    private readonly Func<string, CancellationToken, Task> recycleFileAsync;
    private readonly Func<string, CancellationToken, Task> protectRecycleDirectoryAsync;
    private readonly Action<string>? beforeRecycleRollback;

    public WindowsConfigCheckNative()
        : this(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            new SystemConfigCheckProcessFactory(),
            ProcessTimeout)
    {
    }

    internal WindowsConfigCheckNative(
        string programFilesRoot,
        string system32Root,
        IConfigCheckProcessFactory processFactory,
        TimeSpan? processTimeout = null,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null,
        Action<string>? afterSourceIdentityVerification = null,
        Func<string, CancellationToken, Task>? recycleFileAsync = null,
        Action<string>? afterQuarantineIdentityVerification = null,
        Func<string, CancellationToken, Task>? protectRecycleDirectoryAsync = null,
        Action<string>? beforeRecycleRollback = null)
    {
        this.programFilesRoot = programFilesRoot;
        this.system32Root = system32Root;
        this.processFactory = processFactory;
        this.processTimeout = processTimeout ?? ProcessTimeout;
        this.delayAsync = delayAsync ?? Task.Delay;
        this.afterSourceIdentityVerification = afterSourceIdentityVerification;
        this.recycleFileAsync = recycleFileAsync ?? RecycleFile;
        this.afterQuarantineIdentityVerification = afterQuarantineIdentityVerification;
        this.protectRecycleDirectoryAsync = protectRecycleDirectoryAsync ?? ProtectRecycleDirectoryAsync;
        this.beforeRecycleRollback = beforeRecycleRollback;
    }

    internal static string ResolveExecutablePath(string fileName, string programFilesRoot, string system32Root)
    {
        var wireGuard = fileName is "wireguard.exe" or "wg.exe";
        if (!wireGuard && fileName is not ("sc.exe" or "curl.exe" or "netsh.exe" or "icacls.exe"))
            throw new InvalidDataException("The requested native executable is not allowed.");
        var directory = Path.GetFullPath(wireGuard
            ? Path.Combine(programFilesRoot, "WireGuard")
            : system32Root);
        var executable = Path.GetFullPath(Path.Combine(directory, fileName));
        if (!Directory.Exists(directory) || !File.Exists(executable) ||
            !string.Equals(Path.GetFileName(executable), fileName, StringComparison.OrdinalIgnoreCase) ||
            !WindowsConfigCheckPrimitives.IsPathWithinRoot(directory, executable))
            throw new InvalidDataException("A required trusted native executable is missing or invalid.");
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(directory);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(executable);
        return executable;
    }

    public async Task<string> GetJsonAsync(Uri uri, CancellationToken token)
    {
        if (uri.Scheme != Uri.UriSchemeHttps) throw new InvalidDataException("Metadata requires HTTPS.");
        using var response = await MetadataClient.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new IOException("Metadata request failed (status code " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ").");
        if (response.Content.Headers.ContentLength > MaxJsonBytes)
            throw new InvalidDataException("Metadata response is too large.");
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        var bytes = await ReadBounded(stream, MaxJsonBytes, token).ConfigureAwait(false);
        return Encoding.UTF8.GetString(bytes);
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string hostName, CancellationToken token)
    {
        try
        {
            return await Dns.GetHostAddressesAsync(hostName, token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException)
        {
            throw new IOException("DNS resolution failed for " + hostName + ".");
        }
    }

    public async Task<ConfigCheckNativeResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var executable = ResolveExecutablePath(fileName, programFilesRoot, system32Root);
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        IConfigCheckProcess process;
        try
        {
            process = processFactory.Start(startInfo);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new IOException(fileName + " could not be started.");
        }
        using (process)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(processTimeout);
            try
            {
                var standardOutput = process.ReadStandardOutputAsync(timeout.Token);
                var standardError = process.ReadStandardErrorAsync(timeout.Token);
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                var output = await standardOutput.ConfigureAwait(false);
                var error = await standardError.ConfigureAwait(false);
                return new ConfigCheckNativeResult(process.ExitCode, process.ExitCode == 0 ? output : error);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException) when (process.HasExited)
                {
                    // The process exited between the state check and kill request.
                }
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                if (token.IsCancellationRequested) throw new OperationCanceledException(token);
                throw new IOException(fileName + " timed out.");
            }
        }
    }

    public async Task<IReadOnlyList<ConfigCheckServiceState>> GetTunnelServicesAsync(CancellationToken token)
    {
        var query = await RunRequired("sc.exe", ["query", "state=", "all"], token).ConfigureAwait(false);
        var tunnels = ParseTunnelServiceStates(query.Output);
        var result = new List<ConfigCheckServiceState>(tunnels.Count);
        foreach (var (name, status) in tunnels)
        {
            var configuration = await RunRequired("sc.exe", ["qc", name], token).ConfigureAwait(false);
            var binaryPath = ParseBinaryPath(configuration.Output);
            result.Add(new ConfigCheckServiceState(
                name,
                ServiceIdentity(name, binaryPath),
                status == ConfigCheckServiceStatus.Running,
                status));
        }
        return result;
    }

    public async Task StopServiceAsync(ConfigCheckServiceState service, CancellationToken token)
    {
        await RequireCurrentIdentity(service, token).ConfigureAwait(false);
        await RunRequired("sc.exe", ["stop", service.Name], token).ConfigureAwait(false);
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var snapshot = await GetTunnelServicesAsync(token).ConfigureAwait(false);
            var current = snapshot.SingleOrDefault(item => item.Name == service.Name);
            if (current is null || current.Identity != service.Identity)
                throw new IOException("A tunnel service identity changed while it was stopping.");
            if (current.EffectiveStatus == ConfigCheckServiceStatus.Stopped) return;
            await DelayAsync(TimeSpan.FromMilliseconds(250), token).ConfigureAwait(false);
        }
        throw new IOException("A tunnel service did not reach the stopped state.");
    }

    public async Task StartServiceAsync(ConfigCheckServiceState service, CancellationToken token)
    {
        await RequireCurrentIdentity(service, token).ConfigureAwait(false);
        await RunRequired("sc.exe", ["start", service.Name], token).ConfigureAwait(false);
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var snapshot = await GetTunnelServicesAsync(token).ConfigureAwait(false);
            var current = snapshot.SingleOrDefault(item => item.Name == service.Name);
            if (current is null || current.Identity != service.Identity)
                throw new IOException("A tunnel service identity changed while it was starting.");
            if (current.EffectiveStatus == ConfigCheckServiceStatus.Running) return;
            if (current.EffectiveStatus != ConfigCheckServiceStatus.StartPending)
                throw new IOException("A tunnel service left the starting state before reaching running.");
            await DelayAsync(TimeSpan.FromMilliseconds(250), token).ConfigureAwait(false);
        }
        throw new IOException("A tunnel service did not reach the running state.");
    }

    public async Task DeleteTunnelServiceAsync(string tunnelName, CancellationToken token)
    {
        var serviceName = "WireGuardTunnel$" + tunnelName;
        var snapshot = await GetTunnelServicesAsync(token).ConfigureAwait(false);
        if (!snapshot.Any(service => service.Name == serviceName)) return;
        await RunRequired("wireguard.exe", ["/uninstalltunnelservice", tunnelName], token).ConfigureAwait(false);
    }

    public Task AddProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token) =>
        RunRequired("netsh.exe",
            ["interface", "ipv4", "add", "route", "prefix=" + probeAddress + "/32", "interface=" + tunnelName, "nexthop=0.0.0.0", "store=active"],
            token);

    public Task DeleteProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token) =>
        RunRequired("netsh.exe",
            ["interface", "ipv4", "delete", "route", "prefix=" + probeAddress + "/32", "interface=" + tunnelName, "store=active"],
            token);

    public async Task VerifyProbeRouteAbsentAsync(string tunnelName, IPAddress probeAddress, CancellationToken token)
    {
        var prefix = probeAddress + "/32";
        // Do not filter by interface: an already-removed owned interface is a valid absent-route state.
        var result = await RunRequired("netsh.exe",
            ["interface", "ipv4", "show", "route", "prefix=" + prefix, "store=active"],
            token).ConfigureAwait(false);
        var routeRemains = result.Output.Split('\r', '\n', StringSplitOptions.RemoveEmptyEntries).Any(line =>
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            return fields.Contains(prefix, StringComparer.OrdinalIgnoreCase) &&
                fields.Contains(tunnelName, StringComparer.OrdinalIgnoreCase);
        });
        if (routeRemains) throw new IOException("The owned temporary probe route is still present.");
    }

    internal static IReadOnlyList<string> BuildPrivateDirectoryAclArguments(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return
        [
            Path.GetFullPath(path),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F"
        ];
    }

    public async Task CreatePrivateDirectoryAsync(string path, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(fullPath);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null || (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)))
            throw new IOException("Config-check recovery requires an elevated principal.");
        await RunRequired("icacls.exe", BuildPrivateDirectoryAclArguments(fullPath), token).ConfigureAwait(false);
    }

    private async Task ProtectRecycleDirectoryAsync(string path, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var fullPath = Path.GetFullPath(path);
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.User is null || (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)))
            throw new IOException("Config-check recycling requires an elevated principal.");
        await RunRequired("icacls.exe", BuildPrivateDirectoryAclArguments(fullPath), token).ConfigureAwait(false);
        VerifyRecycleDirectoryAcl(fullPath);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void VerifyRecycleDirectoryAcl(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var security = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        var expectedInheritance = InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit;
        var trusted = new[] { new SecurityIdentifier("S-1-5-18"), new SecurityIdentifier("S-1-5-32-544") };
        var valid = security.AreAccessRulesProtected && security.AreAccessRulesCanonical && rules.Length == trusted.Length;
        foreach (var identity in trusted)
        {
            var matches = rules.Where(rule =>
                identity.Equals(rule.IdentityReference) &&
                rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights == FileSystemRights.FullControl &&
                rule.InheritanceFlags == expectedInheritance &&
                rule.PropagationFlags == PropagationFlags.None &&
                !rule.IsInherited).ToArray();
            valid &= matches.Length == 1;
        }
        if (!valid) throw new IOException("The recycle quarantine directory ACL is not restricted to SYSTEM and Administrators.");
    }

    public async Task WritePrivateFileAsync(string path, byte[] bytes, CancellationToken token)
    {
        var fullPath = Path.GetFullPath(path);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(Path.GetDirectoryName(fullPath)!);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        await using (var stream = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            await stream.WriteAsync(bytes, token).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
    }

    public async Task<byte[]> ReadPrivateFileAsync(string path, CancellationToken token)
    {
        var fullPath = Path.GetFullPath(path);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        var bytes = await File.ReadAllBytesAsync(fullPath, token).ConfigureAwait(false);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        return bytes;
    }

    public Task DeletePrivateFileAsync(string path, CancellationToken token)
    {
        var fullPath = Path.GetFullPath(path);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        File.Delete(fullPath);
        return Task.CompletedTask;
    }

    public void EnsureNoReparsePoints(string path) => WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);

    public Task DeleteStagedFileAsync(string path, CancellationToken token)
    {
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        File.Delete(path);
        return Task.CompletedTask;
    }

    public Task VerifyStagedFileAbsentAsync(string path, CancellationToken token)
    {
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        if (File.Exists(path)) throw new IOException("An owned replacement staging file remains.");
        return Task.CompletedTask;
    }

    public Task<bool> SourceFileExistsAsync(string path, CancellationToken token)
    {
        var fullPath = ValidateSourcePathAllowMissing(path);
        return Task.FromResult(File.Exists(fullPath));
    }

    public async Task<ConfigCheckSourceFile> ReadSourceFileAsync(string path, CancellationToken token)
    {
        var fullPath = ValidateSourcePath(path);
        await using var stream = new FileStream(
            fullPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
        if (stream.Length > MaxSourceBytes) throw new InvalidDataException("Configuration file is too large.");
        var bytes = await ReadBounded(stream, MaxSourceBytes, token).ConfigureAwait(false);
        var identity = GetOpenedIdentity(stream);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        return new ConfigCheckSourceFile(fullPath, bytes, identity);
    }

    public async Task<ConfigCheckFileIdentity> StageReplacementAsync(
        string sourcePath,
        string stagedPath,
        byte[] bytes,
        CancellationToken token)
    {
        var source = ValidateSourcePathAllowMissing(sourcePath);
        var stage = Path.GetFullPath(stagedPath);
        EnsureSameDirectoryAndVolume(source, stage);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(Path.GetDirectoryName(stage)!);
        await using var stream = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
        return GetOpenedIdentity(stream);
    }

    public async Task AtomicReplaceAsync(
        ConfigCheckReplacementTransaction transaction,
        Func<ConfigCheckReplacementProgress, Task> progressAsync,
        CancellationToken token)
    {
        transaction = ValidateReplacementTransaction(transaction);
        using (var stream = new FileStream(
                   transaction.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                   4096, FileOptions.SequentialScan))
        {
            EnsureExpectedIdentity(stream, transaction.SourceIdentity);
            ConfigCheckParser.EnsureMatchingPathIdentity(stream, transaction.SourcePath);
            afterSourceIdentityVerification?.Invoke(transaction.SourcePath);
        }
        await ReplaceExpectedSource(transaction, progressAsync).ConfigureAwait(false);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(transaction.SourcePath);
    }

    public Task MoveStagedFileToMissingSourceAsync(string stagedPath, string sourcePath, CancellationToken token)
    {
        var source = ValidateSourcePathAllowMissing(sourcePath);
        var stage = Path.GetFullPath(stagedPath);
        EnsureSameDirectoryAndVolume(source, stage);
        if (File.Exists(source)) throw new IOException("Configuration recovery destination appeared before replacement.");
        File.Move(stage, source);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(source);
        return Task.CompletedTask;
    }

    public Task<ConfigCheckReplacementOutcome> RecoverReplacementAsync(
        ConfigCheckReplacementTransaction transaction,
        ConfigCheckFileIdentity? displacedSourceIdentity,
        Func<ConfigCheckReplacementProgress, Task> progressAsync,
        CancellationToken token) =>
        RecoverExpectedSource(ValidateReplacementTransaction(transaction), displacedSourceIdentity, progressAsync);

    private static ConfigCheckReplacementTransaction ValidateReplacementTransaction(
        ConfigCheckReplacementTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var source = ValidateSourcePathAllowMissing(transaction.SourcePath);
        var stage = Path.GetFullPath(transaction.StagedPath);
        var backup = Path.GetFullPath(transaction.ReplacementBackupPath);
        var restoreBackup = Path.GetFullPath(transaction.RestoreBackupPath);
        EnsureSameDirectoryAndVolume(source, stage);
        EnsureSameDirectoryAndVolume(source, backup);
        EnsureSameDirectoryAndVolume(source, restoreBackup);
        if (!string.Equals(backup, stage + ".replace-backup", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(restoreBackup, stage + ".restore-backup", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Replacement transaction artifacts do not match their owned staging path.");
        return transaction with
        {
            StagedPath = stage,
            SourcePath = source,
            ReplacementBackupPath = backup,
            RestoreBackupPath = restoreBackup
        };
    }

    public async Task<string?> ReadJournalAsync(string privateRoot, string journalName, CancellationToken token)
    {
        var path = JournalPath(privateRoot, journalName);
        if (!File.Exists(path)) return null;
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        var json = await File.ReadAllTextAsync(path, Encoding.UTF8, token).ConfigureAwait(false);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        return json;
    }

    public async Task WriteJournalAsync(string privateRoot, string journalName, string json, CancellationToken token)
    {
        var path = JournalPath(privateRoot, journalName);
        var stage = path + ".tmp";
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(stage);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        if (File.Exists(stage)) throw new IOException("A stale config-check journal stage requires review.");
        await using (var stream = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(stage);
            var bytes = new UTF8Encoding(false).GetBytes(json);
            await stream.WriteAsync(bytes, token).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(stage);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        if (File.Exists(path)) File.Replace(stage, path, null, ignoreMetadataErrors: true);
        else File.Move(stage, path);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
    }

    public Task ClearAttemptJournalAsync(string privateRoot, CancellationToken token)
    {
        File.Delete(JournalPath(privateRoot, WindowsConfigCheckAdapter.AttemptJournalName));
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> FindJournalRootsAsync(string dataRoot, CancellationToken token)
    {
        var root = Path.Combine(Path.GetFullPath(dataRoot), "config-check");
        if (!Directory.Exists(root)) return Task.FromResult<IReadOnlyList<string>>([]);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(root);
        IReadOnlyList<string> result = Directory.EnumerateDirectories(root)
            .Where(directory =>
                File.Exists(Path.Combine(directory, WindowsConfigCheckAdapter.SessionJournalName)) ||
                File.Exists(Path.Combine(directory, WindowsConfigCheckAdapter.RecycleJournalName)))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return Task.FromResult(result);
    }

    public async Task VerifyTunnelInactiveAsync(string tunnelName, CancellationToken token)
    {
        var serviceName = "WireGuardTunnel$" + tunnelName;
        var snapshot = await GetTunnelServicesAsync(token).ConfigureAwait(false);
        if (snapshot.Any(service => service.Name == serviceName))
            throw new IOException("The owned temporary tunnel is still present.");
    }

    public async Task RecycleFileAsync(
        ConfigCheckRecycleTransaction transaction,
        Func<ConfigCheckRecycleProgress, Task> progressAsync,
        CancellationToken token)
    {
        transaction = ValidateRecycleTransaction(transaction);
        ArgumentNullException.ThrowIfNull(progressAsync);
        var fullPath = ValidateSourcePath(transaction.SourcePath);
        using (var stream = new FileStream(
                   fullPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan))
        {
            EnsureExpectedIdentity(stream, transaction.SourceIdentity);
            ConfigCheckParser.EnsureMatchingPathIdentity(stream, fullPath);
            afterSourceIdentityVerification?.Invoke(fullPath);
        }

        var quarantineDirectory = transaction.QuarantineDirectory;
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(quarantineDirectory);
        if (File.Exists(quarantineDirectory) || Directory.Exists(quarantineDirectory))
            throw new IOException("The configuration recycle quarantine path is already occupied.");
        var quarantine = transaction.QuarantinePath;
        using var directoryHandle = CreateQuarantineDirectoryAndOpenHandle(quarantineDirectory);
        var sourceMayBeQuarantined = false;
        try
        {
            // Restrict and verify the already-pinned directory before the source enters it.
            await protectRecycleDirectoryAsync(quarantineDirectory, token).ConfigureAwait(false);
            sourceMayBeQuarantined = true;
            File.Move(fullPath, quarantine);
            await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Quarantined)).ConfigureAwait(false);
            using (var stream = new FileStream(
                       quarantine, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                       4096, FileOptions.SequentialScan))
            {
                EnsureExpectedIdentity(stream, transaction.SourceIdentity);
                ConfigCheckParser.EnsureMatchingPathIdentity(stream, quarantine);
            }
            afterQuarantineIdentityVerification?.Invoke(quarantine);

            // Recheck at the mutation boundary and retain both file and directory handles through recycling.
            using (var stream = new FileStream(
                       quarantine, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                       4096, FileOptions.SequentialScan))
            {
                EnsureExpectedIdentity(stream, transaction.SourceIdentity);
                ConfigCheckParser.EnsureMatchingPathIdentity(stream, quarantine);
                var bytes = await ReadBounded(stream, MaxSourceBytes, token).ConfigureAwait(false);
                if (!string.Equals(CheckedConfig.FingerprintBytes(bytes), transaction.SourceFingerprint, StringComparison.Ordinal))
                    throw new IOException("The quarantined configuration content changed after testing; it was retained for recovery.");
                stream.Position = 0;
                await recycleFileAsync(quarantine, token).ConfigureAwait(false);
            }
            if (File.Exists(quarantine))
                throw new IOException("The configuration recycle operation returned without removing the verified file.");
            if (File.Exists(fullPath) || Directory.Exists(fullPath))
                throw new IOException("A newer source appeared during recycling; it was retained for manual review.");
            await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Recycled)).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            // The durable journal remains incomplete so restart recovery can authenticate any
            // ambiguous or newer artifacts. Only an authenticated immediate rollback is cleaned up.
            if (sourceMayBeQuarantined)
                await RestoreQuarantineToAbsentSource(transaction, exception, token).ConfigureAwait(false);
            directoryHandle.Dispose();
            DeleteEmptyQuarantineDirectory(quarantineDirectory);
            throw;
        }
        // The non-delete-shared directory handle must be released before empty-directory cleanup.
        directoryHandle.Dispose();
        DeleteEmptyQuarantineDirectory(quarantineDirectory);
        await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Completed)).ConfigureAwait(false);
    }

    public async Task RecoverRecycleAsync(
        ConfigCheckRecycleTransaction transaction,
        ConfigCheckRecyclePhase phase,
        Func<ConfigCheckRecycleProgress, Task> progressAsync,
        CancellationToken token)
    {
        transaction = ValidateRecycleTransaction(transaction);
        ArgumentNullException.ThrowIfNull(progressAsync);
        if (!Enum.IsDefined(phase)) throw new InvalidDataException("The recycle recovery phase is invalid.");
        if (phase != ConfigCheckRecyclePhase.Completed)
        {
            using (var directoryHandle = OpenQuarantineDirectoryHandleIfExists(transaction.QuarantineDirectory))
            {
                var source = await ReadOptionalArtifact(transaction.SourcePath, token).ConfigureAwait(false);
                var quarantine = await ReadOptionalArtifact(transaction.QuarantinePath, token).ConfigureAwait(false);
                if (phase == ConfigCheckRecyclePhase.Recycled)
                {
                    if (source is not null || quarantine is not null)
                        throw new IOException("A durably recycled transaction has unexpected source or quarantine content.");
                }
                else if (source is not null)
                {
                    if (quarantine is not null || !Matches(source, transaction.SourceIdentity, transaction.SourceFingerprint))
                        throw new IOException("A newer source or unexpected quarantine requires manual review; both were retained.");
                }
                else if (quarantine is not null)
                {
                    if (!Matches(quarantine, transaction.SourceIdentity, transaction.SourceFingerprint))
                        throw new IOException("The quarantined configuration failed identity or content verification.");
                    afterQuarantineIdentityVerification?.Invoke(transaction.QuarantinePath);
                    File.Move(transaction.QuarantinePath, transaction.SourcePath);
                    var restored = await ReadRequiredArtifact(transaction.SourcePath, token).ConfigureAwait(false);
                    if (!Matches(restored, transaction.SourceIdentity, transaction.SourceFingerprint))
                        throw new IOException("The restored quarantine configuration could not be verified.");
                }
                else
                {
                    // The sink may have removed the file before its result became durable. Do not guess:
                    // conservatively restore the authenticated protected original when the source is absent.
                    var original = await ReadPrivateFileAsync(transaction.OriginalBackupPath, token).ConfigureAwait(false);
                    if (!string.Equals(CheckedConfig.FingerprintBytes(original), transaction.SourceFingerprint, StringComparison.Ordinal))
                        throw new InvalidDataException("The original recycle backup failed fingerprint verification.");
                    await RestoreAbsentSourceFromBackup(transaction.SourcePath, original, token).ConfigureAwait(false);
                    var restored = await ReadRequiredArtifact(transaction.SourcePath, token).ConfigureAwait(false);
                    if (!string.Equals(CheckedConfig.FingerprintBytes(restored.Bytes), transaction.SourceFingerprint, StringComparison.Ordinal))
                        throw new IOException("The protected original configuration could not be restored and verified.");
                }
            }
            DeleteEmptyQuarantineDirectory(transaction.QuarantineDirectory);
        }
        await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Completed)).ConfigureAwait(false);
    }

    private static ConfigCheckRecycleTransaction ValidateRecycleTransaction(ConfigCheckRecycleTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        var source = ValidateSourcePathAllowMissing(transaction.SourcePath);
        var quarantineDirectory = Path.GetFullPath(transaction.QuarantineDirectory);
        var quarantine = Path.GetFullPath(transaction.QuarantinePath);
        var backup = Path.GetFullPath(transaction.OriginalBackupPath);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(quarantineDirectory);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(quarantine);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(backup);
        var sourceDirectory = Path.GetDirectoryName(source) ??
            throw new InvalidDataException("The recycle source directory is invalid.");
        var fileName = Path.GetFileName(source);
        var prefix = "." + fileName + ".";
        const string suffix = ".wgst-recycle";
        var directoryName = Path.GetFileName(quarantineDirectory);
        if (!string.Equals(Path.GetDirectoryName(quarantineDirectory), sourceDirectory, StringComparison.OrdinalIgnoreCase) ||
            !directoryName.StartsWith(prefix, StringComparison.Ordinal) ||
            !directoryName.EndsWith(suffix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(directoryName[prefix.Length..^suffix.Length], "N", out _) ||
            !string.Equals(quarantine, Path.Combine(quarantineDirectory, fileName), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(backup), "original.bin", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The recycle transaction paths failed ownership validation.");
        return transaction with
        {
            SourcePath = source,
            OriginalBackupPath = backup,
            QuarantineDirectory = quarantineDirectory,
            QuarantinePath = quarantine
        };
    }

    private static async Task RestoreAbsentSourceFromBackup(string sourcePath, byte[] original, CancellationToken token)
    {
        if (File.Exists(sourcePath) || Directory.Exists(sourcePath))
            throw new IOException("The recycle recovery destination appeared before original restoration.");
        await using (var stream = new FileStream(
                         sourcePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            await stream.WriteAsync(original, token).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(sourcePath);
    }

    private static SafeFileHandle CreateQuarantineDirectoryAndOpenHandle(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        const uint delete = 0x00010000;
        const uint readControl = 0x00020000;
        const uint synchronize = 0x00100000;
        const uint fileReadAttributes = 0x00000080;
        const uint fileAddSubdirectory = 0x00000004;
        const uint fileTraverse = 0x00000020;
        const uint fileShareRead = 0x00000001;
        const uint fileShareWrite = 0x00000002;
        const uint fileShareDelete = 0x00000004;
        const uint openExisting = 3;
        const uint fileCreate = 2;
        const uint fileAttributeNormal = 0x00000080;
        const uint fileFlagBackupSemantics = 0x02000000;
        const uint fileDirectoryFile = 0x00000001;
        const uint fileSynchronousIoNonAlert = 0x00000020;
        const uint fileOpenReparsePoint = 0x00200000;
        const uint objCaseInsensitive = 0x00000040;
        const uint objDontReparse = 0x00001000;

        var fullPath = Path.GetFullPath(path);
        var parentPath = Path.GetDirectoryName(fullPath) ??
            throw new IOException("The recycle quarantine parent directory is invalid.");
        var childName = Path.GetFileName(fullPath);
        if (childName.Length == 0 || childName is "." or ".." ||
            childName.IndexOfAny(['\\', '/', ':', '\0']) >= 0)
            throw new IOException("The recycle quarantine directory name is invalid.");

        using var parent = CreateFile(
            parentPath,
            fileAddSubdirectory | fileTraverse | fileReadAttributes,
            fileShareRead | fileShareWrite | fileShareDelete,
            IntPtr.Zero,
            openExisting,
            fileFlagBackupSemantics,
            IntPtr.Zero);
        if (parent.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            throw new IOException("The recycle quarantine parent directory could not be opened.",
                new System.ComponentModel.Win32Exception(error));
        }

        using var name = new NativeUnicodeString(childName);
        var parentReferenceAdded = false;
        try
        {
            parent.DangerousAddRef(ref parentReferenceAdded);
            var attributes = new NativeObjectAttributes
            {
                Length = Marshal.SizeOf<NativeObjectAttributes>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = name.Structure,
                Attributes = objCaseInsensitive | objDontReparse
            };
            var ioStatus = new NativeIoStatusBlock();
            var status = NtCreateFile(
                out var rawHandle,
                delete | readControl | synchronize | fileReadAttributes,
                ref attributes,
                ref ioStatus,
                IntPtr.Zero,
                fileAttributeNormal,
                fileShareRead | fileShareWrite, // Deliberately exclude FILE_SHARE_DELETE.
                fileCreate,
                fileDirectoryFile | fileSynchronousIoNonAlert | fileOpenReparsePoint,
                IntPtr.Zero,
                0);
            if (status < 0)
                throw new IOException($"The recycle quarantine directory could not be created and locked (NTSTATUS 0x{unchecked((uint)status):X8}).");
            var handle = new SafeFileHandle(rawHandle, ownsHandle: true);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException("The recycle quarantine directory creation returned an invalid handle.");
            }
            return handle;
        }
        finally
        {
            if (parentReferenceAdded) parent.DangerousRelease();
        }
    }

    private sealed class NativeUnicodeString : IDisposable
    {
        private readonly IntPtr buffer;

        public NativeUnicodeString(string value)
        {
            var byteLength = checked(value.Length * sizeof(char));
            if (byteLength > ushort.MaxValue - sizeof(char))
                throw new ArgumentException("The recycle quarantine directory name is too long.", nameof(value));
            buffer = Marshal.StringToHGlobalUni(value);
            var unicode = new NativeUnicodeStringStructure
            {
                Length = (ushort)byteLength,
                MaximumLength = (ushort)(byteLength + sizeof(char)),
                Buffer = buffer
            };
            Structure = Marshal.AllocHGlobal(Marshal.SizeOf<NativeUnicodeStringStructure>());
            Marshal.StructureToPtr(unicode, Structure, fDeleteOld: false);
        }

        public IntPtr Structure { get; }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Structure);
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUnicodeStringStructure
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeIoStatusBlock
    {
        public IntPtr Status;
        public UIntPtr Information;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(
        out IntPtr fileHandle,
        uint desiredAccess,
        ref NativeObjectAttributes objectAttributes,
        ref NativeIoStatusBlock ioStatusBlock,
        IntPtr allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    private static SafeFileHandle OpenQuarantineDirectoryHandle(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        const uint delete = 0x00010000;
        const uint fileShareRead = 0x00000001;
        const uint fileShareWrite = 0x00000002;
        const uint openExisting = 3;
        const uint fileFlagBackupSemantics = 0x02000000;
        var handle = CreateFile(
            path,
            delete,
            fileShareRead | fileShareWrite, // Deliberately exclude FILE_SHARE_DELETE (0x4).
            IntPtr.Zero,
            openExisting,
            fileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("The recycle quarantine directory could not be locked.",
                new System.ComponentModel.Win32Exception(error));
        }
        return handle;
    }

    private static SafeFileHandle? OpenQuarantineDirectoryHandleIfExists(string path) =>
        Directory.Exists(path) ? OpenQuarantineDirectoryHandle(path) : null;

    private static void DeleteEmptyQuarantineDirectory(string path)
    {
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        if (!Directory.Exists(path))
        {
            if (File.Exists(path)) throw new IOException("The recycle quarantine directory path is occupied by a file.");
            return;
        }
        Directory.Delete(path, recursive: false);
    }

    private async Task RestoreQuarantineToAbsentSource(
        ConfigCheckRecycleTransaction transaction,
        Exception originalException,
        CancellationToken token)
    {
        var quarantine = transaction.QuarantinePath;
        var source = transaction.SourcePath;
        try
        {
            beforeRecycleRollback?.Invoke(transaction.QuarantineDirectory);
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(quarantine);
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(source);
            if (File.Exists(source) || Directory.Exists(source))
                throw new IOException("The source path reappeared while the quarantined file was being restored.");

            await using (var stream = new FileStream(
                             quarantine, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                             4096, FileOptions.SequentialScan | FileOptions.Asynchronous))
            {
                EnsureExpectedIdentity(stream, transaction.SourceIdentity);
                ConfigCheckParser.EnsureMatchingPathIdentity(stream, quarantine);
                var bytes = await ReadBounded(stream, MaxSourceBytes, token).ConfigureAwait(false);
                if (!string.Equals(CheckedConfig.FingerprintBytes(bytes), transaction.SourceFingerprint, StringComparison.Ordinal))
                    throw new IOException("The quarantined configuration failed fingerprint verification before rollback.");

                // Keep the authenticated file handle and the quarantine directory lock through the rename.
                File.Move(quarantine, source);
                ConfigCheckParser.EnsureMatchingPathIdentity(stream, source);
                await using (var restored = new FileStream(
                                 source, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                                 4096, FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    EnsureExpectedIdentity(restored, transaction.SourceIdentity);
                    ConfigCheckParser.EnsureMatchingPathIdentity(restored, source);
                    var restoredBytes = await ReadBounded(restored, MaxSourceBytes, token).ConfigureAwait(false);
                    if (!string.Equals(CheckedConfig.FingerprintBytes(restoredBytes), transaction.SourceFingerprint, StringComparison.Ordinal))
                        throw new IOException("The restored configuration failed fingerprint verification.");
                }
            }
        }
        catch (Exception restoreException)
        {
            throw new IOException(
                "Configuration recycle failed and its quarantined file was retained for recovery.",
                new AggregateException(originalException, restoreException));
        }
    }

    private static Task RecycleFile(string path, CancellationToken token)
    {
        Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(
            path,
            UIOption.OnlyErrorDialogs,
            RecycleOption.SendToRecycleBin);
        return Task.CompletedTask;
    }

    public Task DelayAsync(TimeSpan delay, CancellationToken token) => delayAsync(delay, token);

    private static ConfigCheckFileIdentity GetOpenedIdentity(FileStream stream)
    {
        var identity = ConfigCheckParser.GetOpenedIdentity(stream);
        return new ConfigCheckFileIdentity(identity.VolumeSerialNumber, identity.FileIndex);
    }

    private static void EnsureExpectedIdentity(FileStream stream, ConfigCheckFileIdentity expected)
    {
        if (GetOpenedIdentity(stream) != expected)
            throw new IOException("Configuration file identity changed; the newer file was retained.");
    }

    private static async Task ReplaceExpectedSource(
        ConfigCheckReplacementTransaction transaction,
        Func<ConfigCheckReplacementProgress, Task> progressAsync)
    {
        EnsureBackupPathAbsent(transaction.ReplacementBackupPath);
        EnsureBackupPathAbsent(transaction.RestoreBackupPath);
        var staged = await ReadRequiredArtifact(transaction.StagedPath, CancellationToken.None).ConfigureAwait(false);
        if (!Matches(staged, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
            throw new IOException("The journaled replacement staging identity or content changed.");
        File.Replace(transaction.StagedPath, transaction.SourcePath, transaction.ReplacementBackupPath, ignoreMetadataErrors: true);
        var replacedIdentity = ReadIdentity(transaction.ReplacementBackupPath);
        await progressAsync(new ConfigCheckReplacementProgress(
            ConfigCheckReplacementPhase.Replaced, replacedIdentity)).ConfigureAwait(false);
        if (replacedIdentity != transaction.SourceIdentity)
        {
            // The path was swapped after verification. Journal the rollback before restoring the
            // displaced newer file, and never delete the replacement by an unchecked path.
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RollbackRequired, replacedIdentity)).ConfigureAwait(false);
            File.Replace(
                transaction.ReplacementBackupPath,
                transaction.SourcePath,
                transaction.RestoreBackupPath,
                ignoreMetadataErrors: true);
            var restoredAway = await ReadRequiredArtifact(
                transaction.RestoreBackupPath, CancellationToken.None).ConfigureAwait(false);
            if (!Matches(restoredAway, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("Configuration replacement raced again; the unexpected file was retained in its restore backup.");
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RollbackReplaced, replacedIdentity)).ConfigureAwait(false);
            DeleteVerifiedFile(transaction.RestoreBackupPath, transaction.ReplacementIdentity);
            EnsurePathIdentity(transaction.SourcePath, replacedIdentity);
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RolledBack, replacedIdentity)).ConfigureAwait(false);
            throw new IOException("Configuration file identity changed during replacement; the newer file was restored.");
        }
        var original = await ReadRequiredArtifact(transaction.ReplacementBackupPath, CancellationToken.None).ConfigureAwait(false);
        if (!Matches(original, transaction.SourceIdentity, transaction.SourceFingerprint))
            throw new IOException("The displaced original backup failed identity or content verification.");
        DeleteVerifiedFile(transaction.ReplacementBackupPath, transaction.SourceIdentity);
        await progressAsync(new ConfigCheckReplacementProgress(
            ConfigCheckReplacementPhase.Cleaned, replacedIdentity)).ConfigureAwait(false);
    }

    private static async Task<ConfigCheckReplacementOutcome> RecoverExpectedSource(
        ConfigCheckReplacementTransaction transaction,
        ConfigCheckFileIdentity? displacedSourceIdentity,
        Func<ConfigCheckReplacementProgress, Task> progressAsync)
    {
        var source = await ReadOptionalArtifact(transaction.SourcePath, CancellationToken.None).ConfigureAwait(false);
        var stage = await ReadOptionalArtifact(transaction.StagedPath, CancellationToken.None).ConfigureAwait(false);
        var backup = await ReadOptionalArtifact(transaction.ReplacementBackupPath, CancellationToken.None).ConfigureAwait(false);
        var restore = await ReadOptionalArtifact(transaction.RestoreBackupPath, CancellationToken.None).ConfigureAwait(false);

        if (restore is not null)
        {
            if (source is null || backup is not null || stage is not null ||
                !Matches(restore, transaction.ReplacementIdentity, transaction.ReplacementFingerprint) ||
                displacedSourceIdentity is not null && source.Identity != displacedSourceIdentity.Value ||
                Matches(source, transaction.SourceIdentity, transaction.SourceFingerprint) ||
                Matches(source, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The journaled replacement rollback state is inconsistent; all artifacts were retained.");
            DeleteVerifiedFile(transaction.RestoreBackupPath, transaction.ReplacementIdentity);
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RolledBack, source.Identity)).ConfigureAwait(false);
            return ConfigCheckReplacementOutcome.NewerSourceRetained;
        }

        if (backup is not null)
        {
            if (source is null || stage is not null ||
                !Matches(source, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The journaled replacement backup state is inconsistent; all artifacts were retained.");
            if (Matches(backup, transaction.SourceIdentity, transaction.SourceFingerprint))
            {
                DeleteVerifiedFile(transaction.ReplacementBackupPath, transaction.SourceIdentity);
                await progressAsync(new ConfigCheckReplacementProgress(
                    ConfigCheckReplacementPhase.Cleaned, backup.Identity)).ConfigureAwait(false);
                return ConfigCheckReplacementOutcome.ReplacementApplied;
            }
            if (Matches(backup, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The displaced backup unexpectedly contains the replacement; manual review is required.");

            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RollbackRequired, backup.Identity)).ConfigureAwait(false);
            File.Replace(
                transaction.ReplacementBackupPath,
                transaction.SourcePath,
                transaction.RestoreBackupPath,
                ignoreMetadataErrors: true);
            var restoredAway = await ReadRequiredArtifact(
                transaction.RestoreBackupPath, CancellationToken.None).ConfigureAwait(false);
            if (!Matches(restoredAway, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The recovered replacement backup failed verification and was retained.");
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RollbackReplaced, backup.Identity)).ConfigureAwait(false);
            DeleteVerifiedFile(transaction.RestoreBackupPath, transaction.ReplacementIdentity);
            EnsurePathIdentity(transaction.SourcePath, backup.Identity);
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.RolledBack, backup.Identity)).ConfigureAwait(false);
            return ConfigCheckReplacementOutcome.NewerSourceRetained;
        }

        if (source is not null && Matches(source, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
        {
            if (stage is not null)
                throw new IOException("An unexpected staging file remains beside the applied replacement.");
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.Cleaned, displacedSourceIdentity)).ConfigureAwait(false);
            return ConfigCheckReplacementOutcome.ReplacementApplied;
        }
        if (source is not null && Matches(source, transaction.SourceIdentity, transaction.SourceFingerprint))
        {
            if (stage is not null && !Matches(stage, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The original source is intact but its staging file changed; manual review is required.");
            return ConfigCheckReplacementOutcome.OriginalRetained;
        }
        if (source is null)
        {
            if (stage is not null && !Matches(stage, transaction.ReplacementIdentity, transaction.ReplacementFingerprint))
                throw new IOException("The source is missing and its staging file changed; manual review is required.");
            return ConfigCheckReplacementOutcome.SourceMissing;
        }
        if (stage is not null)
            throw new IOException("A newer source and an unexpected staging artifact require manual review.");
        return ConfigCheckReplacementOutcome.NewerSourceRetained;
    }

    private static bool Matches(
        ConfigCheckArtifact artifact,
        ConfigCheckFileIdentity expectedIdentity,
        string expectedFingerprint) =>
        artifact.Identity == expectedIdentity &&
        string.Equals(CheckedConfig.FingerprintBytes(artifact.Bytes), expectedFingerprint, StringComparison.Ordinal);

    private static async Task<ConfigCheckArtifact> ReadRequiredArtifact(string path, CancellationToken token) =>
        await ReadOptionalArtifact(path, token).ConfigureAwait(false) ??
        throw new IOException("A journaled replacement artifact is missing: " + Path.GetFileName(path));

    private static async Task<ConfigCheckArtifact?> ReadOptionalArtifact(string path, CancellationToken token)
    {
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        try
        {
            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
            if (stream.Length > MaxSourceBytes) throw new InvalidDataException("A replacement artifact is too large.");
            var bytes = await ReadBounded(stream, MaxSourceBytes, token).ConfigureAwait(false);
            var identity = GetOpenedIdentity(stream);
            ConfigCheckParser.EnsureMatchingPathIdentity(stream, path);
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
            return new ConfigCheckArtifact(bytes, identity);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private sealed record ConfigCheckArtifact(byte[] Bytes, ConfigCheckFileIdentity Identity);

    private static void EnsureBackupPathAbsent(string path)
    {
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        if (File.Exists(path) || Directory.Exists(path))
            throw new IOException("An owned source-volume replacement backup path is already occupied.");
    }

    private static ConfigCheckFileIdentity ReadIdentity(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
        return GetOpenedIdentity(stream);
    }

    private static void EnsurePathIdentity(string path, ConfigCheckFileIdentity expected)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
        EnsureExpectedIdentity(stream, expected);
    }

    private async Task RequireCurrentIdentity(ConfigCheckServiceState service, CancellationToken token)
    {
        var snapshot = await GetTunnelServicesAsync(token).ConfigureAwait(false);
        var current = snapshot.SingleOrDefault(item => item.Name == service.Name);
        if (current is null || current.Identity != service.Identity)
            throw new IOException("A tunnel service identity changed; manual review is required.");
        if (current.IsTransitional)
            throw new IOException("A tunnel service is in a transitional state; manual review is required.");
    }

    private async Task<ConfigCheckNativeResult> RunRequired(string fileName, IReadOnlyList<string> arguments, CancellationToken token)
    {
        var result = await RunAsync(fileName, arguments, token).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            var error = string.Equals(fileName, "netsh.exe", StringComparison.OrdinalIgnoreCase)
                ? WindowsConfigCheckPrimitives.CreateSafeNetshError(result.ExitCode, result.Output)
                : WindowsConfigCheckPrimitives.CreateSafeNativeError(fileName, result.ExitCode, result.Output);
            throw new IOException(error);
        }
        return result;
    }

    internal static List<(string Name, ConfigCheckServiceStatus Status)> ParseTunnelServiceStates(string output)
    {
        var result = new List<(string Name, ConfigCheckServiceStatus Status)>();
        string? name = null;
        foreach (var line in output.Split('\r', '\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
            {
                name = trimmed["SERVICE_NAME:".Length..].Trim();
            }
            else if (name is not null && trimmed.StartsWith("STATE", StringComparison.OrdinalIgnoreCase))
            {
                if (name.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase))
                {
                    var status = trimmed switch
                    {
                        _ when trimmed.Contains("START_PENDING", StringComparison.OrdinalIgnoreCase) => ConfigCheckServiceStatus.StartPending,
                        _ when trimmed.Contains("STOP_PENDING", StringComparison.OrdinalIgnoreCase) => ConfigCheckServiceStatus.StopPending,
                        _ when trimmed.Contains("RUNNING", StringComparison.OrdinalIgnoreCase) => ConfigCheckServiceStatus.Running,
                        _ when trimmed.Contains("STOPPED", StringComparison.OrdinalIgnoreCase) => ConfigCheckServiceStatus.Stopped,
                        _ => throw new InvalidDataException("A tunnel service has an unsupported state.")
                    };
                    result.Add((name, status));
                }
                name = null;
            }
        }
        return result;
    }

    private static string ParseBinaryPath(string output)
    {
        foreach (var line in output.Split('\r', '\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("BINARY_PATH_NAME", StringComparison.OrdinalIgnoreCase))
            {
                var separator = trimmed.IndexOf(':');
                if (separator >= 0) return trimmed[(separator + 1)..].Trim();
            }
        }
        throw new IOException("A tunnel service binary identity could not be read.");
    }

    private static string ServiceIdentity(string name, string binaryPath) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name + "\0" + binaryPath))).ToLowerInvariant();

    private static string ValidateSourcePath(string path)
    {
        var fullPath = ValidateSourcePathAllowMissing(path);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("Configuration file does not exist.", fullPath);
        return fullPath;
    }

    private static string ValidateSourcePathAllowMissing(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetExtension(fullPath), ".conf", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Only plaintext .conf files are supported.");
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
        return fullPath;
    }

    private static void EnsureSameDirectoryAndVolume(string sourcePath, string stagedPath)
    {
        if (!string.Equals(Path.GetPathRoot(sourcePath), Path.GetPathRoot(stagedPath), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetDirectoryName(sourcePath), Path.GetDirectoryName(stagedPath), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Replacement staging must be on the source volume and in the source directory.");
    }

    private static string JournalPath(string privateRoot, string journalName)
    {
        if (journalName is not (WindowsConfigCheckAdapter.SessionJournalName or
            WindowsConfigCheckAdapter.AttemptJournalName or WindowsConfigCheckAdapter.RecycleJournalName))
            throw new ArgumentException("Unknown config-check journal.", nameof(journalName));
        var root = Path.GetFullPath(privateRoot);
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(root);
        return Path.Combine(root, journalName);
    }

    private static void DeleteVerifiedFile(string path, ConfigCheckFileIdentity expected)
    {
        const uint genericRead = 0x80000000;
        const uint delete = 0x00010000;
        const uint fileShareRead = 0x00000001;
        const uint fileShareDelete = 0x00000004;
        const uint openExisting = 3;
        const uint fileAttributeNormal = 0x00000080;
        var handle = CreateFile(
            path,
            genericRead | delete,
            fileShareRead | fileShareDelete,
            IntPtr.Zero,
            openExisting,
            fileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new IOException("A verified replacement backup could not be opened for deletion.",
                new System.ComponentModel.Win32Exception(error));
        }
        using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        EnsureExpectedIdentity(stream, expected);
        var disposition = new NativeFileDispositionInfo { DeleteFile = true };
        if (!SetFileInformationByHandle(
                stream.SafeFileHandle,
                4,
                ref disposition,
                Marshal.SizeOf<NativeFileDispositionInfo>()))
            throw new IOException("A verified replacement backup could not be marked for deletion.",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileDispositionInfo
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool DeleteFile;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle fileHandle,
        int fileInformationClass,
        ref NativeFileDispositionInfo fileInformation,
        int bufferSize);

    private static async Task<byte[]> ReadBounded(Stream stream, int maximumBytes, CancellationToken token)
    {
        var buffer = new byte[maximumBytes + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), token).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        if (total > maximumBytes) throw new InvalidDataException("Input exceeded the allowed size.");
        return buffer[..total];
    }
}

internal interface IConfigCheckProcessFactory
{
    IConfigCheckProcess Start(ProcessStartInfo startInfo);
}

internal interface IConfigCheckProcess : IDisposable
{
    bool HasExited { get; }
    int ExitCode { get; }
    void Kill(bool entireProcessTree);
    Task WaitForExitAsync(CancellationToken token);
    Task<string> ReadStandardOutputAsync(CancellationToken token);
    Task<string> ReadStandardErrorAsync(CancellationToken token);
}

internal sealed class SystemConfigCheckProcessFactory : IConfigCheckProcessFactory
{
    public IConfigCheckProcess Start(ProcessStartInfo startInfo)
    {
        var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) throw new InvalidOperationException("The native process could not be started.");
            return new SystemConfigCheckProcess(process);
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    private sealed class SystemConfigCheckProcess(Process process) : IConfigCheckProcess
    {
        public bool HasExited => process.HasExited;
        public int ExitCode => process.ExitCode;
        public void Kill(bool entireProcessTree) => process.Kill(entireProcessTree);
        public Task WaitForExitAsync(CancellationToken token) => process.WaitForExitAsync(token);
        public Task<string> ReadStandardOutputAsync(CancellationToken token) => process.StandardOutput.ReadToEndAsync(token);
        public Task<string> ReadStandardErrorAsync(CancellationToken token) => process.StandardError.ReadToEndAsync(token);
        public void Dispose() => process.Dispose();
    }
}
