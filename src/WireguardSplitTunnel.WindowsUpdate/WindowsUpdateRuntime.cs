using System.Diagnostics;
using System.Reflection;
using System.Security.Principal;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.GitHub;
using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Logging;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate;

public sealed record WindowsUpdateProductionOptions(
    bool IsPostInstallSelfTest);

/// <summary>
/// Narrow production facade for the WPF host. Repository endpoints, staging
/// roots, protected roots, validators, and helper launch details remain fixed
/// inside this assembly.
/// </summary>
public sealed class WindowsUpdateRuntime
    : IUpdateCloseParticipant, IDisposable
{
    private readonly WindowsUpdateCoordinator _coordinator;
    private readonly ProtectedUpdateMutex _protectedMutex;
    private readonly UpdateHealthService _health;
    private readonly GitHubReleaseClient _releaseClient;
    private readonly ReleaseAssetDownloader _downloader;
    private bool _disposed;

    private WindowsUpdateRuntime(
        WindowsUpdateCoordinator coordinator,
        ProtectedUpdateMutex protectedMutex,
        UpdateHealthService health,
        GitHubReleaseClient releaseClient,
        ReleaseAssetDownloader downloader)
    {
        _coordinator = coordinator;
        _protectedMutex = protectedMutex;
        _health = health;
        _releaseClient = releaseClient;
        _downloader = downloader;
        _coordinator.StatusChanged += ForwardStatus;
    }

    public event EventHandler<WindowsUpdateStatus>? StatusChanged;

    public static WindowsUpdateRuntime CreateProduction(
        WindowsUpdateProductionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var runningExecutablePath = RunningExecutablePath();
        var installed = new InstalledReleaseLocator()
            .Locate(runningExecutablePath);
        var developerLayout =
            installed.Status
                != InstalledReleaseLocatorStatus.Available
            || installed.Version is null;
        var currentVersion = installed.Version
            ?? StrictEntryAssemblyVersion();
        var currentManagedBytes =
            installed.CurrentManagedBytes;

        var localPaths = new LocalUpdatePaths();
        var localMetadata = new LocalUpdateMetadataStore(
            localPaths);
        var protectedPaths = new ProtectedTransactionPaths();
        var protectedStore = new ProtectedTransactionStore(
            protectedPaths);
        var protectedMutex = new ProtectedUpdateMutex();
        var releaseClient =
            GitHubReleaseClient.CreateProduction();
        var downloader =
            ReleaseAssetDownloader.CreateProduction();
        var validator = new ProductionPackageValidator(
            localPaths,
            currentVersion,
            currentManagedBytes);
        var preparer = new ProductionProtectedPreparer(
            protectedMutex,
            new ProtectedTransactionPreparer());
        var authorization =
            new WindowsUpdateAuthorizationHelper(
                new WindowsUpdateAuthorizationMutex(
                    protectedMutex),
                protectedStore,
                protectedPaths,
                new WindowsUpdateHelperLauncher(),
                new WindowsUpdateProtectedTransactionCleaner(
                    protectedPaths));
        var coordinator = new WindowsUpdateCoordinator(
            currentVersion,
            developerLayout,
            options.IsPostInstallSelfTest,
            releaseClient,
            downloader,
            validator,
            new ProductionLocalStore(
                localPaths,
                localMetadata),
            preparer,
            authorization,
            TimeProvider.System,
            new TimeProviderWindowsUpdateDelay(
                TimeProvider.System),
            new UpdaterFileLogger());
        return new WindowsUpdateRuntime(
            coordinator,
            protectedMutex,
            new UpdateHealthService(
                protectedPaths,
                protectedStore),
            releaseClient,
            downloader);
    }

    public Task StartAsync(
        bool automaticEnabled,
        CancellationToken cancellationToken) =>
        _coordinator.StartAsync(
            automaticEnabled,
            cancellationToken);

    public Task CheckNowAsync(
        CancellationToken cancellationToken) =>
        _coordinator.CheckNowAsync(cancellationToken);

    public Task SetAutomaticEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken) =>
        _coordinator.SetAutomaticEnabledAsync(
            enabled,
            cancellationToken);

    public Task StopForCloseAsync(
        CancellationToken cancellationToken) =>
        _coordinator.StopForCloseAsync(cancellationToken);

    public Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken) =>
        _coordinator.TryAuthorizeAndLaunchAsync(
            context,
            cancellationToken);

    public async Task<UpdateStartupHealthResult>
        MarkMatchingTransactionHealthyAsync(
            UpdateStartupHealthContext context,
            CancellationToken cancellationToken)
    {
        if (!context.IsValid)
        {
            return UpdateStartupHealthResult
                .RecoverableFailure();
        }

        UpdateHealthResult? health = null;
        var result = await _protectedMutex.RunExclusiveAsync(
                (authority, _) =>
                {
                    health = _health.ReportHealthy(
                        authority,
                        new ProtectedTransactionId(
                            context.TransactionId),
                        context.Version);
                    return Task.CompletedTask;
                },
                TimeSpan.FromSeconds(5),
                cancellationToken)
            .ConfigureAwait(false);
        if (!result.ActionInvoked
            || result.Status is not (
                ProtectedUpdateMutexStatus.Acquired
                    or ProtectedUpdateMutexStatus
                        .AbandonedAcquired)
            || health is null)
        {
            return UpdateStartupHealthResult
                .RecoverableFailure();
        }

        if (health.Success)
        {
            return UpdateStartupHealthResult.MarkedHealthy();
        }

        return MapHealthResult(health);
    }

    internal static UpdateStartupHealthResult MapHealthResult(
        UpdateHealthResult health) =>
        health.Error is
            UpdateHealthError.NoActiveTransaction
                or UpdateHealthError.TransactionMismatch
                or UpdateHealthError.WrongPhase
                or UpdateHealthError.VersionMismatch
            ? UpdateStartupHealthResult.NoMatchingTransaction()
            : UpdateStartupHealthResult.RecoverableFailure();

    internal static ProtectedTransactionPreparationResult
        MapProtectedPreparationResult(
            ProtectedUpdateMutexResult mutexResult,
            ProtectedTransactionPreparationResult? prepared) =>
        mutexResult.ActionInvoked && prepared is not null
            ? prepared
            : ProtectedTransactionPreparationResult.Failed(
                ProtectedTransactionPreparationError
                    .ProtectedStorageFailed,
                "protected_mutex");

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _coordinator.StatusChanged -= ForwardStatus;
        _releaseClient.Dispose();
        _downloader.Dispose();
    }

    private void ForwardStatus(
        object? sender,
        WindowsUpdateStatus status) =>
        StatusChanged?.Invoke(this, status);

    private static string? RunningExecutablePath()
    {
        if (!string.IsNullOrWhiteSpace(Environment.ProcessPath))
        {
            return Environment.ProcessPath;
        }

        try
        {
            using var process = Process.GetCurrentProcess();
            return process.MainModule?.FileName;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException
                or System.ComponentModel.Win32Exception
                or NotSupportedException)
        {
            return null;
        }
    }

    private static SemanticVersion StrictEntryAssemblyVersion()
    {
        var value = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<
                AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (!SemanticVersion.TryParseNormalized(
                value,
                out var version))
        {
            throw new InvalidOperationException(
                "The entry assembly has no strict update version.");
        }

        return version;
    }

    private sealed class ProductionLocalStore(
        LocalUpdatePaths paths,
        LocalUpdateMetadataStore metadata)
        : IWindowsUpdateLocalStore
    {
        public LocalUpdateMetadata Load() => metadata.Load();

        public LocalUpdateMetadataStoreResult Save(
            LocalUpdateMetadata value) =>
            metadata.Save(value);

        public LocalUpdatePathResult EnsureStaging(
            SemanticVersion version) =>
            paths.EnsureStaging(version);

        public LocalUpdatePathResult TryResolve(
            LocalStagedUpdate stagedUpdate) =>
            paths.TryResolve(stagedUpdate);

        public LocalUpdatePathResult CleanupCandidate(
            SemanticVersion version) =>
            paths.CleanupCandidate(version);

        public LocalUpdatePathResult CleanupVersion(
            SemanticVersion version) =>
            paths.CleanupVersion(version);
    }

    internal sealed class ProductionPackageValidator(
        LocalUpdatePaths paths,
        SemanticVersion currentVersion,
        long currentManagedBytes)
        : IWindowsUpdatePackageValidator
    {
        private readonly UpdatePackageValidator _inner = new(
            new WindowsExecutableProductVersionReader(),
            new WindowsDiskSpaceProvider(),
            new WindowsPathSafetyInspector());

        public async Task<UpdatePackageValidationResult>
            ValidateAsync(
                SemanticVersion candidateVersion,
                LocalUpdateLayout layout,
                CancellationToken cancellationToken)
        {
            var validatedLayout = paths.TryValidateLayout(layout);
            if (!validatedLayout.Success
                || validatedLayout.Layout is not { } canonicalLayout)
            {
                return UpdatePackageValidationResult.Failure(
                    validatedLayout.Error
                        == LocalUpdatePathError.IoFailure
                        ? UpdatePackageValidationError.IoFailure
                        : UpdatePackageValidationError.InvalidRequest);
            }

            byte[] sidecar;
            try
            {
                var info = new FileInfo(
                    canonicalLayout.ChecksumPath);
                if (!info.Exists
                    || info.Length <= 0
                    || info.Length
                        > UpdateNetworkLimits.ChecksumBytes)
                {
                    return UpdatePackageValidationResult
                        .Failure(
                            UpdatePackageValidationError
                                .InvalidChecksumSidecar);
                }

                sidecar = await File.ReadAllBytesAsync(
                        canonicalLayout.ChecksumPath,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or ArgumentException
                    or NotSupportedException)
            {
                return UpdatePackageValidationResult.Failure(
                    UpdatePackageValidationError.IoFailure);
            }

            return await _inner.ValidateAsync(
                    new UpdatePackageValidationRequest(
                        canonicalLayout.ArchivePath,
                        sidecar,
                        candidateVersion,
                        currentVersion,
                        SupportedStateSchemaVersion: 1,
                        currentManagedBytes,
                        canonicalLayout.CandidateRoot,
                        canonicalLayout.VersionRoot,
                        UpdatePackageLimits.Default),
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private sealed class ProductionProtectedPreparer(
        ProtectedUpdateMutex mutex,
        ProtectedTransactionPreparer inner)
        : IWindowsUpdateProtectedPreparer
    {
        public bool IsElevated
        {
            get
            {
                try
                {
                    using var identity =
                        WindowsIdentity.GetCurrent();
                    return new WindowsPrincipal(identity)
                        .IsInRole(
                            WindowsBuiltInRole.Administrator);
                }
                catch (Exception exception) when (
                    exception is UnauthorizedAccessException
                        or System.Security
                            .SecurityException
                        or InvalidOperationException)
                {
                    return false;
                }
            }
        }

        public async Task<ProtectedTransactionPreparationResult>
            PrepareAsync(
                SelectedWindowsRelease trustedRelease,
                ValidatedUpdatePackage package,
                LocalStagedUpdate stagedUpdate,
                PendingUpdateSource trustedSource,
                WindowsUpdateProtectedState? expectedActive,
                CancellationToken cancellationToken)
        {
            var binding = TrustedReleaseBinding.TryCreate(
                trustedRelease,
                package,
                trustedSource);
            if (binding is null)
            {
                return ProtectedTransactionPreparationResult
                    .Failed(
                        ProtectedTransactionPreparationError
                            .InvalidRequest);
            }

            var trustedStagedUpdate = stagedUpdate with
            {
                Source = trustedSource
            };
            ProtectedActiveTransactionExpectation?
                activeExpectation = null;
            if (expectedActive is not null)
            {
                if (expectedActive is not
                    {
                        Success: true,
                        Exists: true,
                        TransactionId: { IsValid: true } transactionId,
                        Version: { } version,
                        Source: { } source,
                        Phase: ProtectedUpdatePhase.ProtectedStaged
                    })
                {
                    return ProtectedTransactionPreparationResult
                        .Failed(
                            ProtectedTransactionPreparationError
                                .InvalidRequest,
                            "expected_active");
                }

                activeExpectation =
                    new ProtectedActiveTransactionExpectation(
                        transactionId,
                        version,
                        source);
            }

            ProtectedTransactionPreparationResult? prepared =
                null;
            var mutexResult = await mutex.RunExclusiveAsync(
                    async (authority, token) =>
                    {
                        prepared = await inner.PrepareAsync(
                                authority,
                                new ProtectedTransactionPreparationRequest(
                                    trustedStagedUpdate,
                                    binding,
                                    SupportedStateSchemaVersion: 1,
                                    UpdatePackageLimits.Default)
                                {
                                    ExpectedActive =
                                        activeExpectation
                                },
                                token)
                            .ConfigureAwait(false);
                    },
                    TimeSpan.FromSeconds(5),
                    cancellationToken)
                .ConfigureAwait(false);
            return MapProtectedPreparationResult(
                mutexResult,
                prepared);
        }
    }
}
