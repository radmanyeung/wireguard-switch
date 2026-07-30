using System.Security.Cryptography;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.GitHub;
using WireguardSplitTunnel.WindowsUpdate.Logging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Staging;

internal interface IWindowsUpdateDelay
{
    Task DelayAsync(
        TimeSpan delay,
        CancellationToken cancellationToken);
}

internal interface IWindowsUpdatePackageValidator
{
    Task<UpdatePackageValidationResult> ValidateAsync(
        SemanticVersion candidateVersion,
        LocalUpdateLayout layout,
        CancellationToken cancellationToken);
}

internal interface IWindowsUpdateLocalStore
{
    LocalUpdateMetadata Load();

    LocalUpdateMetadataStoreResult Save(
        LocalUpdateMetadata metadata);

    LocalUpdatePathResult EnsureStaging(
        SemanticVersion version);

    LocalUpdatePathResult TryResolve(
        LocalStagedUpdate stagedUpdate);

    LocalUpdatePathResult CleanupCandidate(
        SemanticVersion version);

    LocalUpdatePathResult CleanupVersion(
        SemanticVersion version);
}

internal interface IWindowsUpdateProtectedPreparer
{
    bool IsElevated { get; }

    Task<ProtectedTransactionPreparationResult> PrepareAsync(
        SelectedWindowsRelease trustedRelease,
        ValidatedUpdatePackage package,
        LocalStagedUpdate stagedUpdate,
        PendingUpdateSource trustedSource,
        WindowsUpdateProtectedState? expectedActive,
        CancellationToken cancellationToken);
}

internal sealed record WindowsUpdateProtectedState(
    bool Success,
    bool Exists,
    ProtectedTransactionId? TransactionId,
    SemanticVersion? Version,
    PendingUpdateSource? Source,
    ProtectedUpdatePhase? Phase,
    string? DetailCode)
{
    internal static WindowsUpdateProtectedState None() =>
        new(
            Success: true,
            Exists: false,
            TransactionId: null,
            Version: null,
            Source: null,
            Phase: null,
            DetailCode: null);

    internal static WindowsUpdateProtectedState Found(
        ProtectedTransactionId transactionId,
        SemanticVersion version,
        PendingUpdateSource source,
        ProtectedUpdatePhase phase)
    {
        if (!transactionId.IsValid)
        {
            throw new ArgumentOutOfRangeException(
                nameof(transactionId));
        }

        return new(
            Success: true,
            Exists: true,
            transactionId,
            version,
            source,
            phase,
            DetailCode: null);
    }

    internal static WindowsUpdateProtectedState Failed(
        string? detailCode = null) =>
        new(
            Success: false,
            Exists: false,
            TransactionId: null,
            Version: null,
            Source: null,
            Phase: null,
            detailCode);
}

internal enum WindowsUpdateProtectedCleanupOutcome
{
    NothingToDo,
    Removed,
    PendingElevation,
    LaterPhasePreserved,
    Failed
}

internal sealed record WindowsUpdateProtectedCleanupResult(
    WindowsUpdateProtectedCleanupOutcome Outcome,
    string? DetailCode)
{
    internal static WindowsUpdateProtectedCleanupResult
        NothingToDo() =>
        new(
            WindowsUpdateProtectedCleanupOutcome
                .NothingToDo,
            DetailCode: null);

    internal static WindowsUpdateProtectedCleanupResult
        Removed() =>
        new(
            WindowsUpdateProtectedCleanupOutcome.Removed,
            DetailCode: null);

    internal static WindowsUpdateProtectedCleanupResult
        PendingElevation() =>
        new(
            WindowsUpdateProtectedCleanupOutcome
                .PendingElevation,
            DetailCode: null);

    internal static WindowsUpdateProtectedCleanupResult
        LaterPhasePreserved() =>
        new(
            WindowsUpdateProtectedCleanupOutcome
                .LaterPhasePreserved,
            DetailCode: null);

    internal static WindowsUpdateProtectedCleanupResult Failed(
        string? detailCode = null) =>
        new(
            WindowsUpdateProtectedCleanupOutcome.Failed,
            detailCode);
}

internal interface IWindowsUpdateAuthorizationCommitLease
    : IDisposable
{
}

internal interface IWindowsUpdateAuthorizationHelper
{
    Task<WindowsUpdateProtectedState> InspectAsync(
        CancellationToken cancellationToken);

    Task<WindowsUpdateProtectedCleanupResult>
        CleanupAutomaticProtectedStagedAsync(
            bool isElevated,
            CancellationToken cancellationToken);

    Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            Func<PendingUpdateSource, bool>
                isAuthorizationAllowed,
            Func<PendingUpdateSource,
                IWindowsUpdateAuthorizationCommitLease?>
                tryAcquireAuthorizationCommitLease,
            CancellationToken cancellationToken);
}

internal sealed class TimeProviderWindowsUpdateDelay
    : IWindowsUpdateDelay
{
    private readonly TimeProvider _timeProvider;

    internal TimeProviderWindowsUpdateDelay(
        TimeProvider timeProvider)
    {
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public Task DelayAsync(
        TimeSpan delay,
        CancellationToken cancellationToken) =>
        Task.Delay(
            delay,
            _timeProvider,
            cancellationToken);
}

public sealed class WindowsUpdateCoordinator
    : IUpdateCloseParticipant
{
    private readonly object _stateGate = new();
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly SemaphoreSlim
        _automaticAuthorizationCommitGate = new(1, 1);
    private readonly SemanticVersion _currentVersion;
    private readonly bool _developerLayout;
    private readonly bool _postInstallSelfTest;
    private readonly IGitHubReleaseClient _releaseClient;
    private readonly IReleaseAssetDownloader _downloader;
    private readonly IWindowsUpdatePackageValidator _validator;
    private readonly IWindowsUpdateLocalStore _localStore;
    private readonly IWindowsUpdateProtectedPreparer _preparer;
    private readonly IWindowsUpdateAuthorizationHelper
        _authorization;
    private readonly TimeProvider _timeProvider;
    private readonly IWindowsUpdateDelay _delay;
    private readonly IUpdaterEventLogger _logger;
    private readonly StableReleaseSelector _selector = new();
    private readonly CancellationTokenSource _lifetime = new();

    private CancellationTokenSource? _automaticCancellation;
    private Task? _automaticLoop;
    private bool _automaticEnabled;
    private bool _started;
    private bool _closing;
    private long _automaticAuthorizationGeneration;

    internal WindowsUpdateCoordinator(
        SemanticVersion currentVersion,
        bool developerLayout,
        bool postInstallSelfTest,
        IGitHubReleaseClient releaseClient,
        IReleaseAssetDownloader downloader,
        IWindowsUpdatePackageValidator validator,
        IWindowsUpdateLocalStore localStore,
        IWindowsUpdateProtectedPreparer preparer,
        IWindowsUpdateAuthorizationHelper authorization,
        TimeProvider timeProvider,
        IWindowsUpdateDelay delay,
        IUpdaterEventLogger logger)
    {
        _currentVersion = currentVersion;
        _developerLayout = developerLayout;
        _postInstallSelfTest = postInstallSelfTest;
        _releaseClient = releaseClient
            ?? throw new ArgumentNullException(
                nameof(releaseClient));
        _downloader = downloader
            ?? throw new ArgumentNullException(nameof(downloader));
        _validator = validator
            ?? throw new ArgumentNullException(nameof(validator));
        _localStore = localStore
            ?? throw new ArgumentNullException(nameof(localStore));
        _preparer = preparer
            ?? throw new ArgumentNullException(nameof(preparer));
        _authorization = authorization
            ?? throw new ArgumentNullException(
                nameof(authorization));
        _timeProvider = timeProvider
            ?? throw new ArgumentNullException(nameof(timeProvider));
        _delay = delay
            ?? throw new ArgumentNullException(nameof(delay));
        _logger = logger
            ?? throw new ArgumentNullException(nameof(logger));
    }

    public event EventHandler<WindowsUpdateStatus>?
        StatusChanged;

    public async Task StartAsync(
        bool automaticEnabled,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_postInstallSelfTest)
        {
            Publish(WindowsUpdateStatusKind.Idle);
            return;
        }

        var processPendingRemoval = false;
        var reconcileDisabledAutomatic = !automaticEnabled;
        long automaticGeneration;
        lock (_stateGate)
        {
            if (_closing)
            {
                return;
            }

            _started = true;
            _automaticEnabled = automaticEnabled;
            processPendingRemoval =
                !reconcileDisabledAutomatic
                && _preparer.IsElevated
                && _localStore.Load()
                    .ProtectedRemovalPending;
            automaticGeneration =
                _automaticAuthorizationGeneration;
        }

        if (reconcileDisabledAutomatic
            || processPendingRemoval)
        {
            await CleanupDisabledAutomaticAsync(
                    cancellationToken)
                .ConfigureAwait(false);
        }

        var resumeStatusPublished =
            await ResumeLocalStagedAsync(
                    automaticGeneration,
                    cancellationToken)
                .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        lock (_stateGate)
        {
            if (_closing)
            {
                return;
            }

            if (_automaticEnabled)
            {
                StartAutomaticLoopLocked();
            }
            else if (!resumeStatusPublished
                     && !reconcileDisabledAutomatic)
            {
                Publish(WindowsUpdateStatusKind.Disabled);
            }
        }
    }

    public Task CheckNowAsync(
        CancellationToken cancellationToken)
    {
        if (_postInstallSelfTest || IsClosing())
        {
            return Task.CompletedTask;
        }

        return RunCheckIsolatedAsync(
            PendingUpdateSource.Manual,
            automaticGeneration: 0,
            cancellationToken);
    }

    public async Task SetAutomaticEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_postInstallSelfTest)
        {
            return;
        }

        if (enabled)
        {
            lock (_stateGate)
            {
                _automaticEnabled = true;
                if (_started && !_closing)
                {
                    StartAutomaticLoopLocked();
                }
            }

            return;
        }

        Task? loop = null;
        CancellationTokenSource? cancellation = null;
        await _automaticAuthorizationCommitGate
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            lock (_stateGate)
            {
                _automaticEnabled = false;
                _automaticAuthorizationGeneration++;
                cancellation = _automaticCancellation;
                loop = _automaticLoop;
                cancellation?.Cancel();
            }
        }
        finally
        {
            _automaticAuthorizationCommitGate.Release();
        }

        PersistCleanupPending();

        if (loop is not null)
        {
            await AwaitCancelledLoopAsync(
                    loop,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await CleanupDisabledAutomaticAsync(
                cancellationToken)
            .ConfigureAwait(false);

        lock (_stateGate)
        {
            if (ReferenceEquals(
                    cancellation,
                    _automaticCancellation))
            {
                _automaticCancellation?.Dispose();
                _automaticCancellation = null;
                _automaticLoop = null;
            }

            if (_automaticEnabled
                && _started
                && !_closing)
            {
                StartAutomaticLoopLocked();
            }
        }
    }

    public async Task StopForCloseAsync(
        CancellationToken cancellationToken)
    {
        Task? loop;
        lock (_stateGate)
        {
            if (!_closing)
            {
                _closing = true;
                Publish(WindowsUpdateStatusKind.Closing);
                _lifetime.Cancel();
                _automaticCancellation?.Cancel();
            }

            loop = _automaticLoop;
        }

        if (loop is not null)
        {
            await AwaitCancelledLoopAsync(
                    loop,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await _operationGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        _operationGate.Release();
    }

    public async Task<UpdateCloseAuthorizationResult>
        TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken)
    {
        if (_postInstallSelfTest
            || !UpdateCloseEligibility.IsEligible(context))
        {
            return UpdateCloseAuthorizationResult
                .NoProtectedTransaction();
        }

        await _operationGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var generation = ReadAutomaticGeneration();
            return await _authorization
                .TryAuthorizeAndLaunchAsync(
                    context,
                    source =>
                        source == PendingUpdateSource.Manual
                        || IsAutomaticAuthorizationAllowed(
                            generation),
                    source =>
                        TryAcquireAuthorizationCommitLease(
                            source,
                            generation),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            Log("authorization_failed", "unexpected");
            return UpdateCloseAuthorizationResult
                .RecoverableFailure(
                    "authorization_failed");
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private void StartAutomaticLoopLocked()
    {
        if (_closing
            || !_automaticEnabled
            || _automaticLoop is { IsCompleted: false })
        {
            return;
        }

        _automaticCancellation?.Dispose();
        _automaticCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                _lifetime.Token);
        var cancellation = _automaticCancellation;
        _automaticLoop = Task.Run(
            () => RunAutomaticLoopAsync(
                cancellation,
                cancellation.Token));
    }

    private async Task RunAutomaticLoopAsync(
        CancellationTokenSource owner,
        CancellationToken cancellationToken)
    {
        try
        {
            var metadata = _localStore.Load();
            var now = _timeProvider.GetUtcNow();
            if (!UpdateSchedulePolicy.IsDue(
                    metadata.LastAutomaticAttemptUtc,
                    now))
            {
                var elapsed =
                    metadata.LastAutomaticAttemptUtc.HasValue
                        ? now
                            - metadata
                                .LastAutomaticAttemptUtc.Value
                        : UpdateSchedulePolicy
                            .AutomaticInterval;
                await _delay.DelayAsync(
                        UpdateSchedulePolicy
                            .GetRemainingDelay(elapsed),
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            while (!cancellationToken
                       .IsCancellationRequested
                   && IsAutomaticEnabled(owner))
            {
                var generation = ReadAutomaticGeneration();
                await RunCheckIsolatedAsync(
                        PendingUpdateSource.Automatic,
                        generation,
                        cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (!IsAutomaticEnabled(owner))
                {
                    break;
                }

                await _delay.DelayAsync(
                        UpdateSchedulePolicy
                            .AutomaticInterval,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            Log("automatic_loop_failed", "unexpected");
        }
    }

    private async Task<bool> ResumeLocalStagedAsync(
        long automaticGeneration,
        CancellationToken cancellationToken)
    {
        if (_developerLayout)
        {
            return false;
        }

        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
        var token = linked.Token;
        var acquired = false;
        try
        {
            await _operationGate.WaitAsync(token)
                .ConfigureAwait(false);
            acquired = true;

            var metadata = _localStore.Load();
            if (metadata.StagedUpdate is not { } staged)
            {
                return false;
            }

            if (!Enum.IsDefined(staged.Source)
                || staged.Version.CompareTo(_currentVersion) <= 0
                || !CanContinue(
                    staged.Source,
                    automaticGeneration))
            {
                return false;
            }

            if (!_preparer.IsElevated)
            {
                FailCheck(
                    "online_authentication_required",
                    WindowsUpdateStatusKind.CheckFailed);
                Log(
                    "local_staged_online_authentication_required",
                    version: staged.Version.ToString());
                return true;
            }

            var protectedState = await _authorization
                .InspectAsync(token)
                .ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!protectedState.Success)
            {
                FailCheck(
                    protectedState.DetailCode,
                    WindowsUpdateStatusKind.CheckFailed);
                return true;
            }

            if (protectedState is
                {
                    Exists: true,
                    TransactionId: not { IsValid: true }
                })
            {
                FailCheck(
                    "protected_identity",
                    WindowsUpdateStatusKind.CheckFailed);
                return true;
            }

            if (ShouldPreserveProtected(
                    protectedState,
                    staged.Version,
                    protectedState.Source
                        ?? staged.Source))
            {
                PublishProtectedPreservedStatus(
                    protectedState);
                return true;
            }

            var resolved = _localStore.TryResolve(staged);
            if (!resolved.Success
                || resolved.Layout is not { } layout)
            {
                FailCheck(
                    "local_staged_layout",
                    WindowsUpdateStatusKind.VerificationFailed);
                return true;
            }

            var candidateCleanup =
                _localStore.CleanupCandidate(staged.Version);
            if (!candidateCleanup.Success)
            {
                FailCheck(
                    "local_candidate_cleanup",
                    WindowsUpdateStatusKind.VerificationFailed);
                return true;
            }

            if (!CanContinue(
                    staged.Source,
                    automaticGeneration))
            {
                return false;
            }

            Publish(
                WindowsUpdateStatusKind.Checking,
                staged.Version,
                "local_resume");
            var validation = await _validator
                .ValidateAsync(
                    staged.Version,
                    layout,
                    token)
                .ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!validation.Success
                || validation.Package is not { } package
                || !MatchesStagedHashes(staged, package))
            {
                FailCheck(
                    validation.DetailCode
                    ?? validation.ErrorCode.ToString()
                        .ToLowerInvariant(),
                    WindowsUpdateStatusKind.VerificationFailed);
                return true;
            }

            if (!CanContinue(
                    staged.Source,
                    automaticGeneration))
            {
                return false;
            }

            FailCheck(
                "online_authentication_required",
                WindowsUpdateStatusKind.CheckFailed);
            Log(
                "local_staged_online_authentication_required",
                version: staged.Version.ToString());
            return true;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
            when (token.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception)
        {
            FailCheck(
                "local_resume",
                WindowsUpdateStatusKind.VerificationFailed);
            return true;
        }
        finally
        {
            if (acquired)
            {
                _operationGate.Release();
            }
        }
    }

    private async Task RunCheckIsolatedAsync(
        PendingUpdateSource source,
        long automaticGeneration,
        CancellationToken cancellationToken)
    {
        using var linked =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken,
                _lifetime.Token);
        var token = linked.Token;
        var acquired = false;
        try
        {
            await _operationGate.WaitAsync(token)
                .ConfigureAwait(false);
            acquired = true;

            if (!CanContinue(
                    source,
                    automaticGeneration))
            {
                return;
            }

            var metadata = _localStore.Load();
            if (source == PendingUpdateSource.Automatic)
            {
                metadata = UpdateSchedulePolicy.BeginAttempt(
                    metadata,
                    source,
                    _timeProvider.GetUtcNow());
                var saved = _localStore.Save(metadata);
                if (!saved.Success)
                {
                    FailCheck(
                        "attempt_persistence",
                        WindowsUpdateStatusKind.CheckFailed);
                    return;
                }
            }

            token.ThrowIfCancellationRequested();
            if (!CanContinue(
                    source,
                    automaticGeneration))
            {
                return;
            }

            Publish(WindowsUpdateStatusKind.Checking);
            Log(
                "check_started",
                source == PendingUpdateSource.Automatic
                    ? "automatic"
                    : "manual");
            var query = await _releaseClient
                .GetLatestAsync(token)
                .ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (query.Status != GitHubReleaseQueryStatus.Success
                || query.Release is null)
            {
                FailCheck(
                    query.DetailCode,
                    WindowsUpdateStatusKind.CheckFailed);
                return;
            }

            var selected = _selector.Select(
                _currentVersion,
                query.Release);
            if (selected.Release is not { } release)
            {
                var rejection =
                    selected.Rejection?.ToString()
                        .ToLowerInvariant();
                if (selected.Rejection
                    == ReleaseSelectionRejectionReason.NotNewer)
                {
                    Publish(
                        WindowsUpdateStatusKind.Current,
                        _currentVersion);
                    Log(
                        "check_current",
                        version: _currentVersion.ToString());
                }
                else
                {
                    FailCheck(
                        rejection,
                        WindowsUpdateStatusKind.CheckFailed);
                }

                return;
            }

            if (_developerLayout)
            {
                Publish(
                    WindowsUpdateStatusKind
                        .AutomaticInstallationUnavailable,
                    release.Version,
                    "developer_layout");
                Log(
                    "installation_unavailable",
                    "developer_layout",
                    release.Version.ToString());
                return;
            }

            if (!CanContinue(
                    source,
                    automaticGeneration))
            {
                return;
            }

            var protectedState = await _authorization
                .InspectAsync(token)
                .ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!protectedState.Success)
            {
                FailCheck(
                    protectedState.DetailCode,
                    WindowsUpdateStatusKind.CheckFailed);
                return;
            }

            if (protectedState is
                {
                    Exists: true,
                    TransactionId: not { IsValid: true }
                })
            {
                FailCheck(
                    "protected_identity",
                    WindowsUpdateStatusKind.CheckFailed);
                return;
            }

            if (ShouldPreserveProtected(
                    protectedState,
                    release.Version,
                    source))
            {
                PublishProtectedPreservedStatus(
                    protectedState);
                return;
            }

            var priorStage = metadata.StagedUpdate;
            LocalUpdateLayout? layout = null;
            ValidatedUpdatePackage? package = null;
            if (priorStage is { } exactStage
                && exactStage.Version == release.Version)
            {
                var resolved = _localStore.TryResolve(exactStage);
                if (resolved.Success
                    && resolved.Layout is { } resolvedLayout)
                {
                    var candidateCleanup =
                        _localStore.CleanupCandidate(
                            release.Version);
                    if (!candidateCleanup.Success)
                    {
                        FailCheck(
                            "local_candidate_cleanup",
                            WindowsUpdateStatusKind
                                .VerificationFailed);
                        return;
                    }

                    var stagedValidation = await _validator
                        .ValidateAsync(
                            release.Version,
                            resolvedLayout,
                            token)
                        .ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    if (stagedValidation.Success
                        && stagedValidation.Package
                            is { } stagedPackage
                        && MatchesStagedHashes(
                            exactStage,
                            stagedPackage))
                    {
                        layout = resolvedLayout;
                        package = stagedPackage;
                        Log(
                            "local_staged_reused",
                            version: release.Version.ToString());
                    }
                }

                if (layout is null || package is null)
                {
                    if (!CanContinue(
                            source,
                            automaticGeneration))
                    {
                        return;
                    }

                    var invalidatedMetadata = metadata with
                    {
                        StagedUpdate = null
                    };
                    var invalidated = _localStore.Save(
                        invalidatedMetadata);
                    if (!invalidated.Success)
                    {
                        FailCheck(
                            "staged_invalidation",
                            WindowsUpdateStatusKind.CheckFailed);
                        return;
                    }

                    metadata = invalidatedMetadata;
                }
            }

            if (layout is null || package is null)
            {
                var staleStageCleanup =
                    _localStore.CleanupVersion(
                        release.Version);
                if (!staleStageCleanup.Success)
                {
                    FailCheck(
                        "local_staging_cleanup",
                        WindowsUpdateStatusKind.CheckFailed);
                    return;
                }

                var layoutResult = _localStore.EnsureStaging(
                    release.Version);
                if (!layoutResult.Success
                    || layoutResult.Layout
                        is not { } stagingLayout)
                {
                    FailCheck(
                        "local_staging",
                        WindowsUpdateStatusKind.CheckFailed);
                    return;
                }

                Publish(
                    WindowsUpdateStatusKind.Downloading,
                    release.Version);
                var archive = await _downloader
                    .DownloadArchiveAsync(
                        release,
                        stagingLayout,
                        token)
                    .ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (archive.Status
                    != ReleaseAssetDownloadStatus.Success)
                {
                    FailCheck(
                        archive.DetailCode,
                        WindowsUpdateStatusKind.CheckFailed);
                    return;
                }

                if (!CanContinue(
                        source,
                        automaticGeneration))
                {
                    return;
                }

                var checksum = await _downloader
                    .DownloadChecksumAsync(
                        release,
                        stagingLayout,
                        token)
                    .ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (checksum.Status
                    != ReleaseAssetDownloadStatus.Success)
                {
                    FailCheck(
                        checksum.DetailCode,
                        WindowsUpdateStatusKind.CheckFailed);
                    return;
                }

                if (!CanContinue(
                        source,
                        automaticGeneration))
                {
                    return;
                }

                var downloadedValidation = await _validator
                    .ValidateAsync(
                        release.Version,
                        stagingLayout,
                        token)
                    .ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (!downloadedValidation.Success
                    || downloadedValidation.Package
                        is not { } downloadedPackage)
                {
                    FailCheck(
                        downloadedValidation.DetailCode
                        ?? downloadedValidation.ErrorCode
                            .ToString()
                            .ToLowerInvariant(),
                        WindowsUpdateStatusKind
                            .VerificationFailed);
                    return;
                }

                layout = stagingLayout;
                package = downloadedPackage;
            }

            if (layout is null || package is null)
            {
                FailCheck(
                    "local_staging",
                    WindowsUpdateStatusKind.CheckFailed);
                return;
            }

            if (!MatchesReleaseDigest(
                    release,
                    package))
            {
                FailCheck(
                    "release_digest",
                    WindowsUpdateStatusKind.VerificationFailed);
                return;
            }

            if (!CanContinue(
                    source,
                    automaticGeneration))
            {
                return;
            }

            var staged = new LocalStagedUpdate(
                release.Version,
                layout.ArchivePath,
                layout.ChecksumPath,
                layout.ManifestPath,
                layout.CandidateRoot,
                package.ArchiveSha256,
                package.NewManifestSha256,
                source);
            var stagedMetadata = metadata with
            {
                StagedUpdate = staged,
                LastError = null
            };
            var stagedSave = _localStore.Save(
                stagedMetadata);
            if (!stagedSave.Success)
            {
                FailCheck(
                    "staged_persistence",
                    WindowsUpdateStatusKind.CheckFailed);
                return;
            }

            metadata = stagedMetadata;
            if (priorStage is not null
                && priorStage.Version != release.Version)
            {
                var cleaned =
                    _localStore.CleanupVersion(
                        priorStage.Version);
                if (!cleaned.Success)
                {
                    Log("old_staging_cleanup_failed");
                }
            }

            if (!CanContinue(
                    source,
                    automaticGeneration))
            {
                return;
            }

            if (!_preparer.IsElevated)
            {
                Publish(
                    WindowsUpdateStatusKind
                        .ReadyNeedsElevation,
                    release.Version);
                Log(
                    "update_ready_elevation",
                    version: release.Version.ToString());
                return;
            }

            WindowsUpdateProtectedState? expectedActive = null;
            if (protectedState is
                {
                    Exists: true,
                    Version: { } protectedVersion,
                    Source: { } protectedSource,
                    Phase:
                        ProtectedUpdatePhase.ProtectedStaged
                }
                && ShouldSupersedeProtected(
                    protectedVersion,
                    protectedSource,
                    release.Version,
                    source))
            {
                expectedActive = protectedState;
            }

            var prepared = await _preparer
                .PrepareAsync(
                    release,
                    package,
                    staged,
                    source,
                    expectedActive,
                    token)
                .ConfigureAwait(false);
            if (!prepared.Success)
            {
                token.ThrowIfCancellationRequested();
                if (expectedActive is not null)
                {
                    var surviving = await _authorization
                        .InspectAsync(token)
                        .ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    if (surviving.Success
                        && surviving.Exists)
                    {
                        if (surviving.TransactionId
                            != expectedActive.TransactionId)
                        {
                            FailCheck(
                                "protected_conflict",
                                WindowsUpdateStatusKind.CheckFailed);
                            return;
                        }

                        PublishProtectedPreservedStatus(
                            surviving);
                        return;
                    }
                }

                var detail = prepared.DetailCode
                    ?? prepared.Error.ToString()
                        .ToLowerInvariant();
                FailCheck(
                    detail,
                    prepared.Error
                        == ProtectedTransactionPreparationError
                            .NotElevated
                        ? WindowsUpdateStatusKind
                            .ReadyNeedsElevation
                        : WindowsUpdateStatusKind
                            .VerificationFailed);
                return;
            }

            if (source == PendingUpdateSource.Automatic
                && !IsAutomaticAuthorizationAllowed(
                    automaticGeneration))
            {
                PersistCleanupPending();
                var automaticEnabled =
                    ReadAutomaticEnabled();
                Publish(
                    WindowsUpdateStatusKind.CleanupPending,
                    release.Version,
                    automaticEnabled
                        ? "automatic_generation_changed"
                        : "automatic_authorization_disabled");
                Log(
                    "cleanup_pending",
                    automaticEnabled
                        ? "automatic_generation_changed"
                        : "automatic_authorization_disabled",
                    release.Version.ToString());
                return;
            }

            Publish(
                WindowsUpdateStatusKind.ReadyForClose,
                release.Version);
            Log(
                "update_ready",
                version: release.Version.ToString());
        }
        catch (OperationCanceledException)
            when (token.IsCancellationRequested)
        {
            Log("check_cancelled");
        }
        catch (Exception)
        {
            FailCheck(
                "unexpected",
                WindowsUpdateStatusKind.CheckFailed);
        }
        finally
        {
            if (acquired)
            {
                _operationGate.Release();
            }
        }
    }

    private async Task CleanupDisabledAutomaticAsync(
        CancellationToken cancellationToken)
    {
        await _operationGate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var metadata = _localStore.Load();
            var staged = metadata.StagedUpdate;
            var localCleanupFailed = false;
            if (staged?.Source
                == PendingUpdateSource.Automatic)
            {
                var cleanup =
                    _localStore.CleanupVersion(
                        staged.Version);
                if (cleanup.Success)
                {
                    metadata = metadata with
                    {
                        StagedUpdate = null
                    };
                }
                else
                {
                    localCleanupFailed = true;
                }
            }

            var protectedCleanup = await _authorization
                .CleanupAutomaticProtectedStagedAsync(
                    _preparer.IsElevated,
                    cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var protectedPending =
                protectedCleanup.Outcome is
                    WindowsUpdateProtectedCleanupOutcome
                        .PendingElevation
                    or WindowsUpdateProtectedCleanupOutcome
                        .Failed;
            metadata = metadata with
            {
                ProtectedRemovalPending =
                    protectedPending,
                LastError =
                    localCleanupFailed || protectedPending
                        ? "cleanup_pending"
                        : metadata.LastError
                            == "cleanup_pending"
                                ? null
                                : metadata.LastError
            };
            var saved = _localStore.Save(metadata);
            if (!saved.Success
                || localCleanupFailed
                || protectedPending)
            {
                Publish(
                    WindowsUpdateStatusKind.CleanupPending,
                    detailCode:
                        protectedCleanup.DetailCode
                        ?? "cleanup_pending");
                Log(
                    "cleanup_pending",
                    protectedCleanup.DetailCode);
                return;
            }

            var automaticEnabled = ReadAutomaticEnabled();
            Publish(
                automaticEnabled
                    ? WindowsUpdateStatusKind.Idle
                    : WindowsUpdateStatusKind.Disabled);
            Log(
                automaticEnabled
                    ? "automatic_enabled"
                    : "automatic_disabled");
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            Publish(
                WindowsUpdateStatusKind.CleanupPending,
                detailCode: "cleanup_failed");
            Log("cleanup_pending", "unexpected");
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private void PersistCleanupPending()
    {
        try
        {
            var metadata = _localStore.Load();
            if (metadata.ProtectedRemovalPending)
            {
                return;
            }

            var pending = metadata with
            {
                ProtectedRemovalPending = true,
                LastError = "cleanup_pending"
            };
            var saved = _localStore.Save(pending);
            if (!saved.Success)
            {
                Publish(
                    WindowsUpdateStatusKind.CleanupPending,
                    detailCode: "cleanup_persistence");
                Log(
                    "cleanup_pending",
                    "cleanup_persistence");
            }
        }
        catch (Exception)
        {
            Publish(
                WindowsUpdateStatusKind.CleanupPending,
                detailCode: "cleanup_persistence");
            Log(
                "cleanup_pending",
                "cleanup_persistence");
        }
    }

    private static bool MatchesStagedHashes(
        LocalStagedUpdate staged,
        ValidatedUpdatePackage package)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(staged.ArchiveSha256),
                    Convert.FromHexString(package.ArchiveSha256))
                && CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(
                        staged.NewManifestSha256),
                    Convert.FromHexString(
                        package.NewManifestSha256));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool MatchesReleaseDigest(
        SelectedWindowsRelease release,
        ValidatedUpdatePackage package)
    {
        try
        {
            return release.ArchiveSize == package.ArchiveBytes
                && CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(release.ArchiveSha256),
                    Convert.FromHexString(package.ArchiveSha256));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private void PublishProtectedPreservedStatus(
        WindowsUpdateProtectedState state)
    {
        if (!state.Success
            || !state.Exists
            || state.TransactionId is not { IsValid: true }
            || state.Version is null
            || state.Source is null
            || state.Phase is null)
        {
            FailCheck(
                "protected_identity",
                WindowsUpdateStatusKind.CheckFailed);
            return;
        }

        if (state.Phase
            != ProtectedUpdatePhase.ProtectedStaged)
        {
            FailCheck(
                "protected_in_progress",
                WindowsUpdateStatusKind.CheckFailed);
            return;
        }

        if (state.Source == PendingUpdateSource.Automatic
            && !ReadAutomaticEnabled())
        {
            Publish(
                WindowsUpdateStatusKind.CleanupPending,
                state.Version,
                "automatic_authorization_disabled");
            Log(
                "cleanup_pending",
                "automatic_authorization_disabled",
                state.Version.ToString());
            return;
        }

        if (!_preparer.IsElevated)
        {
            Publish(
                WindowsUpdateStatusKind.ReadyNeedsElevation,
                state.Version);
            Log(
                "update_ready_elevation",
                version: state.Version.ToString());
            return;
        }

        Publish(
            WindowsUpdateStatusKind.ReadyForClose,
            state.Version);
        Log(
            "protected_preserved",
            version: state.Version.ToString());
    }

    private static bool ShouldPreserveProtected(
        WindowsUpdateProtectedState state,
        SemanticVersion candidateVersion,
        PendingUpdateSource requestedSource)
    {
        if (!state.Exists
            || state.Phase is null)
        {
            return false;
        }

        if (state.Phase
            != ProtectedUpdatePhase.ProtectedStaged)
        {
            return true;
        }

        if (state.Version is not { } protectedVersion)
        {
            return false;
        }

        var versionComparison = protectedVersion.CompareTo(
            candidateVersion);
        return versionComparison > 0
            || versionComparison == 0
            && (state.Source == PendingUpdateSource.Manual
                || state.Source == requestedSource);
    }

    private static bool ShouldSupersedeProtected(
        SemanticVersion protectedVersion,
        PendingUpdateSource protectedSource,
        SemanticVersion candidateVersion,
        PendingUpdateSource candidateSource)
    {
        var versionComparison = candidateVersion.CompareTo(
            protectedVersion);
        return versionComparison > 0
            || versionComparison == 0
            && protectedSource == PendingUpdateSource.Automatic
            && candidateSource == PendingUpdateSource.Manual;
    }

    private bool CanContinue(
        PendingUpdateSource source,
        long automaticGeneration)
    {
        lock (_stateGate)
        {
            if (_closing)
            {
                return false;
            }

            return source == PendingUpdateSource.Manual
                || _automaticEnabled
                && _automaticAuthorizationGeneration
                    == automaticGeneration;
        }
    }

    private bool IsAutomaticEnabled(
        CancellationTokenSource owner)
    {
        lock (_stateGate)
        {
            return !_closing
                && _automaticEnabled
                && ReferenceEquals(
                    owner,
                    _automaticCancellation);
        }
    }

    private bool IsClosing()
    {
        lock (_stateGate)
        {
            return _closing;
        }
    }

    private bool ReadAutomaticEnabled()
    {
        lock (_stateGate)
        {
            return _automaticEnabled;
        }
    }
    private long ReadAutomaticGeneration()
    {
        lock (_stateGate)
        {
            return _automaticAuthorizationGeneration;
        }
    }

    private bool IsAutomaticAuthorizationAllowed(
        long expectedGeneration)
    {
        lock (_stateGate)
        {
            return _automaticEnabled
                && _automaticAuthorizationGeneration
                    == expectedGeneration;
        }
    }

    private IWindowsUpdateAuthorizationCommitLease?
        TryAcquireAuthorizationCommitLease(
            PendingUpdateSource source,
            long expectedGeneration)
    {
        if (source == PendingUpdateSource.Manual)
        {
            return AuthorizationCommitLease.Noop;
        }

        if (source != PendingUpdateSource.Automatic)
        {
            return null;
        }

        _automaticAuthorizationCommitGate.Wait();
        var transferred = false;
        try
        {
            if (!IsAutomaticAuthorizationAllowed(
                    expectedGeneration))
            {
                return null;
            }

            var lease = new AuthorizationCommitLease(
                _automaticAuthorizationCommitGate);
            transferred = true;
            return lease;
        }
        finally
        {
            if (!transferred)
            {
                _automaticAuthorizationCommitGate.Release();
            }
        }
    }

    private sealed class AuthorizationCommitLease(
        SemaphoreSlim? gate)
        : IWindowsUpdateAuthorizationCommitLease
    {
        internal static IWindowsUpdateAuthorizationCommitLease
            Noop { get; } =
            new AuthorizationCommitLease(gate: null);

        private SemaphoreSlim? _gate = gate;

        public void Dispose() =>
            Interlocked.Exchange(ref _gate, null)?.Release();
    }

    private static async Task AwaitCancelledLoopAsync(
        Task loop,
        CancellationToken cancellationToken)
    {
        try
        {
            await loop.WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
            when (!cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void FailCheck(
        string? detailCode,
        WindowsUpdateStatusKind kind)
    {
        var safeDetail =
            WindowsUpdateStatus.SanitizeCode(detailCode)
            ?? "unknown";
        Publish(kind, detailCode: safeDetail);
        Log("check_failed", safeDetail);
    }

    private void Publish(
        WindowsUpdateStatusKind kind,
        SemanticVersion? version = null,
        string? detailCode = null)
    {
        var status = WindowsUpdateStatus.Create(
            kind,
            version,
            detailCode);
        var handlers = StatusChanged;
        if (handlers is null)
        {
            return;
        }

        foreach (EventHandler<WindowsUpdateStatus> handler
                 in handlers.GetInvocationList())
        {
            try
            {
                handler(this, status);
            }
            catch (Exception)
            {
            }
        }
    }

    private void Log(
        string eventCode,
        string? detailCode = null,
        string? version = null)
    {
        var safeEvent =
            WindowsUpdateStatus.SanitizeCode(eventCode)
            ?? "invalid";
        var safeDetail =
            WindowsUpdateStatus.SanitizeCode(detailCode);
        var safeVersion = version is null
            ? null
            : IsSafeVersion(version)
                ? version
                : "invalid";
        try
        {
            _logger.TryAppend(
                safeEvent,
                safeDetail,
                safeVersion);
        }
        catch (Exception)
        {
        }
    }

    private static bool IsSafeVersion(string value) =>
        value.Length is >= 5 and <= 64
        && value[0] is >= '0' and <= '9'
        && value[^1] is >= '0' and <= '9'
        && value.All(character =>
            character is
                >= '0' and <= '9'
                or '.'
                or '-'
                or '+'
                or >= 'a' and <= 'z');
}
