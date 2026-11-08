namespace WireguardSplitTunnel.Core.Updates;

public interface IUpdateCloseParticipant
{
    Task StopForCloseAsync(CancellationToken cancellationToken);

    Task<UpdateCloseAuthorizationResult> TryAuthorizeAndLaunchAsync(
        UpdateCloseAuthorizationContext context,
        CancellationToken cancellationToken);
}

public interface IApplicationCloseActions
{
    Task RunRoutingExclusiveAsync(
        Func<CancellationToken, Task> restoreAsync,
        CancellationToken cancellationToken);

    void SavePrimaryState();
}

public sealed record ApplicationCloseRequest(
    bool IsElevated,
    bool IsPostInstallSelfTest,
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ImagePath);

public enum ApplicationCloseOutcome
{
    NoAuthorization = 0,
    NoProtectedTransaction = 1,
    HelperReady = 2,
    RecoverableAuthorizationFailure = 3
}

[Flags]
public enum ApplicationCloseFailureFlags
{
    None = 0,
    StopUpdateWork = 1,
    RoutingGate = 2,
    RestoreRoutes = 4,
    SavePrimaryState = 8,
    Cancelled = 16,
    AuthorizationOrHelper = 32,
    UserCloseDisconnect = 64
}

public sealed class ApplicationCloseResult
{
    private ApplicationCloseResult(
        ApplicationCloseOutcome outcome,
        ApplicationCloseFailureFlags failures,
        UpdateCloseAuthorizationResult? authorizationResult,
        CloseDisconnectResult? disconnectResult)
    {
        Outcome = outcome;
        Failures = failures;
        AuthorizationResult = authorizationResult;
        DisconnectResult = disconnectResult;
    }

    public ApplicationCloseOutcome Outcome { get; }
    public ApplicationCloseFailureFlags Failures { get; }
    public UpdateCloseAuthorizationResult? AuthorizationResult { get; }
    public CloseDisconnectResult? DisconnectResult { get; }

    public bool CanClose =>
        (Failures & ApplicationCloseFailureFlags.UserCloseDisconnect) == 0 &&
        (DisconnectResult is null ||
         (Failures & ApplicationCloseFailureFlags.RestoreRoutes) == 0);

    internal static ApplicationCloseResult WithoutAuthorization(
        ApplicationCloseFailureFlags failures = ApplicationCloseFailureFlags.None,
        CloseDisconnectResult? disconnectResult = null) =>
        new(ApplicationCloseOutcome.NoAuthorization, failures, null, disconnectResult);

    internal static ApplicationCloseResult FromAuthorization(
        UpdateCloseAuthorizationResult result,
        ApplicationCloseFailureFlags failures = ApplicationCloseFailureFlags.None,
        CloseDisconnectResult? disconnectResult = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        var outcome = result.Outcome switch
        {
            UpdateCloseAuthorizationOutcome.NoProtectedTransaction =>
                ApplicationCloseOutcome.NoProtectedTransaction,
            UpdateCloseAuthorizationOutcome.HelperReady =>
                ApplicationCloseOutcome.HelperReady,
            UpdateCloseAuthorizationOutcome.RecoverableFailure =>
                ApplicationCloseOutcome.RecoverableAuthorizationFailure,
            _ => throw new InvalidOperationException("Unsupported update close authorization outcome.")
        };

        return new ApplicationCloseResult(outcome, failures, result, disconnectResult);
    }
}

public sealed class ApplicationCloseOrchestrator
{
    private readonly object _taskCacheLock = new();
    private readonly IUpdateCloseParticipant _updateCloseParticipant;
    private readonly IApplicationCloseActions _closeActions;
    private readonly ApplicationCloseIntentTracker _intentTracker;
    private readonly ApplicationCloseRequest _request;
    private readonly Func<CancellationToken, Task> _restoreRoutesAsync;
    private readonly IUserCloseDisconnectParticipant? _userCloseDisconnect;
    private Task<ApplicationCloseResult>? _cachedRun;

    public ApplicationCloseOrchestrator(
        IUpdateCloseParticipant updateCloseParticipant,
        IApplicationCloseActions closeActions,
        ApplicationCloseIntentTracker intentTracker,
        ApplicationCloseRequest request,
        Func<CancellationToken, Task> restoreRoutesAsync,
        IUserCloseDisconnectParticipant? userCloseDisconnect = null)
    {
        _updateCloseParticipant = updateCloseParticipant
            ?? throw new ArgumentNullException(nameof(updateCloseParticipant));
        _closeActions = closeActions
            ?? throw new ArgumentNullException(nameof(closeActions));
        _intentTracker = intentTracker
            ?? throw new ArgumentNullException(nameof(intentTracker));
        _request = request
            ?? throw new ArgumentNullException(nameof(request));
        _restoreRoutesAsync = restoreRoutesAsync
            ?? throw new ArgumentNullException(nameof(restoreRoutesAsync));
        _userCloseDisconnect = userCloseDisconnect;
    }

    /// <summary>
    /// Runs close orchestration once. The first caller's cancellation token owns
    /// the cached run; all simultaneous and later callers receive that exact task.
    /// </summary>
    public Task<ApplicationCloseResult> RunOnceAsync(
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource<ApplicationCloseResult>? completion = null;
        Task<ApplicationCloseResult> run;

        lock (_taskCacheLock)
        {
            if (_cachedRun is not null)
            {
                return _cachedRun;
            }

            completion = new TaskCompletionSource<ApplicationCloseResult>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            run = completion.Task;
            _cachedRun = run;
        }

        _ = CompleteRunAsync(completion, cancellationToken);
        return run;
    }

    private async Task CompleteRunAsync(
        TaskCompletionSource<ApplicationCloseResult> completion,
        CancellationToken cancellationToken)
    {
        try
        {
            completion.TrySetResult(await ExecuteOnceAsync(cancellationToken));
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
    }

    private async Task<ApplicationCloseResult> ExecuteOnceAsync(
        CancellationToken cancellationToken)
    {
        var failures = ApplicationCloseFailureFlags.None;
        CloseDisconnectPreparation? preparation = null;
        CloseDisconnectResult? disconnectResult = null;
        var disconnectSucceeded = false;

        bool RequiresUserCloseDisconnect() =>
            _userCloseDisconnect is not null &&
            _intentTracker.Current == ApplicationCloseIntent.UserOrApplicationClose;

        try
        {
            await _updateCloseParticipant.StopForCloseAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            failures |= ApplicationCloseFailureFlags.Cancelled;
            if (RequiresUserCloseDisconnect())
            {
                failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
            }
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures |= ApplicationCloseFailureFlags.StopUpdateWork;
        }

        if (RequiresUserCloseDisconnect())
        {
            try
            {
                preparation = await _userCloseDisconnect!.PrepareAsync(cancellationToken);
                if ((preparation is null || preparation.Failure is not null) &&
                    RequiresUserCloseDisconnect())
                {
                    failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                }
            }
            catch (OperationCanceledException)
            {
                failures |= ApplicationCloseFailureFlags.Cancelled;
                if (RequiresUserCloseDisconnect())
                {
                    failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                }
            }
            catch (Exception exception) when (IsOperationalFailure(exception))
            {
                if (RequiresUserCloseDisconnect())
                {
                    failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                }
            }
        }

        try
        {
            await _closeActions.RunRoutingExclusiveAsync(
                async routingToken =>
                {
                    try
                    {
                        if (_intentTracker.Current != ApplicationCloseIntent.InstallerMaintenance)
                        {
                            await _restoreRoutesAsync(routingToken);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        failures |= ApplicationCloseFailureFlags.Cancelled;
                        if (RequiresUserCloseDisconnect())
                        {
                            failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                        }
                    }
                    catch (Exception exception) when (IsOperationalFailure(exception))
                    {
                        failures |= ApplicationCloseFailureFlags.RestoreRoutes;
                    }

                    if (RequiresUserCloseDisconnect() && preparation is not null)
                    {
                        try
                        {
                            disconnectResult = await _userCloseDisconnect!.DisconnectAsync(
                                preparation,
                                routingToken);
                            disconnectSucceeded = disconnectResult is { Success: true };
                            if (!disconnectSucceeded)
                            {
                                failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            failures |= ApplicationCloseFailureFlags.Cancelled |
                                         ApplicationCloseFailureFlags.UserCloseDisconnect;
                        }
                        catch (Exception exception) when (IsOperationalFailure(exception))
                        {
                            failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                        }
                    }

                    var canSavePrimaryState = !RequiresUserCloseDisconnect() ||
                        (disconnectSucceeded &&
                         (failures & (ApplicationCloseFailureFlags.RestoreRoutes |
                                      ApplicationCloseFailureFlags.Cancelled |
                                      ApplicationCloseFailureFlags.UserCloseDisconnect)) == 0 &&
                         !routingToken.IsCancellationRequested);
                    if (canSavePrimaryState)
                    {
                        try
                        {
                            _closeActions.SavePrimaryState();
                        }
                        catch (OperationCanceledException)
                        {
                            failures |= ApplicationCloseFailureFlags.Cancelled;
                            if (RequiresUserCloseDisconnect())
                            {
                                failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
                            }
                        }
                        catch (Exception exception) when (IsOperationalFailure(exception))
                        {
                            failures |= ApplicationCloseFailureFlags.SavePrimaryState;
                        }
                    }
                },
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            failures |= ApplicationCloseFailureFlags.Cancelled;
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            failures |= ApplicationCloseFailureFlags.RoutingGate;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            failures |= ApplicationCloseFailureFlags.Cancelled;
            if (RequiresUserCloseDisconnect())
            {
                failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
            }
        }

        if (RequiresUserCloseDisconnect() && !disconnectSucceeded)
        {
            failures |= ApplicationCloseFailureFlags.UserCloseDisconnect;
        }

        if (failures != ApplicationCloseFailureFlags.None)
        {
            return ApplicationCloseResult.WithoutAuthorization(failures, disconnectResult);
        }

        if (_intentTracker.Current == ApplicationCloseIntent.InstallerMaintenance)
        {
            return ApplicationCloseResult.WithoutAuthorization(disconnectResult: disconnectResult);
        }

        if (!UpdateCloseAuthorizationContext.TryCreate(
                _intentTracker.Current,
                _request.IsElevated,
                _request.IsPostInstallSelfTest,
                _request.ProcessId,
                _request.CreationTimeFileTimeUtc,
                _request.ImagePath,
                out var context) ||
            !UpdateCloseEligibility.IsEligible(context))
        {
            return ApplicationCloseResult.WithoutAuthorization(disconnectResult: disconnectResult);
        }

        try
        {
            var authorizationResult =
                await _updateCloseParticipant.TryAuthorizeAndLaunchAsync(
                    context!,
                    cancellationToken);

            return authorizationResult is null
                ? ApplicationCloseResult.FromAuthorization(
                    UpdateCloseAuthorizationResult.RecoverableFailure(
                        "helper_ready_failed"),
                    ApplicationCloseFailureFlags.AuthorizationOrHelper,
                    disconnectResult)
                : ApplicationCloseResult.FromAuthorization(
                    authorizationResult,
                    disconnectResult: disconnectResult);
        }
        catch (OperationCanceledException)
        {
            return ApplicationCloseResult.FromAuthorization(
                UpdateCloseAuthorizationResult.RecoverableFailure(
                    "helper_ready_cancelled"),
                ApplicationCloseFailureFlags.AuthorizationOrHelper |
                ApplicationCloseFailureFlags.Cancelled,
                disconnectResult);
        }
        catch (Exception exception) when (IsOperationalFailure(exception))
        {
            return ApplicationCloseResult.FromAuthorization(
                UpdateCloseAuthorizationResult.RecoverableFailure(
                    "helper_ready_failed"),
                ApplicationCloseFailureFlags.AuthorizationOrHelper,
                disconnectResult);
        }
    }

    private static bool IsOperationalFailure(Exception exception) =>
        exception is not (
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException);
}
