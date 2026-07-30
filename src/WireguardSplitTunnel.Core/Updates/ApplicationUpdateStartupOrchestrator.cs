namespace WireguardSplitTunnel.Core.Updates;

public enum ApplicationStartupRoutingOutcome
{
    NotReached = 0,
    Completed = 1,
    HandledFailure = 2,
    UnhandledFailure = 3
}

public sealed record UpdateStartupHealthContext(
    Guid TransactionId,
    SemanticVersion Version)
{
    public bool IsValid =>
        TransactionId != Guid.Empty &&
        Version.Major >= 0 &&
        Version.Minor >= 0 &&
        Version.Patch >= 0;
}

public sealed record ApplicationUpdateStartupRequest(
    bool InteractiveWindowInitialized,
    bool PrimaryStateLoaded,
    ApplicationStartupRoutingOutcome RoutingOutcome,
    bool IsPostInstallSelfTest,
    UpdateStartupHealthContext? HealthContext);

public enum UpdateStartupHealthOutcome
{
    MarkedHealthy = 0,
    NoMatchingTransaction = 1,
    RecoverableFailure = 2
}

public sealed class UpdateStartupHealthResult
{
    private UpdateStartupHealthResult(UpdateStartupHealthOutcome outcome)
    {
        Outcome = outcome;
    }

    public UpdateStartupHealthOutcome Outcome { get; }

    public static UpdateStartupHealthResult MarkedHealthy() =>
        new(UpdateStartupHealthOutcome.MarkedHealthy);

    public static UpdateStartupHealthResult NoMatchingTransaction() =>
        new(UpdateStartupHealthOutcome.NoMatchingTransaction);

    public static UpdateStartupHealthResult RecoverableFailure() =>
        new(UpdateStartupHealthOutcome.RecoverableFailure);
}

public interface IApplicationUpdateStartupActions
{
    Task<UpdateStartupHealthResult> MarkMatchingTransactionHealthyAsync(
        UpdateStartupHealthContext context,
        CancellationToken cancellationToken);

    Task StartUpdateChecksAsync(CancellationToken cancellationToken);
}

public enum ApplicationUpdateStartupOutcome
{
    Suppressed = 0,
    NotReady = 1,
    Closing = 2,
    ChecksStarted = 3,
    RecoverableFailure = 4
}

public enum ApplicationStartupHealthDisposition
{
    NotRequested = 0,
    MarkedHealthy = 1,
    NoMatchingTransaction = 2,
    RecoverableFailure = 3
}

public enum ApplicationUpdateStartupFailure
{
    None = 0,
    InvalidHealthContext = 1,
    Health = 2,
    StartChecks = 3,
    Cancelled = 4,
    ClosingPredicate = 5
}

public sealed class ApplicationUpdateStartupResult
{
    private ApplicationUpdateStartupResult(
        ApplicationUpdateStartupOutcome outcome,
        ApplicationStartupHealthDisposition healthDisposition,
        ApplicationUpdateStartupFailure failure,
        UpdateStartupHealthResult? healthResult,
        bool checksStarted)
    {
        Outcome = outcome;
        HealthDisposition = healthDisposition;
        Failure = failure;
        HealthResult = healthResult;
        ChecksStarted = checksStarted;
    }

    public ApplicationUpdateStartupOutcome Outcome { get; }
    public ApplicationStartupHealthDisposition HealthDisposition { get; }
    public ApplicationUpdateStartupFailure Failure { get; }
    public UpdateStartupHealthResult? HealthResult { get; }
    public bool ChecksStarted { get; }

    internal static ApplicationUpdateStartupResult Suppressed() =>
        new(
            ApplicationUpdateStartupOutcome.Suppressed,
            ApplicationStartupHealthDisposition.NotRequested,
            ApplicationUpdateStartupFailure.None,
            null,
            false);

    internal static ApplicationUpdateStartupResult NotReady() =>
        new(
            ApplicationUpdateStartupOutcome.NotReady,
            ApplicationStartupHealthDisposition.NotRequested,
            ApplicationUpdateStartupFailure.None,
            null,
            false);

    internal static ApplicationUpdateStartupResult Closing(
        ApplicationStartupHealthDisposition healthDisposition =
            ApplicationStartupHealthDisposition.NotRequested,
        UpdateStartupHealthResult? healthResult = null) =>
        new(
            ApplicationUpdateStartupOutcome.Closing,
            healthDisposition,
            ApplicationUpdateStartupFailure.None,
            healthResult,
            false);

    internal static ApplicationUpdateStartupResult StartedChecks(
        ApplicationStartupHealthDisposition healthDisposition,
        UpdateStartupHealthResult? healthResult) =>
        new(
            ApplicationUpdateStartupOutcome.ChecksStarted,
            healthDisposition,
            ApplicationUpdateStartupFailure.None,
            healthResult,
            true);

    internal static ApplicationUpdateStartupResult RecoverableFailure(
        ApplicationUpdateStartupFailure failure,
        ApplicationStartupHealthDisposition healthDisposition =
            ApplicationStartupHealthDisposition.RecoverableFailure,
        UpdateStartupHealthResult? healthResult = null) =>
        new(
            ApplicationUpdateStartupOutcome.RecoverableFailure,
            healthDisposition,
            failure,
            healthResult,
            false);
}

public sealed class ApplicationUpdateStartupOrchestrator
{
    private readonly object _taskCacheLock = new();
    private readonly IApplicationUpdateStartupActions _actions;
    private readonly ApplicationUpdateStartupRequest _request;
    private readonly Func<bool> _isClosing;
    private Task<ApplicationUpdateStartupResult>? _cachedRun;

    public ApplicationUpdateStartupOrchestrator(
        IApplicationUpdateStartupActions actions,
        ApplicationUpdateStartupRequest request,
        Func<bool> isClosing)
    {
        _actions = actions ?? throw new ArgumentNullException(nameof(actions));
        _request = request ?? throw new ArgumentNullException(nameof(request));
        _isClosing = isClosing ?? throw new ArgumentNullException(nameof(isClosing));
    }

    /// <summary>
    /// Runs update startup orchestration once. The first caller's cancellation
    /// token owns the cached run, and every caller receives that exact task.
    /// </summary>
    public Task<ApplicationUpdateStartupResult> RunOnceAsync(
        CancellationToken cancellationToken = default)
    {
        TaskCompletionSource<ApplicationUpdateStartupResult>? completion = null;
        Task<ApplicationUpdateStartupResult> run;

        lock (_taskCacheLock)
        {
            if (_cachedRun is not null)
            {
                return _cachedRun;
            }

            completion =
                new TaskCompletionSource<ApplicationUpdateStartupResult>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
            run = completion.Task;
            _cachedRun = run;
        }

        _ = CompleteRunAsync(completion, cancellationToken);
        return run;
    }

    private async Task CompleteRunAsync(
        TaskCompletionSource<ApplicationUpdateStartupResult> completion,
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

    private async Task<ApplicationUpdateStartupResult> ExecuteOnceAsync(
        CancellationToken cancellationToken)
    {
        if (_request.IsPostInstallSelfTest)
        {
            return ApplicationUpdateStartupResult.Suppressed();
        }

        var closingResult = ReadClosing();
        if (closingResult.Failure is not null)
        {
            return closingResult.Failure;
        }

        if (closingResult.IsClosing)
        {
            return ApplicationUpdateStartupResult.Closing();
        }

        if (!_request.InteractiveWindowInitialized ||
            !_request.PrimaryStateLoaded ||
            _request.RoutingOutcome is not (
                ApplicationStartupRoutingOutcome.Completed or
                ApplicationStartupRoutingOutcome.HandledFailure))
        {
            return ApplicationUpdateStartupResult.NotReady();
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return ApplicationUpdateStartupResult.RecoverableFailure(
                ApplicationUpdateStartupFailure.Cancelled);
        }

        var healthDisposition = ApplicationStartupHealthDisposition.NotRequested;
        UpdateStartupHealthResult? healthResult = null;

        if (_request.HealthContext is not null)
        {
            if (!_request.HealthContext.IsValid)
            {
                return ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.InvalidHealthContext);
            }

            closingResult = ReadClosing();
            if (closingResult.Failure is not null)
            {
                return closingResult.Failure;
            }

            if (closingResult.IsClosing)
            {
                return ApplicationUpdateStartupResult.Closing();
            }

            try
            {
                healthResult =
                    await _actions.MarkMatchingTransactionHealthyAsync(
                        _request.HealthContext,
                        cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.Cancelled);
            }
            catch (Exception exception) when (IsNonFatal(exception))
            {
                return ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.Health);
            }

            if (healthResult is null)
            {
                return ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.Health);
            }

            switch (healthResult.Outcome)
            {
                case UpdateStartupHealthOutcome.MarkedHealthy:
                    healthDisposition =
                        ApplicationStartupHealthDisposition.MarkedHealthy;
                    break;
                case UpdateStartupHealthOutcome.NoMatchingTransaction:
                    healthDisposition =
                        ApplicationStartupHealthDisposition.NoMatchingTransaction;
                    break;
                case UpdateStartupHealthOutcome.RecoverableFailure:
                    return ApplicationUpdateStartupResult.RecoverableFailure(
                        ApplicationUpdateStartupFailure.Health,
                        ApplicationStartupHealthDisposition.RecoverableFailure,
                        healthResult);
                default:
                    return ApplicationUpdateStartupResult.RecoverableFailure(
                        ApplicationUpdateStartupFailure.Health,
                        ApplicationStartupHealthDisposition.RecoverableFailure,
                        healthResult);
            }
        }

        closingResult = ReadClosing();
        if (closingResult.Failure is not null)
        {
            return closingResult.Failure;
        }

        if (closingResult.IsClosing)
        {
            return ApplicationUpdateStartupResult.Closing(
                healthDisposition,
                healthResult);
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return ApplicationUpdateStartupResult.RecoverableFailure(
                ApplicationUpdateStartupFailure.Cancelled,
                healthDisposition,
                healthResult);
        }

        try
        {
            await _actions.StartUpdateChecksAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return ApplicationUpdateStartupResult.RecoverableFailure(
                ApplicationUpdateStartupFailure.Cancelled,
                healthDisposition,
                healthResult);
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
            return ApplicationUpdateStartupResult.RecoverableFailure(
                ApplicationUpdateStartupFailure.StartChecks,
                healthDisposition,
                healthResult);
        }

        return ApplicationUpdateStartupResult.StartedChecks(
            healthDisposition,
            healthResult);
    }

    private ClosingReadResult ReadClosing()
    {
        try
        {
            return new ClosingReadResult(_isClosing(), null);
        }
        catch (OperationCanceledException)
        {
            return new ClosingReadResult(
                false,
                ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.Cancelled));
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
            return new ClosingReadResult(
                false,
                ApplicationUpdateStartupResult.RecoverableFailure(
                    ApplicationUpdateStartupFailure.ClosingPredicate));
        }
    }

    private static bool IsNonFatal(Exception exception) =>
        exception is not (
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException);

    private readonly record struct ClosingReadResult(
        bool IsClosing,
        ApplicationUpdateStartupResult? Failure);
}
