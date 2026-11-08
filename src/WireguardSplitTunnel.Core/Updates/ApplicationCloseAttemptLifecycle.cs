namespace WireguardSplitTunnel.Core.Updates;

/// <summary>
/// Joins callers to a latched close attempt and creates a fresh one-shot
/// orchestrator after explicit release or an atomic non-user close transition.
/// </summary>
public sealed class ApplicationCloseAttemptLifecycle
{
    private readonly object sync = new();
    private Task<ApplicationCloseResult>? activeAttempt;

    public Task<ApplicationCloseResult> RunAsync(
        Func<ApplicationCloseOrchestrator> orchestratorFactory,
        ApplicationCloseIntentTracker intentTracker,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(intentTracker);
        return RunAsyncCore(orchestratorFactory, intentTracker, cancellationToken);
    }

    public Task<ApplicationCloseResult> RunAsync(
        Func<ApplicationCloseOrchestrator> orchestratorFactory,
        CancellationToken cancellationToken = default) =>
        RunAsyncCore(orchestratorFactory, null, cancellationToken);

    private Task<ApplicationCloseResult> RunAsyncCore(
        Func<ApplicationCloseOrchestrator> orchestratorFactory,
        ApplicationCloseIntentTracker? intentTracker,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(orchestratorFactory);

        TaskCompletionSource<ApplicationCloseResult> completion;
        lock (sync)
        {
            if (activeAttempt is { } current)
            {
                if (!ShouldTransitionToNonUserClose(current, intentTracker))
                {
                    return current;
                }

                // A non-user intent consumes a completed failed user attempt and
                // reserves its replacement atomically. Pending work is always joined.
                activeAttempt = null;
            }

            // Reserve the attempt before invoking either the factory or any close
            // participant so synchronous reentry also joins this same operation.
            completion = new TaskCompletionSource<ApplicationCloseResult>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            activeAttempt = completion.Task;
        }

        _ = CompleteAttemptAsync(
            completion,
            orchestratorFactory,
            cancellationToken);
        return completion.Task;
    }

    private static bool ShouldTransitionToNonUserClose(
        Task<ApplicationCloseResult> attempt,
        ApplicationCloseIntentTracker? intentTracker) =>
        intentTracker is not null &&
        intentTracker.Current != ApplicationCloseIntent.UserOrApplicationClose &&
        attempt.IsCompleted &&
        (!attempt.IsCompletedSuccessfully || !attempt.Result.CanClose);

    public void Release(Task<ApplicationCloseResult> attempt)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        lock (sync)
        {
            if (ReferenceEquals(activeAttempt, attempt))
            {
                activeAttempt = null;
            }
        }
    }

    private static async Task CompleteAttemptAsync(
        TaskCompletionSource<ApplicationCloseResult> completion,
        Func<ApplicationCloseOrchestrator> orchestratorFactory,
        CancellationToken cancellationToken)
    {
        try
        {
            var orchestrator = orchestratorFactory();
            var result = await orchestrator.RunOnceAsync(cancellationToken)
                .ConfigureAwait(false);
            completion.TrySetResult(result);
        }
        catch (Exception exception)
        {
            completion.TrySetException(exception);
        }
    }
}
