using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ApplicationUpdateStartupOrchestratorTests
{
    [Fact]
    public void StartupContracts_HaveStableExplicitValuesAndHostIndependentHealthValidity()
    {
        Enum.GetValues<ApplicationStartupRoutingOutcome>()
            .Select(value => (int)value)
            .Should().Equal(0, 1, 2, 3);
        Enum.GetValues<UpdateStartupHealthOutcome>()
            .Select(value => (int)value)
            .Should().Equal(0, 1, 2);
        Enum.GetValues<ApplicationUpdateStartupOutcome>()
            .Select(value => (int)value)
            .Should().Equal(0, 1, 2, 3, 4);
        Enum.GetValues<ApplicationStartupHealthDisposition>()
            .Select(value => (int)value)
            .Should().Equal(0, 1, 2, 3);

        ValidHealthContext().IsValid.Should().BeTrue();
        new UpdateStartupHealthContext(Guid.Empty, new SemanticVersion(1, 2, 3))
            .IsValid.Should().BeFalse();
        new UpdateStartupHealthContext(Guid.NewGuid(), new SemanticVersion(-1, 2, 3))
            .IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task RunOnceAsync_AwaitsHealthBeforeStartingChecksInExactOrder()
    {
        var order = new List<string>();
        var healthCompletion = new TaskCompletionSource<UpdateStartupHealthResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var actions = new FakeStartupActions(
            health: (_, _) =>
            {
                order.Add("MarkMatchingTransactionHealthy");
                return healthCompletion.Task;
            },
            checks: _ =>
            {
                order.Add("StartUpdateChecks");
                return Task.CompletedTask;
            });
        var orchestrator = CreateOrchestrator(actions, ValidRequest());

        var run = orchestrator.RunOnceAsync();
        await actions.HealthStarted.Task;

        run.IsCompleted.Should().BeFalse();
        actions.CheckCount.Should().Be(0);

        healthCompletion.SetResult(UpdateStartupHealthResult.MarkedHealthy());
        var result = await run;

        order.Should().Equal(
            "MarkMatchingTransactionHealthy",
            "StartUpdateChecks");
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.ChecksStarted);
        result.HealthDisposition.Should().Be(ApplicationStartupHealthDisposition.MarkedHealthy);
        result.ChecksStarted.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_HandledRoutingFailureQualifiesForHealthAndChecks()
    {
        var actions = new FakeStartupActions();
        var request = ValidRequest() with
        {
            RoutingOutcome = ApplicationStartupRoutingOutcome.HandledFailure
        };

        var result = await CreateOrchestrator(actions, request).RunOnceAsync();

        actions.HealthCount.Should().Be(1);
        actions.CheckCount.Should().Be(1);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.ChecksStarted);
    }

    [Theory]
    [InlineData(false, true, ApplicationStartupRoutingOutcome.Completed)]
    [InlineData(true, false, ApplicationStartupRoutingOutcome.Completed)]
    [InlineData(true, true, ApplicationStartupRoutingOutcome.NotReached)]
    [InlineData(true, true, ApplicationStartupRoutingOutcome.UnhandledFailure)]
    public async Task RunOnceAsync_UnrelatedReadinessConditionDoesNothing(
        bool interactive,
        bool primaryLoaded,
        ApplicationStartupRoutingOutcome routingOutcome)
    {
        var actions = new FakeStartupActions();
        var request = ValidRequest() with
        {
            InteractiveWindowInitialized = interactive,
            PrimaryStateLoaded = primaryLoaded,
            RoutingOutcome = routingOutcome
        };

        var result = await CreateOrchestrator(actions, request).RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.NotReady);
    }

    [Fact]
    public async Task RunOnceAsync_ClosingBeforeReadinessDoesNothing()
    {
        var actions = new FakeStartupActions();
        var request = ValidRequest() with { PrimaryStateLoaded = false };

        var result = await CreateOrchestrator(
            actions,
            request,
            isClosing: () => true).RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.Closing);
    }

    [Fact]
    public async Task RunOnceAsync_ClosingWhileHealthIsBlockedPreventsChecks()
    {
        var closing = false;
        var healthCompletion = new TaskCompletionSource<UpdateStartupHealthResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var actions = new FakeStartupActions(
            health: (_, _) => healthCompletion.Task);
        var orchestrator = CreateOrchestrator(
            actions,
            ValidRequest(),
            isClosing: () => closing);

        var run = orchestrator.RunOnceAsync();
        await actions.HealthStarted.Task;
        closing = true;
        healthCompletion.SetResult(UpdateStartupHealthResult.MarkedHealthy());

        var result = await run;

        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.Closing);
        result.HealthDisposition.Should().Be(ApplicationStartupHealthDisposition.MarkedHealthy);
    }

    [Fact]
    public async Task RunOnceAsync_NoPendingHealthIsTypedNoOpThenStartsChecks()
    {
        var actions = new FakeStartupActions();
        var request = ValidRequest() with { HealthContext = null };

        var result = await CreateOrchestrator(actions, request).RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(1);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.ChecksStarted);
        result.HealthDisposition.Should().Be(ApplicationStartupHealthDisposition.NotRequested);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RunOnceAsync_PostInstallSelfTestSuppressesAllUpdateStartupWork(
        bool includeHealthContext)
    {
        var closingPredicateCalls = 0;
        var actions = new FakeStartupActions();
        var request = ValidRequest() with
        {
            IsPostInstallSelfTest = true,
            HealthContext = includeHealthContext ? ValidHealthContext() : null
        };

        var result = await CreateOrchestrator(
            actions,
            request,
            isClosing: () =>
            {
                closingPredicateCalls++;
                return false;
            }).RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(0);
        closingPredicateCalls.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.Suppressed);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task RunOnceAsync_InvalidHealthContextFailsClosed(
        bool emptyTransactionId,
        bool negativeVersion)
    {
        var actions = new FakeStartupActions();
        var context = new UpdateStartupHealthContext(
            emptyTransactionId ? Guid.Empty : Guid.NewGuid(),
            negativeVersion
                ? new SemanticVersion(1, -1, 3)
                : new SemanticVersion(1, 2, 3));
        var request = ValidRequest() with { HealthContext = context };

        var result = await CreateOrchestrator(actions, request).RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.InvalidHealthContext);
    }

    [Fact]
    public async Task RunOnceAsync_HealthRecoverableFailureSkipsChecks()
    {
        var healthFailure = UpdateStartupHealthResult.RecoverableFailure();
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromResult(healthFailure));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.Health);
        result.HealthResult.Should().BeSameAs(healthFailure);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedHealthExceptionSkipsChecksAndIsTyped()
    {
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromException<UpdateStartupHealthResult>(
                new InvalidOperationException("ordinary")));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.Health);
    }

    [Fact]
    public async Task RunOnceAsync_HealthCancellationSkipsChecksAndIsTyped()
    {
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromException<UpdateStartupHealthResult>(
                new OperationCanceledException()));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.Cancelled);
    }

    [Fact]
    public async Task RunOnceAsync_NullHealthResultSkipsChecksAndFailsClosed()
    {
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromResult<UpdateStartupHealthResult>(null!));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.Health);
    }

    [Fact]
    public async Task RunOnceAsync_NoMatchingTransactionIsNoOpThenStartsChecks()
    {
        var noMatch = UpdateStartupHealthResult.NoMatchingTransaction();
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromResult(noMatch));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.CheckCount.Should().Be(1);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.ChecksStarted);
        result.HealthDisposition.Should().Be(ApplicationStartupHealthDisposition.NoMatchingTransaction);
        result.HealthResult.Should().BeSameAs(noMatch);
    }

    [Fact]
    public async Task RunOnceAsync_CheckStartFailureIsTyped()
    {
        var actions = new FakeStartupActions(
            checks: _ => Task.FromException(new ObjectDisposedException("checks")));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        actions.HealthCount.Should().Be(1);
        actions.CheckCount.Should().Be(1);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.StartChecks);
        result.ChecksStarted.Should().BeFalse();
    }

    [Fact]
    public async Task RunOnceAsync_CheckStartCancellationIsTyped()
    {
        var actions = new FakeStartupActions(
            checks: _ => Task.FromException(new OperationCanceledException()));

        var result = await CreateOrchestrator(actions, ValidRequest()).RunOnceAsync();

        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.Cancelled);
        result.ChecksStarted.Should().BeFalse();
    }

    [Fact]
    public async Task RunOnceAsync_ClosingPredicateFailureIsTypedAndIsolated()
    {
        var actions = new FakeStartupActions();
        var orchestrator = CreateOrchestrator(
            actions,
            ValidRequest(),
            isClosing: () => throw new NullReferenceException("ordinary"));

        var result = await orchestrator.RunOnceAsync();

        actions.HealthCount.Should().Be(0);
        actions.CheckCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationUpdateStartupOutcome.RecoverableFailure);
        result.Failure.Should().Be(ApplicationUpdateStartupFailure.ClosingPredicate);
    }

    [Fact]
    public async Task RunOnceAsync_SimultaneousAndRepeatedCallersReceiveExactTaskAndExecuteOnce()
    {
        var healthCompletion = new TaskCompletionSource<UpdateStartupHealthResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var actions = new FakeStartupActions(
            health: (_, _) => healthCompletion.Task);
        var orchestrator = CreateOrchestrator(actions, ValidRequest());
        const int callerCount = 16;
        using var barrier = new Barrier(callerCount);
        var returnedTasks = new Task<ApplicationUpdateStartupResult>?[callerCount];

        var callers = Enumerable.Range(0, callerCount)
            .Select(index => Task.Run(() =>
            {
                barrier.SignalAndWait();
                returnedTasks[index] = orchestrator.RunOnceAsync();
            }))
            .ToArray();
        await Task.WhenAll(callers);

        returnedTasks.Should().OnlyContain(task => ReferenceEquals(task, returnedTasks[0]));
        actions.HealthCount.Should().Be(1);

        healthCompletion.SetResult(UpdateStartupHealthResult.MarkedHealthy());
        await returnedTasks[0]!;

        orchestrator.RunOnceAsync().Should().BeSameAs(returnedTasks[0]);
        actions.HealthCount.Should().Be(1);
        actions.CheckCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_FirstCallerTokenOwnsCachedRun()
    {
        using var firstSource = new CancellationTokenSource();
        using var secondSource = new CancellationTokenSource();
        var actions = new FakeStartupActions();
        var orchestrator = CreateOrchestrator(actions, ValidRequest());

        var first = orchestrator.RunOnceAsync(firstSource.Token);
        var second = orchestrator.RunOnceAsync(secondSource.Token);
        await first;

        second.Should().BeSameAs(first);
        actions.HealthToken.Should().Be(firstSource.Token);
        actions.CheckToken.Should().Be(firstSource.Token);
    }

    [Fact]
    public async Task RunOnceAsync_CallbackReentryDoesNotHoldTaskCacheLock()
    {
        ApplicationUpdateStartupOrchestrator? orchestrator = null;
        Task<ApplicationUpdateStartupResult>? reentered = null;
        var firstPredicateCall = true;
        var actions = new FakeStartupActions();
        orchestrator = CreateOrchestrator(
            actions,
            ValidRequest(),
            isClosing: () =>
            {
                if (firstPredicateCall)
                {
                    firstPredicateCall = false;
                    reentered = orchestrator!.RunOnceAsync();
                }

                return false;
            });

        var outer = orchestrator.RunOnceAsync();
        await outer.WaitAsync(TimeSpan.FromSeconds(5));

        reentered.Should().BeSameAs(outer);
        actions.HealthCount.Should().Be(1);
        actions.CheckCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_OutOfMemoryExceptionPropagatesAsGenuinelyFatal()
    {
        var actions = new FakeStartupActions(
            health: (_, _) => Task.FromException<UpdateStartupHealthResult>(
                new OutOfMemoryException("fatal")));
        var orchestrator = CreateOrchestrator(actions, ValidRequest());

        Func<Task> run = () => orchestrator.RunOnceAsync();

        await run.Should().ThrowAsync<OutOfMemoryException>().WithMessage("fatal");
    }

    private static ApplicationUpdateStartupOrchestrator CreateOrchestrator(
        FakeStartupActions actions,
        ApplicationUpdateStartupRequest request,
        Func<bool>? isClosing = null) =>
        new(actions, request, isClosing ?? (() => false));

    private static ApplicationUpdateStartupRequest ValidRequest() =>
        new(
            true,
            true,
            ApplicationStartupRoutingOutcome.Completed,
            false,
            ValidHealthContext());

    private static UpdateStartupHealthContext ValidHealthContext() =>
        new(
            Guid.Parse("6a27deaf-a78d-45e7-b10d-dc23d7dafc65"),
            new SemanticVersion(1, 2, 3));

    private sealed class FakeStartupActions(
        Func<UpdateStartupHealthContext, CancellationToken, Task<UpdateStartupHealthResult>>? health = null,
        Func<CancellationToken, Task>? checks = null)
        : IApplicationUpdateStartupActions
    {
        private readonly Func<UpdateStartupHealthContext, CancellationToken, Task<UpdateStartupHealthResult>> _health =
            health ?? ((_, _) => Task.FromResult(UpdateStartupHealthResult.MarkedHealthy()));
        private readonly Func<CancellationToken, Task> _checks =
            checks ?? (_ => Task.CompletedTask);

        public int HealthCount { get; private set; }
        public int CheckCount { get; private set; }
        public CancellationToken HealthToken { get; private set; }
        public CancellationToken CheckToken { get; private set; }
        public UpdateStartupHealthContext? HealthContext { get; private set; }
        public TaskCompletionSource HealthStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<UpdateStartupHealthResult> MarkMatchingTransactionHealthyAsync(
            UpdateStartupHealthContext context,
            CancellationToken cancellationToken)
        {
            HealthCount++;
            HealthContext = context;
            HealthToken = cancellationToken;
            HealthStarted.TrySetResult();
            return _health(context, cancellationToken);
        }

        public Task StartUpdateChecksAsync(CancellationToken cancellationToken)
        {
            CheckCount++;
            CheckToken = cancellationToken;
            return _checks(cancellationToken);
        }
    }
}
