using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed partial class ProtectedTransactionStoreTests
{
    [Fact]
    public async Task AuthorizationHelper_InspectCancellationAfterMutexResultWinsBeforeTypedMapping()
    {
        using var fixture = new StoreFixture();
        using var cancellation = new CancellationTokenSource();
        var helper = new WindowsUpdateAuthorizationHelper(
            new InlineAuthorizationMutex(
                fixture.Authority,
                afterAction: _ => cancellation.Cancel()),
            fixture.Store,
            fixture.Paths,
            new RecordingAuthorizationLauncher(
                WindowsUpdateHelperLaunchResult.Ready()),
            new SuccessfulProtectedTransactionCleaner());

        await FluentActions.Awaiting(
                () => helper.InspectAsync(cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task AuthorizationHelper_NonElevatedCleanupCancellationAfterInspectDoesNotMapPendingResult()
    {
        using var fixture = new StoreFixture();
        using var cancellation = new CancellationTokenSource();
        var helper = new WindowsUpdateAuthorizationHelper(
            new InlineAuthorizationMutex(
                fixture.Authority,
                afterAction: _ => cancellation.Cancel()),
            fixture.Store,
            fixture.Paths,
            new RecordingAuthorizationLauncher(
                WindowsUpdateHelperLaunchResult.Ready()),
            new SuccessfulProtectedTransactionCleaner());

        await FluentActions.Awaiting(
                () => helper
                    .CleanupAutomaticProtectedStagedAsync(
                        isElevated: false,
                        cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData(PendingUpdateSource.Automatic)]
    [InlineData(PendingUpdateSource.Manual)]
    public async Task AuthorizationHelper_TransitionsActualStoreAndRequiresExactReady(
        PendingUpdateSource source)
    {
        using var fixture = new StoreFixture();
        var material = fixture.Material with { Source = source };
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var launcher = new RecordingAuthorizationLauncher(
            WindowsUpdateHelperLaunchResult.Ready());
        var helper = CreateAuthorizationHelper(
            fixture,
            launcher);
        var context = AuthorizationContext(material);

        var result = await helper.TryAuthorizeAndLaunchAsync(
            context,
            candidateSource =>
                candidateSource == PendingUpdateSource.Manual
                || candidateSource == PendingUpdateSource.Automatic,
            AcquireAuthorizationCommitLease,
            CancellationToken.None);

        result.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.HelperReady);
        launcher.Requests.Should().ContainSingle();
        launcher.Requests[0].ExpectedReadyLine.Should().Be(
            $"READY {material.TransactionId.DirectoryName}");
        var stored = fixture.Store.ReadTransaction(
            fixture.Authority,
            material.TransactionId);
        stored.Record!.Phase.Should().Be(
            ProtectedTransactionPhase.CloseAuthorized);
        stored.Record.AuthorizedProcess.Should().Be(
            new ProcessIdentity(
                context.ProcessId,
                context.CreationTimeFileTimeUtc,
                context.ImagePath));
    }

    [Theory]
    [InlineData(
        1,
        "helper_launch")]
    [InlineData(
        2,
        "helper_ready")]
    [InlineData(
        3,
        "helper_timeout")]
    [InlineData(
        4,
        "helper_read")]
    public async Task AuthorizationHelper_PreservesCloseAuthorizedForEveryReadyFailure(
        int outcomeValue,
        string expectedError)
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var launcher = new RecordingAuthorizationLauncher(
            new WindowsUpdateHelperLaunchResult(
                (WindowsUpdateHelperLaunchOutcome)outcomeValue));
        var helper = CreateAuthorizationHelper(
            fixture,
            launcher);

        var result = await helper.TryAuthorizeAndLaunchAsync(
            AuthorizationContext(fixture.Material),
            _ => true,
            AcquireAuthorizationCommitLease,
            CancellationToken.None);

        result.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.RecoverableFailure);
        result.ErrorCode.Should().Be(expectedError);
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.CloseAuthorized);
    }

    [Fact]
    public async Task AuthorizationHelper_AutoDisabledFailsClosedButManualRemainsEligible()
    {
        using var automaticFixture = new StoreFixture();
        var automaticCreated =
            automaticFixture.Store.CreateProtectedStaged(
                automaticFixture.Authority,
                automaticFixture.Material);
        automaticFixture.Store.Activate(
                automaticFixture.Authority,
                automaticCreated.Record)
            .Success.Should().BeTrue();
        var automaticLauncher =
            new RecordingAuthorizationLauncher(
                WindowsUpdateHelperLaunchResult.Ready());
        var automaticHelper = CreateAuthorizationHelper(
            automaticFixture,
            automaticLauncher);

        var automaticResult =
            await automaticHelper.TryAuthorizeAndLaunchAsync(
                AuthorizationContext(
                    automaticFixture.Material),
                source => source == PendingUpdateSource.Manual,
                AcquireAuthorizationCommitLease,
                CancellationToken.None);

        automaticResult.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.NoProtectedTransaction);
        automaticLauncher.Requests.Should().BeEmpty();
        automaticFixture.Store.ReadTransaction(
                automaticFixture.Authority,
                automaticFixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.ProtectedStaged);

        using var manualFixture = new StoreFixture();
        var manualMaterial = manualFixture.Material with
        {
            Source = PendingUpdateSource.Manual
        };
        var manualCreated =
            manualFixture.Store.CreateProtectedStaged(
                manualFixture.Authority,
                manualMaterial);
        manualFixture.Store.Activate(
                manualFixture.Authority,
                manualCreated.Record)
            .Success.Should().BeTrue();
        var manualLauncher =
            new RecordingAuthorizationLauncher(
                WindowsUpdateHelperLaunchResult.Ready());
        var manualHelper = CreateAuthorizationHelper(
            manualFixture,
            manualLauncher);

        var manualResult =
            await manualHelper.TryAuthorizeAndLaunchAsync(
                AuthorizationContext(manualMaterial),
                source => source == PendingUpdateSource.Manual,
                AcquireAuthorizationCommitLease,
                CancellationToken.None);

        manualResult.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.HelperReady);
        manualLauncher.Requests.Should().ContainSingle();
    }

    [Fact]
    public async Task AuthorizationHelper_DisableAfterFinalPredicateWaitsForCommitAndPreservesCloseAuthorized()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var policy = new AuthorizationPolicyGate();
        var compareExchangeEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var continueCompareExchange =
            new ManualResetEventSlim();
        fixture.FileSystem.BeforeAtomicReplace = _ =>
        {
            compareExchangeEntered.TrySetResult();
            if (!continueCompareExchange.Wait(
                    TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException(
                    "CAS release was not signalled.");
            }
        };
        var launcher = new RecordingAuthorizationLauncher(
            WindowsUpdateHelperLaunchResult.Ready());
        var helper = new WindowsUpdateAuthorizationHelper(
            new AsyncAuthorizationMutex(fixture.Authority),
            fixture.Store,
            fixture.Paths,
            launcher,
            new SuccessfulProtectedTransactionCleaner());

        var authorization = helper.TryAuthorizeAndLaunchAsync(
            AuthorizationContext(fixture.Material),
            policy.IsAllowed,
            policy.TryAcquireCommitLease,
            CancellationToken.None);
        await compareExchangeEntered.Task.WaitAsync(
            TimeSpan.FromSeconds(5));
        var disable = policy.DisableAsync();
        var disabledBeforeCompareExchange = disable.IsCompleted;
        continueCompareExchange.Set();
        var result = await authorization.WaitAsync(
            TimeSpan.FromSeconds(5));
        await disable.WaitAsync(TimeSpan.FromSeconds(5));

        disabledBeforeCompareExchange.Should().BeFalse(
            "disable must linearize with the final authorization commit");
        result.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.HelperReady);
        launcher.Requests.Should().ContainSingle();
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.CloseAuthorized);
    }

    [Fact]
    public async Task AuthorizationHelper_PhaseRacePreservesLaterPhaseAndDoesNotLaunch()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var runner = new InlineAuthorizationMutex(
            fixture.Authority,
            beforeAction: call =>
            {
                if (call != 2)
                {
                    return;
                }

                var observed =
                    fixture.Store.ReadJournalForRecovery(
                        fixture.Authority,
                        fixture.Material.TransactionId);
                fixture.Store.CompareExchangeTransaction(
                        fixture.Authority,
                        observed,
                        observed.Record! with
                        {
                            Phase = ProtectedTransactionPhase
                                .CloseAuthorized,
                            AuthorizedProcess = new ProcessIdentity(
                                999,
                                133000000000000001L,
                                fixture.Material.InstalledRelease
                                    .InstallRoot
                                + "\\WireguardSplitTunnel\\"
                                + "WireguardSplitTunnel.App.exe")
                        })
                    .Success.Should().BeTrue();
            });
        var launcher = new RecordingAuthorizationLauncher(
            WindowsUpdateHelperLaunchResult.Ready());
        var helper = new WindowsUpdateAuthorizationHelper(
            runner,
            fixture.Store,
            fixture.Paths,
            launcher,
            new SuccessfulProtectedTransactionCleaner());

        var result = await helper.TryAuthorizeAndLaunchAsync(
            AuthorizationContext(fixture.Material),
            _ => true,
            AcquireAuthorizationCommitLease,
            CancellationToken.None);

        result.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.RecoverableFailure);
        result.ErrorCode.Should().Be("authorization_conflict");
        launcher.Requests.Should().BeEmpty();
        fixture.Store.ReadTransaction(
                fixture.Authority,
                fixture.Material.TransactionId)
            .Record!.Phase.Should().Be(
                ProtectedTransactionPhase.CloseAuthorized);
    }

    [Fact]
    public async Task AuthorizationHelper_TransactionIdRaceFailsClosedWithoutLaunching()
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var replacement = fixture.AddTransaction(
            Guid.Parse(
                "11223344-5566-7788-99aa-bbccddeeff00"),
            patch: 5);
        var runner = new InlineAuthorizationMutex(
            fixture.Authority,
            beforeAction: call =>
            {
                if (call != 2)
                {
                    return;
                }

                var replacementCreated =
                    fixture.Store.CreateProtectedStaged(
                        fixture.Authority,
                        replacement);
                fixture.Store.Activate(
                        fixture.Authority,
                        replacementCreated.Record)
                    .Success.Should().BeTrue();
            });
        var launcher = new RecordingAuthorizationLauncher(
            WindowsUpdateHelperLaunchResult.Ready());
        var helper = new WindowsUpdateAuthorizationHelper(
            runner,
            fixture.Store,
            fixture.Paths,
            launcher,
            new SuccessfulProtectedTransactionCleaner());

        var result = await helper.TryAuthorizeAndLaunchAsync(
            AuthorizationContext(fixture.Material),
            _ => true,
            AcquireAuthorizationCommitLease,
            CancellationToken.None);

        result.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.RecoverableFailure);
        result.ErrorCode.Should().Be("authorization_conflict");
        launcher.Requests.Should().BeEmpty();
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().Be(
                replacement.TransactionId);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AutomaticCleanup_RevokesTheExactPointerEvenWhenPhysicalEvidenceIsPreserved(
        bool cleanupSucceeds)
    {
        using var fixture = new StoreFixture();
        var created = fixture.Store.CreateProtectedStaged(
            fixture.Authority,
            fixture.Material);
        fixture.Store.Activate(
                fixture.Authority,
                created.Record)
            .Success.Should().BeTrue();
        var cleaner = new RecordingProtectedTransactionCleaner(
            cleanupSucceeds);
        var helper = new WindowsUpdateAuthorizationHelper(
            new InlineAuthorizationMutex(fixture.Authority),
            fixture.Store,
            fixture.Paths,
            new RecordingAuthorizationLauncher(
                WindowsUpdateHelperLaunchResult.Ready()),
            cleaner);

        var first = await helper
            .CleanupAutomaticProtectedStagedAsync(
                isElevated: true,
                CancellationToken.None);
        var retry = await helper
            .CleanupAutomaticProtectedStagedAsync(
                isElevated: true,
                CancellationToken.None);

        first.Outcome.Should().Be(
            WindowsUpdateProtectedCleanupOutcome.Removed);
        retry.Outcome.Should().Be(
            WindowsUpdateProtectedCleanupOutcome.NothingToDo);
        fixture.Store.ReadActive(fixture.Authority)
            .TransactionId.Should().BeNull();
        cleaner.TransactionIds.Should().Equal(
            fixture.Material.TransactionId);
    }
    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("READY", false)]
    [InlineData("ready aabbccdd112233445566778899aabbcc", false)]
    [InlineData("READY  aabbccdd112233445566778899aabbcc", false)]
    [InlineData("READY aabbccdd112233445566778899aabbcc ", false)]
    [InlineData("READY aabbccdd112233445566778899aabbcc", true)]
    public void ReadyProtocol_AcceptsOnlyTheExactTransactionBoundLine(
        string? line,
        bool expected)
    {
        var transactionId = new ProtectedTransactionId(
            Guid.Parse(
                "aabbccdd-1122-3344-5566-778899aabbcc"));

        WindowsUpdateHelperReadyProtocol.Matches(
                line,
                transactionId)
            .Should().Be(expected);
    }

    private static WindowsUpdateAuthorizationHelper
        CreateAuthorizationHelper(
            StoreFixture fixture,
            IWindowsUpdateHelperLauncher launcher) =>
        new(
            new InlineAuthorizationMutex(fixture.Authority),
            fixture.Store,
            fixture.Paths,
            launcher,
            new SuccessfulProtectedTransactionCleaner());

    private static UpdateCloseAuthorizationContext
        AuthorizationContext(
            ProtectedStagedTransactionMaterial material) =>
        new(
            ApplicationCloseIntent.UserOrApplicationClose,
            IsElevated: true,
            IsPostInstallSelfTest: false,
            ProcessId: 4242,
            CreationTimeFileTimeUtc:
                133000000000000000L,
            ImagePath: Path.Combine(
                material.InstalledRelease.InstallRoot,
                material.InstalledRelease.ApplicationRelativePath
                    .Replace(
                        '/',
                        Path.DirectorySeparatorChar)));

    private static IWindowsUpdateAuthorizationCommitLease?
        AcquireAuthorizationCommitLease(
            PendingUpdateSource source) =>
        Enum.IsDefined(source)
            ? NoopAuthorizationCommitLease.Instance
            : null;

    private sealed class NoopAuthorizationCommitLease
        : IWindowsUpdateAuthorizationCommitLease
    {
        internal static NoopAuthorizationCommitLease Instance
        {
            get;
        } = new();

        public void Dispose()
        {
        }
    }

    private sealed class InlineAuthorizationMutex
        : IWindowsUpdateAuthorizationMutex
    {
        private readonly ProtectedUpdateMutexContext _authority;
        private readonly Action<int>? _beforeAction;
        private readonly Action<int>? _afterAction;
        private int _calls;

        public InlineAuthorizationMutex(
            ProtectedUpdateMutexContext authority,
            Action<int>? beforeAction = null,
            Action<int>? afterAction = null)
        {
            _authority = authority;
            _beforeAction = beforeAction;
            _afterAction = afterAction;
        }

        public Task<ProtectedUpdateMutexResult<T>>
            RunExclusiveAsync<T>(
                Func<ProtectedUpdateMutexContext, T> action,
                TimeSpan timeout,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var call = ++_calls;
            _beforeAction?.Invoke(call);
            var result =
                ProtectedUpdateMutexResult<T>.Completed(
                    ProtectedUpdateMutexStatus.Acquired,
                    action(_authority));
            _afterAction?.Invoke(call);
            return Task.FromResult(result);
        }
    }

    private sealed class AsyncAuthorizationMutex(
        ProtectedUpdateMutexContext authority)
        : IWindowsUpdateAuthorizationMutex
    {
        public Task<ProtectedUpdateMutexResult<T>>
            RunExclusiveAsync<T>(
                Func<ProtectedUpdateMutexContext, T> action,
                TimeSpan timeout,
                CancellationToken cancellationToken) =>
            Task.Run(
                () =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    return ProtectedUpdateMutexResult<T>.Completed(
                        ProtectedUpdateMutexStatus.Acquired,
                        action(authority));
                },
                cancellationToken);
    }

    private sealed class AuthorizationPolicyGate
    {
        private readonly SemaphoreSlim _gate = new(1, 1);
        private bool _allowed = true;

        public bool IsAllowed(PendingUpdateSource source)
        {
            _gate.Wait();
            try
            {
                return source == PendingUpdateSource.Manual
                    || _allowed;
            }
            finally
            {
                _gate.Release();
            }
        }

        public IWindowsUpdateAuthorizationCommitLease?
            TryAcquireCommitLease(
                PendingUpdateSource source)
        {
            if (source == PendingUpdateSource.Manual)
            {
                return NoopAuthorizationCommitLease.Instance;
            }

            if (source != PendingUpdateSource.Automatic)
            {
                return null;
            }

            _gate.Wait();
            if (_allowed)
            {
                return new PolicyCommitLease(_gate);
            }

            _gate.Release();
            return null;
        }

        public async Task DisableAsync()
        {
            await _gate.WaitAsync();
            try
            {
                _allowed = false;
            }
            finally
            {
                _gate.Release();
            }
        }

        private sealed class PolicyCommitLease(
            SemaphoreSlim gate)
            : IWindowsUpdateAuthorizationCommitLease
        {
            private SemaphoreSlim? _gate = gate;

            public void Dispose() =>
                Interlocked.Exchange(ref _gate, null)
                    ?.Release();
        }
    }

    private sealed class RecordingAuthorizationLauncher
        : IWindowsUpdateHelperLauncher
    {
        private readonly WindowsUpdateHelperLaunchResult _result;

        public RecordingAuthorizationLauncher(
            WindowsUpdateHelperLaunchResult result)
        {
            _result = result;
        }

        public List<WindowsUpdateHelperLaunchRequest> Requests
        {
            get;
        } = [];

        public Task<WindowsUpdateHelperLaunchResult>
            LaunchAndWaitForReadyAsync(
                WindowsUpdateHelperLaunchRequest request,
                CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(_result);
        }
    }

    private sealed class RecordingProtectedTransactionCleaner(
        bool result)
        : IWindowsUpdateProtectedTransactionCleaner
    {
        public List<ProtectedTransactionId> TransactionIds
        {
            get;
        } = [];

        public bool Cleanup(
            ProtectedTransactionId transactionId)
        {
            TransactionIds.Add(transactionId);
            return result;
        }
    }
    private sealed class SuccessfulProtectedTransactionCleaner
        : IWindowsUpdateProtectedTransactionCleaner
    {
        public bool Cleanup(
            ProtectedTransactionId transactionId) => true;
    }
}
