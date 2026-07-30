using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Principal;
using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

[CollectionDefinition(CollectionName, DisableParallelization = true)]
public sealed class ProtectedUpdateMutexCollection
{
    public const string CollectionName = "Protected update mutex";
}

[Collection(ProtectedUpdateMutexCollection.CollectionName)]
public sealed class ProtectedUpdateMutexTests
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);

    [Fact]
    public void Name_IsTheFixedGlobalAuthority()
    {
        ProtectedUpdateMutex.Name.Should()
            .Be(@"Global\WireguardSplitTunnel.UpdateTransaction");
    }

    [Fact]
    public void RunExclusiveAsync_PublicSurfaceAcceptsOnlyANonGenericFullyAwaitedTaskAction()
    {
        var methods = typeof(ProtectedUpdateMutex)
            .GetMethods(
                BindingFlags.Instance
                    | BindingFlags.Public
                    | BindingFlags.DeclaredOnly)
            .Where(method => method.Name == "RunExclusiveAsync")
            .ToArray();

        methods.Should().ContainSingle();
        methods[0].IsGenericMethod.Should().BeFalse();
        methods[0].GetParameters()[0].ParameterType.Should().Be(
            typeof(Func<
                ProtectedUpdateMutexContext,
                CancellationToken,
                Task>));
        methods[0].ReturnType.IsGenericType.Should().BeTrue();
        methods[0].ReturnType.GetGenericTypeDefinition().Should().Be(
            typeof(Task<>));
        methods[0].ReturnType.GenericTypeArguments[0]
            .IsGenericType.Should().BeFalse();
    }

    [Fact]
    public void BuildSecurity_UsesOnlySystemAndAdministratorsFullControl()
    {
        var security = ProtectedUpdateMutex.BuildSecurity();

        security.AreAccessRulesProtected.Should().BeTrue();
        security.AreAccessRulesCanonical.Should().BeTrue();
        security.GetOwner(typeof(SecurityIdentifier)).Should().Be(System);
        var rules = Rules(security);
        rules.Should().HaveCount(2);
        rules.Should().OnlyContain(rule =>
            !rule.IsInherited
            && rule.AccessControlType == AccessControlType.Allow
            && rule.MutexRights == MutexRights.FullControl);
        rules.Select(rule => rule.IdentityReference)
            .Should().BeEquivalentTo([Administrators, System]);
        ProtectedUpdateMutex.HasExactSecurity(security).Should().BeTrue();
    }

    [Fact]
    public void HasExactSecurity_RejectsWrongOwnerExtraIdentityAndWeakerRights()
    {
        var wrongOwner = ProtectedUpdateMutex.BuildSecurity();
        wrongOwner.SetOwner(Administrators);

        var extra = ProtectedUpdateMutex.BuildSecurity();
        extra.AddAccessRule(new MutexAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            MutexRights.FullControl,
            AccessControlType.Allow));

        var weaker = new MutexSecurity();
        weaker.SetOwner(System);
        weaker.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        weaker.AddAccessRule(new MutexAccessRule(
            Administrators,
            MutexRights.Synchronize | MutexRights.Modify,
            AccessControlType.Allow));
        weaker.AddAccessRule(new MutexAccessRule(
            System,
            MutexRights.FullControl,
            AccessControlType.Allow));

        ProtectedUpdateMutex.HasExactSecurity(wrongOwner).Should().BeFalse();
        ProtectedUpdateMutex.HasExactSecurity(extra).Should().BeFalse();
        ProtectedUpdateMutex.HasExactSecurity(weaker).Should().BeFalse();
    }

    [Fact]
    public void HasExactSecurity_RejectsCallbackAndObjectAces()
    {
        var callback = MutexSecurityFromSddl(
            "O:SYD:P"
            + "(XA;;0x1f0001;;;SY;(@USER.Department == \"Finance\"))"
            + "(A;;0x1f0001;;;BA)");

        var objectAcl = new RawAcl(GenericAcl.AclRevisionDS, 2);
        objectAcl.InsertAce(
            0,
            new ObjectAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                (int)MutexRights.FullControl,
                System,
                ObjectAceFlags.ObjectAceTypePresent,
                Guid.NewGuid(),
                Guid.Empty,
                isCallback: false,
                opaque: null));
        objectAcl.InsertAce(
            1,
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                (int)MutexRights.FullControl,
                Administrators,
                isCallback: false,
                opaque: null));
        var objectAce = MutexSecurityFromRawAcl(objectAcl);

        ProtectedUpdateMutex.HasExactSecurity(callback)
            .Should().BeFalse();
        ProtectedUpdateMutex.HasExactSecurity(objectAce)
            .Should().BeFalse();
    }

    [Fact]
    public async Task RunExclusiveAsync_AcquiresRunsAndReleasesOnOneDedicatedThread()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var factory = new RecordingFactory(handle);
        var mutex = new ProtectedUpdateMutex(factory);
        var callerThread = Environment.CurrentManagedThreadId;
        var actionThread = 0;

        var result = await mutex.RunExclusiveAsync(
            (_, _) =>
            {
                actionThread = Environment.CurrentManagedThreadId;
                return 42;
            },
            TimeSpan.FromSeconds(1),
            CancellationToken.None);

        result.Status.Should().Be(ProtectedUpdateMutexStatus.Acquired);
        result.Value.Should().Be(42);
        factory.OpenThread.Should().NotBe(callerThread);
        new[]
            {
                factory.OpenThread,
                handle.SecurityThread,
                handle.WaitThread,
                actionThread,
                handle.ReleaseThread,
                handle.DisposeThread
            }
            .Distinct()
            .Should().ContainSingle();
    }

    [Fact]
    public async Task RunExclusiveAsync_InvalidatesCapturedAuthorityBeforeReturning()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        ProtectedUpdateMutexContext? captured = null;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync(
                (context, _) =>
                {
                    captured = context;
                    context.IsActive.Should().BeTrue();
                    return 42;
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.Acquired);
        captured.Should().NotBeNull();
        captured!.IsActive.Should().BeFalse();
        handle.ReleaseThread.Should().NotBe(0);
    }

    [Fact]
    public async Task RunExclusiveAsync_InvalidatesNewLeasesThenWaitsForStartedLeaseBeforeRelease()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var started = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        ProtectedUpdateMutexContext? captured = null;
        IDisposable? heldLease = null;

        var pending = new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync(
                (context, _) =>
                {
                    captured = context;
                    context.TryAcquireLease(out var acquired)
                        .Should().BeTrue();
                    heldLease = acquired;
                    started.SetResult();
                    return 17;
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        SpinWait.SpinUntil(
                () => captured is not null && !captured.IsActive,
                TimeSpan.FromSeconds(2))
            .Should().BeTrue();
        captured!.TryAcquireLease(out var rejected)
            .Should().BeFalse();
        rejected.Should().BeNull();
        pending.IsCompleted.Should().BeFalse();
        handle.ReleaseThread.Should().Be(0);

        heldLease!.Dispose();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.Acquired);
        handle.ReleaseThread.Should().NotBe(0);
    }

    [Fact]
    public async Task ContextMutationGate_QueuesStartedLeasesAndInvalidationWaitsForBoth()
    {
        var context = new ProtectedUpdateMutexContext(
            wasAbandoned: false);
        context.TryAcquireLease(out var firstAuthority)
            .Should().BeTrue();
        context.TryAcquireLease(out var secondAuthority)
            .Should().BeTrue();
        var firstMutation = context.AcquireMutationLease();
        var secondAcquired = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var releaseSecond = new ManualResetEventSlim();
        var second = Task.Run(
            () =>
            {
                using (secondAuthority)
                using (context.AcquireMutationLease())
                {
                    secondAcquired.SetResult();
                    releaseSecond.Wait(
                            TimeSpan.FromSeconds(5))
                        .Should().BeTrue();
                }
            });
        var invalidation = Task.Run(
            context.InvalidateAndWaitForLeases);

        SpinWait.SpinUntil(
                () => !context.IsActive,
                TimeSpan.FromSeconds(2))
            .Should().BeTrue();
        invalidation.IsCompleted.Should().BeFalse();

        firstMutation.Dispose();
        firstAuthority!.Dispose();
        await secondAcquired.Task.WaitAsync(
            TimeSpan.FromSeconds(2));
        invalidation.IsCompleted.Should().BeFalse();

        releaseSecond.Set();
        await second.WaitAsync(TimeSpan.FromSeconds(2));
        await invalidation.WaitAsync(TimeSpan.FromSeconds(2));
        context.TryAcquireLease(out var rejected)
            .Should().BeFalse();
        rejected.Should().BeNull();
    }

    [Fact]
    public async Task RunExclusiveAsync_SupportsAsyncWorkWhileTheDedicatedThreadRetainsMutexOwnership()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var factory = new RecordingFactory(handle);
        var actionStartedThread = 0;

        var result = await new ProtectedUpdateMutex(factory)
            .RunExclusiveAsync(
                async (_, _) =>
                {
                    actionStartedThread =
                        Environment.CurrentManagedThreadId;
                    await Task.Yield();
                    return 84;
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.Acquired);
        result.Value.Should().Be(84);
        actionStartedThread.Should().Be(factory.OpenThread);
        new[]
            {
                factory.OpenThread,
                handle.SecurityThread,
                handle.WaitThread,
                handle.ReleaseThread,
                handle.DisposeThread
            }
            .Distinct()
            .Should().ContainSingle();
    }

    [Fact]
    public async Task RunExclusiveAsync_DoesNotReleaseUntilAsyncWorkCompletes()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var started = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var pending = new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync(
                async (_, _) =>
                {
                    started.SetResult();
                    await finish.Task;
                    return 91;
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        pending.IsCompleted.Should().BeFalse();
        handle.ReleaseThread.Should().Be(0);

        finish.SetResult();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        result.Status.Should().Be(ProtectedUpdateMutexStatus.Acquired);
        result.Value.Should().Be(91);
        handle.ReleaseThread.Should().NotBe(0);
    }

    [Fact]
    public async Task RunExclusiveAsync_RejectsNestedTaskResultWithoutInvokingAction()
    {
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity())))
            .RunExclusiveAsync<Task<int>>(
                (Func<ProtectedUpdateMutexContext, CancellationToken, Task<int>>)
                ((_, _) =>
                {
                    actionCalled = true;
                    return Task.FromResult(1);
                }),
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeFalse();
        actionCalled.Should().BeFalse();
    }

    [Fact]
    public async Task RunExclusiveAsync_RejectsNestedAsyncTaskResultWithoutInvokingAction()
    {
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity())))
            .RunExclusiveAsync<Task<int>>(
                (_, _) =>
                {
                    actionCalled = true;
                    return Task.FromResult(Task.FromResult(1));
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeFalse();
        actionCalled.Should().BeFalse();
    }

    [Fact]
    public async Task RunExclusiveAsync_RejectsValueTaskResultWithoutInvokingAction()
    {
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity())))
            .RunExclusiveAsync<ValueTask<int>>(
                (_, _) =>
                {
                    actionCalled = true;
                    return ValueTask.FromResult(1);
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeFalse();
        actionCalled.Should().BeFalse();
    }

    [Fact]
    public async Task RunExclusiveAsync_RejectsCustomAwaitableResultWithoutInvokingAction()
    {
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity())))
            .RunExclusiveAsync<CustomAwaitable>(
                (_, _) =>
                {
                    actionCalled = true;
                    return new CustomAwaitable();
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeFalse();
        actionCalled.Should().BeFalse();
    }

    [Fact]
    public async Task RunExclusiveAsync_BoxedTaskResultCannotOutliveMutexRelease()
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var innerStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finishInner = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var inner = CompleteInnerAsync();

        var pending = new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync<object>(
                (_, _) => Task.FromResult<object>(inner),
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        await innerStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Delay(50);
        pending.IsCompleted.Should().BeFalse();
        handle.ReleaseThread.Should().Be(0);

        finishInner.SetResult();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeTrue();
        handle.ReleaseThread.Should().NotBe(0);

        async Task CompleteInnerAsync()
        {
            innerStarted.SetResult();
            await finishInner.Task;
        }
    }

    [Theory]
    [InlineData("task")]
    [InlineData("value-task")]
    [InlineData("value-task-result")]
    [InlineData("custom")]
    public async Task RunExclusiveAsync_BoxedRuntimeAwaitableIsDrainedBeforeAuthorityInvalidationAndRelease(
        string awaitableKind)
    {
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            ProtectedUpdateMutex.BuildSecurity());
        var innerStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finishInner = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        ProtectedUpdateMutexContext? captured = null;

        var pending = new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync<object>(
                (context, _) =>
                {
                    captured = context;
                    object awaitable = awaitableKind switch
                    {
                        "task" => HoldLeaseAndFailAsync(context),
                        "value-task" => new ValueTask(
                            HoldLeaseAndFailAsync(context)),
                        "value-task-result" => new ValueTask<int>(
                            HoldLeaseAndFailWithResultAsync(context)),
                        "custom" => new RuntimeCustomAwaitable(
                            HoldLeaseAndFailAsync(context)),
                        _ => throw new InvalidOperationException()
                    };
                    return Task.FromResult(awaitable);
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        await innerStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        try
        {
            await Task.Delay(50);
            captured.Should().NotBeNull();
            captured!.IsActive.Should().BeTrue(
                "runtime awaitables must finish before authority invalidation starts");
            pending.IsCompleted.Should().BeFalse();
            handle.ReleaseThread.Should().Be(0);
        }
        finally
        {
            finishInner.TrySetResult();
        }

        var result = await pending.WaitAsync(TimeSpan.FromSeconds(2));

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.InvalidRequest);
        result.ActionInvoked.Should().BeTrue();
        captured.IsActive.Should().BeFalse();
        handle.ReleaseThread.Should().NotBe(0);

        async Task HoldLeaseAndFailAsync(
            ProtectedUpdateMutexContext context)
        {
            context.TryAcquireLease(out var lease)
                .Should().BeTrue();
            using (lease)
            {
                innerStarted.TrySetResult();
                await finishInner.Task;
                throw new IOException("nested failure");
            }
        }

        async Task<int> HoldLeaseAndFailWithResultAsync(
            ProtectedUpdateMutexContext context)
        {
            await HoldLeaseAndFailAsync(context);
            return 1;
        }
    }
    [Fact]
    public async Task RunExclusiveAsync_RecordsActionInvocationIndependentlyOfFailureStatus()
    {
        var actionFailed = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity())))
            .RunExclusiveAsync<int>(
                (Func<ProtectedUpdateMutexContext, CancellationToken, int>)
                ((_, _) => throw new InvalidOperationException()),
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        var releaseFailed = await new ProtectedUpdateMutex(
                new RecordingFactory(
                    new RecordingHandle(
                        ProtectedMutexWaitOutcome.Acquired,
                        ProtectedUpdateMutex.BuildSecurity(),
                        new IOException("release failed"))))
            .RunExclusiveAsync(
                (_, _) => 1,
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        actionFailed.Status.Should().Be(
            ProtectedUpdateMutexStatus.ActionFailed);
        actionFailed.ActionInvoked.Should().BeTrue();
        releaseFailed.Status.Should().Be(
            ProtectedUpdateMutexStatus.ReleaseFailed);
        releaseFailed.ActionInvoked.Should().BeTrue();
    }

    [Fact]
    public async Task RunExclusiveAsync_DistinguishesBusyTimeoutCancelledAndAbandoned()
    {
        var busyActionCalled = false;
        var busy = await RunWithOutcome(
            ProtectedMutexWaitOutcome.Busy,
            () => busyActionCalled = true,
            TimeSpan.Zero);
        var timedOutActionCalled = false;
        var timedOut = await RunWithOutcome(
            ProtectedMutexWaitOutcome.Busy,
            () => timedOutActionCalled = true,
            TimeSpan.FromMilliseconds(1));
        var cancelledActionCalled = false;
        var cancelled = await RunWithOutcome(
            ProtectedMutexWaitOutcome.Cancelled,
            () => cancelledActionCalled = true);
        var abandonedActionCalled = false;
        var abandoned = await RunWithOutcome(
            ProtectedMutexWaitOutcome.Abandoned,
            () => abandonedActionCalled = true);

        busy.Status.Should().Be(ProtectedUpdateMutexStatus.Busy);
        busyActionCalled.Should().BeFalse();
        timedOut.Status.Should().Be(ProtectedUpdateMutexStatus.TimedOut);
        timedOutActionCalled.Should().BeFalse();
        cancelled.Status.Should().Be(ProtectedUpdateMutexStatus.Cancelled);
        cancelledActionCalled.Should().BeFalse();
        abandoned.Status.Should().Be(
            ProtectedUpdateMutexStatus.AbandonedAcquired);
        abandonedActionCalled.Should().BeTrue();
    }

    [Fact]
    public async Task RunExclusiveAsync_RejectsWeakExistingSecurityBeforeWaitingOrRunning()
    {
        var weak = ProtectedUpdateMutex.BuildSecurity();
        weak.AddAccessRule(new MutexAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            MutexRights.FullControl,
            AccessControlType.Allow));
        var handle = new RecordingHandle(
            ProtectedMutexWaitOutcome.Acquired,
            weak);
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync(
                (_, _) =>
                {
                    actionCalled = true;
                    return 1;
                },
                TimeSpan.FromSeconds(1),
                CancellationToken.None);

        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.SecurityMismatch);
        actionCalled.Should().BeFalse();
        handle.WaitThread.Should().Be(0);
        handle.ReleaseThread.Should().Be(0);
        handle.DisposeThread.Should().NotBe(0);
    }

    [Fact(Skip = "Requires elevated Windows privileged CI.")]
    public async Task RunExclusiveAsync_CrossProcessContenderCannotAcquireWhileActionRuns_WhenTokenCanCreateExactMutex()
    {
        var mutex = new ProtectedUpdateMutex();

        var result = await mutex.RunExclusiveAsync(
            (_, _) => RunRawContender(),
            TimeSpan.FromSeconds(2),
            CancellationToken.None);
        result.Status.Should().Be(ProtectedUpdateMutexStatus.Acquired);
        result.Value.Should().Be(23);
    }

    [Fact(Skip = "Requires elevated Windows privileged CI.")]
    public async Task RunExclusiveAsync_RejectsAWeakPreexistingGlobalMutex_WhenTokenCanInspectIt()
    {
        using var weak = new Mutex(
            initiallyOwned: false,
            ProtectedUpdateMutex.Name,
            out _);
        var actionCalled = false;

        var result = await new ProtectedUpdateMutex().RunExclusiveAsync(
            (_, _) =>
            {
                actionCalled = true;
                return 1;
            },
            TimeSpan.Zero,
            CancellationToken.None);
        result.Status.Should().Be(
            ProtectedUpdateMutexStatus.SecurityMismatch);
        actionCalled.Should().BeFalse();
    }

    private static async Task<ProtectedUpdateMutexResult<bool>> RunWithOutcome(
        ProtectedMutexWaitOutcome outcome,
        Action action,
        TimeSpan? timeout = null)
    {
        var handle = new RecordingHandle(
            outcome,
            ProtectedUpdateMutex.BuildSecurity());
        return await new ProtectedUpdateMutex(
                new RecordingFactory(handle))
            .RunExclusiveAsync(
                (_, _) =>
                {
                    action();
                    return true;
                },
                timeout ?? TimeSpan.FromSeconds(1),
                CancellationToken.None);
    }

    private static int RunRawContender()
    {
        var script = """
            $mutex = [System.Threading.Mutex]::OpenExisting('Global\WireguardSplitTunnel.UpdateTransaction')
            try {
                if ($mutex.WaitOne(0)) {
                    $mutex.ReleaseMutex()
                    exit 0
                }
                exit 23
            }
            finally {
                $mutex.Dispose()
            }
            """;
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList =
            {
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script
            }
        }) ?? throw new InvalidOperationException(
            "Unable to start the mutex contender.");
        process.WaitForExit(milliseconds: 5000).Should().BeTrue();
        return process.ExitCode;
    }

    private static IReadOnlyList<MutexAccessRule> Rules(
        MutexSecurity security) =>
        security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier))
            .Cast<MutexAccessRule>()
            .ToArray();

    private static MutexSecurity MutexSecurityFromSddl(string sddl)
    {
        var raw = new RawSecurityDescriptor(sddl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new MutexSecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private static MutexSecurity MutexSecurityFromRawAcl(RawAcl acl)
    {
        var raw = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.DiscretionaryAclProtected
                | ControlFlags.SelfRelative,
            System,
            group: null,
            systemAcl: null,
            discretionaryAcl: acl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new MutexSecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private sealed class RecordingFactory(
        RecordingHandle handle)
        : IProtectedUpdateMutexFactory
    {
        public int OpenThread { get; private set; }

        public ProtectedMutexOpenResult Open(
            string name,
            MutexSecurity security)
        {
            OpenThread = Environment.CurrentManagedThreadId;
            name.Should().Be(ProtectedUpdateMutex.Name);
            ProtectedUpdateMutex.HasExactSecurity(security)
                .Should().BeTrue();
            return ProtectedMutexOpenResult.Opened(handle);
        }
    }

    private readonly struct CustomAwaitable
    {
        public TaskAwaiter<int> GetAwaiter() =>
            Task.FromResult(1).GetAwaiter();
    }

    private readonly struct RuntimeCustomAwaitable(Task task)
    {
        public TaskAwaiter GetAwaiter() => task.GetAwaiter();
    }
    private sealed class RecordingHandle(
        ProtectedMutexWaitOutcome waitOutcome,
        MutexSecurity security,
        Exception? releaseException = null)
        : IProtectedUpdateMutexHandle
    {
        private readonly ConcurrentQueue<int> _securityThreads = new();

        public int SecurityThread =>
            _securityThreads.TryPeek(out var value) ? value : 0;

        public int WaitThread { get; private set; }
        public int ReleaseThread { get; private set; }
        public int DisposeThread { get; private set; }

        public MutexSecurity ReadSecurity()
        {
            _securityThreads.Enqueue(
                Environment.CurrentManagedThreadId);
            return security;
        }

        public ProtectedMutexWaitOutcome Wait(
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            WaitThread = Environment.CurrentManagedThreadId;
            return waitOutcome;
        }

        public void Release()
        {
            ReleaseThread = Environment.CurrentManagedThreadId;
            if (releaseException is not null)
            {
                throw releaseException;
            }
        }

        public void Dispose()
        {
            DisposeThread = Environment.CurrentManagedThreadId;
        }
    }
}
