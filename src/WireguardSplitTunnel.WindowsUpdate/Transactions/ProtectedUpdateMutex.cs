using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public enum ProtectedUpdateMutexStatus
{
    Acquired,
    AbandonedAcquired,
    Busy,
    TimedOut,
    Cancelled,
    SecurityMismatch,
    PrivilegeUnavailable,
    AccessDenied,
    Unavailable,
    ActionFailed,
    ReleaseFailed,
    InvalidRequest
}

public sealed record ProtectedUpdateMutexResult(
    ProtectedUpdateMutexStatus Status,
    bool ActionInvoked)
{
    public bool ActionExecuted => ActionInvoked;
}

internal sealed record ProtectedUpdateMutexResult<T>(
    ProtectedUpdateMutexStatus Status,
    T? Value,
    bool ActionInvoked)
{
    public bool ActionExecuted => ActionInvoked;

    internal static ProtectedUpdateMutexResult<T> Completed(
        ProtectedUpdateMutexStatus status,
        T value) =>
        new(status, value, ActionInvoked: true);

    internal static ProtectedUpdateMutexResult<T> Failed(
        ProtectedUpdateMutexStatus status,
        bool actionInvoked = false) =>
        new(status, default, actionInvoked);
}

public sealed class ProtectedUpdateMutexContext
{
    private readonly object _leaseGate = new();
    private readonly SemaphoreSlim _mutationGate = new(
        initialCount: 1,
        maxCount: 1);
    private bool _acceptingLeases = true;
    private int _leaseCount;

    internal ProtectedUpdateMutexContext(bool wasAbandoned)
    {
        WasAbandoned = wasAbandoned;
    }

    public bool WasAbandoned { get; }

    internal bool IsActive
    {
        get
        {
            lock (_leaseGate)
            {
                return _acceptingLeases;
            }
        }
    }

    internal bool TryAcquireLease(
        out ProtectedUpdateMutexAuthorityLease? lease)
    {
        lock (_leaseGate)
        {
            if (!_acceptingLeases)
            {
                lease = null;
                return false;
            }

            checked
            {
                _leaseCount++;
            }

            lease = new ProtectedUpdateMutexAuthorityLease(this);
            return true;
        }
    }

    internal void Invalidate() =>
        InvalidateAndWaitForLeases();

    internal void InvalidateAndWaitForLeases()
    {
        lock (_leaseGate)
        {
            _acceptingLeases = false;
            while (_leaseCount != 0)
            {
                Monitor.Wait(_leaseGate);
            }
        }
    }

    internal void ReleaseLease()
    {
        lock (_leaseGate)
        {
            if (_leaseCount <= 0)
            {
                throw new InvalidOperationException(
                    "The authority lease was released more than once.");
            }

            _leaseCount--;
            if (_leaseCount == 0)
            {
                Monitor.PulseAll(_leaseGate);
            }
        }
    }

    internal ProtectedUpdateMutexMutationLease
        AcquireMutationLease()
    {
        _mutationGate.Wait();
        return new ProtectedUpdateMutexMutationLease(this);
    }

    internal void ReleaseMutationLease() =>
        _mutationGate.Release();
}

internal sealed class ProtectedUpdateMutexMutationLease
    : IDisposable
{
    private ProtectedUpdateMutexContext? _owner;

    internal ProtectedUpdateMutexMutationLease(
        ProtectedUpdateMutexContext owner)
    {
        _owner = owner;
    }

    public void Dispose() =>
        Interlocked.Exchange(ref _owner, null)
            ?.ReleaseMutationLease();
}

internal sealed class ProtectedUpdateMutexAuthorityLease
    : IDisposable
{
    private ProtectedUpdateMutexContext? _owner;

    internal ProtectedUpdateMutexAuthorityLease(
        ProtectedUpdateMutexContext owner)
    {
        _owner = owner;
    }

    public void Dispose() =>
        Interlocked.Exchange(ref _owner, null)?.ReleaseLease();
}

internal enum ProtectedMutexWaitOutcome
{
    Acquired,
    Abandoned,
    Busy,
    Cancelled
}

internal interface IProtectedUpdateMutexHandle : IDisposable
{
    MutexSecurity ReadSecurity();

    ProtectedMutexWaitOutcome Wait(
        TimeSpan timeout,
        CancellationToken cancellationToken);

    void Release();
}

internal interface IProtectedUpdateMutexFactory
{
    ProtectedMutexOpenResult Open(
        string name,
        MutexSecurity security);
}

internal readonly record struct ProtectedMutexOpenResult(
    IProtectedUpdateMutexHandle? Handle,
    ProtectedUpdateMutexStatus Error)
{
    public bool Success => Handle is not null;

    public static ProtectedMutexOpenResult Opened(
        IProtectedUpdateMutexHandle handle) =>
        new(handle, ProtectedUpdateMutexStatus.Acquired);

    public static ProtectedMutexOpenResult Failed(
        ProtectedUpdateMutexStatus error) =>
        new(null, error);
}

/// <summary>
/// Executes protected update work under the one global Windows mutex. The
/// mutex is acquired, the action runs, and the mutex is released on one
/// dedicated OS thread.
/// </summary>
public sealed class ProtectedUpdateMutex
{
    public const string Name =
        @"Global\WireguardSplitTunnel.UpdateTransaction";

    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);

    private readonly IProtectedUpdateMutexFactory _factory;

    public ProtectedUpdateMutex()
        : this(new WindowsProtectedUpdateMutexFactory())
    {
    }

    internal ProtectedUpdateMutex(
        IProtectedUpdateMutexFactory factory)
    {
        _factory = factory
            ?? throw new ArgumentNullException(nameof(factory));
    }

    public async Task<ProtectedUpdateMutexResult> RunExclusiveAsync(
        Func<ProtectedUpdateMutexContext, CancellationToken, Task> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);

        var result = await RunExclusiveCoreAsync(
                async (context, token) =>
                {
                    await action(
                            context,
                            token)
                        .ConfigureAwait(false);
                    return true;
                },
                timeout,
                cancellationToken)
            .ConfigureAwait(false);
        return new ProtectedUpdateMutexResult(
            result.Status,
            result.ActionInvoked);
    }

    internal Task<ProtectedUpdateMutexResult<T>> RunExclusiveAsync<T>(
        Func<ProtectedUpdateMutexContext, CancellationToken, T> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);

        return RunExclusiveCoreAsync(
            (context, token) =>
                Task.FromResult(action(context, token)),
            timeout,
            cancellationToken);
    }

    internal Task<ProtectedUpdateMutexResult<T>> RunExclusiveAsync<T>(
        Func<ProtectedUpdateMutexContext, CancellationToken, Task<T>> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);

        return RunExclusiveCoreAsync(
            action,
            timeout,
            cancellationToken);
    }

    private Task<ProtectedUpdateMutexResult<T>> RunExclusiveCoreAsync<T>(
        Func<ProtectedUpdateMutexContext, CancellationToken, Task<T>> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!IsValidTimeout(timeout)
            || IsTaskLikeResultType(typeof(T)))
        {
            return Task.FromResult(
                ProtectedUpdateMutexResult<T>.Failed(
                    ProtectedUpdateMutexStatus.InvalidRequest));
        }

        return Task.Factory.StartNew(
            () => Execute(
                action,
                timeout,
                cancellationToken),
            CancellationToken.None,
            TaskCreationOptions.LongRunning
                | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default);
    }

    public static MutexSecurity BuildSecurity()
    {
        var security = new MutexSecurity();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(LocalSystem);
        security.AddAccessRule(
            new MutexAccessRule(
                Administrators,
                MutexRights.FullControl,
                AccessControlType.Allow));
        security.AddAccessRule(
            new MutexAccessRule(
                LocalSystem,
                MutexRights.FullControl,
                AccessControlType.Allow));
        return security;
    }

    internal static bool HasExactSecurity(
        MutexSecurity? security)
    {
        if (security is null
            || !security.AreAccessRulesProtected
            || !security.AreAccessRulesCanonical)
        {
            return false;
        }

        try
        {
            if (!LocalSystem.Equals(
                    security.GetOwner(
                        typeof(SecurityIdentifier))))
            {
                return false;
            }

            var descriptorBytes =
                security.GetSecurityDescriptorBinaryForm();
            var descriptor = new RawSecurityDescriptor(
                descriptorBytes,
                offset: 0);
            if ((descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclProtected) == 0
                || (descriptor.ControlFlags
                    & ControlFlags.DiscretionaryAclPresent) == 0
                || descriptor.DiscretionaryAcl is null
                || descriptor.DiscretionaryAcl.Count != 2
                || descriptor.Owner is not SecurityIdentifier owner
                || !LocalSystem.Equals(owner))
            {
                return false;
            }

            var identities = new HashSet<string>(
                StringComparer.Ordinal);
            foreach (GenericAce genericAce
                in descriptor.DiscretionaryAcl)
            {
                if (genericAce is not CommonAce ace
                    || ace.IsCallback
                    || ace.AceQualifier
                        != AceQualifier.AccessAllowed
                    || ace.AccessMask
                        != (int)MutexRights.FullControl
                    || ace.AceFlags != AceFlags.None
                    || ace.OpaqueLength != 0
                    || ace.SecurityIdentifier
                        is not SecurityIdentifier identity)
                {
                    return false;
                }

                identities.Add(identity.Value);
            }

            return identities.Count == 2
                && identities.Contains(Administrators.Value)
                && identities.Contains(LocalSystem.Value);
        }
        catch (Exception exception) when (
            exception is IdentityNotMappedException
                or InvalidOperationException
                or ArgumentException
                or SecurityException)
        {
            return false;
        }
    }

    private ProtectedUpdateMutexResult<T> Execute<T>(
        Func<ProtectedUpdateMutexContext, CancellationToken, Task<T>> action,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ProtectedUpdateMutexResult<T>.Failed(
                ProtectedUpdateMutexStatus.Cancelled);
        }

        ProtectedMutexOpenResult opened;
        try
        {
            opened = _factory.Open(Name, BuildSecurity());
        }
        catch (Exception exception) when (
            IsOrdinaryMutexFailure(exception))
        {
            return ProtectedUpdateMutexResult<T>.Failed(
                MapFailure(exception));
        }

        if (!opened.Success || opened.Handle is null)
        {
            return ProtectedUpdateMutexResult<T>.Failed(
                opened.Error);
        }

        using var handle = opened.Handle;
        try
        {
            if (!HasExactSecurity(handle.ReadSecurity()))
            {
                return ProtectedUpdateMutexResult<T>.Failed(
                    ProtectedUpdateMutexStatus.SecurityMismatch);
            }

            var wait = handle.Wait(
                timeout,
                cancellationToken);
            if (wait == ProtectedMutexWaitOutcome.Busy)
            {
                return ProtectedUpdateMutexResult<T>.Failed(
                    timeout == TimeSpan.Zero
                        ? ProtectedUpdateMutexStatus.Busy
                        : ProtectedUpdateMutexStatus.TimedOut);
            }

            if (wait == ProtectedMutexWaitOutcome.Cancelled)
            {
                return ProtectedUpdateMutexResult<T>.Failed(
                    ProtectedUpdateMutexStatus.Cancelled);
            }

            var wasAbandoned =
                wait == ProtectedMutexWaitOutcome.Abandoned;
            ProtectedUpdateMutexStatus status;
            T? value = default;
            var actionInvoked = false;
            var context = new ProtectedUpdateMutexContext(
                wasAbandoned);
            try
            {
                actionInvoked = true;
                value = action(
                        context,
                        cancellationToken)
                    .GetAwaiter()
                    .GetResult();
                if (TryDrainRuntimeAwaitable(value))
                {
                    status = ProtectedUpdateMutexStatus.InvalidRequest;
                }
                else
                {
                    status = wasAbandoned
                        ? ProtectedUpdateMutexStatus.AbandonedAcquired
                        : ProtectedUpdateMutexStatus.Acquired;
                }
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                status = ProtectedUpdateMutexStatus.Cancelled;
            }
            catch (Exception)
            {
                status = ProtectedUpdateMutexStatus.ActionFailed;
            }
            finally
            {
                context.InvalidateAndWaitForLeases();
            }

            try
            {
                handle.Release();
            }
            catch (Exception exception) when (
                IsOrdinaryMutexFailure(exception))
            {
                return ProtectedUpdateMutexResult<T>.Failed(
                    ProtectedUpdateMutexStatus.ReleaseFailed,
                    actionInvoked);
            }

            return status is ProtectedUpdateMutexStatus.Acquired
                    or ProtectedUpdateMutexStatus.AbandonedAcquired
                ? ProtectedUpdateMutexResult<T>.Completed(
                    status,
                    value!)
                : ProtectedUpdateMutexResult<T>.Failed(
                    status,
                    actionInvoked);
        }
        catch (Exception exception) when (
            IsOrdinaryMutexFailure(exception))
        {
            return ProtectedUpdateMutexResult<T>.Failed(
                MapFailure(exception));
        }
    }

    private static bool IsValidTimeout(TimeSpan timeout) =>
        timeout == Timeout.InfiniteTimeSpan
        || timeout >= TimeSpan.Zero
        && timeout.TotalMilliseconds <= int.MaxValue;

    private static bool IsTaskLikeResultType(Type type)
    {
        if (typeof(Task).IsAssignableFrom(type)
            || type == typeof(ValueTask)
            || type.IsGenericType
            && type.GetGenericTypeDefinition() == typeof(ValueTask<>)
            || type.IsDefined(
                typeof(AsyncMethodBuilderAttribute),
                inherit: false))
        {
            return true;
        }

        return type
            .GetMethods(
                BindingFlags.Instance
                    | BindingFlags.Public
                    | BindingFlags.FlattenHierarchy)
            .Any(method =>
                method.Name == "GetAwaiter"
                && !method.IsGenericMethod
                && method.GetParameters().Length == 0);
    }

    private static bool TryDrainRuntimeAwaitable<T>(T? value)
    {
        if (value is null)
        {
            return false;
        }

        var boxed = (object)value;
        var runtimeType = boxed.GetType();
        if (!IsTaskLikeResultType(runtimeType))
        {
            return false;
        }

        try
        {
            DrainRuntimeAwaitable(boxed, runtimeType);
        }
        catch (Exception)
        {
            // The outer request is invalid regardless of how the nested
            // awaitable completes. Draining it first prevents its work from
            // escaping the authority and mutex lifetime.
        }

        return true;
    }

    private static void DrainRuntimeAwaitable(
        object awaitable,
        Type runtimeType)
    {
        if (awaitable is Task task)
        {
            task.GetAwaiter().GetResult();
            return;
        }

        if (awaitable is ValueTask valueTask)
        {
            valueTask.AsTask().GetAwaiter().GetResult();
            return;
        }

        if (runtimeType.IsGenericType
            && runtimeType.GetGenericTypeDefinition()
                == typeof(ValueTask<>))
        {
            var asTask = runtimeType.GetMethod(
                "AsTask",
                BindingFlags.Instance | BindingFlags.Public,
                binder: null,
                types: Type.EmptyTypes,
                modifiers: null);
            if (asTask?.Invoke(awaitable, null) is not Task nestedTask)
            {
                throw new InvalidOperationException(
                    "The boxed ValueTask did not expose a Task.");
            }

            nestedTask.GetAwaiter().GetResult();
            return;
        }

        var getAwaiter = runtimeType.GetMethod(
            "GetAwaiter",
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            types: Type.EmptyTypes,
            modifiers: null);
        var awaiter = getAwaiter?.Invoke(awaitable, null)
            ?? throw new InvalidOperationException(
                "The runtime awaitable returned no awaiter.");
        var awaiterType = awaiter.GetType();
        var isCompletedProperty = awaiterType.GetProperty(
            "IsCompleted",
            BindingFlags.Instance | BindingFlags.Public);
        if (isCompletedProperty?.PropertyType != typeof(bool)
            || isCompletedProperty.GetValue(awaiter)
                is not bool isCompleted)
        {
            throw new InvalidOperationException(
                "The runtime awaiter has no boolean IsCompleted property.");
        }

        if (!isCompleted)
        {
            using var completed = new ManualResetEventSlim();
            Action continuation = completed.Set;
            if (awaiter is ICriticalNotifyCompletion critical)
            {
                critical.UnsafeOnCompleted(continuation);
            }
            else if (awaiter is INotifyCompletion notifying)
            {
                notifying.OnCompleted(continuation);
            }
            else
            {
                throw new InvalidOperationException(
                    "The runtime awaiter cannot register a continuation.");
            }

            completed.Wait();
        }

        var getResult = awaiterType.GetMethod(
            "GetResult",
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            types: Type.EmptyTypes,
            modifiers: null)
            ?? throw new InvalidOperationException(
                "The runtime awaiter has no GetResult method.");
        _ = getResult.Invoke(awaiter, null);
    }

    private static bool IsOrdinaryMutexFailure(
        Exception exception) =>
        exception is UnauthorizedAccessException
            or SecurityException
            or PrivilegeNotHeldException
            or WaitHandleCannotBeOpenedException
            or IOException
            or InvalidOperationException
            or ArgumentException
            or ObjectDisposedException
            or Win32Exception
            or PlatformNotSupportedException;

    private static ProtectedUpdateMutexStatus MapFailure(
        Exception exception) =>
        exception is UnauthorizedAccessException
            or SecurityException
            or PrivilegeNotHeldException
            ? ProtectedUpdateMutexStatus.AccessDenied
            : ProtectedUpdateMutexStatus.Unavailable;
}

internal sealed class WindowsProtectedUpdateMutexFactory
    : IProtectedUpdateMutexFactory
{
    public ProtectedMutexOpenResult Open(
        string name,
        MutexSecurity security)
    {
        if (!WindowsRestorePrivilegeScope.TryEnable(
                out var privilege))
        {
            return ProtectedMutexOpenResult.Failed(
                ProtectedUpdateMutexStatus.PrivilegeUnavailable);
        }

        try
        {
            Mutex mutex;
            using (privilege)
            {
                mutex = MutexAcl.Create(
                    initiallyOwned: false,
                    name,
                    out _,
                    security);
            }

            return ProtectedMutexOpenResult.Opened(
                new WindowsProtectedUpdateMutexHandle(
                    name,
                    mutex));
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException
                or SecurityException
                or PrivilegeNotHeldException)
        {
            return ProtectedMutexOpenResult.Failed(
                ProtectedUpdateMutexStatus.AccessDenied);
        }
        catch (Exception exception) when (
            exception is WaitHandleCannotBeOpenedException
                or IOException
                or InvalidOperationException
                or ArgumentException
                or Win32Exception
                or PlatformNotSupportedException)
        {
            return ProtectedMutexOpenResult.Failed(
                ProtectedUpdateMutexStatus.Unavailable);
        }
    }
}

internal sealed class WindowsProtectedUpdateMutexHandle
    : IProtectedUpdateMutexHandle
{
    private readonly string _name;
    private readonly Mutex _mutex;

    public WindowsProtectedUpdateMutexHandle(
        string name,
        Mutex mutex)
    {
        _name = name;
        _mutex = mutex;
    }

    public MutexSecurity ReadSecurity() =>
        new(
            _name,
            AccessControlSections.Owner
                | AccessControlSections.Access);

    public ProtectedMutexWaitOutcome Wait(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        try
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return ProtectedMutexWaitOutcome.Cancelled;
            }

            if (!cancellationToken.CanBeCanceled)
            {
                return _mutex.WaitOne(timeout)
                    ? ProtectedMutexWaitOutcome.Acquired
                    : ProtectedMutexWaitOutcome.Busy;
            }

            var index = WaitHandle.WaitAny(
                [_mutex, cancellationToken.WaitHandle],
                timeout);
            return index switch
            {
                0 => ProtectedMutexWaitOutcome.Acquired,
                1 => ProtectedMutexWaitOutcome.Cancelled,
                WaitHandle.WaitTimeout =>
                    ProtectedMutexWaitOutcome.Busy,
                _ => ProtectedMutexWaitOutcome.Busy
            };
        }
        catch (AbandonedMutexException)
        {
            return ProtectedMutexWaitOutcome.Abandoned;
        }
    }

    public void Release() => _mutex.ReleaseMutex();

    public void Dispose() => _mutex.Dispose();
}
