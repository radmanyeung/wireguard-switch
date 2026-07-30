namespace WireguardSplitTunnel.WindowsUpdate.Staging;

/// <summary>
/// Serializes side-effecting operations while allowing callers to detect
/// whether their completion still belongs to the latest requested operation.
/// </summary>
public sealed class LatestOperationSerializer
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _latestOperationId;

    public Operation Begin()
    {
        var operationId = Interlocked.Increment(
            ref _latestOperationId);
        return new Operation(this, operationId);
    }

    public long LatestGeneration =>
        Volatile.Read(ref _latestOperationId);

    private bool IsLatest(long operationId) =>
        LatestGeneration == operationId;

    private async Task RunSerializedAsync(
        Func<CancellationToken, Task> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);

        await _gate.WaitAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await action(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public sealed class Operation
    {
        private readonly LatestOperationSerializer _owner;
        private readonly long _operationId;

        internal Operation(
            LatestOperationSerializer owner,
            long operationId)
        {
            _owner = owner;
            _operationId = operationId;
        }

        public bool IsLatest =>
            _owner.IsLatest(_operationId);

        public long Generation => _operationId;

        internal LatestOperationSerializer Owner => _owner;

        public Task RunSerializedAsync(
            Func<CancellationToken, Task> action,
            CancellationToken cancellationToken = default) =>
            _owner.RunSerializedAsync(
                action,
                cancellationToken);
    }
}

/// <summary>
/// Assigns runtime status events to the operation that can have produced
/// them. The source generation is intentionally retained between serialized
/// operations so there is no nullable or unowned status window.
/// </summary>
public sealed class LatestOperationStatusGate
{
    private readonly LatestOperationSerializer _serializer;
    private readonly object _statusSync = new();
    private long _sourceGeneration;
    private bool _latestStatusIsBusy;

    public LatestOperationStatusGate(
        LatestOperationSerializer serializer)
    {
        _serializer = serializer
            ?? throw new ArgumentNullException(nameof(serializer));
        _sourceGeneration = serializer.LatestGeneration;
    }

    public void SetSource(
        LatestOperationSerializer.Operation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (!ReferenceEquals(operation.Owner, _serializer))
        {
            throw new ArgumentException(
                "The operation belongs to a different serializer.",
                nameof(operation));
        }

        lock (_statusSync)
        {
            _sourceGeneration = operation.Generation;
        }
    }

    public Stamp Capture()
    {
        lock (_statusSync)
        {
            return new Stamp(this, _sourceGeneration);
        }
    }

    public Stamp CaptureStatus(bool isBusy)
    {
        lock (_statusSync)
        {
            _latestStatusIsBusy = isBusy;
            return new Stamp(this, _sourceGeneration);
        }
    }

    public bool LatestStatusIsBusy
    {
        get
        {
            lock (_statusSync)
            {
                return _latestStatusIsBusy;
            }
        }
    }

    private bool IsLatest(long generation) =>
        _serializer.LatestGeneration == generation;

    public sealed class Stamp
    {
        private readonly LatestOperationStatusGate _owner;

        internal Stamp(
            LatestOperationStatusGate owner,
            long generation)
        {
            _owner = owner;
            Generation = generation;
        }

        public long Generation { get; }

        public bool IsLatest =>
            _owner.IsLatest(Generation);
    }
}
