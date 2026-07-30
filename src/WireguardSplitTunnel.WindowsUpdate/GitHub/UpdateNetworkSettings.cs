using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.GitHub;

/// <summary>Immutable, injectable copy of the cross-platform network contract.</summary>
internal sealed record UpdateNetworkSettings(
    long MetadataBytes,
    long ChecksumBytes,
    long ArchiveBytes,
    TimeSpan MetadataTimeout,
    TimeSpan DownloadTimeout,
    TimeSpan NoProgressTimeout,
    int MaximumRedirects)
{
    public static UpdateNetworkSettings Default { get; } = new(
        UpdateNetworkLimits.MetadataBytes,
        UpdateNetworkLimits.ChecksumBytes,
        UpdateNetworkLimits.ArchiveBytes,
        UpdateNetworkLimits.MetadataTimeout,
        UpdateNetworkLimits.DownloadTimeout,
        UpdateNetworkLimits.NoProgressTimeout,
        UpdateNetworkLimits.MaximumRedirects);
}

internal sealed class Deadline : IDisposable
{
    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private readonly CancellationTokenSource _source = new();
    private ITimer? _timer;
    private long _generation;
    private bool _disposed;

    public Deadline(TimeProvider timeProvider, TimeSpan timeout)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        Reset(timeout);
    }

    public CancellationToken Token => _source.Token;
    public bool HasElapsed => _source.IsCancellationRequested;

    public void Reset(TimeSpan timeout)
    {
        ITimer? previous;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var generation = checked(++_generation);
            var timer = _timeProvider.CreateTimer(
                static state =>
                {
                    var callback = (DeadlineCallback)state!;
                    callback.Owner.TryCancel(callback.Generation);
                },
                new DeadlineCallback(this, generation),
                Timeout.InfiniteTimeSpan,
                Timeout.InfiniteTimeSpan);
            previous = _timer;
            _timer = timer;
            timer.Change(timeout, Timeout.InfiniteTimeSpan);
        }

        previous?.Dispose();
    }

    public void Dispose()
    {
        ITimer? timer;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _generation++;
            timer = _timer;
            _timer = null;
            _source.Dispose();
        }

        timer?.Dispose();
    }

    private void TryCancel(long generation)
    {
        lock (_gate)
        {
            if (!_disposed && generation == _generation)
            {
                _source.Cancel();
            }
        }
    }

    private sealed record DeadlineCallback(Deadline Owner, long Generation);
}
