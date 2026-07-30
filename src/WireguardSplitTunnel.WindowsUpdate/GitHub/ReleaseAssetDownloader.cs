using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;

namespace WireguardSplitTunnel.WindowsUpdate.GitHub;

public enum ReleaseAssetDownloadStatus
{
    Success,
    InvalidRequest,
    InvalidRedirect,
    TooManyRedirects,
    HttpFailure,
    ContentTooLarge,
    LengthMismatch,
    EmptyContent,
    DestinationExists,
    TotalTimedOut,
    NoProgressTimedOut,
    NetworkFailure,
    FileFailure
}

public sealed record ReleaseAssetDownloadResult(ReleaseAssetDownloadStatus Status, string DetailCode)
{
    internal static ReleaseAssetDownloadResult Success() => new(ReleaseAssetDownloadStatus.Success, "ok");
    internal static ReleaseAssetDownloadResult Failure(ReleaseAssetDownloadStatus status, string code) => new(status, code);
}

internal interface IReleaseAssetDownloader
{
    Task<ReleaseAssetDownloadResult> DownloadArchiveAsync(SelectedWindowsRelease release, LocalUpdateLayout layout, CancellationToken cancellationToken);
    Task<ReleaseAssetDownloadResult> DownloadChecksumAsync(SelectedWindowsRelease release, LocalUpdateLayout layout, CancellationToken cancellationToken);
}

public sealed class ReleaseAssetDownloader : IReleaseAssetDownloader, IDisposable
{
    private readonly HttpClient _client;
    private readonly UpdateNetworkSettings _settings;
    private readonly TimeProvider _timeProvider;
    private readonly LocalUpdatePaths _localUpdatePaths;
    private readonly IDownloadFileSystem _files;
    private readonly bool _ownsClient;

    public static ReleaseAssetDownloader CreateProduction()
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        var client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("WireguardSplitTunnel-Updater", NormalizedAssemblyVersion()));
        return new ReleaseAssetDownloader(
            client,
            UpdateNetworkSettings.Default,
            TimeProvider.System,
            new LocalUpdatePaths(),
            new SecureDownloadFileSystem(),
            ownsClient: true);
    }

    internal ReleaseAssetDownloader(
        HttpClient client,
        UpdateNetworkSettings settings,
        TimeProvider timeProvider,
        LocalUpdatePaths localUpdatePaths)
        : this(client, settings, timeProvider, localUpdatePaths, new SecureDownloadFileSystem(), ownsClient: false)
    {
    }

    internal ReleaseAssetDownloader(
        HttpClient client,
        UpdateNetworkSettings settings,
        TimeProvider timeProvider,
        LocalUpdatePaths localUpdatePaths,
        IDownloadFileSystem files)
        : this(client, settings, timeProvider, localUpdatePaths, files, ownsClient: false)
    {
    }

    internal ReleaseAssetDownloader(
        HttpClient client,
        UpdateNetworkSettings settings,
        TimeProvider timeProvider,
        LocalUpdatePaths localUpdatePaths,
        IDownloadFileSystem files,
        bool ownsClient)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _localUpdatePaths = localUpdatePaths ?? throw new ArgumentNullException(nameof(localUpdatePaths));
        _files = files ?? throw new ArgumentNullException(nameof(files));
        _ownsClient = ownsClient;
    }

    public Task<ReleaseAssetDownloadResult> DownloadArchiveAsync(
        SelectedWindowsRelease release,
        LocalUpdateLayout layout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (release is null)
        {
            return Task.FromResult(ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.InvalidRequest, "release_contract"));
        }

        return DownloadAsync(
            release,
            layout,
            release.ArchiveUrl,
            UpdateReleaseContract.WindowsAssetName,
            release.ArchiveSize,
            _settings.ArchiveBytes,
            static value => value.ArchivePath,
            cancellationToken);
    }

    public Task<ReleaseAssetDownloadResult> DownloadChecksumAsync(
        SelectedWindowsRelease release,
        LocalUpdateLayout layout,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (release is null)
        {
            return Task.FromResult(ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.InvalidRequest, "release_contract"));
        }

        return DownloadAsync(
            release,
            layout,
            release.ChecksumUrl,
            UpdateReleaseContract.WindowsChecksumAssetName,
            exactSize: null,
            _settings.ChecksumBytes,
            static value => value.ChecksumPath,
            cancellationToken);
    }

    private async Task<ReleaseAssetDownloadResult> DownloadAsync(
        SelectedWindowsRelease release,
        LocalUpdateLayout layout,
        Uri url,
        string assetName,
        long? exactSize,
        long maximumSize,
        Func<LocalUpdateLayout, string> selectDestination,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var layoutValidation = _localUpdatePaths.TryValidateLayout(layout);
        if (layout is null
            || layout.Version != release.Version
            || !layoutValidation.Success
            || layoutValidation.Layout is null)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.InvalidRequest, "layout_contract");
        }

        var trustedLayout = layoutValidation.Layout;

        var tag = "v" + release.Version;
        if (!GitHubReleaseUrlPolicy.IsValidInitialAssetUrl(url, tag, assetName)
            || maximumSize <= 0
            || (exactSize.HasValue && (exactSize <= 0 || exactSize > maximumSize)))
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.InvalidRequest, "release_contract");
        }

        DownloadDestination destination;
        try
        {
            if (!_files.TryCaptureDestination(selectDestination(trustedLayout), out destination))
            {
                return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "unsafe_destination");
            }
        }
        catch (Exception exception) when (IsExpectedFileException(exception))
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "unsafe_destination");
        }

        HttpResponseMessage? response = null;
        DownloadFileLease? lease = null;
        var committed = false;
        using var total = new Deadline(_timeProvider, _settings.DownloadTimeout);
        using var progress = new Deadline(_timeProvider, _settings.NoProgressTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, total.Token, progress.Token);

        try
        {
            var current = url;
            for (var redirects = 0; ; redirects++)
            {
                response?.Dispose();
                response = null;
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                if (!_client.DefaultRequestHeaders.UserAgent.Any())
                {
                    request.Headers.UserAgent.Add(new ProductInfoHeaderValue("WireguardSplitTunnel-Updater", NormalizedAssemblyVersion()));
                }
                response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
                progress.Reset(_settings.NoProgressTimeout);

                if (IsRedirect(response.StatusCode))
                {
                    if (redirects >= _settings.MaximumRedirects)
                    {
                        return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.TooManyRedirects, "redirect_limit");
                    }

                    var location = response.Headers.Location;
                    if (location is null
                        || !location.IsAbsoluteUri
                        || !GitHubReleaseUrlPolicy.IsValidRedirectTarget(location, redirects + 1))
                    {
                        return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.InvalidRedirect, "redirect_target");
                    }

                    current = location;
                    continue;
                }

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.HttpFailure, "http_status");
                }

                if (response.Content.Headers.ContentLength is long declared)
                {
                    if (declared > maximumSize)
                    {
                        return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.ContentTooLarge, "declared_length");
                    }

                    if (declared <= 0)
                    {
                        return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.EmptyContent, "declared_length");
                    }

                    if (exactSize.HasValue && declared != exactSize.Value)
                    {
                        return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.LengthMismatch, "declared_length");
                    }
                }

                bool safeDestination;
                try
                {
                    safeDestination = _files.IsSafeDestination(destination);
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    safeDestination = false;
                }

                if (!_localUpdatePaths.TryValidateLayout(trustedLayout).Success || !safeDestination)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "destination_changed");
                }

                DownloadFileOpenResult open;
                try
                {
                    open = _files.OpenNew(destination);
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "file_open");
                }
                if (open.Status == DownloadFileOpenStatus.Exists)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.DestinationExists, "destination_exists");
                }

                if (open.Status != DownloadFileOpenStatus.Opened || open.Lease is null)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "file_open");
                }

                lease = open.Lease;
                bool safeOpenFile;
                try
                {
                    safeOpenFile = _files.IsSafeOpenFile(lease, destination);
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    safeOpenFile = false;
                }

                if (!safeOpenFile)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "opened_path_changed");
                }

                await using var input = await response.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
                var bytes = await CopyBoundedAsync(
                    input,
                    lease.Stream,
                    maximumSize,
                    progress,
                    _settings.NoProgressTimeout,
                    linked.Token).ConfigureAwait(false);

                if (bytes == 0)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.EmptyContent, "empty_content");
                }

                if (exactSize.HasValue && bytes != exactSize.Value)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.LengthMismatch, "actual_length");
                }

                using var flushLinked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, total.Token);
                try
                {
                    await _files.FlushToDiskAsync(lease, flushLinked.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    throw new DownloadFileException(exception);
                }

                flushLinked.Token.ThrowIfCancellationRequested();
                try
                {
                    safeOpenFile = _files.IsSafeOpenFile(lease, destination);
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    safeOpenFile = false;
                }

                if (!_localUpdatePaths.TryValidateLayout(trustedLayout).Success || !safeOpenFile)
                {
                    return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "committed_path_changed");
                }

                try
                {
                    if (!_files.CommitOwned(lease))
                    {
                        return ReleaseAssetDownloadResult.Failure(
                            ReleaseAssetDownloadStatus.FileFailure,
                            "file_commit");
                    }
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                    throw new DownloadFileException(exception);
                }

                committed = true;
                return ReleaseAssetDownloadResult.Success();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (total.HasElapsed)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.TotalTimedOut, "total_timeout");
        }
        catch (OperationCanceledException) when (progress.HasElapsed)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.NoProgressTimedOut, "progress_timeout");
        }
        catch (OperationCanceledException)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.TotalTimedOut, "request_timeout");
        }
        catch (InvalidDataException)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.ContentTooLarge, "streamed_size");
        }
        catch (DownloadFileException)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.FileFailure, "file_io");
        }
        catch (DownloadTransportException)
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.NetworkFailure, "transport");
        }
        catch (Exception exception) when (IsExpectedTransportException(exception))
        {
            return ReleaseAssetDownloadResult.Failure(ReleaseAssetDownloadStatus.NetworkFailure, "transport");
        }
        finally
        {
            try
            {
                response?.Dispose();
            }
            catch (Exception exception) when (IsExpectedTransportException(exception))
            {
            }

            if (lease is not null)
            {
                if (!committed)
                {
                    try
                    {
                        _files.DeleteOwned(lease);
                    }
                    catch (Exception exception) when (IsExpectedFileException(exception))
                    {
                    }
                }

                try
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception) when (IsExpectedFileException(exception))
                {
                }
            }

            destination.Dispose();
        }
    }

    private static bool IsRedirect(HttpStatusCode status) => status is HttpStatusCode.Moved
        or HttpStatusCode.Found
        or HttpStatusCode.SeeOther
        or HttpStatusCode.TemporaryRedirect
        or HttpStatusCode.PermanentRedirect;

    private static async Task<long> CopyBoundedAsync(
        Stream input,
        Stream output,
        long maximum,
        Deadline progress,
        TimeSpan noProgressTimeout,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        long total = 0;
        while (true)
        {
            int read;
            try
            {
                read = await input.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (IsExpectedTransportException(exception))
            {
                throw new DownloadTransportException(exception);
            }

            if (read == 0)
            {
                return total;
            }

            if (total > maximum - read)
            {
                throw new InvalidDataException();
            }

            try
            {
                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (IsExpectedFileException(exception))
            {
                throw new DownloadFileException(exception);
            }

            total += read;
            progress.Reset(noProgressTimeout);
        }
    }

    private static bool IsExpectedTransportException(Exception exception) => exception is HttpRequestException
        or IOException
        or NotSupportedException
        or ObjectDisposedException
        or InvalidOperationException
        or SecurityException;

    private static bool IsExpectedFileException(Exception exception) => exception is IOException
        or UnauthorizedAccessException
        or ArgumentException
        or NotSupportedException
        or ObjectDisposedException
        or InvalidOperationException
        or SecurityException;

    public void Dispose()
    {
        if (_ownsClient)
        {
            _client.Dispose();
        }
    }

    private static string NormalizedAssemblyVersion()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
        return $"{Math.Max(0, version.Major)}.{Math.Max(0, version.Minor)}.{Math.Max(0, version.Build)}";
    }

    private sealed class DownloadTransportException(Exception innerException) : Exception(null, innerException);
    private sealed class DownloadFileException(Exception innerException) : Exception(null, innerException);
}
