using Microsoft.Win32.SafeHandles;
using System.Net;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.GitHub;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ReleaseAssetDownloaderTests
{
    [Fact]
    public void Deadline_ResetIgnoresACallbackAlreadyQueuedByThePreviousGeneration()
    {
        var time = new ControlledTimeProvider();
        using var deadline = new Deadline(time, TimeSpan.FromMinutes(1));
        var stale = time.Timers.Single();

        deadline.Reset(TimeSpan.FromMinutes(2));
        var current = time.Timers.Last();

        stale.FireQueuedCallback();
        deadline.HasElapsed.Should().BeFalse();

        current.FireQueuedCallback();
        deadline.HasElapsed.Should().BeTrue();
    }

    [Fact]
    public void Deadline_DisposeMakesAQueuedCallbackHarmless()
    {
        var time = new ControlledTimeProvider();
        var deadline = new Deadline(time, TimeSpan.FromMinutes(1));
        var queued = time.Timers.Single();

        deadline.Dispose();

        queued.Invoking(timer => timer.FireQueuedCallback()).Should().NotThrow();
    }

    [Fact]
    public async Task DownloadArchiveAsync_UsesOnlyTheValidatedLayoutPathAndMatchingVersion()
    {
        using var fixture = new DownloadFixture();
        var otherLayout = fixture.Paths.EnsureStaging(new SemanticVersion(1, 2, 5)).Layout!;
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));
        var subject = fixture.Subject(client);

        var mismatch = await subject.DownloadArchiveAsync(Release(1), otherLayout, CancellationToken.None);
        var success = await subject.DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        mismatch.Status.Should().Be(ReleaseAssetDownloadStatus.InvalidRequest);
        success.Status.Should().Be(ReleaseAssetDownloadStatus.Success);
        File.ReadAllBytes(fixture.Layout.ArchivePath).Should().Equal(1);
    }

    [Theory]
    [InlineData("\\\\server\\share\\archive.zip")]
    [InlineData("Z:\\mapped\\archive.zip")]
    [InlineData("C:\\outside-staging\\archive.zip")]
    public async Task DownloadArchiveAsync_RejectsForgedMappedOrOutsideStagingPaths(string archivePath)
    {
        using var fixture = new DownloadFixture();
        var expected = fixture.Layout;
        var forged = new LocalUpdateLayout(
            expected.Version,
            expected.ProductRoot,
            expected.MetadataPath,
            expected.UpdatesRoot,
            expected.VersionRoot,
            expected.StagingRoot,
            archivePath,
            expected.ChecksumPath,
            expected.CandidateRoot,
            expected.ManifestPath);
        var calls = 0;
        using var client = Client(_ => { calls++; return Bytes(HttpStatusCode.OK, [1]); });

        var result = await fixture.Subject(client).DownloadArchiveAsync(Release(1), forged, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.InvalidRequest);
        calls.Should().Be(0);
    }

    [Fact]
    public async Task DownloadArchiveAsync_UsesStableUserAgentAndDisposesFinalResponse()
    {
        using var fixture = new DownloadFixture();
        HttpRequestMessage? request = null;
        var content = new TrackingContent([1]);
        using var client = Client(message =>
        {
            request = message;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });

        (await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.Success);
        var captured = request!;
        captured.Headers.UserAgent.Should().ContainSingle();
        captured.Headers.UserAgent.Single().Product!.Name.Should().Be("WireguardSplitTunnel-Updater");
        captured.Headers.UserAgent.Single().Product!.Version.Should().MatchRegex("^\\d+\\.\\d+\\.\\d+$");
        content.Disposed.Should().BeTrue();
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.SeeOther)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task DownloadArchiveAsync_FollowsEveryAllowedRedirectStatusAndDisposesHop(HttpStatusCode status)
    {
        using var fixture = new DownloadFixture();
        var hopContent = new TrackingContent();
        var calls = 0;
        using var client = Client(_ =>
        {
            if (calls++ == 0)
            {
                var response = new HttpResponseMessage(status) { Content = hopContent };
                response.Headers.Location = new Uri("https://objects.githubusercontent.com/asset?token=opaque");
                return response;
            }

            return Bytes(HttpStatusCode.OK, [1]);
        });

        (await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.Success);
        calls.Should().Be(2);
        hopContent.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task DownloadArchiveAsync_AllowsExactlyFiveRedirects()
    {
        using var fixture = new DownloadFixture();
        var calls = 0;
        using var client = Client(_ => calls++ < UpdateNetworkLimits.MaximumRedirects
            ? Redirect($"https://objects.githubusercontent.com/asset?hop={calls}")
            : Bytes(HttpStatusCode.OK, [1]));

        var result = await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.Success);
        calls.Should().Be(UpdateNetworkLimits.MaximumRedirects + 1);
    }

    [Theory]
    [InlineData("http://github.com/a")]
    [InlineData("https://evil.example/a")]
    [InlineData("/relative")]
    [InlineData("https://user@github.com/a")]
    [InlineData("https://github.com:444/a")]
    [InlineData("https://github.com/a#fragment")]
    public async Task DownloadArchiveAsync_RejectsInvalidRedirectTargets(string location)
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Redirect(location));

        var result = await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.InvalidRedirect);
    }

    [Fact]
    public async Task DownloadArchiveAsync_RejectsSixthRedirect()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Redirect("https://github.com/a"));

        (await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.TooManyRedirects);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task DownloadArchiveAsync_MapsEveryNonSuccessTerminalStatus(HttpStatusCode status)
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => new HttpResponseMessage(status));

        (await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.HttpFailure);
    }

    [Theory]
    [InlineData(0, ReleaseAssetDownloadStatus.InvalidRequest)]
    [InlineData(3, ReleaseAssetDownloadStatus.Success)]
    [InlineData(4, ReleaseAssetDownloadStatus.InvalidRequest)]
    public async Task DownloadArchiveAsync_EnforcesZeroMaximumAndMaximumPlusOne(long selectedSize, ReleaseAssetDownloadStatus expected)
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1, 2, 3]));
        var settings = UpdateNetworkSettings.Default with { ArchiveBytes = 3 };

        var result = await fixture.Subject(client, settings).DownloadArchiveAsync(Release(selectedSize), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(expected);
    }

    [Fact]
    public async Task DownloadArchiveAsync_EnforcesDeclaredAndActualExactLength()
    {
        using var declaredFixture = new DownloadFixture();
        using var declaredClient = Client(_ => Bytes(HttpStatusCode.OK, [1], declared: 2));
        (await declaredFixture.Subject(declaredClient).DownloadArchiveAsync(Release(1), declaredFixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.LengthMismatch);

        using var actualFixture = new DownloadFixture();
        using var actualClient = Client(_ => Bytes(HttpStatusCode.OK, [1, 2]));
        (await actualFixture.Subject(actualClient).DownloadArchiveAsync(Release(1), actualFixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.LengthMismatch);
    }

    [Fact]
    public async Task DownloadChecksumAsync_UsesTheLayoutChecksumPathAndRejectsStreamAboveLimit()
    {
        using var fixture = new DownloadFixture();
        var settings = UpdateNetworkSettings.Default with { ChecksumBytes = 3 };
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1, 2, 3, 4]));

        var result = await fixture.Subject(client, settings).DownloadChecksumAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.ContentTooLarge);
        File.Exists(fixture.Layout.ChecksumPath).Should().BeFalse();
    }

    [Fact]
    public async Task DownloadArchiveAsync_CreateNewPreservesExistingDestination()
    {
        using var fixture = new DownloadFixture();
        await File.WriteAllBytesAsync(fixture.Layout.ArchivePath, [9]);
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));

        var result = await fixture.Subject(client).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.DestinationExists);
        File.ReadAllBytes(fixture.Layout.ArchivePath).Should().Equal(9);
    }

    [Fact]
    public async Task DownloadArchiveAsync_RevalidatesParentImmediatelyBeforeOpen()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));
        var files = new FakeDownloadFileSystem { SafeBeforeOpen = false };

        var result = await fixture.Subject(client, files: files).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.FileFailure);
        files.OpenCalls.Should().Be(0);
    }

    [Fact]
    public async Task DownloadArchiveAsync_PostOpenSwapDeletesOnlyTheOwnedHandle()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));
        var files = new FakeDownloadFileSystem { SafeOpenFile = false, ReplacementPresent = true };

        var result = await fixture.Subject(client, files: files).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.FileFailure);
        files.OwnedHandleDeleted.Should().BeTrue();
        files.ReplacementPresent.Should().BeTrue("cleanup must never delete a path replacement");
    }

    [Fact]
    public async Task DownloadArchiveAsync_MapsExpectedFileOpenFailures()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));
        var files = new FakeDownloadFileSystem { OpenException = new UnauthorizedAccessException("denied") };

        var result = await fixture.Subject(client, files: files).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.FileFailure);
    }

    [Fact]
    public async Task DownloadArchiveAsync_DistinguishesTotalAndNoProgressTimeouts()
    {
        using var totalFixture = new DownloadFixture();
        using var totalClient = Client(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return Bytes(HttpStatusCode.OK, [1]);
        });
        var totalSettings = UpdateNetworkSettings.Default with { DownloadTimeout = TimeSpan.FromMilliseconds(30), NoProgressTimeout = TimeSpan.FromSeconds(5) };
        (await totalFixture.Subject(totalClient, totalSettings).DownloadArchiveAsync(Release(1), totalFixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.TotalTimedOut);

        using var progressFixture = new DownloadFixture();
        using var progressClient = Client(_ => Stream(new BlockingAfterFirstByteStream()));
        var progressSettings = UpdateNetworkSettings.Default with { DownloadTimeout = TimeSpan.FromSeconds(5), NoProgressTimeout = TimeSpan.FromMilliseconds(30) };
        (await progressFixture.Subject(progressClient, progressSettings).DownloadArchiveAsync(Release(2), progressFixture.Layout, CancellationToken.None)).Status
            .Should().Be(ReleaseAssetDownloadStatus.NoProgressTimedOut);
        File.Exists(progressFixture.Layout.ArchivePath).Should().BeFalse();
    }

    [Fact]
    public async Task DownloadArchiveAsync_RethrowsMidstreamCallerCancellationAndDeletesPartial()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Stream(new BlockingAfterFirstByteStream()));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));

        await fixture.Subject(client).Invoking(subject => subject.DownloadArchiveAsync(Release(2), fixture.Layout, cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();
        File.Exists(fixture.Layout.ArchivePath).Should().BeFalse();
    }

    [Fact]
    public async Task DownloadArchiveAsync_MapsThrowingResponseStreamAndDeletesPartial()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Stream(new ThrowingAfterFirstByteStream()));

        var result = await fixture.Subject(client).DownloadArchiveAsync(Release(2), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.NetworkFailure);
        File.Exists(fixture.Layout.ArchivePath).Should().BeFalse();
    }

    [Fact]
    public async Task DownloadArchiveAsync_TotalDeadlineCoversDurableFlush()
    {
        using var fixture = new DownloadFixture();
        using var client = Client(_ => Bytes(HttpStatusCode.OK, [1]));
        var files = new FakeDownloadFileSystem { BlockFlushUntilCancellation = true };
        var settings = UpdateNetworkSettings.Default with { DownloadTimeout = TimeSpan.FromMilliseconds(30), NoProgressTimeout = TimeSpan.FromSeconds(5) };

        var result = await fixture.Subject(client, settings, files).DownloadArchiveAsync(Release(1), fixture.Layout, CancellationToken.None);

        result.Status.Should().Be(ReleaseAssetDownloadStatus.TotalTimedOut);
        files.OwnedHandleDeleted.Should().BeTrue();
    }

    [Fact]
    public async Task SecureFileSystem_PinsTheStagingDirectoryAcrossRelativeCreate()
    {
        using var fixture = new DownloadFixture();
        var files = new SecureDownloadFileSystem();
        files.TryCaptureDestination(fixture.Layout.ArchivePath, out var destination).Should().BeTrue();
        using (destination)
        {
            var moved = fixture.Layout.StagingRoot + ".moved";
            Action swap = () => Directory.Move(fixture.Layout.StagingRoot, moved);
            swap.Should().Throw<IOException>(
                "the no-delete-share directory chain must remain pinned until create completes");

            var opened = files.OpenNew(destination);
            opened.Status.Should().Be(DownloadFileOpenStatus.Opened);
            var lease = opened.Lease!;
            try
            {
                await lease.Stream.WriteAsync(new byte[] { 1 });
                await files.FlushToDiskAsync(lease, CancellationToken.None);
                files.CommitOwned(lease).Should().BeTrue();
            }
            finally
            {
                await lease.DisposeAsync();
            }
        }

        File.ReadAllBytes(fixture.Layout.ArchivePath).Should().Equal(1);
    }

    [Fact]
    public async Task SecureFileSystem_LeavesAnUncommittedPartialDeletePending()
    {
        using var fixture = new DownloadFixture();
        var files = new SecureDownloadFileSystem();
        files.TryCaptureDestination(fixture.Layout.ArchivePath, out var destination).Should().BeTrue();
        using (destination)
        {
            var opened = files.OpenNew(destination);
            opened.Status.Should().Be(DownloadFileOpenStatus.Opened);
            await opened.Lease!.Stream.WriteAsync(new byte[] { 1 });
            await opened.Lease.DisposeAsync();
        }

        File.Exists(fixture.Layout.ArchivePath).Should().BeFalse(
            "a crash or exceptional exit closes the exact delete-pending handle");
    }

    [Fact]
    public async Task SecureFileSystem_WriteThroughFlushHonorsAnAlreadyCancelledToken()
    {
        using var fixture = new DownloadFixture();
        var files = new SecureDownloadFileSystem();
        files.TryCaptureDestination(fixture.Layout.ArchivePath, out var destination).Should().BeTrue();
        using (destination)
        {
            var opened = files.OpenNew(destination);
            opened.Status.Should().Be(DownloadFileOpenStatus.Opened);
            var lease = opened.Lease!;
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            await files.Invoking(subject => subject.FlushToDiskAsync(lease, cancellation.Token).AsTask())
                .Should().ThrowAsync<OperationCanceledException>();

            files.DeleteOwned(lease);
            await lease.DisposeAsync();
        }
    }

    [Fact]
    public async Task SecureFileSystem_DeleteOwnedReportsTheNativeDispositionFailure()
    {
        using var fixture = new DownloadFixture();
        var disposition = new RecordingDownloadFileDisposition();
        var files = new SecureDownloadFileSystem(new WindowsPinnedLocalDirectoryService(), disposition);
        files.TryCaptureDestination(fixture.Layout.ArchivePath, out var destination).Should().BeTrue();
        using (destination)
        {
            var opened = files.OpenNew(destination);
            opened.Status.Should().Be(DownloadFileOpenStatus.Opened);
            var lease = opened.Lease!;
            files.CommitOwned(lease).Should().BeTrue();
            disposition.FailDelete = true;

            Action delete = () => files.DeleteOwned(lease);

            delete.Should().Throw<IOException>();
            await lease.DisposeAsync();
        }
    }

    [Fact]
    public void Dispose_DisposesOnlyAnOwnedHttpClient()
    {
        using var fixture = new DownloadFixture();
        var injectedHandler = new TrackingHandler();
        var injectedClient = new HttpClient(injectedHandler);
        fixture.Subject(injectedClient).Dispose();
        injectedHandler.Disposed.Should().BeFalse();
        injectedClient.Dispose();

        var ownedHandler = new TrackingHandler();
        var ownedClient = new HttpClient(ownedHandler);
        new ReleaseAssetDownloader(ownedClient, UpdateNetworkSettings.Default, TimeProvider.System, fixture.Paths, new SecureDownloadFileSystem(), ownsClient: true).Dispose();
        ownedHandler.Disposed.Should().BeTrue();
    }

    private static SelectedWindowsRelease Release(long size) => new(
        new SemanticVersion(1, 2, 4),
        new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip"),
        new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip.sha256"),
        size,
        new string('a', 64));

    private static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> send) => new(new DelegateHandler(send));
    private static HttpClient Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => new(new DelegateHandler(send));
    private static HttpResponseMessage Redirect(string value) { var response = new HttpResponseMessage(HttpStatusCode.Found); response.Headers.TryAddWithoutValidation("Location", value); return response; }
    private static HttpResponseMessage Bytes(HttpStatusCode status, byte[] bytes, long? declared = null) { var response = new HttpResponseMessage(status) { Content = new ByteArrayContent(bytes) }; if (declared.HasValue) response.Content.Headers.ContentLength = declared; return response; }
    private static HttpResponseMessage Stream(System.IO.Stream stream) => new(HttpStatusCode.OK) { Content = new StreamContent(stream) };

    private sealed class DownloadFixture : IDisposable
    {
        private readonly TemporaryDirectory _directory = new();
        public DownloadFixture()
        {
            Paths = new LocalUpdatePaths(_directory.Path, new WindowsPathSafetyInspector(), _ => DriveType.Fixed);
            Layout = Paths.EnsureStaging(new SemanticVersion(1, 2, 4)).Layout!;
        }
        public LocalUpdatePaths Paths { get; }
        public LocalUpdateLayout Layout { get; }
        public ReleaseAssetDownloader Subject(HttpClient client, UpdateNetworkSettings? settings = null, IDownloadFileSystem? files = null) =>
            new(client, settings ?? UpdateNetworkSettings.Default, TimeProvider.System, Paths, files ?? new SecureDownloadFileSystem());
        public void Dispose() => _directory.Dispose();
    }

    private sealed class FakeDownloadFileSystem : IDownloadFileSystem
    {
        private readonly FakeDownloadFileLease _lease = new();
        public bool SafeBeforeOpen { get; init; } = true;
        public bool SafeOpenFile { get; init; } = true;
        public bool ReplacementPresent { get; set; }
        public bool BlockFlushUntilCancellation { get; init; }
        public Exception? OpenException { get; init; }
        public int OpenCalls { get; private set; }
        public bool OwnedHandleDeleted { get; private set; }
        public bool TryCaptureDestination(string path, out DownloadDestination destination)
        {
            destination = new DownloadDestination(Path.GetFullPath(path), Path.GetDirectoryName(Path.GetFullPath(path))!);
            return true;
        }
        public bool IsSafeDestination(DownloadDestination destination) => SafeBeforeOpen;
        public DownloadFileOpenResult OpenNew(DownloadDestination destination)
        {
            OpenCalls++;
            if (OpenException is not null) throw OpenException;
            return DownloadFileOpenResult.Opened(_lease);
        }
        public bool IsSafeOpenFile(DownloadFileLease lease, DownloadDestination destination) => SafeOpenFile;
        public async ValueTask FlushToDiskAsync(DownloadFileLease lease, CancellationToken cancellationToken)
        {
            if (BlockFlushUntilCancellation) await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        public bool CommitOwned(DownloadFileLease lease) => true;
        public void DeleteOwned(DownloadFileLease lease) => OwnedHandleDeleted = true;
    }

    private sealed class RecordingDownloadFileDisposition : IDownloadFileDisposition
    {
        public bool FailDelete { get; set; }

        public bool TrySetDeletePending(
            SafeFileHandle handle,
            bool deletePending,
            out int error)
        {
            error = FailDelete && deletePending ? 5 : 0;
            return error == 0;
        }
    }

    private sealed class FakeDownloadFileLease : DownloadFileLease
    {
        private readonly MemoryStream _stream = new();
        public override System.IO.Stream Stream => _stream;
        public override ValueTask DisposeAsync() { _stream.Dispose(); return ValueTask.CompletedTask; }
    }

    private class BlockingAfterFirstByteStream : System.IO.Stream
    {
        private bool _sent;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_sent) { _sent = true; buffer.Span[0] = 1; return 1; }
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ThrowingAfterFirstByteStream : BlockingAfterFirstByteStream
    {
        private int _reads;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_reads++ == 0) { buffer.Span[0] = 1; return ValueTask.FromResult(1); }
            throw new IOException("midstream");
        }
    }

    private sealed class TrackingContent : ByteArrayContent
    {
        public TrackingContent(byte[]? bytes = null) : base(bytes ?? []) { }
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing) { Disposed = disposing; base.Dispose(disposing); }
    }

    private sealed class DelegateHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        public DelegateHandler(Func<HttpRequestMessage, HttpResponseMessage> send) => _send = (request, _) => Task.FromResult(send(request));
        public DelegateHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => _send(request, cancellationToken);
    }

    private sealed class TrackingHandler : HttpMessageHandler
    {
        public bool Disposed { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { Disposed = disposing; base.Dispose(disposing); }
    }

    private sealed class ControlledTimeProvider : TimeProvider
    {
        public List<ControlledTimer> Timers { get; } = [];

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            var timer = new ControlledTimer(callback, state, dueTime, period);
            Timers.Add(timer);
            return timer;
        }
    }

    private sealed class ControlledTimer(
        TimerCallback callback,
        object? state,
        TimeSpan dueTime,
        TimeSpan period) : ITimer
    {
        public TimeSpan DueTime { get; private set; } = dueTime;
        public TimeSpan Period { get; private set; } = period;
        public bool IsDisposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException(nameof(ControlledTimer));
            }

            DueTime = dueTime;
            Period = period;
            return true;
        }

        public void FireQueuedCallback() => callback(state);

        public void Dispose() => IsDisposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory() { Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "WireguardSplitTunnel.DownloadTests", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Path); }
        public string Path { get; }
        public void Dispose() { try { Directory.Delete(Path, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    }
}
