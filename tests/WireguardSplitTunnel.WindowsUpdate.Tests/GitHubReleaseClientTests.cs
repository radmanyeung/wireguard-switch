using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.GitHub;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class GitHubReleaseClientTests
{
    [Fact]
    public async Task GetLatestAsync_UsesTheFixedEndpointAndStableUserAgent()
    {
        HttpRequestMessage? request = null;
        using var client = new HttpClient(new DelegateHandler(message =>
        {
            request = message;
            return Json(ValidReleaseJson());
        }));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        var result = await subject.GetLatestAsync(CancellationToken.None);

        result.Status.Should().Be(GitHubReleaseQueryStatus.Success);
        var captured = request!;
        captured.Method.Should().Be(HttpMethod.Get);
        captured.RequestUri.Should().Be(UpdateReleaseContract.LatestReleaseApiUri);
        captured.Headers.UserAgent.Should().ContainSingle();
        captured.Headers.UserAgent.Single().Product!.Name.Should().Be("WireguardSplitTunnel-Updater");
        captured.Headers.UserAgent.Single().Product!.Version.Should().MatchRegex("^\\d+\\.\\d+\\.\\d+$");
        captured.Headers.Accept.Should().ContainSingle()
            .Which.MediaType.Should().Be("application/vnd.github+json");
        captured.Headers.GetValues("X-GitHub-Api-Version")
            .Should().Equal("2022-11-28");
    }

    [Fact]
    public async Task GetLatestAsync_ParsesRequiredSnakeCaseFieldsAndToleratesUnknownProperties()
    {
        using var client = new HttpClient(new DelegateHandler(_ => Json(ValidReleaseJson("\"new_field\":true,"))));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        var result = await subject.GetLatestAsync(CancellationToken.None);

        result.Status.Should().Be(GitHubReleaseQueryStatus.Success);
        result.Release!.TagName.Should().Be("v1.2.4");
        result.Release.Assets.Should().ContainSingle();
        result.Release.Assets![0].BrowserDownloadUrl.Should().Be(new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip"));
        result.Release.Assets[0].Sha256.Should().Be(new string('a', 64));
    }

    [Theory]
    [InlineData("\"unknown\":1,\"unknown\":2,", false)]
    [InlineData("", true)]
    public async Task GetLatestAsync_RejectsDuplicatePropertyNamesIncludingUnknownFields(string rootPrefix, bool duplicateInAsset)
    {
        var assetPrefix = duplicateInAsset ? "\"unknown\":1,\"unknown\":2," : "";
        var json = $$$"""{"tag_name":"v1.2.4","draft":false,"prerelease":false,{{{rootPrefix}}}"assets":[{ {{{assetPrefix}}}"name":"wireguard-split-tunnel-win-x64.zip","browser_download_url":"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip","size":7,"digest":"sha256:{{{new string('a', 64)}}}"}]}""";
        using var client = new HttpClient(new DelegateHandler(_ => Json(json)));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        (await subject.GetLatestAsync(CancellationToken.None)).Status.Should().Be(GitHubReleaseQueryStatus.InvalidResponse);
    }

    [Theory]
    [InlineData("")]
    [InlineData(",\"digest\":null")]
    [InlineData(",\"digest\":\"sha256:abc\"")]
    [InlineData(",\"digest\":\"sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    [InlineData(",\"digest\":\"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"")]
    [InlineData(",\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"")]
    public async Task GetLatestAsync_RejectsMissingNullMalformedOrDuplicateArchiveDigest(
        string digestProperty)
    {
        var json =
            $$"""{"tag_name":"v1.2.4","draft":false,"prerelease":false,"assets":[{"name":"wireguard-split-tunnel-win-x64.zip","browser_download_url":"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip","size":7{{digestProperty}}}]}""";
        using var client = new HttpClient(
            new DelegateHandler(_ => Json(json)));
        var subject = new GitHubReleaseClient(
            client,
            UpdateNetworkSettings.Default,
            TimeProvider.System);

        (await subject.GetLatestAsync(CancellationToken.None))
            .Status.Should().Be(
                GitHubReleaseQueryStatus.InvalidResponse);
    }

    [Fact]
    public async Task GetLatestAsync_AllowsChecksumAssetWithoutADigestWhenArchiveDigestIsPresent()
    {
        var archiveDigest = new string('a', 64);
        var json =
            $$"""{"tag_name":"v1.2.4","draft":false,"prerelease":false,"assets":[{"name":"wireguard-split-tunnel-win-x64.zip","browser_download_url":"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip","size":7,"digest":"sha256:{{archiveDigest}}"},{"name":"wireguard-split-tunnel-win-x64.zip.sha256","browser_download_url":"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip.sha256","size":64}]}""";
        using var client = new HttpClient(
            new DelegateHandler(_ => Json(json)));
        var subject = new GitHubReleaseClient(
            client,
            UpdateNetworkSettings.Default,
            TimeProvider.System);

        var result = await subject.GetLatestAsync(
            CancellationToken.None);

        result.Status.Should().Be(
            GitHubReleaseQueryStatus.Success);
        result.Release!.Assets![1].Sha256.Should().BeNull();
    }

    [Theory]
    [InlineData("{", GitHubReleaseQueryStatus.InvalidResponse)]
    [InlineData("{\"tag_name\":1,\"draft\":false,\"prerelease\":false,\"assets\":[]}", GitHubReleaseQueryStatus.InvalidResponse)]
    public async Task GetLatestAsync_RejectsInvalidJsonOrRequiredFieldTypes(string json, GitHubReleaseQueryStatus expected)
    {
        using var client = new HttpClient(new DelegateHandler(_ => Json(json)));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        (await subject.GetLatestAsync(CancellationToken.None)).Status.Should().Be(expected);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, GitHubReleaseQueryStatus.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError, GitHubReleaseQueryStatus.HttpFailure)]
    [InlineData(HttpStatusCode.TooManyRequests, GitHubReleaseQueryStatus.RateLimited)]
    public async Task GetLatestAsync_MapsHttpFailuresWithoutExposingServerBody(HttpStatusCode status, GitHubReleaseQueryStatus expected)
    {
        using var client = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(status) { Content = new StringContent("secret server body") }));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        var result = await subject.GetLatestAsync(CancellationToken.None);

        result.Status.Should().Be(expected);
        result.DetailCode.Should().NotContain("secret");
    }

    [Fact]
    public async Task GetLatestAsync_MapsExhausted403ToRateLimit()
    {
        using var client = new HttpClient(new DelegateHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Forbidden);
            response.Headers.Add("X-RateLimit-Remaining", "0");
            return response;
        }));
        var subject = new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System);

        (await subject.GetLatestAsync(CancellationToken.None)).Status.Should().Be(GitHubReleaseQueryStatus.RateLimited);
    }

    [Fact]
    public async Task GetLatestAsync_RejectsDeclaredAndStreamedResponsesAboveTwoMiB()
    {
        var tooLarge = new byte[checked((int)UpdateNetworkLimits.MetadataBytes + 1)];
        using var declaredClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([1]) { Headers = { ContentLength = UpdateNetworkLimits.MetadataBytes + 1 } }
        }));
        using var streamedClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(tooLarge)
        }));

        (await new GitHubReleaseClient(declaredClient, UpdateNetworkSettings.Default, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status.Should().Be(GitHubReleaseQueryStatus.ResponseTooLarge);
        (await new GitHubReleaseClient(streamedClient, UpdateNetworkSettings.Default, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status.Should().Be(GitHubReleaseQueryStatus.ResponseTooLarge);
    }

    [Fact]
    public async Task GetLatestAsync_EnforcesZeroMaximumAndMaximumPlusOneBoundaries()
    {
        var payload = Encoding.UTF8.GetBytes(ValidReleaseJson());
        using var exactClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) }));
        var exactSettings = UpdateNetworkSettings.Default with { MetadataBytes = payload.Length };
        (await new GitHubReleaseClient(exactClient, exactSettings, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status
            .Should().Be(GitHubReleaseQueryStatus.Success);

        using var plusOneClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) }));
        var plusOneSettings = UpdateNetworkSettings.Default with { MetadataBytes = payload.Length - 1 };
        (await new GitHubReleaseClient(plusOneClient, plusOneSettings, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status
            .Should().Be(GitHubReleaseQueryStatus.ResponseTooLarge);

        using var zeroClient = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) }));
        var zeroSettings = UpdateNetworkSettings.Default with { MetadataBytes = 0 };
        (await new GitHubReleaseClient(zeroClient, zeroSettings, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status
            .Should().Be(GitHubReleaseQueryStatus.InvalidResponse);
    }

    [Theory]
    [InlineData("io")]
    [InlineData("not-supported")]
    [InlineData("disposed")]
    [InlineData("invalid-operation")]
    [InlineData("security")]
    public async Task GetLatestAsync_MapsExpectedMidstreamFailuresWithoutThrowing(string failure)
    {
        using var client = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new ThrowingReadStream(failure))
        }));

        var result = await new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System)
            .GetLatestAsync(CancellationToken.None);

        result.Status.Should().Be(GitHubReleaseQueryStatus.NetworkFailure);
    }

    [Fact]
    public async Task GetLatestAsync_DisposesResponseContent()
    {
        var content = new TrackingContent(ValidReleaseJson());
        using var client = new HttpClient(new DelegateHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = content }));

        (await new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System).GetLatestAsync(CancellationToken.None)).Status
            .Should().Be(GitHubReleaseQueryStatus.Success);
        content.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task GetLatestAsync_DistinguishesCallerCancellationFromDeadline()
    {
        using var callerClient = new HttpClient(new DelegateHandler(_ => throw new OperationCanceledException()));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var caller = new GitHubReleaseClient(callerClient, UpdateNetworkSettings.Default, TimeProvider.System);
        await caller.Invoking(x => x.GetLatestAsync(cancellation.Token)).Should().ThrowAsync<OperationCanceledException>();

        using var timeoutClient = new HttpClient(new DelegateHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return Json(ValidReleaseJson());
        }));
        var shortSettings = UpdateNetworkSettings.Default with { MetadataTimeout = TimeSpan.FromMilliseconds(10) };
        var timeout = new GitHubReleaseClient(timeoutClient, shortSettings, TimeProvider.System);
        (await timeout.GetLatestAsync(CancellationToken.None)).Status.Should().Be(GitHubReleaseQueryStatus.TimedOut);
    }

    [Fact]
    public void Settings_DefaultMapsEveryCoreNetworkConstant()
    {
        var settings = UpdateNetworkSettings.Default;
        settings.MetadataBytes.Should().Be(UpdateNetworkLimits.MetadataBytes);
        settings.ChecksumBytes.Should().Be(UpdateNetworkLimits.ChecksumBytes);
        settings.ArchiveBytes.Should().Be(UpdateNetworkLimits.ArchiveBytes);
        settings.MetadataTimeout.Should().Be(UpdateNetworkLimits.MetadataTimeout);
        settings.DownloadTimeout.Should().Be(UpdateNetworkLimits.DownloadTimeout);
        settings.NoProgressTimeout.Should().Be(UpdateNetworkLimits.NoProgressTimeout);
        settings.MaximumRedirects.Should().Be(UpdateNetworkLimits.MaximumRedirects);
    }

    [Fact]
    public void Dispose_DisposesOnlyAnOwnedHttpClient()
    {
        var injectedHandler = new TrackingHandler();
        var injectedClient = new HttpClient(injectedHandler);
        new GitHubReleaseClient(injectedClient, UpdateNetworkSettings.Default, TimeProvider.System).Dispose();
        injectedHandler.Disposed.Should().BeFalse();
        injectedClient.Dispose();

        var ownedHandler = new TrackingHandler();
        var ownedClient = new HttpClient(ownedHandler);
        new GitHubReleaseClient(ownedClient, UpdateNetworkSettings.Default, TimeProvider.System, ownsClient: true).Dispose();
        ownedHandler.Disposed.Should().BeTrue();
    }

    private static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string ValidReleaseJson(string prefix = "") => $$"""{"tag_name":"v1.2.4","draft":false,"prerelease":false,{{prefix}}"assets":[{"name":"wireguard-split-tunnel-win-x64.zip","browser_download_url":"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip","size":7,"digest":"sha256:{{new string('a', 64)}}"}]}""";

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
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            Disposed = disposing;
            base.Dispose(disposing);
        }
    }

    private sealed class TrackingContent(string json) : StringContent(json, Encoding.UTF8, "application/json")
    {
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing)
        {
            Disposed = disposing;
            base.Dispose(disposing);
        }
    }

    private sealed class ThrowingReadStream(string failure) : Stream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => failure switch
        {
            "io" => throw new IOException("stream"),
            "not-supported" => throw new NotSupportedException("stream"),
            "disposed" => throw new ObjectDisposedException("stream"),
            "invalid-operation" => throw new InvalidOperationException("stream"),
            "security" => throw new SecurityException("stream"),
            _ => throw new ArgumentOutOfRangeException(nameof(failure))
        };
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
}
