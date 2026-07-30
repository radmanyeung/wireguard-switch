using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security;
using System.Text.Json;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.GitHub;

public enum GitHubReleaseQueryStatus
{
    Success,
    NotFound,
    RateLimited,
    HttpFailure,
    NetworkFailure,
    InvalidResponse,
    ResponseTooLarge,
    TimedOut
}

public sealed record GitHubReleaseQueryResult(
    GitHubReleaseQueryStatus Status,
    GitHubReleaseMetadata? Release,
    string DetailCode)
{
    internal static GitHubReleaseQueryResult Success(GitHubReleaseMetadata release) => new(GitHubReleaseQueryStatus.Success, release, "ok");
    internal static GitHubReleaseQueryResult Failure(GitHubReleaseQueryStatus status, string detailCode) => new(status, null, detailCode);
}

internal interface IGitHubReleaseClient
{
    Task<GitHubReleaseQueryResult> GetLatestAsync(CancellationToken cancellationToken);
}

public sealed class GitHubReleaseClient : IGitHubReleaseClient, IDisposable
{
    private static readonly string[] RequiredReleaseProperties = ["tag_name", "draft", "prerelease", "assets"];
    private static readonly string[] RequiredAssetProperties = ["name", "browser_download_url", "size"];
    private readonly HttpClient _client;
    private readonly UpdateNetworkSettings _settings;
    private readonly TimeProvider _timeProvider;
    private readonly bool _ownsClient;

    public static GitHubReleaseClient CreateProduction()
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        var client = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("WireguardSplitTunnel-Updater", NormalizedAssemblyVersion()));
        return new GitHubReleaseClient(client, UpdateNetworkSettings.Default, TimeProvider.System, ownsClient: true);
    }

    internal GitHubReleaseClient(HttpClient client, UpdateNetworkSettings settings, TimeProvider timeProvider)
        : this(client, settings, timeProvider, ownsClient: false)
    {
    }

    internal GitHubReleaseClient(HttpClient client, UpdateNetworkSettings settings, TimeProvider timeProvider, bool ownsClient)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _ownsClient = ownsClient;
    }

    public async Task<GitHubReleaseQueryResult> GetLatestAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new Deadline(_timeProvider, _settings.MetadataTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, UpdateReleaseContract.LatestReleaseApiUri);
            if (!_client.DefaultRequestHeaders.UserAgent.Any())
            {
                request.Headers.UserAgent.Add(new ProductInfoHeaderValue("WireguardSplitTunnel-Updater", NormalizedAssemblyVersion()));
            }
            request.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue(
                    "application/vnd.github+json"));
            request.Headers.TryAddWithoutValidation(
                "X-GitHub-Api-Version",
                "2022-11-28");

            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound) return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.NotFound, "not_found");
            if (response.StatusCode == HttpStatusCode.TooManyRequests || (response.StatusCode == HttpStatusCode.Forbidden && response.Headers.TryGetValues("X-RateLimit-Remaining", out var values) && values.Any(value => value == "0")))
                return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.RateLimited, "rate_limited");
            if (response.StatusCode != HttpStatusCode.OK) return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.HttpFailure, "http_status");
            if (response.Content.Headers.ContentLength is long contentLength && contentLength > _settings.MetadataBytes)
                return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.ResponseTooLarge, "declared_size");

            await using var stream = await response.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
            var bytes = await ReadBoundedAsync(stream, _settings.MetadataBytes, linked.Token).ConfigureAwait(false);
            return TryParseRelease(bytes, out var release)
                ? GitHubReleaseQueryResult.Success(release!)
                : GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.InvalidResponse, "invalid_json");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (deadline.HasElapsed)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.TimedOut, "metadata_timeout");
        }
        catch (OperationCanceledException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.TimedOut, "request_timeout");
        }
        catch (InvalidDataException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.ResponseTooLarge, "streamed_size");
        }
        catch (JsonException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.InvalidResponse, "invalid_json");
        }
        catch (HttpRequestException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.NetworkFailure, "transport");
        }
        catch (IOException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.NetworkFailure, "transport");
        }
        catch (Exception exception) when (exception is NotSupportedException
            or ObjectDisposedException
            or InvalidOperationException
            or SecurityException)
        {
            return GitHubReleaseQueryResult.Failure(GitHubReleaseQueryStatus.NetworkFailure, "transport");
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, long maximum, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0) return output.ToArray();
            if (output.Length > maximum - count) throw new InvalidDataException();
            output.Write(buffer, 0, count);
        }
    }

    private static bool TryParseRelease(byte[] bytes, out GitHubReleaseMetadata? release)
    {
        release = null;
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || !HasUniquePropertyNames(root)
            || !HasOneRequiredPropertyOfType(root, RequiredReleaseProperties, [JsonValueKind.String, JsonValueKind.True, JsonValueKind.True, JsonValueKind.Array])) return false;
        var draft = root.GetProperty("draft");
        var prerelease = root.GetProperty("prerelease");
        if (draft.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || prerelease.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        var assets = new List<GitHubReleaseAsset>();
        foreach (var asset in root.GetProperty("assets").EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object
                || !HasUniquePropertyNames(asset)
                || !HasOneRequiredPropertyOfType(asset, RequiredAssetProperties, [JsonValueKind.String, JsonValueKind.String, JsonValueKind.Number])
                || !asset.GetProperty("size").TryGetInt64(out var size) || size < 0
                || !Uri.TryCreate(asset.GetProperty("browser_download_url").GetString(), UriKind.Absolute, out var uri)
                || !TryParseOptionalSha256Digest(
                    asset,
                    out var sha256)) return false;
            var name = asset.GetProperty("name").GetString()!;
            if (name == UpdateReleaseContract.WindowsAssetName
                && sha256 is null)
            {
                return false;
            }
            assets.Add(new GitHubReleaseAsset(
                name,
                uri,
                size,
                sha256));
        }
        release = new GitHubReleaseMetadata(root.GetProperty("tag_name").GetString()!, draft.GetBoolean(), prerelease.GetBoolean(), assets);
        return true;
    }

    private static bool HasOneRequiredPropertyOfType(JsonElement value, IReadOnlyList<string> names, IReadOnlyList<JsonValueKind> kinds)
    {
        for (var index = 0; index < names.Count; index++)
        {
            var matches = value.EnumerateObject().Where(property => property.NameEquals(names[index])).ToArray();
            if (matches.Length != 1 || (kinds[index] == JsonValueKind.True ? matches[0].Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False) : matches[0].Value.ValueKind != kinds[index])) return false;
        }
        return true;
    }

    private static bool HasUniquePropertyNames(JsonElement value)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return value.EnumerateObject().All(property => names.Add(property.Name));
    }

    private static bool TryParseSha256Digest(
        string? value,
        out string? sha256)
    {
        sha256 = null;
        const string prefix = "sha256:";
        if (value is not { Length: 71 }
            || !value.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var digest = value[prefix.Length..];
        if (!digest.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f'))
        {
            return false;
        }

        sha256 = digest;
        return true;
    }

    private static bool TryParseOptionalSha256Digest(
        JsonElement asset,
        out string? sha256)
    {
        sha256 = null;
        if (!asset.TryGetProperty("digest", out var digest)
            || digest.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        return digest.ValueKind == JsonValueKind.String
            && TryParseSha256Digest(
                digest.GetString(),
                out sha256);
    }

    private static string NormalizedAssemblyVersion()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
        return $"{Math.Max(0, version.Major)}.{Math.Max(0, version.Minor)}.{Math.Max(0, version.Build)}";
    }

    public void Dispose()
    {
        if (_ownsClient) _client.Dispose();
    }
}
