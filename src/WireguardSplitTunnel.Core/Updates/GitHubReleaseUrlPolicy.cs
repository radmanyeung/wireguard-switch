namespace WireguardSplitTunnel.Core.Updates;

public static class GitHubReleaseUrlPolicy
{
    private static readonly IReadOnlyList<string> allowedRedirectHosts = Array.AsReadOnly(
    [
        "api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"
    ]);

    public static IReadOnlyList<string> AllowedRedirectHosts => allowedRedirectHosts;

    public static bool IsValidInitialAssetUrl(Uri? url, string exactTag, string exactFilename)
    {
        if (url is null || string.IsNullOrEmpty(exactTag) || string.IsNullOrEmpty(exactFilename))
        {
            return false;
        }

        var expected = $"https://github.com/{UpdateReleaseContract.Repository}/releases/download/{exactTag}/{exactFilename}";
        return url.IsAbsoluteUri
            && string.Equals(url.OriginalString, expected, StringComparison.Ordinal)
            && string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            && string.Equals(url.Host, "github.com", StringComparison.Ordinal)
            && url.IsDefaultPort
            && string.IsNullOrEmpty(url.UserInfo)
            && string.IsNullOrEmpty(url.Query)
            && string.IsNullOrEmpty(url.Fragment);
    }

    public static bool IsValidRedirectTarget(Uri? url, int redirectHop)
    {
        if (url is null || redirectHop < 1 || redirectHop > UpdateNetworkLimits.MaximumRedirects || !url.IsAbsoluteUri)
        {
            return false;
        }

        return string.Equals(url.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            && url.IsDefaultPort
            && string.IsNullOrEmpty(url.UserInfo)
            && string.IsNullOrEmpty(url.Fragment)
            && allowedRedirectHosts.Contains(url.Host, StringComparer.OrdinalIgnoreCase);
    }
}
