using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class GitHubReleaseUrlPolicyTests
{
    [Fact]
    public void IsValidInitialAssetUrl_AcceptsOnlyTheExactCanonicalGitHubAssetUrl()
    {
        GitHubReleaseUrlPolicy.IsValidInitialAssetUrl(
            new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip"),
            "v1.2.3",
            UpdateReleaseContract.WindowsAssetName).Should().BeTrue();
    }

    [Theory]
    [InlineData("http://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://user@github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com:444/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip?x=1")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip#fragment")]
    [InlineData("https://github.com.evil.example/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://evilgithub.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/other.zip")]
    [InlineData("https://github.com/radmanyeung/other/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/extra/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3%2Fwireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/%2E%2E/wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.3\\wireguard-split-tunnel-win-x64.zip")]
    [InlineData("https://gіthub.com/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip")]
    public void IsValidInitialAssetUrl_RejectsNonCanonicalOrUnsafeUrls(string value)
    {
        GitHubReleaseUrlPolicy.IsValidInitialAssetUrl(new Uri(value), "v1.2.3", UpdateReleaseContract.WindowsAssetName).Should().BeFalse();
    }

    [Fact]
    public void IsValidInitialAssetUrl_RejectsRelativeUriWithoutThrowing()
    {
        GitHubReleaseUrlPolicy.IsValidInitialAssetUrl(new Uri("/radmanyeung/wireguard-switch/releases/download/v1.2.3/wireguard-split-tunnel-win-x64.zip", UriKind.Relative), "v1.2.3", UpdateReleaseContract.WindowsAssetName).Should().BeFalse();
    }

    [Theory]
    [InlineData("api.github.com")]
    [InlineData("github.com")]
    [InlineData("objects.githubusercontent.com")]
    [InlineData("release-assets.githubusercontent.com")]
    [InlineData("GITHUB.COM")]
    public void IsValidRedirectTarget_AcceptsEachExactAllowedHost(string host)
    {
        GitHubReleaseUrlPolicy.IsValidRedirectTarget(new Uri($"https://{host}/download?signature=1"), 5).Should().BeTrue();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(7)]
    public void IsValidRedirectTarget_RejectsOutOfRangeHop(int hop)
    {
        GitHubReleaseUrlPolicy.IsValidRedirectTarget(new Uri("https://github.com/download"), hop).Should().BeFalse();
    }

    [Theory]
    [InlineData("http://github.com/download")]
    [InlineData("https://user@github.com/download")]
    [InlineData("https://github.com:444/download")]
    [InlineData("https://github.com/download#fragment")]
    [InlineData("https://github.com.evil.example/download")]
    [InlineData("https://evilgithub.com/download")]
    public void IsValidRedirectTarget_RejectsUnsafeTargets(string value)
    {
        GitHubReleaseUrlPolicy.IsValidRedirectTarget(new Uri(value), 1).Should().BeFalse();
    }

    [Fact]
    public void IsValidRedirectTarget_RejectsRelativeUriWithoutThrowing()
    {
        GitHubReleaseUrlPolicy.IsValidRedirectTarget(new Uri("/download", UriKind.Relative), 1).Should().BeFalse();
    }

    [Fact]
    public void AllowedRedirectHosts_IsDefensivelyReadOnly()
    {
        var hosts = GitHubReleaseUrlPolicy.AllowedRedirectHosts;

        ((IList<string>)hosts).Invoking(list => list.Add("evil.example")).Should().Throw<NotSupportedException>();
        GitHubReleaseUrlPolicy.AllowedRedirectHosts.Should().Equal(UpdateReleaseContract.RedirectHosts);
    }

    [Fact]
    public void ReleaseContractLists_AreDefensivelyReadOnly()
    {
       ((IList<string>)UpdateReleaseContract.RequiredLauncherPaths).Invoking(list => list.Add("evil.cmd")).Should().Throw<NotSupportedException>();
       ((IList<string>)UpdateReleaseContract.RedirectHosts).Invoking(list => list.Add("evil.example")).Should().Throw<NotSupportedException>();
        ((IList<string>)UpdateReleaseContract.RequiredLauncherPaths).Invoking(list => list[0] = "evil.cmd").Should().Throw<NotSupportedException>();
        ((IList<string>)UpdateReleaseContract.RedirectHosts).Invoking(list => list[0] = "evil.example").Should().Throw<NotSupportedException>();
        UpdateReleaseContract.RequiredLauncherPaths.Should().Equal("install.cmd", "start.cmd", "start-admin.cmd", "start-safe.cmd", "scripts/install.ps1", "scripts/start.ps1");
        UpdateReleaseContract.RedirectHosts.Should().Equal("api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com");
    }

    [Fact]
    public void DefaultSelector_UsesTheStrictInitialUrlPolicy()
    {
        var archive = new GitHubReleaseAsset(UpdateReleaseContract.WindowsAssetName, new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip"), 1, new string('a', 64));
        var checksum = new GitHubReleaseAsset(UpdateReleaseContract.WindowsChecksumAssetName, new Uri("https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/wireguard-split-tunnel-win-x64.zip.sha256"), 1, new string('b', 64));
        var selector = new StableReleaseSelector();

        selector.Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false, [archive, checksum])).Release.Should().NotBeNull();
        selector.Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false, [archive with { BrowserDownloadUrl = new Uri("https://evil.example/archive.zip") }, checksum])).Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidArchiveUrl);
        selector.Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false, [archive, checksum with { BrowserDownloadUrl = new Uri("https://evil.example/archive.sha256") }])).Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidChecksumUrl);
    }
}
