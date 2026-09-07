using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class InstallStartupHandshakeTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "wgst-install-health-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void TryParse_AcceptsOneCanonicalTokenAndHealthPath()
    {
        Directory.CreateDirectory(root);
        var token = Guid.NewGuid();
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WireguardSplitTunnel",
            "install-health",
            $"{token:N}.json");

        var parsed = InstallStartupHandshake.TryParse(
            ["--install-health-token", token.ToString("N"), "--install-health-path", path],
            out var handshake);

        parsed.Should().BeTrue();
        handshake.Should().NotBeNull();
        handshake!.Token.Should().Be(token);
        handshake.HealthPath.Should().Be(Path.GetFullPath(path));
    }

    [Fact]
    public void TryParse_RejectsHealthPathOutsideInstallerHealthDirectory()
    {
        var token = Guid.NewGuid();

        InstallStartupHandshake.TryParse(
            ["--install-health-token", token.ToString("N"), "--install-health-path", Path.Combine(root, "health.json")],
            out _).Should().BeFalse();
    }

    [Theory]
    [InlineData("not-a-guid")]
    [InlineData("00112233-4455-6677-8899-aabbccddeeff")]
    public void TryParse_RejectsNonCanonicalTokens(string token)
    {
        InstallStartupHandshake.TryParse(
            ["--install-health-token", token, "--install-health-path", Path.Combine(root, "health.json")],
            out _).Should().BeFalse();
    }

    [Fact]
    public void WriteReady_PublishesExactTokenVersionProcessAndPathAtomically()
    {
        Directory.CreateDirectory(root);
        var token = Guid.NewGuid();
        var healthPath = Path.Combine(root, "health.json");
        var executable = Path.Combine(root, "WireguardSplitTunnel.App.exe");
        var handshake = new InstallStartupHandshake(token, healthPath);

        handshake.WriteReady("0.2.10", 1234, executable);

        var json = File.ReadAllText(healthPath);
        json.Should().Contain(token.ToString("N"));
        json.Should().Contain("0.2.10");
        json.Should().Contain("1234");
        json.Should().Contain(Path.GetFullPath(executable).Replace("\\", "\\\\"));
        json.Should().Contain("\"settingsLoaded\":true");
        json.Should().Contain("\"mainWindowInitialized\":true");
        Directory.EnumerateFiles(root, "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public void CommitEventName_IsBoundToTheCanonicalInstallToken()
    {
        var token = Guid.ParseExact(
            "00112233445566778899aabbccddeeff",
            "N");
        var handshake = new InstallStartupHandshake(
            token,
            Path.Combine(root, "health.json"));

        handshake.CommitEventName.Should().Be(
            "Local\\WireguardSplitTunnel.InstallCommit.00112233445566778899aabbccddeeff");
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
