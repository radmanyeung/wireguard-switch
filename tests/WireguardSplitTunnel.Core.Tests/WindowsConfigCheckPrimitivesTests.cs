using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsConfigCheckPrimitivesTests : IDisposable
{
    private const string PrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string PublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
    private static readonly string CandidateKey = Convert.ToBase64String(
        Enumerable.Range(32, 32).Select(value => (byte)value).ToArray());
    private readonly string root = Directory.CreateTempSubdirectory("wgst-probe-primitives-").FullName;

    [Fact]
    public void ProbeArguments_DisableUserCurlConfigAndBindSource()
    {
        var args = WindowsConfigCheckPrimitives.BuildCurlArguments("1.1.1.1", "10.5.0.2");
        args.Should().Equal(["-q", "-4", "--interface", "10.5.0.2", "--resolve", "www.cloudflare.com:443:1.1.1.1", "--noproxy", "*", "--proto", "=https", "--connect-timeout", "8", "--max-time", "15", "--max-filesize", "16384", "--fail", "--silent", "--show-error", "https://www.cloudflare.com/cdn-cgi/trace"]);
    }

    [Theory]
    [InlineData("abc\t0\n", "abc", 100, false)]
    [InlineData("abc\t100\n", "abc", 100, false)]
    [InlineData("abc\t101\n", "abc", 100, true)]
    [InlineData("abc\tnot-a-number\n", "abc", 100, false)]
    [InlineData("abc\n", "abc", 100, false)]
    [InlineData("abc\t101\textra\n", "abc", 100, false)]
    [InlineData("other\t200\n", "abc", 100, false)]
    public void FreshHandshake_RequiresExpectedPeerAndNewTimestamp(string output, string key, long started, bool expected)
    {
        WindowsConfigCheckPrimitives.HasFreshHandshake(output, key, started).Should().Be(expected);
    }

    [Fact]
    public void ProbeConfig_UsesExistingIdentityAndCandidateWithoutAutomaticRoutesOrDns()
    {
        var config = CreateConfig();
        var server = new ConfigCheckServer("uk6001.nordvpn.com", CandidateKey, "GB");

        var probe = WindowsConfigCheckPrimitives.NewProbeConfig(config, server);

        probe.Should().Be(
            "[Interface]\r\n" +
            "PrivateKey = " + PrivateKey + "\r\n" +
            "Address = 10.5.0.2/32\r\n" +
            "Table = off\r\n" +
            "\r\n" +
            "[Peer]\r\n" +
            "PublicKey = " + CandidateKey + "\r\n" +
            "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\n" +
            "Endpoint = uk6001.nordvpn.com:51820\r\n" +
            "PersistentKeepalive = 3\r\n");
        probe.Should().NotContain("DNS").And.NotContain("0.0.0.0/0").And.NotContain("::/0");
    }

    [Fact]
    public void OwnedTunnelNames_MatchTheOwnedPatternAndAreUnique()
    {
        var names = Enumerable.Range(0, 256)
            .Select(_ => WindowsConfigCheckPrimitives.NewOwnedTunnelName())
            .ToArray();

        names.Should().OnlyContain(name => Regex.IsMatch(
            name,
            "^WGSTCheck-[a-f0-9]{12}$",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1)));
        names.Distinct(StringComparer.Ordinal).Should().HaveCount(names.Length);
    }

    [Fact]
    public void FullPathContainment_RejectsSiblingPrefixAndParentTraversalTricks()
    {
        var child = Path.Combine(root, "nested", "..", "probe.conf");
        var siblingPrefix = root + "-sibling" + Path.DirectorySeparatorChar + "probe.conf";
        var parentTraversal = Path.Combine(root, "..", "probe.conf");

        WindowsConfigCheckPrimitives.IsPathWithinRoot(root, child).Should().BeTrue();
        WindowsConfigCheckPrimitives.IsPathWithinRoot(root, root).Should().BeTrue();
        WindowsConfigCheckPrimitives.IsPathWithinRoot(root, siblingPrefix).Should().BeFalse();
        WindowsConfigCheckPrimitives.IsPathWithinRoot(root, parentTraversal).Should().BeFalse();
    }

    [Fact]
    public void ReparseChecks_RejectFileAndDirectoryLinksWhereSupported()
    {
        var ordinaryFile = Path.Combine(root, "ordinary.conf");
        var targetFile = Path.Combine(root, "target.conf");
        File.WriteAllText(ordinaryFile, "ordinary", new UTF8Encoding(false));
        File.WriteAllText(targetFile, "target", new UTF8Encoding(false));
        WindowsConfigCheckPrimitives.EnsureNoReparsePoints(ordinaryFile);

        var fileLink = Path.Combine(root, "file-link.conf");
        if (!TryCreateFileLink(fileLink, targetFile)) return;

        Action fileCheck = () => WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fileLink);
        fileCheck.Should().Throw<InvalidDataException>().WithMessage("*reparse point*");

        var targetDirectory = Directory.CreateDirectory(Path.Combine(root, "target-directory"));
        File.WriteAllText(Path.Combine(targetDirectory.FullName, "probe.conf"), "probe", new UTF8Encoding(false));
        var directoryLink = Path.Combine(root, "directory-link");
        if (!TryCreateDirectoryLink(directoryLink, targetDirectory.FullName)) return;

        Action directoryCheck = () => WindowsConfigCheckPrimitives.EnsureNoReparsePoints(
            Path.Combine(directoryLink, "probe.conf"));
        directoryCheck.Should().Throw<InvalidDataException>().WithMessage("*reparse point*");
    }

    [Fact]
    public void FingerprintFile_ReturnsLowercaseSha256()
    {
        var path = Path.Combine(root, "fingerprint.bin");
        File.WriteAllBytes(path, Encoding.ASCII.GetBytes("abc"));

        var fingerprint = WindowsConfigCheckPrimitives.FingerprintFile(path);

        fingerprint.Should().Be("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        fingerprint.Should().MatchRegex("^[a-f0-9]{64}$");
    }

    [Fact]
    public void SafeNativeError_NeverIncludesRawNativeOutputOrKeyMaterial()
    {
        var rawOutput = "curl: (28) sensitive receiver output\r\nPrivateKey = " + PrivateKey + "\r\n" + PublicKey;

        var error = WindowsConfigCheckPrimitives.CreateSafeNativeError("curl probe", 28, rawOutput);

        error.Should().Be("curl probe failed (exit code 28).");
        error.Should().NotContain(rawOutput)
            .And.NotContain("sensitive receiver output")
            .And.NotContain(PrivateKey)
            .And.NotContain(PublicKey);
    }

    [Fact]
    public void NetshError_PreservesLocalizedDiagnosticAndRedactsSecrets()
    {
        var rawOutput = "路由新增失敗：\r\n元素找不到。\r\nPrivateKey = " + PrivateKey + "\r\n" + PublicKey;

        var error = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, rawOutput);

        error.Should().StartWith(
            "netsh.exe failed (exit code 1). Diagnostic: 路由新增失敗： 元素找不到。 [redacted] [redacted]");
        error.Should().NotContain("PrivateKey")
            .And.NotContain("PublicKey")
            .And.NotContain(PrivateKey)
            .And.NotContain(PublicKey)
            .And.NotContain("\r")
            .And.NotContain("\n");
    }

    [Fact]
    public void NetshError_TruncatesLongOutputAndOmitsEmptyDiagnostic()
    {
        var error = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, new string('x', 600));
        var empty = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, " \r\n\t");

        error.Should().StartWith("netsh.exe failed (exit code 1). Diagnostic: " + new string('x', 512));
        error.Should().EndWith("… [truncated]");
        error.Length.Should().BeLessThan(570);
        empty.Should().Be("netsh.exe failed (exit code 1).");
    }

    private CheckedConfig CreateConfig()
    {
        const string text = "[Interface]\r\n" +
            "PrivateKey = " + PrivateKey + "\r\n" +
            "Address = 10.5.0.2/32\r\n" +
            "DNS = 103.86.96.100\r\n" +
            "\r\n" +
            "[Peer]\r\n" +
            "PublicKey = " + PublicKey + "\r\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\r\n" +
            "Endpoint = uk6000.nordvpn.com:51820\r\n";
        var encoding = new UTF8Encoding(false);
        var bytes = encoding.GetBytes(text);
        return new CheckedConfig(
            Path.Combine(root, "original.conf"),
            "original",
            text,
            bytes,
            encoding,
            [],
            CheckedConfig.FingerprintBytes(bytes),
            PrivateKey,
            PublicKey,
            "uk6000.nordvpn.com",
            51820,
            "GB",
            "10.5.0.2",
            "uk6000.nordvpn.com:51820");
    }

    private static bool TryCreateFileLink(string path, string target)
    {
        try
        {
            File.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateDirectoryLink(string path, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }
}
