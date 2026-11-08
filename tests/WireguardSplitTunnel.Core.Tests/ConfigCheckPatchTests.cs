using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckPatchTests : IDisposable
{
    private const string PrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string PublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
    private const string ReplacementPublicKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    private readonly string root = Directory.CreateTempSubdirectory("wgst-config-patch-").FullName;

    [Fact]
    public void PatchPeer_ChangesOnlyEndpointAndPublicKey()
    {
        var sourceText = SourceText();
        var expectedText = ExpectedText();
        var config = CheckedConfig.Parse(Write("GB.conf", sourceText));
        var server = new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey, "GB");

        var patched = config.WithPeerServer(server);

        Encoding.UTF8.GetString(patched).Should().Be(expectedText);
        NonPeerLines(sourceText).Should().Equal(NonPeerLines(Encoding.UTF8.GetString(patched)));
    }

    [Theory]
    [InlineData("utf-8")]
    [InlineData("utf-16")]
    public void PatchPeer_PreservesExplicitPreambleEncodingAndEveryNonPeerByte(string encodingName)
    {
        var encoding = Encoding.GetEncoding(encodingName);
        var sourceText = SourceText();
        var originalBytes = encoding.GetPreamble().Concat(encoding.GetBytes(sourceText)).ToArray();
        var path = Path.Combine(root, encodingName + ".conf");
        File.WriteAllBytes(path, originalBytes);
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey, "GB");

        var patched = config.WithPeerServer(server);

        patched.Take(encoding.GetPreamble().Length).Should().Equal(encoding.GetPreamble());
        var expectedBytes = encoding.GetPreamble().Concat(encoding.GetBytes(ExpectedText())).ToArray();
        patched.Should().Equal(expectedBytes);
        AssertOnlyPeerValueBytesChanged(originalBytes, patched, encoding);
    }

    [Fact]
    public void PatchPeer_RejectsWrongCountryAndInvalidKey()
    {
        var config = CheckedConfig.Parse(Write("GB.conf", SourceText()));

        Action wrongCountry = () => config.WithPeerServer(config.OriginalServer with { Country = "US" });
        Action invalidKey = () => config.WithPeerServer(config.OriginalServer with { PublicKey = "invalid" });

        wrongCountry.Should().Throw<InvalidDataException>();
        invalidKey.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_RejectsNonCanonicalCandidateKey()
    {
        var config = CheckedConfig.Parse(Write("GB.conf", SourceText()));
        var nonCanonical = ReplacementPublicKey[..^2] + (char)(ReplacementPublicKey[^2] + 1) + "=";

        Action patch = () => config.WithPeerServer(config.OriginalServer with { PublicKey = nonCanonical });

        patch.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_DoesNotPatchCommentedPeerLookalikes()
    {
        var sourceText = SourceText() + "# PublicKey = " + ReplacementPublicKey + "\r\n# Endpoint = uk9999.nordvpn.com:51820\r\n";
        var config = CheckedConfig.Parse(Write("comments.conf", sourceText));

        var patched = config.WithPeerServer(new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey, "GB"));

        Encoding.UTF8.GetString(patched).Should().Be(ExpectedText() + "# PublicKey = " + ReplacementPublicKey + "\r\n# Endpoint = uk9999.nordvpn.com:51820\r\n");
    }

    private static string SourceText() =>
        "# retained header with Endpoint = attacker.example:1 and PublicKey = invalid\r\n" +
        "[Interface]\r\n" +
        "PrivateKey = " + PrivateKey + " # retain private-key comment\r\n" +
        "Address = 10.5.0.2/32\r\n" +
        "DNS = 103.86.96.100\r\n" +
        "\r\n" +
        "[Peer]\r\n" +
        "PublicKey\t = \t" + PublicKey + " \t# retain peer-key comment\r\n" +
        "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\n" +
        "Endpoint  =\tuk6000.nordvpn.com:51820\t # retain endpoint comment\r\n";

    private static string ExpectedText() => SourceText()
        .Replace(PublicKey, ReplacementPublicKey)
        .Replace("uk6000.nordvpn.com", "uk6001.nordvpn.com");

    private static string[] NonPeerLines(string text) => text
        .Split("\r\n", StringSplitOptions.None)
        .Where(line => !line.StartsWith("PublicKey", StringComparison.Ordinal) && !line.StartsWith("Endpoint", StringComparison.Ordinal))
        .ToArray();

    private static void AssertOnlyPeerValueBytesChanged(byte[] original, byte[] patched, Encoding encoding)
    {
        var preambleLength = encoding.GetPreamble().Length;
        patched[..preambleLength].Should().Equal(original[..preambleLength]);
        var originalLines = encoding.GetString(original, preambleLength, original.Length - preambleLength).Split("\r\n", StringSplitOptions.None);
        var patchedLines = encoding.GetString(patched, preambleLength, patched.Length - preambleLength).Split("\r\n", StringSplitOptions.None);
        originalLines.Should().HaveSameCount(patchedLines);
        for (var index = 0; index < originalLines.Length; index++)
        {
            if (originalLines[index].StartsWith("PublicKey", StringComparison.Ordinal) || originalLines[index].StartsWith("Endpoint", StringComparison.Ordinal)) continue;
            encoding.GetBytes(patchedLines[index]).Should().Equal(encoding.GetBytes(originalLines[index]), "non-peer line {0} must remain byte-identical", index);
        }
    }

    private string Write(string name, string text)
    {
        var path = Path.Combine(root, name);
        File.WriteAllText(path, text, new UTF8Encoding(false));
        return path;
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }
}
