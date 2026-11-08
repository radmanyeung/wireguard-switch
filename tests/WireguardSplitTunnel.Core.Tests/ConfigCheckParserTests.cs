using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckParserTests : IDisposable
{
    private readonly string root = Directory.CreateTempSubdirectory("wgst-config-check-").FullName;
    private const string PrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string PublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
    private const string Valid = "[Interface]\r\nPrivateKey = {0}\r\nAddress = 10.5.0.2/32\r\nDNS = 103.86.96.100\r\n\r\n[Peer]\r\nPublicKey = {1} # keep\r\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\nEndpoint = uk6000.nordvpn.com:51820 # keep\r\n";
    private static readonly string ReplacementPublicKey = Convert.ToBase64String(Enumerable.Range(32, 32).Select(value => (byte)value).ToArray());

    [Fact]
    public void Parse_RetainsIdentityAndFingerprint()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);
        config.Path.Should().Be(Path.GetFullPath(path));
        config.HostName.Should().Be("uk6000.nordvpn.com");
        config.Country.Should().Be("GB");
        config.SourceAddress.Should().Be("10.5.0.2");
        config.Fingerprint.Should().HaveLength(64);
        config.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(File.ReadAllBytes(path)));
    }

    [Theory]
    [InlineData("PostUp = malicious-command", "hooks")]
    [InlineData("PresharedKey = " + PublicKey, "preshared keys")]
    [InlineData("[Peer]", "multiple peers")]
    public void Parse_RejectsUnsafeOrUnsupportedInput(string addition, string reason)
    {
        var path = Write("invalid.conf", string.Format(Valid, PrivateKey, PublicKey) + addition + "\r\n");
        Action parse = () => CheckedConfig.Parse(path);
        parse.Should().Throw<InvalidDataException>(reason);
    }

    [Fact]
    public void Parse_RejectsDpapiAndNonNordEndpoints()
    {
        File.WriteAllText(Path.Combine(root, "secret.conf.dpapi"), "secret");
        Action dpapi = () => CheckedConfig.Parse(Path.Combine(root, "secret.conf.dpapi"));
        dpapi.Should().Throw<InvalidDataException>();
        var path = Write("other.conf", string.Format(Valid, PrivateKey, PublicKey).Replace("uk6000.nordvpn.com", "vpn.example.org"));
        Action other = () => CheckedConfig.Parse(path);
        other.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_RoundTripsWithoutChangingOtherText()
    {
        var originalText = string.Format(Valid, PrivateKey, PublicKey)
            .Replace("PublicKey =", "PublicKey\t = \t")
            .Replace("Endpoint =", "Endpoint  =\t");
        var path = Write("GB.conf", originalText);
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("gb9000.nordvpn.com", ReplacementPublicKey, "GB");

        var patched = config.WithPeerServer(server);

        var expectedText = originalText.Replace(PublicKey, ReplacementPublicKey).Replace("uk6000.nordvpn.com", "gb9000.nordvpn.com");
        patched.Should().Equal(Encoding.UTF8.GetBytes(expectedText));
        var patchedPath = Path.Combine(root, "patched.conf");
        File.WriteAllBytes(patchedPath, patched);
        var roundTripped = CheckedConfig.Parse(patchedPath);
        roundTripped.HostName.Should().Be(server.HostName);
        roundTripped.PublicKey.Should().Be(server.PublicKey);
        roundTripped.Port.Should().Be(config.Port);
        roundTripped.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(patched));
    }

    [Theory]
    [InlineData("utf-8")]
    [InlineData("utf-16")]
    [InlineData("utf-16BE")]
    public void PatchPeer_PreservesOriginalBomAndEncoding(string encodingName)
    {
        var encoding = Encoding.GetEncoding(encodingName);
        var originalText = string.Format(Valid, PrivateKey, PublicKey);
        var path = Path.Combine(root, encodingName + ".conf");
        File.WriteAllBytes(path, encoding.GetPreamble().Concat(encoding.GetBytes(originalText)).ToArray());
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("gb9000.nordvpn.com", ReplacementPublicKey, "GB");

        var patched = config.WithPeerServer(server);

        patched.Take(config.Preamble.Length).Should().Equal(config.Preamble);
        var patchedText = config.Encoding.GetString(patched, config.Preamble.Length, patched.Length - config.Preamble.Length);
        patchedText.Should().Be(originalText.Replace(PublicKey, ReplacementPublicKey).Replace("uk6000.nordvpn.com", "gb9000.nordvpn.com"));
        config.Encoding.GetBytes(patchedText).Should().Equal(patched.Skip(config.Preamble.Length));
    }

    [Theory]
    [InlineData("PrivateKey", "not-a-key")]
    [InlineData("Address", "2001:db8::1/128")]
    [InlineData("Address", "10.5.0.2/33")]
    [InlineData("AllowedIPs", "0.0.0.0/33")]
    [InlineData("AllowedIPs", "not-an-ip/8")]
    [InlineData("Endpoint", "uk6000.nordvpn.com:0")]
    [InlineData("Endpoint", "uk6000.nordvpn.com:65536")]
    public void Parse_RejectsInvalidScalarValues(string field, string value)
    {
        var text = string.Format(Valid, PrivateKey, PublicKey);
        var originalValue = field switch
        {
            "PrivateKey" => PrivateKey,
            "Address" => "10.5.0.2/32",
            "AllowedIPs" => "0.0.0.0/1, 128.0.0.0/1",
            "Endpoint" => "uk6000.nordvpn.com:51820",
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };
        var path = Write("invalid-value.conf", text.Replace($"{field} = {originalValue}", $"{field} = {value}"));

        Action parse = () => CheckedConfig.Parse(path);

        parse.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void Parse_RejectsInvalidUtf8AndOversizedFiles()
    {
        var invalidUtf8 = Path.Combine(root, "invalid-utf8.conf");
        File.WriteAllBytes(invalidUtf8, [0xC3, 0x28]);
        Action invalid = () => CheckedConfig.Parse(invalidUtf8);
        invalid.Should().Throw<InvalidDataException>();

        var oversized = Path.Combine(root, "oversized.conf");
        File.WriteAllBytes(oversized, new byte[65_537]);
        Action tooLarge = () => CheckedConfig.Parse(oversized);
        tooLarge.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void Parse_RejectsDuplicateSectionsAndFields()
    {
        var duplicateField = Write("duplicate-field.conf", string.Format(Valid, PrivateKey, PublicKey).Replace("DNS = 103.86.96.100", "DNS = 103.86.96.100\r\nDNS = 103.86.96.101"));
        Action duplicate = () => CheckedConfig.Parse(duplicateField);
        duplicate.Should().Throw<InvalidDataException>();

        var duplicateInterface = Write("duplicate-interface.conf", string.Format(Valid, PrivateKey, PublicKey) + "[Interface]\r\n");
        Action section = () => CheckedConfig.Parse(duplicateInterface);
        section.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_RejectsDifferentCountryInvalidKeyAndInvalidHost()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);

        Action country = () => config.WithPeerServer(new ConfigCheckServer("de9000.nordvpn.com", ReplacementPublicKey, "DE"));
        Action key = () => config.WithPeerServer(new ConfigCheckServer("gb9000.nordvpn.com", "invalid-key", "GB"));
        Action host = () => config.WithPeerServer(new ConfigCheckServer("vpn.example.org", ReplacementPublicKey, "GB"));

        country.Should().Throw<InvalidDataException>();
        key.Should().Throw<InvalidDataException>();
        host.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void Parse_ErrorsDoNotExposeConfigTextOrKeyMaterial()
    {
        var path = Write("redacted.conf", string.Format(Valid, PrivateKey, PublicKey).Replace("10.5.0.2/32", "invalid-address"));

        var exception = Record.Exception(() => CheckedConfig.Parse(path));

        exception.Should().BeOfType<InvalidDataException>();
        exception!.Message.Should().NotContain(PrivateKey).And.NotContain(PublicKey).And.NotContain("PrivateKey =").And.NotContain("invalid-address");
    }

    [Fact]
    public void ToString_ExposesOnlyNonSensitiveMetadata()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);

        var rendered = config.ToString();

        rendered.Should().Contain(config.Path).And.Contain(config.HostName).And.Contain(config.Fingerprint)
            .And.NotContain(PrivateKey).And.NotContain(PublicKey).And.NotContain(config.Text)
            .And.NotContain("[Interface]").And.NotContain("PrivateKey =");
    }

    [Fact]
    public void ByteProperties_CannotInvalidateFingerprintOrRepeatedPatches()
    {
        var encoding = new UTF8Encoding(true);
        var path = Path.Combine(root, "bom.conf");
        File.WriteAllBytes(path, encoding.GetPreamble().Concat(encoding.GetBytes(string.Format(Valid, PrivateKey, PublicKey))).ToArray());
        var originalBytes = File.ReadAllBytes(path);
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey, "GB");
        var originalPatch = config.WithPeerServer(server);

        var exposedBytes = config.Bytes;
        exposedBytes[3] ^= 0xFF;
        var exposedPreamble = config.Preamble;
        exposedPreamble[0] ^= 0xFF;
        originalPatch[0] ^= 0xFF;

        config.Bytes.Should().Equal(originalBytes);
        config.Preamble.Should().Equal(encoding.GetPreamble());
        config.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(config.Bytes));
        config.WithPeerServer(server).Should().Equal(config.WithPeerServer(server));
        config.WithPeerServer(server)[..3].Should().Equal(encoding.GetPreamble());
    }

    [Fact]
    public void WithExpressions_DoNotExposeInputOrShallowCopyArrayAliases()
    {
        var encoding = new UTF8Encoding(true);
        var path = Path.Combine(root, "aliases.conf");
        File.WriteAllBytes(path, encoding.GetPreamble().Concat(encoding.GetBytes(string.Format(Valid, PrivateKey, PublicKey))).ToArray());
        var originalBytes = File.ReadAllBytes(path);
        var config = CheckedConfig.Parse(path);
        var inputBytes = (byte[])originalBytes.Clone();
        var inputPreamble = encoding.GetPreamble();

        var initializedAlias = config with { Bytes = inputBytes, Preamble = inputPreamble };
        inputBytes[3] ^= 0xFF;
        inputPreamble[0] ^= 0xFF;

        initializedAlias.Bytes.Should().Equal(originalBytes);
        initializedAlias.Preamble.Should().Equal(encoding.GetPreamble());
        initializedAlias.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(initializedAlias.Bytes));

        var shallowAlias = config with { };
        var shallowBytes = shallowAlias.Bytes;
        shallowBytes[3] ^= 0xFF;
        var shallowPreamble = shallowAlias.Preamble;
        shallowPreamble[0] ^= 0xFF;

        config.Bytes.Should().Equal(originalBytes);
        config.Preamble.Should().Equal(encoding.GetPreamble());
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\t")]
    [InlineData("\r\n")]
    public void Parse_RejectsWhitespaceInOriginalKeys(string whitespace)
    {
        var privatePath = Write("private-whitespace.conf", string.Format(Valid, PrivateKey.Insert(4, whitespace), PublicKey));
        Action privateKey = () => CheckedConfig.Parse(privatePath);
        privateKey.Should().Throw<InvalidDataException>();

        var publicPath = Write("public-whitespace.conf", string.Format(Valid, PrivateKey, PublicKey.Insert(4, whitespace)));
        Action publicKey = () => CheckedConfig.Parse(publicPath);
        publicKey.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void Parse_RejectsNonCanonicalKeyPadding()
    {
        var privatePath = Write("private-padding.conf", string.Format(Valid, NonCanonicalPadding(PrivateKey), PublicKey));
        Action privateKey = () => CheckedConfig.Parse(privatePath);
        privateKey.Should().Throw<InvalidDataException>();

        var publicPath = Write("public-padding.conf", string.Format(Valid, PrivateKey, NonCanonicalPadding(PublicKey)));
        Action publicKey = () => CheckedConfig.Parse(publicPath);
        publicKey.Should().Throw<InvalidDataException>();
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\t")]
    public void PatchPeer_RejectsWhitespaceInCandidateKeys(string whitespace)
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey.Insert(4, whitespace), "GB");

        Action patch = () => config.WithPeerServer(server);

        patch.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_CandidateKeyWithNewlineCannotCreateUnparseablePatch()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("uk6001.nordvpn.com", ReplacementPublicKey.Insert(4, "\r\n"), "GB");

        Action patch = () => config.WithPeerServer(server);

        patch.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void PatchPeer_RejectsNonCanonicalCandidatePadding()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);
        var server = new ConfigCheckServer("uk6001.nordvpn.com", NonCanonicalPadding(ReplacementPublicKey), "GB");

        Action patch = () => config.WithPeerServer(server);

        patch.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void OpenedFileIdentity_DifferentiatesFilesWithIdenticalLengthsAndTimestamps()
    {
        var text = string.Format(Valid, PrivateKey, PublicKey);
        var firstPath = Write("first.conf", text);
        var secondPath = Write("second.conf", text);
        SetMatchingTimestamps(firstPath, secondPath);
        using var first = File.OpenRead(firstPath);
        using var second = File.OpenRead(secondPath);
        using var sameFirst = File.OpenRead(firstPath);

        var firstIdentity = ConfigCheckParser.GetOpenedIdentity(first);
        var secondIdentity = ConfigCheckParser.GetOpenedIdentity(second);

        new FileInfo(firstPath).Length.Should().Be(new FileInfo(secondPath).Length);
        new FileInfo(firstPath).CreationTimeUtc.Should().Be(new FileInfo(secondPath).CreationTimeUtc);
        new FileInfo(firstPath).LastWriteTimeUtc.Should().Be(new FileInfo(secondPath).LastWriteTimeUtc);
        firstIdentity.Should().NotBe(secondIdentity);
        ConfigCheckParser.GetOpenedIdentity(sameFirst).Should().Be(firstIdentity);
    }

    [Fact]
    public void OpenedFileIdentity_RejectsSubstitutionWithIdenticalMetadata()
    {
        var text = string.Format(Valid, PrivateKey, PublicKey);
        var firstPath = Write("first.conf", text);
        var secondPath = Write("second.conf", text);
        SetMatchingTimestamps(firstPath, secondPath);
        using var opened = new FileStream(firstPath, FileMode.Open, FileAccess.Read, FileShare.Read);

        Action samePath = () => ConfigCheckParser.EnsureMatchingPathIdentity(opened, firstPath);
        Action substitutedPath = () => ConfigCheckParser.EnsureMatchingPathIdentity(opened, secondPath);

        samePath.Should().NotThrow();
        substitutedPath.Should().Throw<InvalidDataException>();
    }

    [Theory]
    [InlineData(@"\\?\C:\Temp\GB.conf", @"C:\Temp\GB.conf")]
    [InlineData(@"\\?\UNC\server\share\GB.conf", @"\\server\share\GB.conf")]
    public void FinalHandlePath_NormalizesExtendedPaths(string returned, string expected)
    {
        ConfigCheckParser.NormalizeFinalPath(returned).Should().Be(expected);
    }

    [Fact]
    public void OpenedFinalPath_RejectsDifferentTargetIndependentlyOfHandleIdentity()
    {
        var expected = Path.Combine(root, "expected", "GB.conf");
        var substitutedTarget = Path.Combine(root, "substituted", "GB.conf");

        Action validate = () => ConfigCheckParser.EnsureMatchingFinalPath(expected, substitutedTarget);

        validate.Should().Throw<InvalidDataException>();
    }

    [Theory]
    [InlineData(@"\\?\C:\Temp\GB.conf", @"C:\Temp\GB.conf")]
    [InlineData(@"\\?\UNC\server\share\GB.conf", @"\\server\share\GB.conf")]
    public void OpenedFinalPath_AllowsCanonicalNormalizationEquivalentSpellings(string expected, string openedFinalPath)
    {
        Action validate = () => ConfigCheckParser.EnsureMatchingFinalPath(expected, openedFinalPath);

        validate.Should().NotThrow();
    }

    private static void SetMatchingTimestamps(string firstPath, string secondPath)
    {
        var timestamp = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        foreach (var path in new[] { firstPath, secondPath })
        {
            File.SetCreationTimeUtc(path, timestamp);
            File.SetLastWriteTimeUtc(path, timestamp);
        }
    }

    private static string NonCanonicalPadding(string key) => key[..^2] + (char)(key[^2] + 1) + "=";

    [Fact]
    public void ReadBounded_RejectsOversizedContentWithoutReadingFurther()
    {
        using var stream = new UnboundedReadStream();

        Action read = () => ConfigCheckParser.ReadBounded(stream);

        read.Should().Throw<InvalidDataException>();
        stream.TotalRead.Should().Be(65_537);
    }

    private sealed class UnboundedReadStream : Stream
    {
        public long TotalRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => TotalRead; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            buffer.AsSpan(offset, count).Fill((byte)'A');
            TotalRead += count;
            return count;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private string Write(string name, string text)
    {
        var path = Path.Combine(root, name);
        File.WriteAllText(path, text, new UTF8Encoding(false));
        return path;
    }

    public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, true); }
}
