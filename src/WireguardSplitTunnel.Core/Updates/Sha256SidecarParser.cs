using System.Text;

namespace WireguardSplitTunnel.Core.Updates;

public enum Sha256SidecarParseError
{
    None,
    NullInput,
    TooLarge,
    Utf8Bom,
    InvalidUtf8,
    InvalidFormat
}

public readonly record struct Sha256SidecarParseResult(
    bool Success,
    string? Digest,
    Sha256SidecarParseError ErrorCode,
    string? ErrorMessage)
{
    public static Sha256SidecarParseResult Failure(Sha256SidecarParseError errorCode, string errorMessage) =>
        new(false, null, errorCode, errorMessage);

    public static Sha256SidecarParseResult Parsed(string digest) => new(true, digest, Sha256SidecarParseError.None, null);
}

public static class Sha256SidecarParser
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static Sha256SidecarParseResult Parse(byte[]? value)
    {
        if (value is null)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.NullInput, "Checksum content is required.");
        }

        if (value.Length > UpdateNetworkLimits.ChecksumBytes)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.TooLarge, "Checksum content exceeds the configured limit.");
        }

        if (value.Length >= 3 && value[0] == 0xEF && value[1] == 0xBB && value[2] == 0xBF)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.Utf8Bom, "UTF-8 BOM is not permitted.");
        }

        try
        {
            return Parse(StrictUtf8.GetString(value));
        }
        catch (DecoderFallbackException)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.InvalidUtf8, "Checksum content is not valid UTF-8.");
        }
    }

    public static Sha256SidecarParseResult Parse(string? value)
    {
        if (value is null)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.NullInput, "Checksum content is required.");
        }

        try
        {
            if (StrictUtf8.GetByteCount(value) > UpdateNetworkLimits.ChecksumBytes)
            {
                return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.TooLarge, "Checksum content exceeds the configured limit.");
            }
        }
        catch (EncoderFallbackException)
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.InvalidUtf8, "Checksum content is not valid UTF-8.");
        }

        if (value.StartsWith('\uFEFF'))
        {
            return Sha256SidecarParseResult.Failure(Sha256SidecarParseError.Utf8Bom, "UTF-8 BOM is not permitted.");
        }

        var content = value.AsSpan();
        if (content.EndsWith("\r\n"))
        {
            content = content[..^2];
        }
        else if (content.EndsWith("\n"))
        {
            content = content[..^1];
        }

        var expectedLength = 64 + 2 + UpdateReleaseContract.WindowsAssetName.Length;
        if (content.Length != expectedLength
            || !content.Slice(64, 2).SequenceEqual("  ")
            || !content[66..].SequenceEqual(UpdateReleaseContract.WindowsAssetName))
        {
            return InvalidFormat();
        }

        Span<char> digest = stackalloc char[64];
        for (var index = 0; index < digest.Length; index++)
        {
            var character = content[index];
            if (!IsAsciiHex(character))
            {
                return InvalidFormat();
            }

            digest[index] = character is >= 'A' and <= 'F' ? (char)(character + ('a' - 'A')) : character;
        }

        return Sha256SidecarParseResult.Parsed(new string(digest));
    }

    private static bool IsAsciiHex(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static Sha256SidecarParseResult InvalidFormat() =>
        Sha256SidecarParseResult.Failure(Sha256SidecarParseError.InvalidFormat, "Checksum sidecar does not match the required single-line format.");
}
