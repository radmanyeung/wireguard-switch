using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public sealed record CheckedConfig(
    string Path, string Name, string Text, byte[] Bytes, Encoding Encoding, byte[] Preamble,
    string Fingerprint, string PrivateKey, string PublicKey, string HostName, int Port,
    string Country, string SourceAddress, string Endpoint)
{
    private byte[] bytes = (byte[])Bytes.Clone();
    private byte[] preamble = (byte[])Preamble.Clone();
    public byte[] Bytes { get => (byte[])bytes.Clone(); init => bytes = (byte[])value.Clone(); }
    public byte[] Preamble { get => (byte[])preamble.Clone(); init => preamble = (byte[])value.Clone(); }
    public ConfigCheckServer OriginalServer => new(HostName, PublicKey, Country);
    public override string ToString() => $"{nameof(CheckedConfig)} {{ Path = {Path}, HostName = {HostName}, Port = {Port}, Country = {Country}, Fingerprint = {Fingerprint} }}";
    public static CheckedConfig Parse(string path) => ConfigCheckParser.Parse(path);
    public byte[] WithPeerServer(ConfigCheckServer server) => ConfigCheckParser.PatchPeer(this, server);
    public static string FingerprintBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static bool IsValidKey(string? key) => ConfigCheckParser.IsValidKey(key);
    internal static (string HostName, int Port, string Country) ParseEndpoint(string endpoint) => ConfigCheckParser.ParseEndpoint(endpoint);
}

internal readonly record struct OpenedFileIdentity(uint VolumeSerialNumber, ulong FileIndex);

internal static class ConfigCheckParser
{
    private const int MaxConfigBytes = 65_536;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
    private static readonly Regex EndpointPattern = new(
        @"^(?<host>[a-z]{2}[0-9]+\.nordvpn\.com):(?<port>[0-9]+)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex EndpointLinePattern = PeerLinePattern("Endpoint");
    private static readonly Regex PublicKeyLinePattern = PeerLinePattern("PublicKey");

    public static CheckedConfig Parse(string path)
    {
        string fullPath;
        byte[] bytes;
        try
        {
            fullPath = Path.GetFullPath(path);
            bytes = ReadFile(fullPath);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw Reject("Configuration file could not be read safely.");
        }

        var (text, encoding, preamble) = Decode(bytes);
        var values = ParseValues(text);
        var privateKey = Required(values, "Interface", "PrivateKey");
        var publicKey = Required(values, "Peer", "PublicKey");
        if (!IsValidKey(privateKey) || !IsValidKey(publicKey))
            throw Reject("Configuration keys must be 32-byte Base64 values.");

        var sourceAddress = ParseClientAddress(Required(values, "Interface", "Address"));
        ValidateAllowedIps(Required(values, "Peer", "AllowedIPs"));
        var endpoint = Required(values, "Peer", "Endpoint");
        var parsedEndpoint = ParseEndpoint(endpoint);

        return new CheckedConfig(
            fullPath,
            Path.GetFileNameWithoutExtension(fullPath),
            text,
            bytes,
            encoding,
            preamble,
            CheckedConfig.FingerprintBytes(bytes),
            privateKey,
            publicKey,
            parsedEndpoint.HostName,
            parsedEndpoint.Port,
            parsedEndpoint.Country,
            sourceAddress,
            endpoint);
    }

    public static byte[] PatchPeer(CheckedConfig config, ConfigCheckServer server)
    {
        if (server is null || !IsValidKey(server.PublicKey)) throw Reject("Invalid peer server key.");
        var endpoint = ParseEndpoint(server.HostName + ":" + config.Port.ToString(CultureInfo.InvariantCulture));
        if (!string.Equals(server.Country, config.Country, StringComparison.Ordinal) ||
            !string.Equals(endpoint.Country, config.Country, StringComparison.Ordinal))
            throw Reject("Peer server country does not match the configuration country.");

        var patched = ReplaceExactlyOnce(config.Text, EndpointLinePattern, endpoint.HostName + ":" + endpoint.Port.ToString(CultureInfo.InvariantCulture));
        patched = ReplaceExactlyOnce(patched, PublicKeyLinePattern, server.PublicKey);
        var body = config.Encoding.GetBytes(patched);
        var result = new byte[config.Preamble.Length + body.Length];
        config.Preamble.CopyTo(result, 0);
        body.CopyTo(result, config.Preamble.Length);
        return result;
    }

    internal static bool IsValidKey(string? key)
    {
        if (key is null) return false;
        try
        {
            var decoded = Convert.FromBase64String(key);
            return decoded.Length == 32 && string.Equals(key, Convert.ToBase64String(decoded), StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static (string HostName, int Port, string Country) ParseEndpoint(string endpoint)
    {
        Match match;
        try
        {
            match = EndpointPattern.Match(endpoint);
        }
        catch (ArgumentNullException)
        {
            throw Reject("Invalid NordVPN endpoint.");
        }
        if (!match.Success ||
            !int.TryParse(match.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
            port is < 1 or > 65_535)
            throw Reject("Invalid NordVPN endpoint.");
        var host = match.Groups["host"].Value;
        var prefix = host[..2].ToUpperInvariant();
        return (host, port, prefix == "UK" ? "GB" : prefix);
    }

    private const uint FinalPathFlags = 0x2; // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    private const int MaxFinalPathLength = 32_767;

    private static byte[] ReadFile(string fullPath)
    {
        RequireWindows();
        EnsureSafeFile(fullPath);
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length > MaxConfigBytes) throw Reject("Configuration file is too large.");

        var openedFinalPath = ValidateOpenedFile(stream, fullPath);
        var bytes = ReadBounded(stream);
        var finalPath = ValidateOpenedFile(stream, fullPath);
        if (!string.Equals(openedFinalPath, finalPath, StringComparison.OrdinalIgnoreCase) ||
            stream.Length != bytes.Length || stream.Position != bytes.Length)
            throw Reject("Configuration file changed while it was being read.");
        return bytes;
    }

    private static string ValidateOpenedFile(FileStream stream, string expectedPath)
    {
        EnsureSafeFile(expectedPath);
        var finalPath = GetFinalPath(stream);
        EnsureMatchingFinalPath(expectedPath, finalPath);
        EnsureSafeFile(finalPath);
        EnsureMatchingPathIdentity(stream, expectedPath);
        EnsureSafeFile(expectedPath);
        return finalPath;
    }

    internal static void EnsureMatchingFinalPath(string expectedPath, string openedFinalPath)
    {
        RequireWindows();
        string normalizedExpected;
        try
        {
            normalizedExpected = NormalizeFinalPath(Path.GetFullPath(expectedPath));
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw Reject("Expected configuration file path is invalid.");
        }
        var normalizedFinal = NormalizeFinalPath(openedFinalPath);
        if (!string.Equals(normalizedExpected, normalizedFinal, StringComparison.OrdinalIgnoreCase))
            throw Reject("Opened configuration file target differs from the expected path.");
    }

    internal static OpenedFileIdentity GetOpenedIdentity(FileStream stream) => GetOpenedIdentity(stream.SafeFileHandle);

    private static OpenedFileIdentity GetOpenedIdentity(SafeFileHandle handle)
    {
        RequireWindows();
        if (!GetFileInformationByHandle(handle, out var information))
            throw Reject("Opened configuration file identity could not be verified.");
        var fileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow;
        return new OpenedFileIdentity(information.VolumeSerialNumber, fileIndex);
    }

    internal static void EnsureMatchingPathIdentity(FileStream opened, string expectedPath)
    {
        RequireWindows();
        var openedIdentity = GetOpenedIdentity(opened);
        using var pathHandle = File.OpenHandle(expectedPath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.None);
        var pathIdentity = GetOpenedIdentity(pathHandle);
        if (openedIdentity != pathIdentity)
            throw Reject("Configuration path does not identify the opened file.");
    }

    private static string GetFinalPath(FileStream stream)
    {
        RequireWindows();
        var required = GetFinalPathNameByHandle(stream.SafeFileHandle, null, 0, FinalPathFlags);
        if (required == 0 || required > MaxFinalPathLength)
            throw Reject("Opened configuration file path could not be resolved.");
        var builder = new StringBuilder((int)required + 1);
        var written = GetFinalPathNameByHandle(stream.SafeFileHandle, builder, (uint)builder.Capacity, FinalPathFlags);
        if (written == 0 || written > required || written >= builder.Capacity)
            throw Reject("Opened configuration file path could not be resolved.");
        return NormalizeFinalPath(builder.ToString());
    }

    internal static string NormalizeFinalPath(string finalPath)
    {
        RequireWindows();
        if (string.IsNullOrEmpty(finalPath)) throw Reject("Opened configuration file path is invalid.");
        string normalized;
        if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ||
            finalPath.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase))
            normalized = @"\\" + finalPath[8..];
        else if (finalPath.StartsWith(@"\\?\", StringComparison.Ordinal) ||
                 finalPath.StartsWith(@"\??\", StringComparison.Ordinal))
            normalized = finalPath[4..];
        else
            normalized = finalPath;

        try
        {
            if (normalized.StartsWith(@"\\", StringComparison.Ordinal)) return Path.GetFullPath(normalized);
            if (normalized.Length >= 3 && char.IsLetter(normalized[0]) && normalized[1] == ':' &&
                (normalized[2] == '\\' || normalized[2] == '/'))
                return Path.GetFullPath(normalized);
            if (normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                return NormalizeDevicePath(normalized);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            throw Reject("Opened configuration file path is invalid.");
        }
        throw Reject("Opened configuration file path uses an unsupported device form.");
    }

    private static string NormalizeDevicePath(string devicePath)
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.Name.Length < 2 || drive.Name[1] != ':') continue;
            var target = new StringBuilder(2048);
            if (QueryDosDevice(drive.Name[..2], target, (uint)target.Capacity) == 0) continue;
            var device = target.ToString().TrimEnd('\\');
            if (device.Length == 0) continue;
            if (string.Equals(devicePath, device, StringComparison.OrdinalIgnoreCase)) return drive.Name;
            var prefix = device + "\\";
            if (devicePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return Path.GetFullPath(drive.Name + devicePath[prefix.Length..]);
        }
        throw Reject("Opened configuration file path uses an unsupported device form.");
    }

    private static void EnsureSafeFile(string fullPath)
    {
        if (!string.Equals(Path.GetExtension(fullPath), ".conf", StringComparison.OrdinalIgnoreCase))
            throw Reject("Only plaintext .conf files are supported.");

        var file = new FileInfo(fullPath);
        if (!file.Exists) throw Reject("Configuration file does not exist.");
        if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw Reject("Configuration file must not be a reparse point.");

        for (var directory = file.Directory; directory is not null; directory = directory.Parent)
        {
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw Reject("Configuration directory must not contain reparse points.");
        }
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw Reject("Configuration file identity validation is supported only on Windows.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, [Out] StringBuilder? finalPath, uint finalPathLength, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, [Out] StringBuilder targetPath, uint targetPathLength);

    internal static byte[] ReadBounded(Stream stream)
    {
        var buffer = new byte[MaxConfigBytes + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);
            if (read == 0) break;
            total += read;
        }
        if (total > MaxConfigBytes) throw Reject("Configuration file is too large.");
        return buffer[..total];
    }

    private static (string Text, Encoding Encoding, byte[] Preamble) Decode(byte[] bytes)
    {
        Encoding encoding;
        var preambleLength = 0;
        if (StartsWith(bytes, 0x00, 0x00, 0xFE, 0xFF) || StartsWith(bytes, 0xFF, 0xFE, 0x00, 0x00))
            throw Reject("Configuration text encoding is not supported.");
        if (StartsWith(bytes, 0xEF, 0xBB, 0xBF))
        {
            encoding = new UTF8Encoding(true, true);
            preambleLength = 3;
        }
        else if (StartsWith(bytes, 0xFF, 0xFE))
        {
            encoding = new UnicodeEncoding(false, true, true);
            preambleLength = 2;
        }
        else if (StartsWith(bytes, 0xFE, 0xFF))
        {
            encoding = new UnicodeEncoding(true, true, true);
            preambleLength = 2;
        }
        else
        {
            encoding = new UTF8Encoding(false, true);
        }

        try
        {
            var text = encoding.GetString(bytes, preambleLength, bytes.Length - preambleLength);
            return (text, encoding, bytes[..preambleLength]);
        }
        catch (DecoderFallbackException)
        {
            throw Reject("Configuration text encoding is invalid.");
        }
    }

    private static Dictionary<string, Dictionary<string, string>> ParseValues(string text)
    {
        var values = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal)
        {
            ["Interface"] = new Dictionary<string, string>(StringComparer.Ordinal),
            ["Peer"] = new Dictionary<string, string>(StringComparer.Ordinal)
        };
        var sectionCounts = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Interface"] = 0,
            ["Peer"] = 0
        };
        string? section = null;

        foreach (var rawLine in text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None))
        {
            var comment = rawLine.IndexOf('#');
            var line = (comment >= 0 ? rawLine[..comment] : rawLine).Trim();
            if (line.Length == 0) continue;

            if (line.StartsWith('[') || line.EndsWith(']'))
            {
                if (line.Length < 3 || line[0] != '[' || line[^1] != ']' || line.IndexOf('[', 1) >= 0 || line.IndexOf(']', 0, line.Length - 1) >= 0)
                    throw Reject("Configuration contains an invalid section.");
                section = line[1..^1];
                if (!sectionCounts.ContainsKey(section)) throw Reject("Configuration contains an unsupported section.");
                sectionCounts[section]++;
                if (section == "Peer" && sectionCounts[section] > 1) throw Reject("Configuration contains multiple peers.");
                if (sectionCounts[section] > 1) throw Reject("Configuration must contain one interface and one peer.");
                continue;
            }

            var equals = line.IndexOf('=');
            if (equals <= 0 || section is null) throw Reject("Configuration contains an invalid scalar field.");
            var field = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            if (value.Length == 0) throw Reject("Configuration contains an empty scalar field.");
            if (IsHook(field)) throw Reject("Configuration hooks are not allowed.");
            if (string.Equals(field, "PresharedKey", StringComparison.OrdinalIgnoreCase))
                throw Reject("Configuration preshared keys are not allowed.");
            if (!IsAllowedField(section, field)) throw Reject("Configuration contains an unsupported scalar field.");
            if (!values[section].TryAdd(field, value)) throw Reject("Configuration scalar fields must be unique.");
        }

        if (sectionCounts["Interface"] != 1 || sectionCounts["Peer"] != 1)
            throw Reject("Configuration must contain one interface and one peer.");
        return values;
    }

    private static string Required(Dictionary<string, Dictionary<string, string>> values, string section, string field)
    {
        if (!values[section].TryGetValue(field, out var value)) throw Reject("Configuration is missing a required scalar field.");
        return value;
    }

    private static bool IsAllowedField(string section, string field) => section == "Interface"
        ? field is "PrivateKey" or "Address" or "DNS"
        : field is "PublicKey" or "AllowedIPs" or "Endpoint";

    private static bool IsHook(string field) => string.Equals(field, "PreUp", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(field, "PostUp", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(field, "PreDown", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(field, "PostDown", StringComparison.OrdinalIgnoreCase);

    private static string ParseClientAddress(string value)
    {
        var parts = value.Split('/');
        if (parts.Length != 2 ||
            !TryParseIpv4(parts[0], out var address) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) ||
            prefix is < 0 or > 32)
            throw Reject("Configuration client address must be an IPv4 prefix.");
        return address.ToString();
    }

    private static void ValidateAllowedIps(string value)
    {
        var prefixes = value.Split(',', StringSplitOptions.TrimEntries);
        if (prefixes.Length == 0) throw Reject("Configuration AllowedIPs value is invalid.");
        foreach (var prefixText in prefixes)
        {
            var parts = prefixText.Split('/');
            if (parts.Length != 2 || !TryParseIp(parts[0], out var address) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix))
                throw Reject("Configuration AllowedIPs value is invalid.");
            var maximum = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > maximum) throw Reject("Configuration AllowedIPs value is invalid.");
        }
    }

    private static bool TryParseIp(string value, out IPAddress address)
    {
        if (!value.Contains(':')) return TryParseIpv4(value, out address!);
        if (value.Contains('%') || !IPAddress.TryParse(value, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetworkV6)
        {
            address = IPAddress.None;
            return false;
        }
        address = parsed;
        return true;
    }

    private static bool TryParseIpv4(string value, out IPAddress address)
    {
        var parts = value.Split('.');
        var octets = new byte[4];
        if (parts.Length != 4)
        {
            address = IPAddress.None;
            return false;
        }
        for (var index = 0; index < parts.Length; index++)
        {
            if (!byte.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out octets[index]))
            {
                address = IPAddress.None;
                return false;
            }
        }
        address = new IPAddress(octets);
        return true;
    }

    private static Regex PeerLinePattern(string field) => new(
        @"(?m)^(?<prefix>[ \t]*" + Regex.Escape(field) + @"(?<equals>[ \t]*=[ \t]*))(?<value>[^#\r\n]*?)(?<suffix>[ \t]*(?:#.*)?)(?<newline>\r\n|\n|\r|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        RegexTimeout);

    private static string ReplaceExactlyOnce(string text, Regex pattern, string value)
    {
        var replacements = 0;
        var result = pattern.Replace(text, match =>
        {
            replacements++;
            return match.Groups["prefix"].Value + value + match.Groups["suffix"].Value + match.Groups["newline"].Value;
        });
        if (replacements != 1) throw Reject("Configuration peer fields must occur exactly once.");
        return result;
    }

    private static bool StartsWith(byte[] bytes, params byte[] prefix)
    {
        if (bytes.Length < prefix.Length) return false;
        for (var index = 0; index < prefix.Length; index++)
        {
            if (bytes[index] != prefix[index]) return false;
        }
        return true;
    }

    private static InvalidDataException Reject(string message) => new(message);
}
