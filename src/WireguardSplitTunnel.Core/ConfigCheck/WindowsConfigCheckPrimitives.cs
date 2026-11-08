using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class WindowsConfigCheckPrimitives
{
    public static IReadOnlyList<string> BuildCurlArguments(string probeIp, string sourceAddress) =>
        ["-q", "-4", "--interface", sourceAddress, "--resolve", "www.cloudflare.com:443:" + probeIp, "--noproxy", "*", "--proto", "=https", "--connect-timeout", "8", "--max-time", "15", "--max-filesize", "16384", "--fail", "--silent", "--show-error", "https://www.cloudflare.com/cdn-cgi/trace"];

    public static bool HasFreshHandshake(string output, string publicKey, long started) =>
        output.Split('\r', '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('\t'))
            .Any(columns => columns.Length == 2 && columns[0] == publicKey && long.TryParse(columns[1], out var stamp) && stamp > started);

    public static string NewOwnedTunnelName() => "WGSTCheck-" + Guid.NewGuid().ToString("N")[..12];

    public static string NewProbeConfig(CheckedConfig config, ConfigCheckServer server) =>
        "[Interface]\r\nPrivateKey = " + config.PrivateKey + "\r\nAddress = " + config.SourceAddress + "/32\r\nTable = off\r\n\r\n[Peer]\r\nPublicKey = " + server.PublicKey + "\r\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\nEndpoint = " + server.HostName + ":" + config.Port + "\r\nPersistentKeepalive = 3\r\n";

    public static string FingerprintFile(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    public static bool IsPathWithinRoot(string rootPath, string candidatePath)
    {
        var root = Path.GetFullPath(rootPath);
        var candidate = Path.GetFullPath(candidatePath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(root, candidate, comparison)) return true;

        var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    public static void EnsureNoReparsePoints(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(current);
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
            {
                continue;
            }

            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Path must not contain a reparse point.");
        }
    }

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
    private static readonly Regex SensitiveAssignment = new(
        @"(?i)\b(?:PrivateKey|PublicKey)\s*=\s*[^\r\n]*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex WireGuardKey = new(
        @"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        RegexTimeout);
    private static readonly Regex RepeatedWhitespace = new(
        @"\s+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        RegexTimeout);

    public static string CreateSafeNetshError(int exitCode, string rawOutput)
    {
        const int maxDiagnosticLength = 512;
        var generic = CreateSafeNativeError("netsh.exe", exitCode, string.Empty);
        var sanitized = SensitiveAssignment.Replace(rawOutput, "[redacted]");
        sanitized = WireGuardKey.Replace(sanitized, "[redacted]");
        sanitized = RepeatedWhitespace.Replace(sanitized, " ").Trim();
        if (sanitized.Length == 0) return generic;
        if (sanitized.Length > maxDiagnosticLength)
            sanitized = sanitized[..maxDiagnosticLength] + "… [truncated]";
        return generic + " Diagnostic: " + sanitized;
    }

    public static string CreateSafeNativeError(string operation, int exitCode, string rawOutput) =>
        operation + " failed (exit code " + exitCode.ToString(CultureInfo.InvariantCulture) + ").";
}
