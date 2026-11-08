namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Rewrites WireGuard <c>AllowedIPs</c> so the Windows root tunnel service
/// never engages its automatic kill switch.
/// <para>
/// <c>wireguard.exe /installtunnelservice</c> blocks ALL untunneled traffic
/// (LAN included) when a config's AllowedIPs contains <c>0.0.0.0/0</c> or
/// <c>::/0</c>. The split pair <c>0.0.0.0/1, 128.0.0.0/1</c> covers every IPv4
/// address without triggering that behavior. IPv6 entries are dropped because
/// split-tunnel route management is IPv4-only.
/// </para>
/// </summary>
public static class WireguardAllowedIpsSanitizer
{
    public const string Ipv4FullRange = "0.0.0.0/0";
    public const string SplitPairFirst = "0.0.0.0/1";
    public const string SplitPairSecond = "128.0.0.0/1";

    public static SanitizedWireguardConfig SanitizeText(string configText)
    {
        ArgumentNullException.ThrowIfNull(configText);

        var lines = configText.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var changed = false;

        for (var index = 0; index < lines.Length; index++)
        {
            var sanitized = SanitizeAllowedIpsLine(lines[index], out var lineChanged);
            if (lineChanged)
            {
                lines[index] = sanitized;
                changed = true;
            }
        }

        return new SanitizedWireguardConfig(
            changed ? string.Join('\n', lines) : configText,
            changed);
    }

    /// <summary>
    /// Returns a config path whose AllowedIPs cannot trigger the WireGuard
    /// Windows kill switch. When the source needs no rewrite, the source path
    /// itself is returned. Otherwise a derived copy (same file name, so the
    /// tunnel name stays identical) is written under
    /// <paramref name="derivedDirectory"/> and its path is returned. Plaintext
    /// reads, derived creation, and exact-content validation are fail-closed:
    /// a failure never falls back to installing the potentially unsafe source.
    /// </summary>
    public static string EnsureSanitizedConfigFile(string sourcePath, string derivedDirectory)
    {
        if (string.IsNullOrWhiteSpace(sourcePath)
            || sourcePath.EndsWith(".conf.dpapi", StringComparison.OrdinalIgnoreCase))
        {
            return sourcePath;
        }

        var text = File.ReadAllText(sourcePath);
        var sanitized = SanitizeText(text);
        if (!sanitized.Changed)
        {
            return sourcePath;
        }

        Directory.CreateDirectory(derivedDirectory);
        var derivedPath = Path.Combine(derivedDirectory, Path.GetFileName(sourcePath));
        if (!File.Exists(derivedPath)
            || !string.Equals(
                File.ReadAllText(derivedPath),
                sanitized.Text,
                StringComparison.Ordinal))
        {
            File.WriteAllText(derivedPath, sanitized.Text);
        }

        var verifiedText = File.ReadAllText(derivedPath);
        if (!string.Equals(verifiedText, sanitized.Text, StringComparison.Ordinal)
            || SanitizeText(verifiedText).Changed)
        {
            throw new IOException("The sanitized derived config failed exact-content validation.");
        }

        return derivedPath;
    }

    /// <summary>
    /// Atomically rebuilds the exact derived copy used by an enabled tunnel from
    /// a verified repaired source, additionally authenticating its journal
    /// fingerprint, peer identity, and owned derived-content relationship.
    /// </summary>
    public static void ReconcileRepairedConfigFile(
        string sourcePath,
        string derivedConfigPath,
        string expectedFingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(derivedConfigPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedFingerprint);

        var repaired = global::WireguardSplitTunnel.Core.ConfigCheck.CheckedConfig.Parse(sourcePath);
        if (!string.Equals(repaired.Fingerprint, expectedFingerprint, StringComparison.Ordinal))
            throw new IOException("The repaired source fingerprint does not match the recovery journal.");

        var sanitized = SanitizeText(repaired.Text);
        if (!sanitized.Changed)
            throw new IOException("Derived config reconciliation requires a source that needs AllowedIPs sanitization.");

        var derivedFullPath = Path.GetFullPath(derivedConfigPath);
        if (!string.Equals(
                Path.GetFileName(derivedFullPath),
                Path.GetFileName(repaired.Path),
                StringComparison.OrdinalIgnoreCase))
            throw new IOException("The derived config must have exactly the same file name as its source.");
        global::WireguardSplitTunnel.Core.ConfigCheck.WindowsConfigCheckPrimitives.EnsureNoReparsePoints(derivedFullPath);

        var expectedBytes = new System.Text.UTF8Encoding(false).GetBytes(sanitized.Text);
        var derivedExists = File.Exists(derivedFullPath);
        if (derivedExists)
        {
            var existing = global::WireguardSplitTunnel.Core.ConfigCheck.CheckedConfig.Parse(derivedFullPath);
            byte[] comparableBytes;
            try
            {
                comparableBytes = existing.WithPeerServer(repaired.OriginalServer);
            }
            catch (Exception exception) when (exception is InvalidDataException or IOException)
            {
                throw new IOException("The existing derived config is not an owned peer-only variant.", exception);
            }
            if (!comparableBytes.AsSpan().SequenceEqual(expectedBytes))
                throw new IOException("The existing same-name file is not an owned derived config; it was not modified.");
        }

        var derivedDirectory = Path.GetDirectoryName(derivedFullPath)
            ?? throw new IOException("The derived config directory is unavailable.");
        Directory.CreateDirectory(derivedDirectory);
        global::WireguardSplitTunnel.Core.ConfigCheck.WindowsConfigCheckPrimitives.EnsureNoReparsePoints(derivedFullPath);
        var temporaryPath = Path.Combine(
            derivedDirectory,
            "." + Path.GetFileName(derivedFullPath) + "." + Guid.NewGuid().ToString("N") + ".wgst-derived.tmp");
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(expectedBytes);
                stream.Flush(flushToDisk: true);
            }

            if (derivedExists)
                File.Replace(temporaryPath, derivedFullPath, null);
            else
                File.Move(temporaryPath, derivedFullPath);

            global::WireguardSplitTunnel.Core.ConfigCheck.WindowsConfigCheckPrimitives.EnsureNoReparsePoints(derivedFullPath);
            var verifiedBytes = File.ReadAllBytes(derivedFullPath);
            if (!verifiedBytes.AsSpan().SequenceEqual(expectedBytes))
                throw new IOException("The rebuilt derived config failed exact byte verification.");
            var verified = global::WireguardSplitTunnel.Core.ConfigCheck.CheckedConfig.Parse(derivedFullPath);
            if (!string.Equals(verified.Endpoint, repaired.Endpoint, StringComparison.Ordinal) ||
                !string.Equals(verified.PublicKey, repaired.PublicKey, StringComparison.Ordinal) ||
                SanitizeText(verified.Text).Changed ||
                !verifiedBytes.AsSpan().SequenceEqual(verified.Bytes))
                throw new IOException("The rebuilt derived config failed peer or AllowedIPs verification.");
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public static string GetDefaultDerivedConfigDirectory() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WireguardSplitTunnel",
            "derived-confs");

    private static string SanitizeAllowedIpsLine(string line, out bool changed)
    {
        changed = false;

        var trimmedStart = line.TrimStart();
        var equalsIndex = trimmedStart.IndexOf('=');
        if (equalsIndex < 0
            || !trimmedStart[..equalsIndex].TrimEnd().Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase))
        {
            return line;
        }

        var valuePart = trimmedStart[(equalsIndex + 1)..];
        var comment = string.Empty;
        var commentIndex = valuePart.IndexOf('#');
        if (commentIndex >= 0)
        {
            comment = valuePart[commentIndex..];
            valuePart = valuePart[..commentIndex];
        }

        var entries = valuePart.Split(',');
        var kept = new List<string>(entries.Length + 1);
        var hasFullRange = false;
        var droppedIpv6 = false;
        var ipv4Kept = 0;

        foreach (var rawEntry in entries)
        {
            var entry = rawEntry.Trim();
            if (entry.Length == 0)
            {
                continue;
            }

            if (entry.Equals(Ipv4FullRange, StringComparison.Ordinal))
            {
                hasFullRange = true;
                continue;
            }

            if (entry.Contains(':', StringComparison.Ordinal))
            {
                droppedIpv6 = true;
                continue;
            }

            ipv4Kept++;
            kept.Add(entry);
        }

        if (!hasFullRange && (!droppedIpv6 || ipv4Kept == 0))
        {
            return line;
        }

        if (hasFullRange)
        {
            if (!kept.Contains(SplitPairFirst, StringComparer.Ordinal))
            {
                kept.Insert(0, SplitPairFirst);
            }

            if (!kept.Contains(SplitPairSecond, StringComparer.Ordinal))
            {
                kept.Insert(kept.IndexOf(SplitPairFirst) + 1, SplitPairSecond);
            }
        }

        var prefix = line[..(line.Length - trimmedStart.Length)]
            + trimmedStart[..(equalsIndex + 1)];
        var suffix = string.IsNullOrEmpty(comment) ? string.Empty : " " + comment;
        changed = true;
        return $"{prefix} {string.Join(", ", kept)}{suffix}";
    }
}

public readonly record struct SanitizedWireguardConfig(string Text, bool Changed);
