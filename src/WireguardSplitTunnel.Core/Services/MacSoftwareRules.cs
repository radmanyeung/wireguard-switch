using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record MacAppBundleInfo(
    string BundleIdentifier,
    string DisplayName,
    string? ExecutableName);

public sealed record MacSoftwareRuleApplyCapability(
    bool CanApply,
    string Message);

public static class MacTunnelProfileService
{
    public static MacTunnelProfile CreateProfile(string configPath)
    {
        var normalizedPath = NormalizePath(configPath);
        var tunnelName = WireguardConfigCatalog.GetTunnelName(normalizedPath);
        var displayName = string.IsNullOrWhiteSpace(tunnelName)
            ? Path.GetFileNameWithoutExtension(normalizedPath)
            : tunnelName;

        return new MacTunnelProfile(
            Id: MakeStableId(normalizedPath),
            DisplayName: displayName,
            ConfigPath: normalizedPath,
            Enabled: true,
            TunnelName: tunnelName);
    }

    private static string NormalizePath(string path) => path.Trim();

    private static string MakeStableId(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant()));
        return "profile-" + Convert.ToHexString(bytes)[..12].ToLowerInvariant();
    }
}

public static class MacSoftwareRuleMutations
{
    public static bool TryAddProfile(AppState state, MacTunnelProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Id)
            || string.IsNullOrWhiteSpace(profile.ConfigPath)
            || string.IsNullOrWhiteSpace(profile.DisplayName))
        {
            return false;
        }

        if (state.MacTunnelProfiles.Any(existing =>
                string.Equals(existing.Id, profile.Id, StringComparison.OrdinalIgnoreCase)
                || string.Equals(existing.ConfigPath.Trim(), profile.ConfigPath.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        state.MacTunnelProfiles.Add(profile with
        {
            Id = profile.Id.Trim(),
            DisplayName = profile.DisplayName.Trim(),
            ConfigPath = profile.ConfigPath.Trim(),
            TunnelName = string.IsNullOrWhiteSpace(profile.TunnelName)
                ? WireguardConfigCatalog.GetTunnelName(profile.ConfigPath)
                : profile.TunnelName.Trim()
        });
        return true;
    }

    public static bool TrySetProfileEnabled(AppState state, string profileId, bool enabled)
    {
        var index = state.MacTunnelProfiles.FindIndex(profile =>
            string.Equals(profile.Id, profileId, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        state.MacTunnelProfiles[index] = state.MacTunnelProfiles[index] with { Enabled = enabled };
        return true;
    }

    public static bool RemoveProfile(AppState state, string profileId)
    {
        var index = state.MacTunnelProfiles.FindIndex(profile =>
            string.Equals(profile.Id, profileId, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        state.MacTunnelProfiles.RemoveAt(index);
        state.MacSoftwareRules.RemoveAll(rule =>
            string.Equals(rule.ProfileId, profileId, StringComparison.OrdinalIgnoreCase));
        state.MacDomainProfileAssignments.RemoveAll(rule =>
            string.Equals(rule.ProfileId, profileId, StringComparison.OrdinalIgnoreCase));
        return true;
    }

    public static bool TryAddSoftwareRule(
        AppState state,
        string bundleIdentifier,
        string displayName,
        string? bundlePath,
        string profileId)
    {
        var normalizedBundleId = NormalizeBundleIdentifier(bundleIdentifier);
        var normalizedProfileId = profileId.Trim();
        if (string.IsNullOrWhiteSpace(normalizedBundleId) || string.IsNullOrWhiteSpace(normalizedProfileId))
        {
            return false;
        }

        if (state.MacSoftwareRules.Any(rule =>
                string.Equals(rule.BundleIdentifier, normalizedBundleId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(rule.ProfileId, normalizedProfileId, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        state.MacSoftwareRules.Add(new MacSoftwareRule(
            normalizedBundleId,
            string.IsNullOrWhiteSpace(displayName) ? normalizedBundleId : displayName.Trim(),
            string.IsNullOrWhiteSpace(bundlePath) ? null : bundlePath.Trim(),
            normalizedProfileId,
            true));
        return true;
    }

    public static bool TrySetSoftwareRuleEnabled(AppState state, string bundleIdentifier, string profileId, bool enabled)
    {
        var index = FindSoftwareRuleIndex(state, bundleIdentifier, profileId);
        if (index < 0)
        {
            return false;
        }

        state.MacSoftwareRules[index] = state.MacSoftwareRules[index] with { Enabled = enabled };
        return true;
    }

    public static bool RemoveSoftwareRule(AppState state, string bundleIdentifier, string profileId)
    {
        var index = FindSoftwareRuleIndex(state, bundleIdentifier, profileId);
        if (index < 0)
        {
            return false;
        }

        state.MacSoftwareRules.RemoveAt(index);
        return true;
    }

    private static int FindSoftwareRuleIndex(AppState state, string bundleIdentifier, string profileId)
    {
        var normalizedBundleId = NormalizeBundleIdentifier(bundleIdentifier);
        var normalizedProfileId = profileId.Trim();
        return state.MacSoftwareRules.FindIndex(rule =>
            string.Equals(rule.BundleIdentifier, normalizedBundleId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(rule.ProfileId, normalizedProfileId, StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeBundleIdentifier(string bundleIdentifier) =>
        bundleIdentifier.Trim().ToLowerInvariant();
}

public static class MacAppBundleInfoParser
{
    public static MacAppBundleInfo? ParseInfoPlistContent(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        try
        {
            var document = XDocument.Parse(content);
            var dict = document.Root?.Element("dict");
            if (dict is null)
            {
                return null;
            }

            var values = ReadDictionary(dict);
            if (!values.TryGetValue("CFBundleIdentifier", out var bundleIdentifier)
                || string.IsNullOrWhiteSpace(bundleIdentifier))
            {
                return null;
            }

            var displayName = FirstNonEmpty(
                values.GetValueOrDefault("CFBundleDisplayName"),
                values.GetValueOrDefault("CFBundleName"),
                values.GetValueOrDefault("CFBundleExecutable"),
                bundleIdentifier);

            return new MacAppBundleInfo(
                bundleIdentifier.Trim(),
                displayName,
                FirstNonEmptyOrNull(values.GetValueOrDefault("CFBundleExecutable")));
        }
        catch
        {
            return null;
        }
    }

    public static MacAppBundleInfo? TryReadBundle(string bundlePath)
    {
        if (string.IsNullOrWhiteSpace(bundlePath))
        {
            return null;
        }

        var infoPath = Path.Combine(bundlePath.Trim(), "Contents", "Info.plist");
        if (!File.Exists(infoPath))
        {
            return null;
        }

        try
        {
            var parsed = ParseInfoPlistContent(File.ReadAllText(infoPath));
            if (parsed is not null)
            {
                return parsed;
            }
        }
        catch
        {
            // Binary plists are common for installed macOS apps; fall back below.
        }

        return OperatingSystem.IsMacOS()
            ? TryReadBundleWithPlistBuddy(infoPath)
            : null;
    }

    private static Dictionary<string, string> ReadDictionary(XElement dict)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var children = dict.Elements().ToList();
        for (var i = 0; i < children.Count - 1; i++)
        {
            if (children[i].Name.LocalName != "key")
            {
                continue;
            }

            var valueElement = children[i + 1];
            if (valueElement.Name.LocalName == "string")
            {
                values[children[i].Value] = valueElement.Value;
            }
        }

        return values;
    }

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))!.Trim();

    private static string? FirstNonEmptyOrNull(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim();

    private static MacAppBundleInfo? TryReadBundleWithPlistBuddy(string infoPath)
    {
        var bundleIdentifier = TryReadPlistValue(infoPath, "CFBundleIdentifier");
        if (string.IsNullOrWhiteSpace(bundleIdentifier))
        {
            return null;
        }

        var displayName = FirstNonEmpty(
            TryReadPlistValue(infoPath, "CFBundleDisplayName"),
            TryReadPlistValue(infoPath, "CFBundleName"),
            TryReadPlistValue(infoPath, "CFBundleExecutable"),
            bundleIdentifier);

        return new MacAppBundleInfo(
            bundleIdentifier.Trim(),
            displayName,
            FirstNonEmptyOrNull(TryReadPlistValue(infoPath, "CFBundleExecutable")));
    }

    private static string? TryReadPlistValue(string infoPath, string key)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "/usr/libexec/PlistBuddy",
                Arguments = $"-c \"Print :{key}\" \"{infoPath.Replace("\"", "\\\"", StringComparison.Ordinal)}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null || !process.WaitForExit(2000) || process.ExitCode != 0)
            {
                return null;
            }

            return process.StandardOutput.ReadToEnd().Trim();
        }
        catch
        {
            return null;
        }
    }
}

public static class MacSoftwareRuleApplyGuard
{
    public static MacSoftwareRuleApplyCapability CheckCapability(bool hasNetworkExtensionEntitlement = false)
    {
        if (hasNetworkExtensionEntitlement)
        {
            return new MacSoftwareRuleApplyCapability(true, "Network Extension entitlement detected.");
        }

        return new MacSoftwareRuleApplyCapability(
            false,
            "True app routing requires Apple Developer Network Extension entitlement and a signed Network Extension build. No pf/user fallback was applied.");
    }
}
