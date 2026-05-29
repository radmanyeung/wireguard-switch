using System.Reflection;

namespace WireguardSplitTunnel.Core.Services;

public static class VersionDisplay
{
    public static string FromAssembly(Assembly assembly)
    {
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informationalVersion))
        {
            return FromInformationalVersion(informationalVersion);
        }

        return FromInformationalVersion(assembly.GetName().Version?.ToString());
    }

    public static string FromInformationalVersion(string? informationalVersion)
    {
        if (string.IsNullOrWhiteSpace(informationalVersion))
        {
            return "vunknown";
        }

        var normalized = informationalVersion.Trim();
        var metadataIndex = normalized.IndexOf('+', StringComparison.Ordinal);
        if (metadataIndex >= 0)
        {
            normalized = normalized[..metadataIndex];
        }

        return normalized.StartsWith("v", StringComparison.OrdinalIgnoreCase)
            ? normalized
            : $"v{normalized}";
    }
}