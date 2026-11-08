namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// An exact, validated WireGuard tunnel service identity.
/// </summary>
public sealed record WindowsTunnelServiceIdentity
{
    private const string ServiceNamePrefix = "WireGuardTunnel$";

    private WindowsTunnelServiceIdentity(string serviceName, string tunnelName)
    {
        ServiceName = serviceName;
        TunnelName = tunnelName;
    }

    public string ServiceName { get; }

    public string TunnelName { get; }

    public static WindowsTunnelServiceIdentity FromServiceName(string serviceName)
    {
        ArgumentNullException.ThrowIfNull(serviceName);
        if (!serviceName.StartsWith(ServiceNamePrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Service name must start with '{ServiceNamePrefix}'.",
                nameof(serviceName));
        }

        var identity = FromTunnelName(serviceName[ServiceNamePrefix.Length..]);
        return new WindowsTunnelServiceIdentity(serviceName, identity.TunnelName);
    }

    public static WindowsTunnelServiceIdentity FromTunnelName(string tunnelName)
    {
        ArgumentNullException.ThrowIfNull(tunnelName);
        if (!IsValidTunnelName(tunnelName))
        {
            throw new ArgumentException("Tunnel name contains invalid characters or is empty.", nameof(tunnelName));
        }

        return new WindowsTunnelServiceIdentity(ServiceNamePrefix + tunnelName, tunnelName);
    }

    public static bool IsValidTunnelName(string? tunnelName)
    {
        if (string.IsNullOrEmpty(tunnelName) || tunnelName is "." or "..")
        {
            return false;
        }

        foreach (var character in tunnelName)
        {
            if (!IsAllowedCharacter(character))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAllowedCharacter(char character) =>
        character is >= 'A' and <= 'Z'
        || character is >= 'a' and <= 'z'
        || character is >= '0' and <= '9'
        || character is '_' or '=' or '+' or '.' or '-';
}
