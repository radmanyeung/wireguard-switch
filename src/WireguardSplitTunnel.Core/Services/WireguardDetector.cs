using System.Net.NetworkInformation;

namespace WireguardSplitTunnel.Core.Services;

public interface IWireguardDetector
{
    bool TryGetActiveInterface(out string interfaceName);
}

public sealed class SystemWireguardDetector : IWireguardDetector
{
    public bool TryGetActiveInterface(out string interfaceName)
    {
        var candidate = NetworkInterface
            .GetAllNetworkInterfaces()
            .FirstOrDefault(networkInterface =>
                networkInterface.OperationalStatus == OperationalStatus.Up
                && (networkInterface.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                    || networkInterface.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase)));

        if (candidate is null)
        {
            interfaceName = string.Empty;
            return false;
        }

        interfaceName = candidate.Name;
        return true;
    }
}
