using System.Net;
using System.Net.Sockets;

namespace WireguardSplitTunnel.Core.Services;

public interface IDomainResolver
{
    Task<IReadOnlyCollection<string>> ResolveAsync(string domain, CancellationToken cancellationToken);
}

public sealed class SystemDomainResolver : IDomainResolver
{
    public async Task<IReadOnlyCollection<string>> ResolveAsync(string domain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalized = NormalizeForLookup(domain);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return [];
        }

        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(normalized);
        }
        catch (SocketException)
        {
            return [];
        }
        catch (ArgumentException)
        {
            return [];
        }

        return addresses
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string NormalizeForLookup(string domain)
    {
        var value = domain.Trim();
        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            value = value[2..];
        }

        return value;
    }
}
