using System.Text.Json;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class NordVpnMetadata
{
    internal static IEqualityComparer<string> HostNameComparer { get; } = StringComparer.OrdinalIgnoreCase;

    public static string CountryFromHost(string host) => CheckedConfig.ParseEndpoint(host + ":51820").Country;

    public static IReadOnlyList<ConfigCheckServer> SelectCandidates(JsonElement servers, string country, int limit)
    {
        if (servers.ValueKind != JsonValueKind.Array || limit is < 1 or > 5) throw new InvalidDataException("Invalid metadata.");
        var seen = new HashSet<string>(HostNameComparer);
        var selected = new List<ConfigCheckServer>();
        foreach (var server in servers.EnumerateArray())
        {
            if (selected.Count >= limit) break;
            try
            {
                if (server.GetProperty("status").GetString() != "online") continue;
                var host = server.GetProperty("hostname").GetString() ?? "";
                string serverCountry;
                try { serverCountry = CountryFromHost(host); } catch (InvalidDataException) { continue; }
                if (serverCountry != country || !seen.Add(host)) continue;
                if (!HasSingleCountry(server, country)) continue;
                var key = SingleOnlineWireGuardKey(server);
                if (key is null) continue;
                selected.Add(new ConfigCheckServer(host.ToLowerInvariant(), key, country));
            }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or KeyNotFoundException)
            {
                // A malformed record is not a candidate; the remaining records can still be used.
            }
        }
        return selected;
    }

    private static bool HasSingleCountry(JsonElement server, string country) =>
        server.GetProperty("locations").EnumerateArray().Select(location => location.GetProperty("country").GetProperty("code").GetString()).Distinct(StringComparer.Ordinal).SingleOrDefault() == country;

    private static string? SingleOnlineWireGuardKey(JsonElement server)
    {
        var technologies = server.GetProperty("technologies").EnumerateArray().Where(technology =>
            technology.GetProperty("identifier").GetString() == "wireguard_udp" &&
            technology.GetProperty("pivot").GetProperty("status").GetString() == "online").ToArray();
        if (technologies.Length != 1) return null;
        var keys = technologies[0].GetProperty("metadata").EnumerateArray().Where(item => item.GetProperty("name").GetString() == "public_key").Select(item => item.GetProperty("value").GetString()).ToArray();
        return keys.Length == 1 && CheckedConfig.IsValidKey(keys[0]) ? keys[0] : null;
    }
}
