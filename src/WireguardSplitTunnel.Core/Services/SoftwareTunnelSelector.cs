namespace WireguardSplitTunnel.Core.Services;
public static class SoftwareTunnelSelector
{
    public static string? Select(string? selectedConfigPath, IEnumerable<string> activeTunnelNames)
    {
        var names = activeTunnelNames.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (!string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            var selectedName = WireguardConfigCatalog.GetTunnelName(selectedConfigPath);
            return names.FirstOrDefault(n => n.Equals(selectedName, StringComparison.OrdinalIgnoreCase));
        }
        return names.Length == 1 ? names[0] : null;
    }
}
