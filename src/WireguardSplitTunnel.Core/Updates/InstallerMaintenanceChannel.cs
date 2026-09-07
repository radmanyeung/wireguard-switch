namespace WireguardSplitTunnel.Core.Updates;

public static class InstallerMaintenanceChannel
{
    public static string CreateEventName(int processId, long creationTimeFileTimeUtc)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }
        if (creationTimeFileTimeUtc <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(creationTimeFileTimeUtc));
        }

        return $"Local\\WireguardSplitTunnel.InstallerMaintenance.{processId}.{creationTimeFileTimeUtc}";
    }
}
