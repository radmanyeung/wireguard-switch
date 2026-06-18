namespace WireguardSplitTunnel.Core.Services;

public enum MonitorTabAutoRunAction
{
    None,
    Start,
    Stop
}

public static class MonitorTabAutoRunPolicy
{
    public static MonitorTabAutoRunAction GetAction(bool wasMonitorTabSelected, bool isMonitorTabSelected)
    {
        if (!wasMonitorTabSelected && isMonitorTabSelected)
        {
            return MonitorTabAutoRunAction.Start;
        }

        if (wasMonitorTabSelected && !isMonitorTabSelected)
        {
            return MonitorTabAutoRunAction.Stop;
        }

        return MonitorTabAutoRunAction.None;
    }
}
