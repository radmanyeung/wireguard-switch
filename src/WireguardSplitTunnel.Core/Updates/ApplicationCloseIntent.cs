using System.Threading;

namespace WireguardSplitTunnel.Core.Updates;

public enum ApplicationCloseIntent
{
    UnknownOrAbnormal = 0,
    UserOrApplicationClose = 1,
    SessionEnding = 2,
    ElevationHandoff = 3
}

public sealed class ApplicationCloseIntentTracker
{
    private int _intent = (int)ApplicationCloseIntent.UnknownOrAbnormal;

    public ApplicationCloseIntent Current => (ApplicationCloseIntent)Volatile.Read(ref _intent);

    public void ResolveNormalClose() =>
        Interlocked.CompareExchange(
            ref _intent,
            (int)ApplicationCloseIntent.UserOrApplicationClose,
            (int)ApplicationCloseIntent.UnknownOrAbnormal);

    public void RecordElevationHandoff()
    {
        while (true)
        {
            var current = Volatile.Read(ref _intent);
            if (current is (int)ApplicationCloseIntent.SessionEnding or (int)ApplicationCloseIntent.ElevationHandoff)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _intent, (int)ApplicationCloseIntent.ElevationHandoff, current) == current)
            {
                return;
            }
        }
    }

    public void RecordSessionEnding() =>
        Interlocked.Exchange(ref _intent, (int)ApplicationCloseIntent.SessionEnding);
}
