using WireguardSplitTunnel.WindowsUpdate;
using WireguardSplitTunnel.WindowsUpdate.Logging;

namespace WireguardSplitTunnel.Updater;

internal static class Program
{
    public static async Task<int> Main(string[] arguments)
    {
        try
        {
            var logger = new UpdaterFileLogger();
            var application = new UpdaterCommandApplication(
                new UpdaterCommandLine(),
                new ProtectedUpdaterInvocationBoundary(),
                logger);
            return await application.RunAsync(
                    arguments,
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (IsNonFatal(exception))
        {
            return UpdaterExitCodes.Failed;
        }
    }

    private static bool IsNonFatal(Exception exception) =>
        exception is not (
            OutOfMemoryException
                or StackOverflowException
                or AccessViolationException);
}
