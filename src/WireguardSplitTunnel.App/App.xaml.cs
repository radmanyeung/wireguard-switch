using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.App.Services;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.App;

public partial class App : Application
{
    private readonly ApplicationCloseIntentTracker
        closeIntentTracker = new();

    public App()
    {
        ShutdownMode = ShutdownMode.OnMainWindowClose;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var requireAdmin = ShouldRequireAdministratorForCurrentMode();
        var isAdmin = IsRunningAsAdministrator();
        var elevatedLaunchRequested = e.Args.Any(arg =>
            string.Equals(arg, "--elevated-launch", StringComparison.OrdinalIgnoreCase));
        var runPostInstallSelfTest = e.Args.Any(arg =>
            string.Equals(arg, "--post-install-self-test", StringComparison.OrdinalIgnoreCase));
        var updateHealthContext =
            TryReadUpdateHealthContext(e.Args);

        WriteBootstrapLog(
            $"Startup. requireAdmin={requireAdmin}, "
            + $"isAdmin={isAdmin}, "
            + $"elevatedArg={elevatedLaunchRequested}, "
            + $"selfTestArg={runPostInstallSelfTest}, "
            + $"healthContext={updateHealthContext is not null}, "
            + $"hasArguments={e.Args.Length > 0}");

        if (requireAdmin && !isAdmin)
        {
            using var autoElevationLease =
                IsCurrentExecutableEligibleForAutoElevation();
            var autoElevationEligible =
                autoElevationLease is not null;
            WriteBootstrapLog(
                $"Auto-elevation eligibility={autoElevationEligible}.");
            if (!autoElevationEligible)
            {
                WriteBootstrapLog(
                    "Auto-elevation refused for an unprotected executable.");
                MessageBox.Show(
                    "This copy cannot be auto-elevated. Install it with install.cmd, then start the protected installed copy, or explicitly run a trusted developer build as administrator.",
                    "Wireguard Split Tunnel",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            else if (!elevatedLaunchRequested)
            {
                var relaunched = TryRelaunchAsAdministrator(
                    e.Args,
                    autoElevationLease!);
                WriteBootstrapLog(
                    $"Auto-elevation attempted. relaunched={relaunched}");

                if (relaunched)
                {
                    closeIntentTracker.RecordElevationHandoff();
                    Shutdown();
                    return;
                }
            }
            else
            {
                WriteBootstrapLog("Startup still non-admin after --elevated-launch; continuing without auto-retry.");
            }
        }

        WindowsUpdateCompositionRoot? updates = null;
        try
        {
            updates =
                WindowsUpdateCompositionRoot.CreateProduction(
                    runPostInstallSelfTest);
        }
        catch (Exception)
        {
            WriteBootstrapLog(
                "Windows update runtime available=false.");
        }

        var window = new MainWindow(
            runPostInstallSelfTest,
            closeIntentTracker,
            updateCloseParticipant: updates,
            windowsUpdate: updates,
            updateStartupHealthContext:
                updateHealthContext);
        MainWindow = window;
        window.Show();
    }

    protected override void OnSessionEnding(
        SessionEndingCancelEventArgs e)
    {
        closeIntentTracker.RecordSessionEnding();
        base.OnSessionEnding(e);
    }

    private static UpdateStartupHealthContext?
        TryReadUpdateHealthContext(
            IReadOnlyList<string> arguments)
    {
        string? transactionValue = null;
        string? versionValue = null;
        var invalid = false;
        for (var index = 0;
             index < arguments.Count;
             index++)
        {
            var argument = arguments[index];
            if (argument is not (
                "--update-transaction"
                    or "--update-version"))
            {
                continue;
            }

            if (index + 1 >= arguments.Count)
            {
                invalid = true;
                break;
            }

            var value = arguments[++index];
            if (argument == "--update-transaction")
            {
                if (transactionValue is not null)
                {
                    invalid = true;
                    break;
                }

                transactionValue = value;
            }
            else
            {
                if (versionValue is not null)
                {
                    invalid = true;
                    break;
                }

                versionValue = value;
            }
        }

        if (invalid
            || transactionValue is null
            || versionValue is null
            || transactionValue
                != transactionValue.ToLowerInvariant()
            || !Guid.TryParseExact(
                transactionValue,
                "N",
                out var transactionId)
            || !SemanticVersion.TryParseNormalized(
                versionValue,
                out var version))
        {
            return null;
        }

        return new UpdateStartupHealthContext(
            transactionId,
            version);
    }

    private static InstalledReleaseLaunchLease?
        IsCurrentExecutableEligibleForAutoElevation()
    {
        try
        {
            var locator = new InstalledReleaseLocator();
            var location = locator.Locate(Environment.ProcessPath);
            if (location.Status
                != InstalledReleaseLocatorStatus.Available)
            {
                return null;
            }

            if (!AppAutoElevationPolicy
                    .IsLocatedReleaseEligibleForAutoElevation(
                    location,
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.ProgramFiles)))
            {
                return null;
            }

            return locator.AcquireLaunchLease(
                Environment.ProcessPath);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool ShouldRequireAdministratorForCurrentMode()
    {
        try
        {
            var dataDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WireguardSplitTunnel");
            var statePath = Path.Combine(dataDirectory, "state.json");
            var state = new StateStore(statePath).Load();

            return state.DomainGlobalDefaultMode == DomainRouteMode.BypassWireGuard
                || state.SoftwareGlobalDefaultMode == DomainRouteMode.BypassWireGuard;
        }
        catch
        {
            // Fail-safe to keep bypass mode stable when state cannot be read.
            return true;
        }
    }

    private static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool TryRelaunchAsAdministrator(
        string[] args,
        InstalledReleaseLaunchLease launchLease) =>
        TryRelaunchAsAdministrator(
            args,
            launchLease,
            startInfo => Process.Start(startInfo));

    private static bool TryRelaunchAsAdministrator(
        string[] args,
        InstalledReleaseLaunchLease launchLease,
        Func<ProcessStartInfo, Process?> processStarter) =>
        AppAutoElevationRelaunch.TryRelaunchAsAdministrator(
            args,
            launchLease,
            processStarter);

    private static void WriteBootstrapLog(string message)
    {
        try
        {
            if (!AppBootstrapLoggingPolicy.ShouldWrite(IsRunningAsAdministrator()))
            {
                return;
            }

            var dataDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WireguardSplitTunnel");
            Directory.CreateDirectory(dataDirectory);

            var line = $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}] [BOOT] {message}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(dataDirectory, "runtime.log"), line);
        }
        catch
        {
        }
    }
}

internal static class AppAutoElevationRelaunch
{
    internal static bool TryRelaunchAsAdministrator(
        string[] args,
        InstalledReleaseLaunchLease launchLease,
        Func<ProcessStartInfo, Process?> processStarter)
    {
        var forwardedArgs = args
            .Where(arg => !string.Equals(
                arg,
                "--elevated-launch",
                StringComparison.OrdinalIgnoreCase))
            .ToList();
        forwardedArgs.Add("--elevated-launch");

        try
        {
            return launchLease.TryLaunch(applicationPath =>
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = applicationPath,
                    WorkingDirectory =
                        Path.GetDirectoryName(applicationPath)!,
                    Arguments = string.Join(
                        " ",
                        forwardedArgs.Select(QuoteArgument)),
                    UseShellExecute = true,
                    Verb = "runas"
                };
                processStarter(startInfo);
                return true;
            });
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // User canceled UAC.
            return false;
        }
        catch
        {
            return false;
        }
    }

    private static string QuoteArgument(string argument)
    {
        if (string.IsNullOrEmpty(argument))
        {
            return "\"\"";
        }

        if (!argument.Contains(' ') && !argument.Contains('"'))
        {
            return argument;
        }

        return $"\"{argument.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
    }
}

internal static class AppBootstrapLoggingPolicy
{
    internal static bool ShouldWrite(bool isAdministrator) =>
        !isAdministrator;
}

internal static class AppAutoElevationPolicy
{
    internal static bool IsExecutableEligibleForAutoElevation(
        string? executablePath)
    {
        try
        {
            var locator = new InstalledReleaseLocator();
            var location = locator.Locate(executablePath);
            if (!IsLocatedReleaseEligibleForAutoElevation(
                location,
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ProgramFiles)))
            {
                return false;
            }

            using var lease = locator.AcquireLaunchLease(
                executablePath);
            return lease is not null;
        }
        catch (Exception)
        {
            return false;
        }
    }

    internal static bool IsLocatedReleaseEligibleForAutoElevation(
        InstalledReleaseLocation location,
        string? programFiles)
    {
        if (string.IsNullOrWhiteSpace(programFiles)
            || location.Status
                != InstalledReleaseLocatorStatus.Available
            || location.InstallationRoot is null)
        {
            return false;
        }

        var protectedRoot = Path.GetFullPath(
            Path.Combine(
                programFiles,
                "WireguardSplitTunnel"));
        var locatedRoot = Path.GetFullPath(
            location.InstallationRoot);
        return string.Equals(
            Path.TrimEndingDirectorySeparator(locatedRoot),
            Path.TrimEndingDirectorySeparator(protectedRoot),
            StringComparison.OrdinalIgnoreCase);
    }
}
