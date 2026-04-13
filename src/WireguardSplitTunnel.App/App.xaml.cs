using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.App;

public partial class App : Application
{
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

        WriteBootstrapLog($"Startup. requireAdmin={requireAdmin}, isAdmin={isAdmin}, elevatedArg={elevatedLaunchRequested}, args={string.Join(" ", e.Args)}");

        if (requireAdmin && !isAdmin)
        {
            if (!elevatedLaunchRequested)
            {
                var relaunched = TryRelaunchAsAdministrator(e.Args);
                WriteBootstrapLog($"Auto-elevation attempted. relaunched={relaunched}");

                if (relaunched)
                {
                    Shutdown();
                    return;
                }
            }
            else
            {
                WriteBootstrapLog("Startup still non-admin after --elevated-launch; continuing without auto-retry.");
            }
        }

        var runPostInstallSelfTest = e.Args.Any(arg =>
            string.Equals(arg, "--post-install-self-test", StringComparison.OrdinalIgnoreCase));

        var window = new MainWindow(runPostInstallSelfTest);
        MainWindow = window;
        window.Show();
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

    private static bool TryRelaunchAsAdministrator(string[] args)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return false;
        }

        var forwardedArgs = args
            .Where(arg => !string.Equals(arg, "--elevated-launch", StringComparison.OrdinalIgnoreCase))
            .ToList();
        forwardedArgs.Add("--elevated-launch");

        var startInfo = new ProcessStartInfo
        {
            FileName = processPath,
            Arguments = string.Join(" ", forwardedArgs.Select(QuoteArgument)),
            UseShellExecute = true,
            Verb = "runas"
        };

        try
        {
            Process.Start(startInfo);
            return true;
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

    private static void WriteBootstrapLog(string message)
    {
        try
        {
            var dataDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WireguardSplitTunnel");
            Directory.CreateDirectory(dataDirectory);

            var line = $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}] [BOOT] {message}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(dataDirectory, "runtime.log"), line);

            try
            {
                File.AppendAllText(Path.Combine(Environment.CurrentDirectory, "runtime.log"), line);
            }
            catch
            {
            }
        }
        catch
        {
        }
    }
}
