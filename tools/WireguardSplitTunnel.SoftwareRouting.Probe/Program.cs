using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Text.Json;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

if (args.Length == 3 && args[0] == "--snapshot")
{
    var statePath = Path.GetFullPath(args[1]);
    var evidencePath = Path.GetFullPath(args[2]);
    if (!File.Exists(statePath) || File.Exists(evidencePath))
        throw new InvalidOperationException("Snapshot needs an existing state file and a new evidence file.");
    var original = File.ReadAllBytes(statePath);
    var state = new StateStore(statePath).Load();
    var repaired = SoftwareRulePathRepair.RepairEnabledRulePaths(state, new SystemSoftwareExecutableLocator());
    var snapshot = await new WindowsSoftwareConnectionSnapshotReader().ReadAsync(CancellationToken.None);
    // Planning only: these candidates have not passed transport-endpoint exclusion and
    // must never be applied from this diagnostic output.
    var observation = new SoftwareRoutePlanner().Observe(state.SoftwareRules ?? [], [], snapshot, []);
    var report = new
    {
        PlanningOnly = true,
        StateUnchanged = original.SequenceEqual(File.ReadAllBytes(statePath)),
        InMemoryPathRepairs = repaired.Updated + repaired.Added,
        Processes = snapshot.Processes.Count,
        Connections = snapshot.Connections.Count,
        Rules = (state.SoftwareRules ?? []).Where(rule => rule.Enabled).Select(rule => new
        {
            rule.ProcessName, rule.IncludeSubprocesses,
            Children = observation.ChildCounts.GetValueOrDefault(SoftwareRoutePlanner.Fingerprint(rule)),
            Destinations = observation.Learned.FirstOrDefault(item => item.Fingerprint == SoftwareRoutePlanner.Fingerprint(rule))?.IpAddresses ?? []
        }).ToArray()
    };
    Directory.CreateDirectory(Path.GetDirectoryName(evidencePath)!);
    File.WriteAllText(evidencePath, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"Read-only snapshot: {report.Processes} identified processes, {report.Connections} TCP rows; state unchanged={report.StateUnchanged}.");
    return report.StateUnchanged ? 0 : 1;
}

// Explicit opt-in live acceptance test. No service, firewall or default-route changes.
if (args.Length != 3 || args[0] != "--live")
{
    Console.Error.WriteLine("Usage: SoftwareRouting.Probe --live <WireGuard interface name> <new evidence directory>");
    return 2;
}
if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
    throw new InvalidOperationException("The explicit live test requires an elevated process.");
var adapter = NetworkInterface.GetAllNetworkInterfaces().Single(n => n.Name == args[1]
    && n.OperationalStatus == OperationalStatus.Up
    && n.Description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase));
var expectedSources = adapter.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString()).ToHashSet();
var output = Path.GetFullPath(args[2]);
if (Directory.Exists(output)) throw new InvalidOperationException("Use a new evidence directory; existing results are never overwritten.");
Directory.CreateDirectory(output);
var log = Path.Combine(output, "result.txt");
void Log(string message) { File.AppendAllText(log, message + Environment.NewLine); Console.WriteLine(message); }
const string target = "1.0.0.1"; // Cloudflare public HTTPS endpoint; no credentials or application data.
var writer = new WindowsSoftwareRouteWriter();
var owned = new List<SoftwareOwnedRoute>();
var debtFile = Path.Combine(output, "owned-routes.json");
void SaveDebt() => File.WriteAllText(debtFile, JsonSerializer.Serialize(owned));
using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(75));
Process? child = null;
var success = false;
try
{
    var excluded = await WindowsSoftwareConnectionSnapshotReader.ReadTransportEndpointsAsync(timeout.Token);
    if (excluded.Contains(target)) throw new InvalidOperationException("Test endpoint is a WireGuard transport endpoint.");
    var script = Path.Combine(output, "child.ps1");
    File.WriteAllText(script, """
        param([string]$Evidence)
        $ErrorActionPreference='Stop'
        try {
            $before=[Net.Sockets.TcpClient]::new()
            $before.ConnectAsync('1.0.0.1',443).GetAwaiter().GetResult()
            $before.Client.LocalEndPoint.Address.ToString() | Set-Content -LiteralPath (Join-Path $Evidence 'before.txt')
            $deadline=[DateTime]::UtcNow.AddSeconds(45)
            while (!(Test-Path -LiteralPath (Join-Path $Evidence 'route-ready')) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
            if (!(Test-Path -LiteralPath (Join-Path $Evidence 'route-ready'))) { throw 'Route was not installed before deadline' }
            $before.Dispose()
            $after=[Net.Sockets.TcpClient]::new()
            $after.ConnectAsync('1.0.0.1',443).GetAwaiter().GetResult()
            $after.Client.LocalEndPoint.Address.ToString() | Set-Content -LiteralPath (Join-Path $Evidence 'after.txt')
            $tls=[Net.Security.SslStream]::new($after.GetStream(),$false)
            $tls.ReadTimeout=10000
            $tls.AuthenticateAsClient('one.one.one.one')
            $request=[Text.Encoding]::ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1`r`nHost: one.one.one.one`r`nConnection: close`r`n`r`n")
            $tls.Write($request)
            $reader=[IO.StreamReader]::new($tls)
            $reader.ReadToEnd() | Set-Content -LiteralPath (Join-Path $Evidence 'peer-response.txt')
            $reader.Dispose(); $after.Dispose()
        } catch { $_ | Out-String | Set-Content -LiteralPath (Join-Path $Evidence 'child-error.txt'); exit 1 }
        """);
    var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true };
    foreach (var argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-Evidence", output }) start.ArgumentList.Add(argument);
    child = Process.Start(start) ?? throw new InvalidOperationException("Cannot start controlled child");
    while (!File.Exists(Path.Combine(output, "before.txt")))
    {
        if (child.HasExited) throw new InvalidOperationException("Controlled child exited before initial connection");
        await Task.Delay(100, timeout.Token);
    }
    var snapshot = await new WindowsSoftwareConnectionSnapshotReader().ReadAsync(timeout.Token);
    var rule = new SoftwareRule(Path.GetFileName(Environment.ProcessPath)!, ExecutablePath: Environment.ProcessPath, IncludeSubprocesses: true);
    var planner = new SoftwareRoutePlanner();
    var observation = planner.Observe([rule], [], snapshot, excluded);
    var destinations = observation.Learned.SelectMany(item => item.IpAddresses).ToHashSet();
    if (!destinations.Contains(target)) throw new InvalidOperationException("The real child TCP destination was not learned");
    var withoutChildren = new SoftwareRoutePlanner().Observe([rule with { IncludeSubprocesses = false }], [], snapshot, excluded);
    if (withoutChildren.Learned.SelectMany(item => item.IpAddresses).Contains(target))
        throw new InvalidOperationException("IncludeSubprocesses=false unexpectedly includes the child");
    Log($"Observed child PID {child.Id}; include=true learns target, include=false excludes it.");
    var before = File.ReadAllText(Path.Combine(output, "before.txt")).Trim();
    Log("Before socket source: " + before);
    if (expectedSources.Contains(before)) throw new InvalidOperationException("Target already uses VPN; choose a fresh baseline for a meaningful transition test.");
    var reconcile = new SoftwareRouteReconciler(writer);
    await reconcile.ReconcileAsync([target], [], adapter.GetIPProperties().GetIPv4Properties().Index, owned, SaveDebt, () => true, timeout.Token);
    if (owned.Count != 1) throw new InvalidOperationException("Probe did not create a fresh route; existing routes are not adopted.");
    File.WriteAllText(Path.Combine(output, "route-ready"), "ready");
    await child.WaitForExitAsync(timeout.Token);
    if (child.ExitCode != 0) throw new InvalidOperationException("Controlled child failed; inspect child-error.txt");
    var after = File.ReadAllText(Path.Combine(output, "after.txt")).Trim();
    Log("After socket source: " + after);
    if (!expectedSources.Contains(after)) throw new InvalidOperationException("New child connection did not bind to the WireGuard source address");
    var response = File.ReadAllText(Path.Combine(output, "peer-response.txt"));
    if (!response.Contains("200 OK") || !response.Contains("ip=")) throw new InvalidOperationException("No successful HTTPS peer trace evidence");
    Log("HTTPS peer trace received after route learning; response retained locally.");
    success = true;
}
catch (Exception exception) { Log("FAILED: " + exception); }
finally
{
    if (child is not null)
    {
        try
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await child.WaitForExitAsync(cleanupTimeout.Token);
            }
        }
        catch (Exception exception) { Log("CHILD CLEANUP FAILED: " + exception); success = false; }
        finally { child.Dispose(); }
    }
    foreach (var route in owned.ToArray())
    {
        try { await writer.DeleteAsync(route, CancellationToken.None); owned.Remove(route); SaveDebt(); }
        catch (Exception exception) { Log("CLEANUP FAILED: " + exception); success = false; }
    }
    Log(success ? "PASS: learned child destination, reconnected through VPN, exact test route removed." : "FAIL: acceptance is incomplete; inspect evidence and cleanup debt.");
}
return success ? 0 : 1;
