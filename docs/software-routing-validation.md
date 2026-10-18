# Software subprocess destination routing validation

Date: 2026-10-18 (Asia/Hong_Kong).

## Accepted scope

The user chose observed public TCP/IPv4 destination routing while preserving
split tunneling. Strict first-packet interception and the Mullvad signed-driver
experiment are deferred. No new driver is installed. Existing connections are
not reset and the running WireGuard tunnel must remain intact.

The live acceptance probe passed on 2026-10-18. The change is prepared as v0.2.11
for the authorized commit and GitHub push. This document is a validation record,
not a claim that the installed app was replaced or a GitHub Release published.

## Evidence collected

- Read-only live socket inspection confirmed ChatGPT simultaneously had
  connections bound to the WireGuard address and the physical-interface address.
  The reported issue was therefore not solely a Monitor label.
- A regression test reproduced the old Monitor parser discarding local socket
  addresses. A second regression demonstrated two connections with the same
  process/destination being merged and classified VPN after a route change,
  despite one retaining its physical source address. Both regressions pass with
  source-address retention and separate grouping.
- The first explicit live acceptance-probe launch was cancelled at Windows UAC.
  The helper did not run and did not create a test route.
- A read-only probe exercised the real Windows process/TCP reader and planner:
  332 identified processes and 93 TCP rows, including observed descendants for
  ChatGPT and Codex. The existing settings file was byte-for-byte unchanged.
  This confirms discovery only; it does not prove route installation or egress.
- After executable-discovery optimization, a fresh read-only run completed in
  0.57 seconds, identifying 342 processes and 100 TCP rows. Settings again stayed
  byte-for-byte unchanged. Counts are observations at that instant, not guarantees.
- After explicit authorization to retry UAC, the live probe passed: a controlled
  child destination was learned only with IncludeSubprocesses enabled; its socket
  changed from the physical interface to the WireGuard interface after reconnect;
  an HTTPS peer trace returned successfully. The exact temporary route was removed
  and the ownership journal was empty. A separate route-table query confirmed no
  remaining test /32. The WireGuard service remained running with the same PID.

## Reproducible checks

Latest Windows Core run: 659 passed, zero failed. Release builds of the app and
the probe succeeded with zero warnings and zero errors. Focused lifecycle/spec
review approved the revised ownership and cleanup behavior. Native route creation,
controlled child reconnection and cleanup passed the explicit live probe.

Final code-quality review also approved after a two-active-tunnel Monitor
regression was reproduced and fixed: the selected tunnel is `Vpn`, another
WireGuard tunnel is `Unknown`, and a recognized physical interface is `Normal`.

Run from the repository root:

```powershell
$env:PATH = 'C:\Program Files\PowerShell\7;' + $env:PATH
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter 'FullyQualifiedName!~Mac'
dotnet test tests/WireguardSplitTunnel.WindowsUpdate.Tests/WireguardSplitTunnel.WindowsUpdate.Tests.csproj
dotnet build src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj -c Release
dotnet build tools/WireguardSplitTunnel.SoftwareRouting.Probe/WireguardSplitTunnel.SoftwareRouting.Probe.csproj -c Release
```

The Windows Core filter matches `scripts/test.ps1`. Running the unfiltered Core
suite on Windows exposes ten existing macOS absolute-path failures; the same ten
were reproduced in unchanged main at `ceb5658`. They are not a new routing
regression and have not been hidden by changing their tests.

The full Windows updater suite completed with 1,070 passed, five privilege-gated
tests skipped, and one failure: `DryRun_RunsUnderPowerShellCoreWithoutCompatibilityRemoting`.
The identical failure was reproduced on unchanged main: the discovered PowerShell
Core executable is outside the protected Program Files installation required by
the existing launcher. No launcher security check was weakened to obtain a pass.
Selecting the already-installed `C:\Program Files\PowerShell\7` first in the
test process's PATH made that test pass. No machine-wide PATH setting changed.
The final full v0.2.11 updater run with that process environment passed: 1,071
passed, zero failed, five privilege-gated tests skipped. The final v0.2.11 Windows
Core run also passed all 659 tests.

The v0.2.11 Release executable reports product version 0.2.11 and file version
0.2.11.0. Windows PowerShell 5.1 `scripts/start.ps1 -DryRun` selected that worktree's
Release executable. The installed v0.2.10 app has not been replaced by these checks.

The live probe requires explicit elevation and an active WireGuard interface:

```powershell
# Run in an elevated shell; replace GB if necessary and use a new output directory.
& 'tools/WireguardSplitTunnel.SoftwareRouting.Probe/bin/Release/net8.0-windows/WireguardSplitTunnel.SoftwareRouting.Probe.exe' --live GB '.build/software-routing-live-new'
```

It must demonstrate child-only destination discovery, exclusion when
IncludeSubprocesses=false, a physical-source baseline, a new WireGuard-source
connection after learning, a successful HTTPS peer response, and exact cleanup
of the route created by the probe. A pre-existing VPN route fails the baseline
instead of producing a false pass. Local evidence includes a cleanup-debt file;
do not commit endpoint responses or machine-specific logs.

## Limits

Host routes affect all applications using the same IP. A connection can occur
before observation, short-lived descendants may be missed, UDP/IPv6 are outside
this feature, and existing TCP sessions may need an application reconnect.
Monitor source binding and a successful controlled reconnect do not establish
strict first-packet or fail-closed guarantees. The feature does not provide a
VPN kill switch.
