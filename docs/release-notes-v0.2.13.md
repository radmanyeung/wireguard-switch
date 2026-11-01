# v0.2.13

Fixes standalone WireGuard routing after the Windows app closes, including closing the window while startup DNS renewal is still running.

- Tracks the physical default-route metric and bypass `/1` routes before changing them. A normal close restores the previous metric and removes app-created bypass routes, allowing a full-tunnel WireGuard configuration to take over again.
- Runs bypass cleanup even when the WireGuard adapter has already disconnected. Routes changed by another owner are preserved, and failed cleanup records are retained for retry.
- Migrates the complete metric-5 bypass `/1` pair left by older app versions on the known normal gateway.
- Cancels startup DNS renewal and pending software-routing work before waiting for close cleanup, preventing an early close from timing out behind routing locks.
- Preserves saved rules and settings. The original WireGuard configuration is not modified.

Enable **Restore normal routing when app exits** to restore standalone WireGuard behavior on a normal close. With that setting disabled, split-tunnel routing remains active. Forced termination or a crash can defer cleanup until the next app session.

Windows 0.2.12 installations can use the in-app updater. Installations on 0.2.10 or 0.2.11 still need the one-time installer repair described in the v0.2.12 Release: download this Release's Windows ZIP, extract it, and run `install.cmd`. The installer uses maintenance shutdown and leaves the WireGuard tunnel service running.

Software destination learning remains TCP/IPv4-based and is not strict per-process VPN enforcement. First connections, UDP, IPv6, and external-browser sign-in traffic are not comprehensively covered. A working VPN exit does not guarantee a service's account or country eligibility.

Local validation before release included 678 passing non-Mac Core tests and a Windows self-contained publish. The installed local repair was also tested by closing during startup, restarting the existing WireGuard tunnel without editing its configuration, and verifying both IPv4 routing halves and a successful HTTPS VPN exit. Release CI independently builds and validates the published artifacts.
