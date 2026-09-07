# Wireguard Split Tunnel v0.2.10

`install.cmd` is now a self-contained bootstrap. It works from the complete
Windows Release, a GitHub source ZIP, or as the only copied file. Incomplete or
damaged packages are replaced with one checksum-verified official Release; a
.NET SDK is not required.

Existing installations now upgrade through a full staged directory swap. The
running app exits through a process-bound installer-maintenance channel while
the WireGuard service and active tunnel remain running. Older app versions use
an exact PID, executable-path, and creation-time fallback. Settings and known
runtime logs are retained, and other old files remain in the rollback backup.

The installer records staged, switching, and published transaction phases.
Startup must report the install token, executable path, version, settings load,
and main-window initialization within 60 seconds. A failure restores the prior
installation; a later `install.cmd` run recovers an interrupted transaction.

The Windows Release remains self-contained and installs the signed official
WireGuard MSI only when WireGuard is missing. MSI reboot requests are reported
without restarting Windows.
