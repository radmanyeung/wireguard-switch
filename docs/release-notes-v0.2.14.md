# v0.2.14

Adds **Test Config** to the Windows app for checking and, when possible, repairing the selected NordVPN configuration.

- Tests only the selected plaintext, single-peer NordVPN `.conf`. A warning shows its full path and explains that the original WireGuard services and network connection may be interrupted.
- Tries the original server first, then at most three same-country NordVPN candidates. A server passes only with a fresh handshake, HTTPS bound to the VPN source address, and the expected exit country.
- A healthy original file is not edited. A successful candidate repairs only `[Peer]` `Endpoint` and `PublicKey`, preserving the remaining content, comments, formatting, and encoding.
- Rechecks file identity and content before replacement. Concurrent edits or substitutions are preserved instead of overwritten or recycled.
- Restores originally running services, the app-managed derived configuration, and applicable application routes before reporting a result. Startup recovery handles interrupted replacement, service restoration, derived-file reconciliation, and recycle transactions before automatic enable or renewal.
- Only an **Unrepaired** result offers to move the exact tested file to the Recycle Bin. The prompt includes its full path and defaults to **No**. Cancellation, invalid configuration, metadata failure, restoration failure, or a changed file does not offer deletion.
- Coordinates Enable Now, DNS learning, software-policy application, route renewal, Test Config, startup recovery, and window close through shared operation gates. Plaintext configuration read or sanitization failures now fail closed instead of installing an unsanitized full-tunnel configuration.

- A deliberate user close now restores app-managed routes, then stops and uninstalls all installed WireGuard tunnel services, including externally created tunnels, before saving state or authorizing a staged update. Installer-maintenance close preserves tunnels.
- Interrupted close recovery records exact service and pending Enable process identities and reconciles only those recorded targets before automatic enable or renewal. Cleanup failures offer Retry and a separately confirmed Close anyway; Close anyway does not claim restored networking or authorize an update.

Windows 0.2.13 installations can use the in-app updater. Installations on 0.2.10 or 0.2.11 still need the one-time installer repair described in the v0.2.12 Release: download this Release's Windows ZIP, extract it, and run `install.cmd`.

Local offline validation included 1113 passing non-Mac Core tests, a Windows App build with zero warnings and errors, and 891 selected passing updater tests using fakes and temporary files. Real NordVPN handshake/HTTPS repair, elevated service and route restoration, Recycle Bin integration, close-time tunnel removal, and end-to-end automatic updating were not exercised locally. Release CI independently runs platform tests and builds and validates the published artifacts.
