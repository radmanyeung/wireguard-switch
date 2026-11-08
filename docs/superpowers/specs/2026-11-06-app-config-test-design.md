# Windows App Selected-Config Test And Repair

Approved in chat on 2026-11-06. Add the selected-config connection test,
verified repair, and Recycle Bin confirmation to the existing Windows WPF app.
Do not use the standalone batch utility as the user-facing entry point.

## Scope

- Add a `Test Config` button beside the existing Windows config controls.
- Test only the plaintext `.conf` selected in the drop-down.
- Support the same single-peer NordVPN client-config subset as the existing
  checker. Unsupported or invalid files are reported as not testable and never
  executed, repaired, or offered for deletion.
- Leave the macOS app and standalone `check-conf-servers.bat` workflow unchanged
  in this sub-project.
- Automatic-update review and app-close network restoration are separate
  follow-up investigations, not hidden inside this feature.

## User Flow

1. The user selects a config and clicks `Test Config`.
2. The app explains that internet access may be interrupted and asks for
   confirmation before changing any tunnel or route.
3. While checking, config/test/enable controls are disabled and automatic
   re-enable and route renewal are prevented from racing the check.
4. The app tests the original endpoint. A healthy original remains unchanged.
5. If the original fails, the app tries at most three authenticated,
   same-country NordVPN WireGuard recommendations, each with the same complete
   connection test.
6. A verified replacement updates only the source peer `Endpoint` and
   `PublicKey`. Private key, Address, DNS, AllowedIPs, filename, encoding,
   comments, and line endings are preserved.
7. The app removes its temporary tunnel and restores the original tunnel
   services and app routing state before showing the final result.
8. Only an `Unrepaired` result opens a confirmation dialog containing the full
   source `.conf` path and `Move this file to the Recycle Bin?`, with `No` as the
   default. Healthy, repaired, skipped, canceled, and fatal-error results never
   offer deletion.
9. If the user confirms, the app rechecks that the source is unchanged, moves it
   to the Recycle Bin, clears it from the saved selection, and refreshes the
   config list. Otherwise the source remains selected and untouched.

## Architecture

Create a small Core workflow with an adapter boundary rather than embedding
native operations in `MainWindow`:

- A config parser validates the supported structure and retains source bytes,
  encoding, path, fingerprint, peer identity, country, and endpoint.
- A metadata component downloads and validates country and recommendation data
  before any running tunnel is stopped. A replacement hostname, country,
  technology status, and public key must come from one trusted metadata record.
- A workflow coordinates backup, original-service suspension, tests, verified
  commit, and restoration in `finally`. It returns explicit Healthy, Repaired,
  and Unrepaired results.
- A Windows adapter owns WireGuard/wg.exe, the temporary probe route, system
  curl, restricted backups/journal, source replacement, and Recycle Bin actions.
- A focused WPF partial class owns confirmation, progress, deletion consent,
  selection refresh, and safe error presentation.

The implementation is native to the C# app. It may follow the safety semantics
of the PowerShell checker but must not require closing the GUI, reading its CSV,
or interacting with a console.

## Connection Test Contract

Each candidate uses a uniquely named temporary tunnel with automatic route/DNS
changes disabled and only the temporary HTTPS-probe host route. Success requires
all of the following:

- a fresh handshake for the expected peer public key;
- certificate-validated HTTPS explicitly bound to the test source address;
- an observed exit country matching the config's expected country.

Ping, DNS success, a NordVPN `online` flag, a stale handshake, or a running
Windows service alone is not success. A failed candidate never changes the
source. The temporary tunnel is removed after every attempt.

## Safety And Recovery

- Before stopping services, save original bytes in an ACL-restricted backup and
  recovery directory under the app's local application-data directory.
- Record only the original running services and the unique test artifacts owned
  by this session. Never uninstall or reconfigure the original services.
- Restore only services stopped by this session, using their saved identities.
- Retain a recovery journal on incomplete cleanup and block further checks until
  recovery succeeds. A different running tunnel or changed service identity
  requires manual review rather than guessing.
- Reject reparse-point source paths. Before repair or recycling, compare the
  current source fingerprint with the tested source. Concurrent edits are kept.
- Recycling applies only to the exact full path that produced Unrepaired, never
  to a directory, `.conf.dpapi`, derived/sanitized config, or another result.
- A recycle failure leaves the file in place and displays a safe error. Logs and
  UI messages may contain paths, endpoint names, and status codes, but never
  private/preshared keys, raw config text, or unsanitized native output.
- Canceling the initial warning performs no network or file mutation. Closing
  the window during an active check is deferred until restoration finishes.

## Error Handling

- Metadata, DNS, or probe-preparation failures occur before service suspension
  when possible and do not authorize repair or deletion.
- A failed candidate is an ordinary test outcome; backup, cleanup, and restore
  failures are fatal and suppress the deletion prompt.
- After all candidates fail, the original remains untouched unless the user
  explicitly confirms recycling after restoration.
- Repair uses same-volume staged replacement and readback verification. An
  interrupted replacement is recovered from its retained displaced version;
  verified completed repairs stay applied.

## Verification

Use test-driven development with fake adapters and temporary synthetic configs.
Cover:

- selected-only scope and initial warning cancellation;
- healthy originals, successful first/later replacement, and all candidates
  failing;
- stale handshakes, HTTPS failure, wrong country, and invalid metadata;
- no deletion offer for healthy, repaired, skipped, canceled, or fatal outcomes;
- full-path display, default-No behavior, explicit confirmation, list refresh,
  and saved-selection clearing after recycling;
- concurrent source edits and recycle failures preserving the source;
- byte-preserving repair, backup ordering, temporary cleanup, and restoration on
  every success/failure path;
- auto-enable/route-renewal exclusion while the selected-config check runs.

Run the existing non-Mac Core regression suite and Windows app wiring tests.
No live VPN, real route/service mutation, real Recycle Bin deletion, automatic
update installation, or app-close experiment is implied by offline tests. Live
verification requires separate user authorization and an explicit test plan.
