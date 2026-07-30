# Windows GitHub Release Auto-Update Design

Date: 2026-07-29
Status: Approved in chat; architecture and security reviews incorporated

## Objective

Add a Windows-only automatic updater that detects a newer stable release from
the official GitHub repository, downloads and verifies it in the background,
and installs it only after the user next closes the application normally.

The updater must not:

- interrupt an active VPN session or route-restoration operation;
- force-close or unexpectedly reopen the application;
- overwrite user state, domain/IP rules, VPN configuration, or existing logs;
- execute an unverified package with elevated privileges;
- treat a download followed by a crash or system shutdown as install consent;
- start an installation known to be partially applied.

Automatic updates are enabled by default for new and legacy application state.
The user can disable them at any time.

## Initial rollout constraint

An already installed pre-updater binary such as `v0.1.9` cannot gain updater
code by itself. The first release containing this feature must be installed
once through the existing manual package flow. That bootstrap must preserve the
existing LocalAppData state.

The current Release ZIP and installer need one compatibility fix as part of the
feature: when a valid release manifest and bundled executable are present,
`install.ps1` must validate and prefer that bundled release even if a .NET SDK
is installed. It must not try `dotnet publish` when the Release ZIP has no
`src` project or `Directory.Build.props`. Source publishing remains available
only in a real source checkout or when explicitly requested.

The first bundled install also establishes the privileged installation
boundary. The initially running Release script binds the exact package identity
before UAC, elevates only a self-contained in-memory bootstrap, revalidates the
bound manifest and every managed file after elevation, and copies those files
to the fixed protected root:

`%ProgramFiles%\WireguardSplitTunnel`

It then applies and verifies a protected installed-root ACL before executing
any packaged script from that root. No elevated process imports or executes
PowerShell code by a mutable Downloads/Desktop pathname. Desktop shortcuts
point only to the protected root. LocalAppData state, WireGuard configuration,
logs, and the original extracted folder are not moved or deleted.

After the first updater-capable release and manifest are installed, future
compatible Windows releases use the automatic flow below. There is no claim
that an untouched `v0.1.9` executable can self-bootstrap.

## Confirmed user experience

- Check for an update after startup when the persisted 24-hour interval is due.
- Continue checking at most once every 24 hours while the application remains
  open.
- Provide a manual **Check now** action that bypasses the interval without
  re-enabling automatic checks.
- Download and validate a newer stable Windows release in the background.
- Show non-modal progress and the version that is ready.
- Install only after an eligible normal application close.
- Complete route restoration and state persistence before authorizing apply.
- Do not automatically reopen after close-time installation.
- Recover an already authorized interrupted transaction before the next start.
- Preserve all user state, custom rules, VPN settings, and existing logs.

## Scope

This feature covers Windows `win-x64` stable GitHub Releases from the
compile-time fixed repository:

`radmanyeung/wireguard-switch`

Out of scope:

- macOS automatic updates;
- beta, prerelease, draft, or alternate channels;
- user-configurable repository or asset URLs;
- automatic tags, releases, commits, or Git pushes;
- acquiring a Windows code-signing certificate;
- deleting arbitrary stale files from an older release;
- automatically updating across a declared state/rollback compatibility break.

The pipeline may continue to publish its macOS asset, but the Windows updater
never selects or installs it.

## Considered approaches

### Selected: verified staging plus a detached update helper

The application downloads to LocalAppData and fully validates the package. An
elevated process copies it into a protected transaction directory. Only an
eligible normal close may change that protected transaction to
`CloseAuthorized`. A detached compiled helper then waits for the exact
application process to exit, backs up the current release-managed files, and
applies a journalled, reversible update.

This fits the existing root launcher and `WireguardSplitTunnel` publish
directory while permitting safe replacement of the executable and launchers.

### Rejected: side-by-side version directories and a stable launcher

Separate version directories simplify atomic switching but require a larger
migration of the current install, shortcut, and launcher model.

### Rejected: in-process overwrite

The main process cannot safely replace its own executable and launchers.
In-process replacement also widens the partial-failure window.

## Release contract

The updater accepts only a release that satisfies every condition:

- it comes from the fixed official repository;
- it is neither a draft nor a prerelease;
- its tag has the strict form `vMAJOR.MINOR.PATCH`;
- its semantic version is greater than the running version;
- the current version satisfies the manifest's
  `MinimumAutoUpdateVersion` and `RollbackCompatibleFromVersion`;
- exactly one asset is named `wireguard-split-tunnel-win-x64.zip`;
- exactly one checksum asset is named
  `wireguard-split-tunnel-win-x64.zip.sha256`.

The current GitHub Releases API response must also contain one canonical
`sha256:<64-lowercase-hex>` digest for the ZIP asset. That current-run API
digest is the download authentication anchor: the downloaded ZIP hash and the
fixed-name sidecar digest must both equal it. Malformed or missing API digests,
extra filenames, duplicate assets, or any digest mismatch reject the release.

### Release workflow gates

The Windows release workflow must:

1. run all automated tests;
2. build the solution in Release configuration;
3. confirm the pushed tag exactly matches `VersionPrefix` in
   `Directory.Build.props`;
4. publish the self-contained `win-x64` application and compiled updater;
5. assemble a package with a generated release manifest;
6. verify package layout and executable product versions;
7. run launcher dry-run against the assembled package;
8. create the fixed-name Windows ZIP and SHA-256 sidecar;
9. publish only after verified Windows artifacts exist.

Workflow actions are pinned to full commit SHAs, with readable version comments.
Default permissions are `contents: read`; only the final publishing job gets
`contents: write`. Build/test jobs cannot modify Releases.

When the workflow publishes multiple platforms, one final publish job depends
on the verified build jobs so a stable Release is not visible while the Windows
asset is still being assembled.

### Release manifest

The package contains a fixed-path, versioned manifest recording:

- release version and `win-x64` runtime identifier;
- `MinimumAutoUpdateVersion`;
- `RollbackCompatibleFromVersion`;
- state schema version;
- application entry point;
- required launcher and updater-helper paths;
- every release-managed payload path;
- SHA-256 and length of each payload file.

The manifest cannot hash itself. Its exact bytes are protected by the outer ZIP
checksum and a separate `NewManifestSha256` in protected transaction state.
The manifest is installed through a special journalled `ReplaceManifest`
operation after all normal payload operations. Its old bytes are backed up, and
rollback restores them. Interruption immediately before or after the manifest
replacement is recoverable.

State, updater metadata, backups, temporary files, and logs are never
release-managed. Version 1 creates or replaces only paths in the new verified
manifest plus the fixed manifest path. It does not delete paths merely because
an old installed manifest lists them, and leaves unknown files untouched.

## Application components

### Stable release selector

A platform-neutral component strictly parses release metadata, semantic
versions, and compatibility fields. It has no network or filesystem dependency
and returns either one selected Windows release or a typed rejection reason.

### GitHub release client

The application calls only:

`https://api.github.com/repos/radmanyeung/wireguard-switch/releases/latest`

The initial `browser_download_url` must be HTTPS and match the expected
repository, tag, and exact filename. Redirect URLs are CDN URLs and therefore
are validated only by HTTPS, redirect count, and exact host allowlist; they are
not required to repeat the repository/tag path.

The client requests the versioned GitHub JSON media type and parses the ZIP
asset's API-provided `digest`. A digest read from LocalAppData, a sidecar by
itself, or a prior process is not a substitute for this current response.

At most five redirects are allowed through:

- `api.github.com`
- `github.com`
- `objects.githubusercontent.com`
- `release-assets.githubusercontent.com`

Any other initial or redirect host is rejected. The client uses an explicit
User-Agent, cancellation, bounded responses, and bounded timeouts. Runtime URL
overrides are unsupported.

Network, API, JSON, and rate-limit failures become update status results and
never escape into routing initialization or shutdown.

### Update package validator

Unprivileged download staging is:

`%LOCALAPPDATA%\WireguardSplitTunnel\updates\<version>\staging`

The validator checks the sidecar digest before extracting to a separate
candidate directory. It then verifies:

- canonical paths remain below the candidate root;
- no ZIP entry is absolute, traverses upward, or collides after
  case-normalization;
- no entry or destination is a symlink, junction, or reparse point;
- file count, file length, expanded length, and compression ratio are bounded;
- manifest schema, paths, lengths, hashes, and compatibility fields are valid;
- expected application and compiled updater executables exist;
- both executables' `ProductVersion` equals the normalized Release tag;
- the manifest declares `win-x64`;
- all required launchers are present.

Only a fully validated candidate whose archive hash remains bound to the
current in-memory API selection can become `LocalStaged`.

### Update coordinator

The WPF application owns one coordinator with cancellation and an in-process
semaphore. It starts after primary state loading and startup routing
initialization have completed or reached their normal handled failure path.

The coordinator:

- skips scheduled work when automatic updates are disabled;
- checks on startup only when the persisted interval is due;
- schedules the next due check while open;
- lets a manual check bypass the interval;
- prevents overlapping checks and downloads;
- reports progress without recurring message boxes;
- atomically records a fully validated candidate;
- asks an already elevated application to prepare protected staging;
- cancels unfinished network work during close.

After a process restart, a LocalAppData-only candidate remains inert until a
fresh GitHub API check reauthenticates its exact tag, asset URL, size, and
archive digest. An offline restart may retain the files for a later retry, but
cannot promote them into protected staging or report them ready to install.

Update exceptions remain isolated from VPN and route operations.

### Primary-state load result

`AppState.AutoUpdateEnabled` remains a non-nullable runtime boolean. To
distinguish a missing JSON property from explicit `false`, `StateStore` returns
a load result containing the deserialized state plus raw property-presence
metadata. It does not choose a migration value.

`PrimaryAppStateLoader` owns the compatibility policy:

- property absent: set and persist `true`;
- explicit `false`: preserve `false`;
- explicit `true`: preserve `true`.

This keeps migration policy out of the low-level store while making the
missing-value decision implementable.

### Updater metadata stores

Ordinary scheduling/download metadata lives below LocalAppData and uses atomic
replace. It may contain:

- `LastAutomaticAttemptUtc`;
- staged version and `PendingSource` (`Automatic` or `Manual`);
- verified ZIP/checksum/manifest/candidate locations;
- non-sensitive last error.

It contains no account, browser, credential, or routing-rule data. LocalAppData
metadata is never trusted as elevated authorization, executable identity,
release authentication, trusted `PendingSource` provenance, or a destination
path. A forged `CloseAuthorized`, `Manual` source, hash, or candidate path in
LocalAppData cannot authorize or promote an update.

Protected lifecycle and transaction state lives only under:

`%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<transaction-id>`

### Protected transaction preparation

An elevated application may prepare protected staging after validation, before
the user closes the app. This avoids copying a large candidate during close but
does not authorize apply.

The transaction directory has a protected ACL granting modification only to
Administrators and SYSTEM and removing inherited medium-integrity user write
access. UNC paths and reparse-point ancestors are rejected.

The preparer copies the candidate and compiled helper from LocalAppData, then
revalidates:

- ZIP, manifest, and payload hashes;
- helper hash and executable version;
- canonical install root equal to the protected
  `%ProgramFiles%\WireguardSplitTunnel` anchor, never LocalAppData or an
  extracted user-writable directory;
- protected install-root and parent namespace authority;
- current release marker and version;
- transaction identifier and lifecycle state.

Trusted release/source provenance is supplied by the current authenticated
invocation or by already protected transaction state. It is never reconstructed
from LocalAppData metadata.

The helper is hashed again immediately before process creation. This closes the
medium-integrity LocalAppData time-of-check/time-of-use gap. A process already
running as administrator is outside this boundary because it can modify the
installation directly.

If the application is not elevated, the update remains `LocalStaged`. It cannot
write `ProtectedStaged` or `CloseAuthorized`, and no UAC prompt is introduced
at close. A later elevated run may prepare it, but still requires a later
eligible normal close to authorize apply.

### Detached Windows updater

The helper is a compiled executable launched only from the protected
transaction directory. It reads a strict protected transaction record rather
than arbitrary shell text and revalidates all canonical paths.

It acquires a named system mutex and rejects concurrent apply/rollback.

For the closing old application, it opens a process handle while the process is
still identifiable and validates PID, creation time, and image path. It holds
that handle in memory and waits on the handle, not the numeric PID. The handle
is never serialized. If the observer/helper exits, later recovery stores only
PID, creation time, and image path and must call `OpenProcess` again and
revalidate identity.

It never terminates the old or candidate process.

### Launcher recovery integration

`start.ps1` reads only protected lifecycle state before selecting an
executable:

- `LocalStaged` or protected `ProtectedStaged` is not consent; start the current
  version.
- `CloseAuthorized` may be applied after normal launcher elevation.
- apply/rollback phases are recovered idempotently before launching a version;
- `AppliedAwaitingHealth` invokes the health protocol;
- `RecoveryBlocked` refuses automatic launch and shows repair guidance.

The launcher never promotes staging to `CloseAuthorized`. Cancelling UAC
changes no protected phase and leaves the current install unchanged.

## Supported installation boundary

Automatic installation is allowed only for an updater-capable standard Release
package with a valid installed manifest, the expected root-launcher layout,
and the exact protected `%ProgramFiles%\WireguardSplitTunnel` installation
authority. A valid Release launched directly from an extracted user-writable
folder may support package `-DryRun`, but it cannot auto-elevate, run recovery,
or prepare/install an automatic update; it directs the user to `install.cmd`.

Visual Studio, test-output, and `bin` runs may report a newer release but cannot
prepare staging or overwrite developer output. Missing/inconsistent release
markers disable installation with an explanatory status.

The initial pre-updater transition uses the corrected bundled-release installer
path described under **Initial rollout constraint**.

## Preference behavior

Add `AutoUpdateEnabled` at the end of `AppState` and use the primary-load
metadata/migration above. Applied-state rollback preserves the current updater
preference rather than restoring a stale value. Existing domain/IP migrations
remain unchanged.

When the user changes automatic updates from enabled to disabled:

- an in-progress automatic check/download is cancelled;
- `Automatic` LocalAppData staging is removed;
- an `Automatic` protected `ProtectedStaged` transaction is removed immediately
  when elevated, or is marked for protected removal on the next elevated run;
- future scheduled checks stop.

The setting cannot revoke an already protected `CloseAuthorized` transaction
because the application has already completed the qualifying close and exited.

A manual **Check now** performs one complete check/download/queue cycle without
changing the preference. Its `Manual` staging represents explicit intent and
remains eligible for later close authorization while the checkbox is false.

## Scheduling and limits

Scheduling uses UTC for persistence and a monotonic timer in one process:

- `LastAutomaticAttemptUtc` is atomically written when an automatic attempt
  begins, including attempts later failed or cancelled;
- the next automatic attempt is due 24 hours later;
- a manual check does not change automatic due time;
- a persisted time over five minutes in the future is invalid, so one attempt
  becomes due and replaces it with current UTC;
- there is no tight automatic retry loop.

Initial limits:

- metadata response: 2 MiB;
- release ZIP: 256 MiB;
- download total time: 15 minutes;
- download no-progress timeout: 60 seconds;
- ZIP entries: 4,096;
- one expanded file: 512 MiB;
- total expanded content: 1 GiB;
- per-entry compression ratio: 200:1;
- old-process close wait: 60 seconds.

Required free space is candidate expanded bytes, current managed bytes to back
up, archive bytes, plus 256 MiB. Constants and exact boundary behavior are
tested.

## User interface

Place near the current version/settings:

- **Automatically update from GitHub Releases** checkbox;
- **Check now** button;
- compact update status.

Representative non-modal statuses:

- Checking for updates
- Version `vX.Y.Z` is current
- Downloading `vX.Y.Z`
- `vX.Y.Z` is ready and will install after an eligible normal close
- Update ready; run the application elevated before a later normal close
- Update check failed; retry when next due
- Package verification failed; nothing was installed
- Automatic installation is unavailable from this developer build

Background failures are logged without recurring dialogs. A manual check may
show one concise user-initiated result.

## Close intent and authorization

Close intent is explicit:

- `UserOrApplicationClose`: window close, Alt+F4, or an in-app normal close
  command;
- `SessionEnding`: Windows shutdown or logoff;
- `ElevationHandoff`: the unelevated bootstrap process exits after launching
  its elevated replacement;
- `UnknownOrAbnormal`: crash, forced termination, or unclassified exit.

`Application.SessionEnding` or equivalent sets `SessionEnding` before window
close handling. Only an elevated `UserOrApplicationClose` may authorize an
update. System shutdown/logoff, elevation handoff, and abnormal exits never
create `CloseAuthorized`.

For an eligible close:

1. mark the window as closing and record close intent;
2. stop timers and cancel unfinished updater network work;
3. finish the serialized route-restoration operation;
4. atomically save primary state;
5. confirm a fully verified `ProtectedStaged` transaction still exists;
6. atomically transition protected state to `CloseAuthorized`;
7. launch the protected helper and allow the main process to exit;
8. helper waits for the exact old process handle;
9. helper applies without relaunching the application.

If route cleanup/state persistence does not reach its normal completed/handled
point, authorization is not written.

A crash or session end with only `LocalStaged`/`ProtectedStaged` starts the
current version next time. A later elevated eligible close can authorize it.
Closing during partial download never stages or authorizes.

## Transaction and rollback

Protected high-level phases:

- `ProtectedStaged`
- `CloseAuthorized`
- `Prepared`
- `BackingUp`
- `Applying`
- `AppliedAwaitingHealth`
- `Committed`
- `RollingBack`
- `RolledBack`
- `RecoveryBlocked`

The helper creates a durable operation plan before mutation. Each operation
records:

- kind (`Create`, `Replace`, or special `ReplaceManifest`);
- canonical relative target;
- whether target existed;
- expected old length/hash;
- protected backup path/hash;
- expected new length/hash;
- per-operation pre/post state.

Before and after every filesystem mutation, it atomically updates and flushes
the journal. Recovery can distinguish a planned operation from a completed one.

Apply:

1. revalidate protected ACL and canonical paths;
2. revalidate manifest, payload, helper, current executable, and compatibility;
3. wait for the validated old process handle without killing it;
4. build and flush the complete operation plan;
5. back up and verify every existing target;
6. write replacements to same-volume temporary paths;
7. atomically move each verified payload replacement into place;
8. never delete obsolete or unknown paths;
9. apply `ReplaceManifest` last using its protected exact hash;
10. verify installed manifest and executable/helper versions;
11. transition to `AppliedAwaitingHealth`.

Rollback reverses completed operations:

- replaced files restore only from verified backups;
- newly created files are removed only if still equal to the exact new hash;
- a target already equal to expected old hash is already restored;
- manifest follows the same journalled rules;
- unexpected target content stops destructive recovery.

Unexpected content or an unrecoverable journal enters `RecoveryBlocked`. In
that state the launcher must not select the old or new executable, must not
retry automatically, and must preserve transaction/backup evidence. It shows a
clear path to the updater log and instructs the user to repair with a verified
Release package through the manual installer.

Forward recovery and rollback are idempotent. Fault injection before/after each
checkpoint must converge to old, new, or explicit `RecoveryBlocked`; it may
never silently launch a partial installation.

The helper never recursively deletes an unvalidated/computed directory.
Cleanup is restricted to a canonical child of the fixed protected ProgramData
root.

## Post-update health and process identity

Backups remain until the new application reports the matching transaction and
version healthy.

Health means:

- normal interactive main-window initialization was reached;
- primary state loaded successfully;
- startup routing completed or reached its normal handled failure path;
- the protected health marker was written atomically.

WireGuard availability is not itself a health requirement.

On the next user-initiated start:

- the launcher starts the candidate;
- durable metadata records PID, creation time, and image path only;
- the current observer process opens/holds its own process handle;
- a later launcher reopens a handle and revalidates all recorded identity;
- matching health commits and permits backup cleanup;
- candidate exit before health rolls back and starts the old version;
- no timeout force-kills a live candidate;
- a second launcher seeing the same live unconfirmed candidate neither rolls
  back nor opens another instance;
- a dead unconfirmed candidate is rolled back before old-version launch.

If the observer process itself exits, the next launcher follows the same
reopen-and-revalidate rule; it never reuses a serialized handle value.

The close-time updater never automatically reopens the app. Old-version launch
occurs only during failure recovery after a later user-initiated start.

## State compatibility during health rollback

The updater never rolls back user state, because that could erase changes made
while the candidate was running. Therefore every automatically installable
release must keep persisted application state backward-readable by every
version allowed by `RollbackCompatibleFromVersion`.

Before health:

- migrations must be additive/non-destructive;
- unknown fields must be tolerated by the rollback version;
- domain/IP and applied-state semantics must remain readable;
- no irreversible schema rewrite is allowed.

A release requiring an incompatible state rewrite raises its minimum
compatibility version and is not automatically offered to an older
installation; it requires a manual migration path.

Tests require the rollback version to load state saved by the candidate before
health and preserve user-rule semantics. Byte-for-byte preservation applies to
the updater's apply operation before candidate launch; after candidate startup,
tests assert backward readability and semantic preservation rather than
identical serialization.

## Error behavior

| Failure | Required behavior |
| --- | --- |
| GitHub unavailable, timeout, invalid JSON, or API limit | Keep current app/VPN behavior; non-blocking status; retry only when due/requested |
| Same version, downgrade, draft, prerelease, or incompatible release | Ignore or report manual update required |
| Invalid initial URL or redirect host | Refuse download |
| Missing/invalid checksum | Delete untrusted candidate; refuse install |
| Unsafe ZIP or wrong manifest/platform/version | Delete candidate; refuse install |
| Insufficient disk space | Keep current version and report reason |
| Close during incomplete download | Cancel; do not stage/authorize |
| Crash/session end with only staged state | Start current version; never apply |
| Non-elevated close | Keep staged; never authorize |
| Old process exceeds 60-second wait | Leave install unchanged and protected authorization retryable |
| File locked/access denied | Roll back completed operations |
| Shutdown during apply | Recover from detailed journal next start |
| Candidate alive without health | Do not kill, roll back, or launch another |
| Candidate exits before health | Roll back and start old version |
| Unexpected target hash/unrecoverable journal | Enter `RecoveryBlocked`; launch neither version |

Updater logs live below:

`%LOCALAPPDATA%\WireguardSplitTunnel\logs`

Existing logs are never deleted/truncated. The updater may append its own
records or create a separate log. Logs exclude GitHub bodies, credentials,
tokens, state contents, and browser data.

## Preserved data

The updater never declares/replaces/deletes:

- primary `state.json`;
- `applied-state.json`;
- temporary/user-list state such as `temp-lists.json`;
- WireGuard `.conf` or DPAPI-protected material;
- existing application, launcher, installer, or runtime logs;
- unknown/custom files outside the verified new manifest.

Before candidate launch, tests compare user data byte-for-byte. Existing log
bytes must remain unchanged or an exact prefix while allowing a new updater
record.

## Security boundary

Integrity comes from:

- a hash-bound first-install bootstrap that publishes only into a protected
  Program Files namespace;
- fixed repository/stable-release selection;
- exact assets and redirect hosts;
- current-run GitHub API asset digest, matched by the archive and sidecar;
- manifest path/size/file-hash checks;
- strict extraction limits;
- protected administrative transaction storage;
- helper rehash immediately before launch;
- process identity plus live handles rather than PID alone;
- durable per-operation journaling and conservative rollback;
- explicit refusal to trust LocalAppData authorization.

The updater does not access Firefox, browser accounts, cookies, login
selection, or credentials.

The current Windows executable is not Authenticode-signed. The GitHub
API-provided asset digest plus matching sidecar protects corruption and
mix-ups, but all of those values remain under the GitHub publisher's control.
Authenticode or an independent signing key is still out of scope and can be
added later without changing staging/transaction architecture.

## Final implementation hardening

The protected preparer completes and validates the proposed transaction in an
inactive workspace before it attempts to publish it. Publication is an exact
active-pointer compare-and-exchange bound to both the canonical pointer bytes
and the 128-bit file identity captured by a held read lease. The destination
handle remains pinned through the POSIX-semantics replacement. Consequently an
`A -> B -> A` byte sequence is a conflict rather than an idempotent success.
Cancellation before publication aborts; once the pointer CAS commits, the
committed result wins over late cancellation. Cleanup of a superseded
transaction is attempted twice after commit. If both attempts fail, the new
pointer remains committed and the result reports `superseded_cleanup_pending`
for later cleanup rather than undoing the durable publication.

Automatic-disable and close authorization share a dedicated commit gate. The
helper first revalidates the exact active transaction, record bytes, phase,
source, and application path, then holds a commit lease through the real
`CloseAuthorized` record CAS. Disable obtains the same gate before it changes
the enabled flag and authorization generation. Whichever operation commits
first is the linearization winner; an already committed `CloseAuthorized`
transaction is intentionally preserved.

The normal launcher holds protected leases for the Program Files parent,
installation root, and exact application executable through `Process.Start`,
and sets the child's working directory to that verified application directory.
The privileged DNS repair payload is a canonical Base64-encoded GUID only; the
elevated helper proves a stable active WireGuard/Wintun interface, applies only
the fixed DNS pair, verifies ordered readback, and checks the cache flush.

UI operation generations and the latest busy snapshot are lock-linearized, so
a terminal status arriving during a settings-save handoff cannot leave the
controls permanently busy. The packaged launcher also disables inherited
module autoloading: Windows PowerShell imports fixed System32 module manifests,
while PowerShell Core accepts only its protected Program Files installation
and imports the exact edition-matched manifests from that root. This keeps
`-DryRun` functional under supported PowerShell Core without compatibility
remoting or caller-controlled `PSModulePath` execution.

## Test architecture

Close orchestration, lifecycle transitions, scheduling, package policy, and
journal planning are extracted behind injected interfaces in Core so
cross-platform deterministic tests can execute real async interleavings.

Windows filesystem/process/ACL behavior is covered in a Windows-targeted
updater test project run on `windows-latest`. Thin WPF bindings may use a
Windows STA test project where valuable, while routing/update close ordering is
proved primarily through the extracted close orchestrator.

Real UAC UI cancellation and a true medium-token ACL access attempt are not
reliable on headless GitHub runners. CI tests the injected elevation-cancel
boundary, generated ACL, and protected-path enforcement. A local Windows smoke
test verifies an actual standard-user write denial and UAC cancellation.

Fault injection proves durable interruption recovery; it does not claim to
switch off physical power in CI.

## Automated tests

### Release selection and HTTP

- strict stable tag, newer/same/downgrade behavior;
- compatibility-version acceptance/rejection;
- wrong/duplicate/missing assets and checksum parsing;
- initial repository/tag/filename URL validation;
- CDN redirect HTTPS/host/count validation without repository-path matching;
- response and every numeric limit boundary.

### Scheduling and state

- 24-hour UTC/monotonic/manual/failure/cancel/future-clock cases;
- missing auto-update property migrates true;
- explicit true/false round-trip through presence metadata;
- applied-state rollback preserves preference;
- `Automatic` versus `Manual` staged-disable behavior;
- rollback version reads pre-health candidate state semantically.

### Package and installer

- valid package acceptance;
- checksum, traversal, absolute/case-collision, reparse, entry/size/ratio,
  hash/length, RID, entry-point/helper, and version failures;
- manifest special-operation hash binding;
- SDK-present Release ZIP uses bundled files and never attempts missing source
  publish;
- bound bootstrap rejects a same-bytes package-root namespace swap;
- bundled install publishes only to the protected Program Files root and
  refuses elevated execution from the extracted source pathname;
- inherited user PATH and caller-controlled elevated log/prerequisite paths are
  never executed or written;
- source checkout retains explicit publish behavior;
- manual bootstrap preserves representative `v0.1.9` user state.

### Authorization and close orchestration

- only elevated `UserOrApplicationClose` may create protected authorization;
- route restore and primary save complete first;
- session ending, elevation handoff, crash, forced exit, and non-elevated close
  leave staging unapproved;
- forged LocalAppData `CloseAuthorized` is ignored;
- partial download cannot stage;
- helper launch/preparation failure cannot bypass route cleanup.

### Protected execution

- ACL descriptor and protected-root enforcement;
- protected Program Files parent owner/DACL enforcement and medium-token root
  rename/create denial;
- packaged `start`, direct App launch, DNS repair, and network reset refuse
  mutable-root elevation;
- reparse/UNC/unexpected install root rejection;
- staging/helper mutation detected at protected revalidation/pre-launch;
- PID reuse rejected by creation time/image/handle;
- observer exit causes a later launcher to reopen/revalidate a handle;
- injectable UAC cancellation leaves unchanged staging;
- user-writable and protected install-root policies.

### Apply, interruption, and recovery

- create/replace only verified new-manifest payload paths;
- special manifest replace/rollback before-and-after interruption;
- unknown/obsolete files retained;
- user data unchanged before candidate launch; logs not truncated;
- locked file/injected mutation failures roll back;
- mutex excludes second helper;
- interruption before/after every backup, write, replace, journal flush, and
  phase transition converges idempotently;
- unexpected target hash enters `RecoveryBlocked`;
- `RecoveryBlocked` starts neither executable;
- no force-kill or unvalidated recursive deletion path.

### Health and launcher

- matching health commits;
- early exit rolls back and selects old;
- live unconfirmed candidate blocks rollback and second launch;
- dead unconfirmed candidate rolls back;
- observer exit/recovery uses a newly opened verified handle;
- close-time apply never launches candidate;
- startup applies only protected `CloseAuthorized`/later phases;
- Local/Protected staging launches current version.

### Release workflow

- tag and `VersionPrefix` mismatch fails;
- tests/build/package/manifest/version/checksum/dry-run failures block publish;
- publishing requires verified Windows artifacts;
- actions are full-SHA pinned and job permissions are least privilege.

## Manual Windows smoke tests

Before completion:

1. install the first updater-capable package over representative `v0.1.9` state
   on a machine that has a .NET SDK; confirm bundled release is used;
2. verify all existing user data survives manual bootstrap;
3. expose deterministic valid N+1 metadata/package to an updater-capable N;
4. verify download, validation, protected staging, and ready status;
5. simulate crash and Windows session-ending paths; confirm no authorization;
6. close normally; confirm route restore/save precede protected authorization;
7. confirm close-time apply does not reopen the app;
8. launch and confirm N+1 health plus preserved state/rules/logs;
9. test corrupt package rejection and early-exit rollback;
10. keep candidate alive without health; confirm second launch does nothing;
11. test standard-user denial against protected transaction ACL;
12. cancel a real UAC prompt; confirm installation remains unchanged;
13. induce an unexpected recovery hash; confirm `RecoveryBlocked` and repair
    guidance rather than either executable starting.

Production evidence also requires:

- all automated tests passing;
- successful Release build;
- successful manifest/package/checksum validation;
- `scripts\start.ps1 -DryRun` selecting the intended packaged executable.

Live Release creation, tagging, committing, and pushing remain separately
authorized operations.
