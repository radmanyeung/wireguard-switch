# Windows GitHub Release Auto-Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Windows-only updater that securely downloads a newer stable GitHub Release, stages it in the background, authorizes installation only after an elevated normal close, applies it transactionally, and rolls back an unhealthy candidate.

**Architecture:** Pure update policy, lifecycle, package-contract, and close-ordering logic lives in the existing cross-platform Core project. A new `WireguardSplitTunnel.WindowsUpdate` library owns Windows HTTP, filesystem, ACL, process, staging, transaction, and health mechanics; a small self-contained `WireguardSplitTunnel.Updater` executable hosts apply/recovery commands. WPF composes these services, while `start.ps1`, `install.ps1`, and the Release workflow provide the protected launcher, first-install bootstrap, manifest, checksum, and publishing boundaries.

**Tech Stack:** C# 12, .NET 8, WPF, `System.Net.Http`, `System.IO.Compression`, Windows ACL/process APIs, PowerShell 5.1+, xUnit, FluentAssertions, GitHub Actions

**Design:** `docs/superpowers/specs/2026-07-29-windows-github-release-auto-update-design.md`

**Repository rule:** Do not stage, commit, tag, push, publish a Release, close the running application, or install the new build until the user separately authorizes that action. Keep all existing `logs/*.log` changes unstaged. Each task lists a proposed commit boundary; execute it only after commit authorization.

**Final security amendment:** Treat the canonical SHA-256 digest returned for
the ZIP asset by the current GitHub Releases API request as the authentication
anchor. The downloaded archive and sidecar must both match that digest. A
LocalAppData-only staged candidate is inert after restart until a fresh online
API response reauthenticates the exact release and digest. Trusted
Automatic/Manual provenance may come only from the current invocation or
protected transaction state, never from LocalAppData metadata. Authenticode or
an independent publisher signing key remains outside this version's scope.

**Execution prerequisite:** Before implementation, use `superpowers:using-git-worktrees` to create a clean `codex/windows-auto-update` worktree. Copy the approved uncommitted spec and this plan into that worktree without copying runtime logs.

**Baseline evidence:** On 2026-07-29, the Windows Core run reported 280 tests: 270 passed and 10 pre-existing Mac-path tests failed under Windows path semantics. Focused updater tests must be green throughout. The Release workflow will use a platform matrix: Windows runs non-Mac Core tests plus Windows updater tests; macOS runs Mac Core tests. Do not attribute those 10 baseline failures to updater changes or silently modify unrelated Mac behavior.

---

## Locked file structure

### Existing files to modify

- `WireguardSplitTunnel.sln` — add the Windows update library, updater executable,
  deterministic test-process fixture, Release tool, and Windows test project.
- `Directory.Build.props` — final version bump to `0.2.0`.
- `src/WireguardSplitTunnel.Core/Models/AppState.cs` — append automatic-update preference.
- `src/WireguardSplitTunnel.Core/Services/StateStore.cs` — return raw JSON property-presence metadata without applying migration policy.
- `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs` — own missing-property migration.
- `src/WireguardSplitTunnel.Core/Services/RuleStateMutations.cs` — preserve current preference during applied-snapshot rollback.
- `src/WireguardSplitTunnel.App/App.xaml.cs` — parse sanitized launch context and record session-ending intent.
- `src/WireguardSplitTunnel.App/MainWindow.xaml` — add update preference, status, and manual-check controls.
- `src/WireguardSplitTunnel.App/MainWindow.xaml.cs` — compose startup/health/close integration and remove duplicate close-time saves.
- `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs` — preserve the shared preference during applied-snapshot rollback only; no Mac updater.
- `scripts/start.ps1` — invoke protected recovery before normal executable selection.
- `scripts/install.ps1` — prefer a validated bundled Release even when an SDK is installed.
- `scripts/ensure-prebuilt.ps1` — keep it bootstrap-only and require the exact Windows asset/checksum/manifest.
- `scripts/test.ps1` — run the platform-correct test set.
- `.github/workflows/release-prebuilt.yml` — test gates, manifest, checksum, artifacts, least privilege, and one final publisher.
- `README.md` — explain first bootstrap, automatic updates, disabling, recovery, and logs.
- Existing Core tests named in the tasks below.

### New Core files

- `src/WireguardSplitTunnel.Core/Models/StateLoadResult.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdateReleaseContract.cs`
- `src/WireguardSplitTunnel.Core/Updates/SemanticVersion.cs`
- `src/WireguardSplitTunnel.Core/Updates/GitHubReleaseModels.cs`
- `src/WireguardSplitTunnel.Core/Updates/StableReleaseSelector.cs`
- `src/WireguardSplitTunnel.Core/Updates/GitHubReleaseUrlPolicy.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdateNetworkLimits.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdateSchedulePolicy.cs`
- `src/WireguardSplitTunnel.Core/Updates/LocalUpdateMetadata.cs`
- `src/WireguardSplitTunnel.Core/Updates/ReleaseManifest.cs`
- `src/WireguardSplitTunnel.Core/Updates/Sha256SidecarParser.cs`
- `src/WireguardSplitTunnel.Core/Updates/WindowsReleasePathPolicy.cs`
- `src/WireguardSplitTunnel.Core/Updates/ReleaseManifestValidator.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdatePackageLimits.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdateDiskSpacePolicy.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdatePackageValidationAbstractions.cs`
- `src/WireguardSplitTunnel.Core/Updates/SafeZipExtractor.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdatePackageValidator.cs`
- `src/WireguardSplitTunnel.Core/Updates/UpdateLifecycle.cs`
- `src/WireguardSplitTunnel.Core/Updates/ApplicationCloseIntent.cs`
- `src/WireguardSplitTunnel.Core/Updates/ApplicationCloseOrchestrator.cs`
- `src/WireguardSplitTunnel.Core/Updates/ApplicationUpdateStartupOrchestrator.cs`

### New Windows update library files

- `src/WireguardSplitTunnel.WindowsUpdate/WireguardSplitTunnel.WindowsUpdate.csproj`
- `src/WireguardSplitTunnel.WindowsUpdate/GitHub/GitHubReleaseClient.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/GitHub/ReleaseAssetDownloader.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Staging/LocalUpdatePaths.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Staging/LocalUpdateMetadataStore.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Staging/WindowsUpdateCoordinator.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Staging/WindowsUpdateStatus.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsExecutableProductVersionReader.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsPathSafetyInspector.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsDiskSpaceProvider.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Validation/InstalledReleaseLocator.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionPaths.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionStore.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionPreparer.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedDirectoryAcl.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedUpdateMutex.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/UpdateOperationJournal.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/UpdateFileSystem.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/TransactionalUpdateExecutor.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Transactions/TransactionRecoveryService.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Processes/WindowsProcessIdentityService.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Health/UpdateHealthService.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Launcher/LauncherRecoveryService.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Logging/UpdaterFileLogger.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/UpdaterCommandLine.cs`
- `src/WireguardSplitTunnel.WindowsUpdate/Properties/AssemblyInfo.cs`

### New updater executable files

- `src/WireguardSplitTunnel.Updater/WireguardSplitTunnel.Updater.csproj`
- `src/WireguardSplitTunnel.Updater/Program.cs`

### New build/test support projects

- `tools/WireguardSplitTunnel.ReleaseTool/WireguardSplitTunnel.ReleaseTool.csproj`
- `tools/WireguardSplitTunnel.ReleaseTool/Program.cs`
- `tools/WireguardSplitTunnel.ReleaseTool/ReleaseToolApplication.cs`
- `tests/WireguardSplitTunnel.TestProcess/WireguardSplitTunnel.TestProcess.csproj`
- `tests/WireguardSplitTunnel.TestProcess/Program.cs`

### New WPF integration files

- `src/WireguardSplitTunnel.App/Services/WindowsUpdateCompositionRoot.cs`
- `src/WireguardSplitTunnel.App/Services/WpfApplicationCloseActions.cs`
- `src/WireguardSplitTunnel.App/MainWindow.Update.cs`

### New packaging and launcher scripts

- `scripts/WindowsRelease.psm1`
- `scripts/lib/release-package.ps1`
- `scripts/package-windows.ps1`
- `scripts/new-release-manifest.ps1`
- `scripts/validate-release-package.ps1`
- `scripts/update-launcher.ps1`

### New tests

- Focused Core test files named in Tasks 1–5.
- `tests/WireguardSplitTunnel.WindowsUpdate.Tests/WireguardSplitTunnel.WindowsUpdate.Tests.csproj`
- Windows test files named in Tasks 6–13.
- `tests/WireguardSplitTunnel.Core.Tests/WindowsUpdateWiringContractTests.cs`

---

### Task 1: Persist the update preference without confusing missing JSON with explicit false

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/Models/AppState.cs`
- Create: `src/WireguardSplitTunnel.Core/Models/StateLoadResult.cs`
- Modify: `src/WireguardSplitTunnel.Core/Services/StateStore.cs`
- Modify: `src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs`
- Modify: `src/WireguardSplitTunnel.Core/Services/RuleStateMutations.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Modify: `src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/StateStoreTests.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/PrimaryAppStateLoaderTests.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/RuleStateMutationsTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/AppStateRollbackCompatibilityTests.cs`

- [ ] **Step 1: Write failing state-presence and rollback tests**

Add cases proving:

```csharp
loadResult.HasProperty(nameof(AppState.AutoUpdateEnabled)).Should().BeFalse();
PrimaryAppStateLoader.Load(store).AutoUpdateEnabled.Should().BeTrue();
```

for legacy JSON, and:

```csharp
PrimaryAppStateLoader.Load(store).AutoUpdateEnabled.Should().Be(explicitValue);
```

for both explicit values. Require `PrimaryAppStateLoader` to persist a missing
property once, while `StateStore.Load()` remains migration-free. Update
`Load_NonLegacyState_DoesNotRewriteStateFile` so its fixture explicitly contains
`"AutoUpdateEnabled": true`.

Add rollback assertions:

```csharp
var restored = RuleStateMutations.CloneForAppliedRollback(snapshot, current);
restored.AutoUpdateEnabled.Should().Be(current.AutoUpdateEnabled);
restored.DomainRules.Should().BeEquivalentTo(snapshot.DomainRules);
```

Cover current `true`/snapshot `false` and the inverse. Add a `v0.1.9`-shaped
test DTO that ignores the new property while preserving domain/IP semantics.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~StateStoreTests|FullyQualifiedName~PrimaryAppStateLoaderTests|FullyQualifiedName~RuleStateMutationsTests|FullyQualifiedName~AppStateRollbackCompatibilityTests"
```

Expected: compilation failures for `AutoUpdateEnabled`, `StateLoadResult`,
`LoadWithMetadata`, and `CloneForAppliedRollback`.

- [ ] **Step 3: Add the runtime preference and load metadata**

Append this final positional parameter:

```csharp
bool AutoUpdateEnabled = true
```

Create:

```csharp
namespace WireguardSplitTunnel.Core.Models;

public sealed record StateLoadResult(
    AppState State,
    IReadOnlySet<string> PresentPropertyNames)
{
    public bool HasProperty(string propertyName) =>
        PresentPropertyNames.Contains(propertyName);
}
```

Keep the existing API:

```csharp
public AppState Load() => LoadWithMetadata().State;
public StateLoadResult LoadWithMetadata();
```

`LoadWithMetadata` reads the file once, parses a root `JsonDocument`, collects
exact property names in `HashSet<string>(StringComparer.Ordinal)`, deserializes,
and passes the state through the existing normalization. Missing/blank files
return default state with an empty property set.

- [ ] **Step 4: Put migration and rollback policy at the correct boundaries**

`PrimaryAppStateLoader.Load` must:

```csharp
var loadResult = store.LoadWithMetadata();
var state = loadResult.State;
var changed = false;
if (!loadResult.HasProperty(nameof(AppState.AutoUpdateEnabled)))
{
    state = state with { AutoUpdateEnabled = true };
    changed = true;
}
```

Then run the existing OpenAI/Claude migrations and save once when any change
occurred.

Add:

```csharp
public static AppState CloneForAppliedRollback(
    AppState appliedSnapshot,
    AppState currentState) =>
    Clone(appliedSnapshot) with
    {
        AutoUpdateEnabled = currentState.AutoUpdateEnabled
    };
```

Use it at the Windows and Mac applied-snapshot rollback callsites.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 2 command. Expected: all selected tests pass.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.Core/Models/AppState.cs src/WireguardSplitTunnel.Core/Models/StateLoadResult.cs src/WireguardSplitTunnel.Core/Services/StateStore.cs src/WireguardSplitTunnel.Core/Services/PrimaryAppStateLoader.cs src/WireguardSplitTunnel.Core/Services/RuleStateMutations.cs src/WireguardSplitTunnel.App/MainWindow.xaml.cs src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: persist automatic update preference"
```

Expected: commit created only after user authorization; runtime logs remain
unstaged.

### Task 2: Add strict release identity, URL, compatibility, and schedule policy

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdateReleaseContract.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/SemanticVersion.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/GitHubReleaseModels.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/StableReleaseSelector.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/GitHubReleaseUrlPolicy.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdateNetworkLimits.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdateSchedulePolicy.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/LocalUpdateMetadata.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/SemanticVersionTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/StableReleaseSelectorTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/GitHubReleaseUrlPolicyTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/UpdateSchedulePolicyTests.cs`

- [ ] **Step 1: Write strict failing policy tests**

Require the parser to accept only `vMAJOR.MINOR.PATCH` tags and normalized
`MAJOR.MINOR.PATCH` values. Reject whitespace, signs, leading zeroes,
prerelease/build suffixes, missing/extra components, and integer overflow.

Require selection to reject draft/prerelease/same/downgrade releases and
missing/duplicate assets. Require exactly:

```csharp
UpdateReleaseContract.Repository == "radmanyeung/wireguard-switch";
UpdateReleaseContract.WindowsAssetName ==
    "wireguard-split-tunnel-win-x64.zip";
UpdateReleaseContract.WindowsChecksumAssetName ==
    "wireguard-split-tunnel-win-x64.zip.sha256";
```

Require initial URLs to match HTTPS, repository, tag, and filename. Redirects
must be HTTPS, stop after five hops, and use only this exact allowlist:

```text
api.github.com
github.com
objects.githubusercontent.com
release-assets.githubusercontent.com
```

Schedule boundary assertions:

```csharp
UpdateSchedulePolicy.IsDue(lastAttempt, lastAttempt.AddHours(24)).Should().BeTrue();
UpdateSchedulePolicy.IsFutureTimestampInvalid(now.AddMinutes(5), now).Should().BeFalse();
UpdateSchedulePolicy.IsFutureTimestampInvalid(now.AddMinutes(5).AddTicks(1), now).Should().BeTrue();
UpdateSchedulePolicy.IsDue(now.AddMinutes(5).AddTicks(1), now).Should().BeTrue();
```

Also prove that automatic failure/cancellation still advances the persisted due
time, while a manual attempt never changes it. In-process waiting uses the
injected monotonic `TimeProvider` timer, so backward/forward wall-clock changes
cannot create a tight retry loop.

- [ ] **Step 2: Run policy tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~SemanticVersionTests|FullyQualifiedName~StableReleaseSelectorTests|FullyQualifiedName~GitHubReleaseUrlPolicyTests|FullyQualifiedName~UpdateSchedulePolicyTests"
```

Expected: missing update policy types.

- [ ] **Step 3: Implement the locked contracts**

Create:

```csharp
public readonly record struct SemanticVersion(
    int Major,
    int Minor,
    int Patch) : IComparable<SemanticVersion>
{
    public static bool TryParseTag(string? value, out SemanticVersion version);
    public static bool TryParseNormalized(string? value, out SemanticVersion version);
    public int CompareTo(SemanticVersion other);
    public override string ToString();
}
```

Create immutable metadata/result types:

```csharp
public sealed record GitHubReleaseAsset(string Name, Uri BrowserDownloadUrl, long Size);
public sealed record GitHubReleaseMetadata(
    string TagName,
    bool Draft,
    bool Prerelease,
    IReadOnlyList<GitHubReleaseAsset> Assets);
public sealed record SelectedWindowsRelease(
    SemanticVersion Version,
    Uri ArchiveUrl,
    Uri ChecksumUrl,
    long ArchiveSize);
```

Keep `VersionDisplay` unchanged because it is display-only.

- [ ] **Step 4: Implement URL, schedule, and local metadata models**

`UpdateReleaseContract` fixes the API URI, asset names, redirect hosts,
`release-manifest.json`, `win-x64`, application/helper paths, and this exact
minimum launcher set:

```text
install.cmd
start.cmd
start-admin.cmd
start-safe.cmd
scripts/install.ps1
scripts/start.ps1
```

`UpdateNetworkLimits` fixes:

```csharp
MetadataBytes = 2L * 1024 * 1024;
ChecksumBytes = 4L * 1024;
ArchiveBytes = 256L * 1024 * 1024;
MetadataTimeout = TimeSpan.FromSeconds(30);
DownloadTimeout = TimeSpan.FromMinutes(15);
NoProgressTimeout = TimeSpan.FromSeconds(60);
MaximumRedirects = 5;
```

Create `PendingUpdateSource`, `LocalStagedUpdate`, and `LocalUpdateMetadata`
records. Manual checks never alter `LastAutomaticAttemptUtc`.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.Core/Updates tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: define stable release update policy"
```

### Task 3: Define the checksum, manifest, and Windows path contract

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Updates/ReleaseManifest.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/Sha256SidecarParser.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/WindowsReleasePathPolicy.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/ReleaseManifestValidator.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/Sha256SidecarParserTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/WindowsReleasePathPolicyTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/ReleaseManifestValidatorTests.cs`

- [ ] **Step 1: Write failing contract tests**

Use this schema:

```csharp
public sealed record ReleaseManifest(
    int SchemaVersion,
    string Version,
    string RuntimeIdentifier,
    string MinimumAutoUpdateVersion,
    string RollbackCompatibleFromVersion,
    int StateSchemaVersion,
    string EntryPoint,
    string UpdaterEntryPoint,
    List<string> RequiredLaunchers,
    List<ReleasePayloadFile> Files);

public sealed record ReleasePayloadFile(
    string Path,
    long Length,
    string Sha256);
```

Require the checksum parser to accept one lowercase/uppercase 64-hex digest,
two spaces, the exact archive name, and an optional final newline. Reject BOM,
extra lines/files, malformed whitespace, and wrong-length/non-hex values.

Require forward-slash relative payload paths. Reject UNC/drive/absolute paths,
backslashes, `.`/`..`, empty segments, ADS colons, trailing dots/spaces,
reserved Windows names, and case-insensitive collisions.

Require exact schema, RID, versions, entry/helper/launcher paths, hashes,
lengths, and archive file-set equality excluding the manifest. Deny
`state.json`, `applied-state.json`, `temp-lists.json`, `install.status.txt`,
`runtime.log`, `logs/**`, `.conf`, `.dpapi`, update metadata, backups, and
temporary paths.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~Sha256SidecarParserTests|FullyQualifiedName~WindowsReleasePathPolicyTests|FullyQualifiedName~ReleaseManifestValidatorTests"
```

- [ ] **Step 3: Implement parsers and typed validation results**

Use typed success/failure records rather than exceptions for untrusted package
content:

```csharp
public sealed record ManifestValidationResult(
    bool IsValid,
    ReleaseManifest? Manifest,
    string? ErrorCode,
    string? ErrorMessage);
```

Bind `MinimumAutoUpdateVersion` and `RollbackCompatibleFromVersion` against the
current strict `SemanticVersion`. The new manifest may overwrite only its
declared payload paths plus the fixed manifest path.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.Core/Updates tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: define verified Windows release manifest"
```

### Task 4: Preflight and validate ZIP packages without touching a live install

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdatePackageLimits.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdateDiskSpacePolicy.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdatePackageValidationAbstractions.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/SafeZipExtractor.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdatePackageValidator.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/SafeZipExtractorTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/UpdateDiskSpacePolicyTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/UpdatePackageValidatorTests.cs`

- [ ] **Step 1: Write generated-fixture failing tests**

Generate small ZIPs in test temp directories. Cover valid extraction and:

- traversal, absolute, backslash, and case-collision paths;
- symlink/reparse attributes and a reported reparse ancestor;
- 4,096-entry, 512 MiB file, 1 GiB total, and 200:1 ratio boundaries;
- arithmetic overflow and exact free-space boundary;
- manifest/payload hash or length mismatch;
- wrong RID/application/helper product version;
- cancellation and cleanup of a partial candidate.

- [ ] **Step 2: Run package tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~SafeZipExtractorTests|FullyQualifiedName~UpdateDiskSpacePolicyTests|FullyQualifiedName~UpdatePackageValidatorTests"
```

- [ ] **Step 3: Add explicit limits and adapters**

```csharp
public sealed record UpdatePackageLimits(
    int MaximumEntries = 4096,
    long MaximumFileBytes = 512L * 1024 * 1024,
    long MaximumExpandedBytes = 1024L * 1024 * 1024,
    double MaximumCompressionRatio = 200d,
    long ReserveBytes = 256L * 1024 * 1024);

public interface IExecutableProductVersionReader
{
    string? ReadProductVersion(string executablePath);
}

public interface IPathSafetyInspector
{
    bool IsReparsePoint(string path);
}

public interface IDiskSpaceProvider
{
    long GetAvailableBytes(string path);
}
```

Use checked arithmetic. Required free space is exactly archive bytes plus
expanded candidate bytes plus the current managed bytes that may require
backup plus `ReserveBytes`; equality is accepted and one byte less is rejected.

- [ ] **Step 4: Implement deterministic validation order**

`UpdatePackageValidator.ValidateAsync` must perform:

```text
sidecar parse
archive SHA-256
ZIP preflight
bounded manifest read and validation
compatibility and disk-space decision
separate candidate extraction with CreateNew
every payload hash/length
application/helper ProductVersion
ValidatedUpdatePackage result
```

No operation receives a live install-root mutation callback.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.Core/Updates tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: validate bounded Windows update packages"
```

### Task 5: Model close intent, lifecycle authorization, and startup ordering in Core

**Files:**
- Create: `src/WireguardSplitTunnel.Core/Updates/UpdateLifecycle.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/ApplicationCloseIntent.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/ApplicationCloseOrchestrator.cs`
- Create: `src/WireguardSplitTunnel.Core/Updates/ApplicationUpdateStartupOrchestrator.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/UpdateLifecycleTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/ApplicationCloseIntentTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/ApplicationCloseOrchestratorTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/ApplicationUpdateStartupOrchestratorTests.cs`

- [ ] **Step 1: Write lifecycle and eligibility tests**

Define:

```csharp
public enum ApplicationCloseIntent
{
    UnknownOrAbnormal,
    UserOrApplicationClose,
    SessionEnding,
    ElevationHandoff
}

public enum ProtectedUpdatePhase
{
    ProtectedStaged,
    CloseAuthorized,
    Prepared,
    BackingUp,
    Applying,
    AppliedAwaitingHealth,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryBlocked
}
```

Only an elevated, non-self-test `UserOrApplicationClose` may authorize. A later
`SessionEnding` must override a previously recorded normal close.

- [ ] **Step 2: Write executable close interleaving tests**

Use `TaskCompletionSource` with
`TaskCreationOptions.RunContinuationsAsynchronously` to prove:

```text
StopUpdateWork
acquire software gate
acquire renew gate
RestoreRoutes
SavePrimaryState
release renew
release software
re-read close intent
AuthorizeProtectedTransaction
LaunchHelperAndAwaitReady
```

Required interleavings:

- route reconciliation commits before close restoration observes/removes it;
- software apply owns software then waits renew without deadlocking close;
- session ending arrives while restore is blocked, so state saves but no
  authorization/helper launch occurs;
- stop/restore/save failure skips authorization;
- helper launch or readiness failure leaves protected `CloseAuthorized`
  recoverable;
- the parent does not finish the close orchestration until the verified helper
  has opened and validated a live old-process handle and acknowledged `READY`;
- repeated `RunOnceAsync` calls share one task.

- [ ] **Step 3: Run close/startup tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~UpdateLifecycleTests|FullyQualifiedName~ApplicationCloseIntentTests|FullyQualifiedName~ApplicationCloseOrchestratorTests|FullyQualifiedName~ApplicationUpdateStartupOrchestratorTests"
```

- [ ] **Step 4: Implement the close and startup contracts**

Use:

```csharp
public interface IUpdateCloseParticipant
{
    Task StopForCloseAsync(CancellationToken cancellationToken);
    Task<UpdateCloseAuthorizationResult> TryAuthorizeAndLaunchAsync(
        UpdateCloseAuthorizationContext context,
        CancellationToken cancellationToken);
}

public interface IApplicationCloseActions
{
    Task RunRoutingExclusiveAsync(
        Func<CancellationToken, Task> restoreAsync,
        CancellationToken cancellationToken);
    void SavePrimaryState();
}
```

The orchestrator receives `ApplicationCloseIntentTracker`, not a snapshot, and
reads `tracker.Current` immediately before authorization.

`ApplicationUpdateStartupOrchestrator` marks a matching transaction healthy
after interactive state/routing readiness and before starting update checks.
Post-install self-test suppresses health, checks, protected preparation, and
close authorization.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 3 command.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.Core/Updates tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: model protected update lifecycle"
```

### Task 6: Add the Windows update projects and concrete platform adapters

**Files:**
- Modify: `WireguardSplitTunnel.sln`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/WireguardSplitTunnel.WindowsUpdate.csproj`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsExecutableProductVersionReader.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsPathSafetyInspector.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Validation/WindowsDiskSpaceProvider.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Validation/InstalledReleaseLocator.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Properties/AssemblyInfo.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/WireguardSplitTunnel.WindowsUpdate.Tests.csproj`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/WindowsValidationAdapterTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/InstalledReleaseLocatorTests.cs`
- Create: `tests/WireguardSplitTunnel.TestProcess/WireguardSplitTunnel.TestProcess.csproj`
- Create: `tests/WireguardSplitTunnel.TestProcess/Program.cs`

- [ ] **Step 1: Create a failing Windows adapter test project**

The test project references Core and WindowsUpdate, targets `net8.0-windows`,
and uses the same xUnit/FluentAssertions versions as Core tests. Add only the
precise `[assembly: InternalsVisibleTo("WireguardSplitTunnel.WindowsUpdate.Tests")]`
needed for injected internal constructors; do not expose test seams publicly.

Require ProductVersion normalization, actual drive free-space reporting, and
reparse detection on a temporary junction when the test token permits it.

`InstalledReleaseLocatorTests` require the running executable to resolve only
from this exact supported layout:

```text
<root>\release-manifest.json
<root>\WireguardSplitTunnel\WireguardSplitTunnel.App.exe
```

The manifest, ProductVersion, updater helper, and required root launchers must
match. Visual Studio, `bin`, test output, missing-marker, UNC, and reparse-root
layouts return `AutomaticInstallationUnavailable` and never expose a writable
install destination.

The deterministic test process accepts only fixed test modes (`wait`,
`exit-before-health`, and `write-health-then-wait`) so process tests do not rely
on `cmd.exe`, PID timing guesses, or the xUnit runner itself.

- [ ] **Step 2: Add project files**

Library:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\WireguardSplitTunnel.Core\WireguardSplitTunnel.Core.csproj" />
  </ItemGroup>
</Project>
```

Test project:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
    <IsTestProject>true</IsTestProject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="coverlet.collector" Version="6.0.0" />
    <PackageReference Include="FluentAssertions" Version="8.9.0" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.8.0" />
    <PackageReference Include="xunit" Version="2.5.3" />
    <PackageReference Include="xunit.runner.visualstudio" Version="2.5.3" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\..\src\WireguardSplitTunnel.WindowsUpdate\WireguardSplitTunnel.WindowsUpdate.csproj" />
    <ProjectReference Include="..\WireguardSplitTunnel.TestProcess\WireguardSplitTunnel.TestProcess.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 3: Add projects to the solution**

```powershell
dotnet sln .\WireguardSplitTunnel.sln add .\src\WireguardSplitTunnel.WindowsUpdate\WireguardSplitTunnel.WindowsUpdate.csproj
dotnet sln .\WireguardSplitTunnel.sln add .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj
dotnet sln .\WireguardSplitTunnel.sln add .\tests\WireguardSplitTunnel.TestProcess\WireguardSplitTunnel.TestProcess.csproj
```

- [ ] **Step 4: Implement minimal Windows adapters and run GREEN**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~WindowsValidationAdapterTests|FullyQualifiedName~InstalledReleaseLocatorTests"
```

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add WireguardSplitTunnel.sln src/WireguardSplitTunnel.WindowsUpdate tests/WireguardSplitTunnel.WindowsUpdate.Tests tests/WireguardSplitTunnel.TestProcess
git commit -m "feat: add Windows update platform library"
```

### Task 7: Implement fixed GitHub metadata, redirects, downloads, and local staging state

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/GitHub/GitHubReleaseClient.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/GitHub/ReleaseAssetDownloader.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Staging/LocalUpdatePaths.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Staging/LocalUpdateMetadataStore.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/GitHubReleaseClientTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ReleaseAssetDownloaderTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/LocalUpdatePathsTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/LocalUpdateMetadataStoreTests.cs`

- [ ] **Step 1: Write fake-handler and atomic-store tests**

Cover the fixed endpoint/User-Agent, 2 MiB JSON response limit, invalid JSON,
404/rate limit, caller cancellation, metadata timeout, exact URL checks, each
redirect host, hop six rejection, 256 MiB archive limit, total/no-progress
timeouts, `CreateNew`, partial deletion, and checksum response limit.

For the metadata store, prove missing, round-trip, corrupt isolation,
temp-write/flush/replace, automatic attempt timestamp, manual timestamp
preservation, and non-sensitive error serialization.

`LocalUpdatePathsTests` derive every archive/checksum/staging/candidate path only
from the fixed LocalAppData update root plus a strict `SemanticVersion`.
Metadata paths are hints, never copy/delete authority. Test forged metadata
pointing at the install root, Windows directories, another version, UNC,
traversal, and a junction/reparse ancestor; cleanup must refuse all of them and
must never recursively delete an unvalidated/computed directory.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~GitHubReleaseClientTests|FullyQualifiedName~ReleaseAssetDownloaderTests|FullyQualifiedName~LocalUpdatePathsTests|FullyQualifiedName~LocalUpdateMetadataStoreTests"
```

- [ ] **Step 3: Implement production and test constructors**

```csharp
public sealed class GitHubReleaseClient
{
    public static GitHubReleaseClient CreateProduction();
    internal GitHubReleaseClient(HttpClient client, UpdateNetworkLimits limits);
    public Task<GitHubReleaseQueryResult> GetLatestAsync(
        CancellationToken cancellationToken);
}
```

Production uses:

```csharp
new SocketsHttpHandler { AllowAutoRedirect = false };
```

The downloader manually validates each redirect before following it and streams
to a new file with progress-deadline checks.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.WindowsUpdate tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "feat: download fixed GitHub release assets"
```

### Task 8: Prepare an ACL-protected transaction without granting apply consent

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionPaths.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionStore.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedTransactionPreparer.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedDirectoryAcl.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/ProtectedUpdateMutex.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ProtectedTransactionPathsTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ProtectedTransactionStoreTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ProtectedTransactionPreparerTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ProtectedUpdateMutexTests.cs`

- [ ] **Step 1: Write protected-boundary tests**

Require:

- canonical `%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>`;
- a protected, atomically replaced `active-transaction.json` containing only the
  schema version and active transaction GUID;
- every transaction child path recomputed from the fixed root plus GUID, never
  accepted from serialized absolute child paths;
- local fixed-drive paths only, with no UNC/reparse ancestor;
- ACL inheritance disabled and write/full-control access only for the
  Administrators and SYSTEM well-known SIDs;
- an Administrators/SYSTEM-only `Global\WireguardSplitTunnel.UpdateTransaction`
  mutex excluding concurrent prepare/apply/recovery;
- LocalAppData `CloseAuthorized` ignored;
- copy from a `LocalUpdatePaths`-derived candidate followed by full
  ZIP/manifest/payload/helper revalidation;
- installed manifest marker, current version, current managed-file old hashes,
  compatibility floors, and current executable are revalidated independently;
- install root derived from current launcher context;
- helper rehash immediately before launch;
- resulting phase remains `ProtectedStaged`.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~ProtectedTransaction|FullyQualifiedName~ProtectedUpdateMutex"
```

- [ ] **Step 3: Implement protected records and atomic writes**

Protected state contains transaction/version/source/install-root identity,
candidate and manifest hashes, helper hash, current-process identity when close
is authorized, phase, and journal metadata. Child paths are derived by
`ProtectedTransactionPaths`; serialized helper, candidate, journal, backup, or
target absolute paths are never trusted. It contains no browser/account/VPN
state and accepts no destination path from LocalAppData.

Use this fixed layout:

```text
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\active-transaction.json
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\transaction.json
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\journal.json
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\health.json
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\helper\WireguardSplitTunnel.Updater.exe
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\candidate\<payload-files>
%ProgramData%\WireguardSplitTunnel\UpdateTransactions\<guid>\backups\<backup-files>
```

The ACL builder sets owner to SYSTEM and uses
`WellKnownSidType.BuiltinAdministratorsSid` plus
`WellKnownSidType.LocalSystemSid`, not localized account names. It protects and
revalidates the ProgramData product root, UpdateTransactions root, active
pointer, transaction directory, and helper before every privileged use, and
emits:

```text
BUILTIN\Administrators: FullControl
NT AUTHORITY\SYSTEM: FullControl
inheritance: disabled
```

Reject a pre-existing user-owned, reparse, or weaker root/transaction instead
of taking it over or silently trusting it. Pointer activation happens only
after the complete `ProtectedStaged` record and candidate have been durably
written.

Recompute checked free-space requirements on every actual volume: LocalAppData
for download/extraction, ProgramData for protected candidate/backups, and the
install volume for same-volume replacement files. Any one-byte-short volume
fails before authorization or mutation; apply rechecks immediately before its
first mutation.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command. A real medium-token denial remains a manual smoke test;
CI verifies the descriptor and protected-root enforcement.

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.WindowsUpdate/Transactions tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "feat: protect staged update transactions"
```

### Task 9: Journal every file mutation and recover to old, new, or RecoveryBlocked

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/UpdateOperationJournal.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/UpdateFileSystem.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/TransactionalUpdateExecutor.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Transactions/TransactionRecoveryService.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/TransactionalUpdateExecutorTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/TransactionRecoveryServiceTests.cs`

- [ ] **Step 1: Write operation-plan and fault-injection tests**

Use:

```csharp
public enum UpdateOperationKind { Create, Replace, ReplaceManifest }
public enum UpdateOperationState { Planned, BackupStarted, BackupComplete, WriteStarted, WriteComplete }
```

Each record includes canonical relative target, existed flag, old/new
length/hash, protected backup path/hash, and state.

Inject process interruption immediately before and after every backup, temp
write, atomic replace, manifest replace, journal flush, and phase transition.
Temporary replacement files must be created on the target's volume, opened with
`CreateNew`, hash/length verified, and moved/replaced atomically.
Every restart must converge to the complete old install, complete new install,
or `RecoveryBlocked`.

Require unknown target hashes to stop destructive recovery. Newly created files
are removed only when still equal to the exact new hash. Obsolete/unknown files
are retained.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~TransactionalUpdateExecutorTests|FullyQualifiedName~TransactionRecoveryServiceTests"
```

- [ ] **Step 3: Implement durable ordering**

Immediately before the first mutation, repeat installed manifest/current
version/compatibility, old managed hashes, protected candidate/helper,
`NewManifestSha256`, owner/DACL, and every target-parent canonical/reparse check.
Fault/interleaving tests swap a target file or junction after preflight and prove
safe refusal or `RecoveryBlocked` without touching unrelated paths.

Before/after every filesystem mutation:

```text
write journal temp
flush file
atomic replace journal
flush containing directory when supported
perform one mutation
write and flush post-state
```

Apply payload operations first and the special `ReplaceManifest` last. Verify
the installed manifest/application/helper before
`AppliedAwaitingHealth`.

- [ ] **Step 4: Implement conservative recovery**

`RecoveryBlocked` preserves journal/backups, starts neither executable, retries
nothing automatically, and returns a typed repair path/log message to the
launcher.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.WindowsUpdate/Transactions tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "feat: apply updates with durable rollback"
```

### Task 10: Bind process identity, health confirmation, and launcher recovery

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Processes/WindowsProcessIdentityService.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Health/UpdateHealthService.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Launcher/LauncherRecoveryService.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/WindowsProcessIdentityServiceTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/UpdateHealthServiceTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/LauncherRecoveryServiceTests.cs`

- [ ] **Step 1: Write process and health tests**

Durable identity stores only:

```csharp
public sealed record ProcessIdentity(
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ImagePath);
```

Require the current observer to open/hold its own process handle. Later
launchers reopen a new handle and verify PID, creation time, and image path.
Cover PID reuse, observer exit, live unconfirmed candidate, dead unconfirmed
candidate, matching/wrong transaction marker, candidate early exit, and
installed payload tampering before candidate launch. Use native
`OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`,
and `QueryFullProcessImageName`; never serialize a handle.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~WindowsProcessIdentityServiceTests|FullyQualifiedName~UpdateHealthServiceTests|FullyQualifiedName~LauncherRecoveryServiceTests"
```

- [ ] **Step 3: Implement health/recovery decisions**

The launcher service returns one of:

```csharp
public enum LauncherRecoveryAction
{
    ContinueNormalLaunch,
    CandidateLaunchHandled,
    ExistingCandidateStillRunning,
    OldVersionLaunchHandled,
    RecoveryBlocked
}
```

Before candidate launch, revalidate the installed manifest, every managed
payload hash/length, application/helper ProductVersion, and expected candidate
path. Any unexpected installed hash enters `RecoveryBlocked`.

The helper launches the candidate with only sanitized transaction GUID and
version arguments. The candidate health writer accepts them only when they
match the protected `AppliedAwaitingHealth` record and its own executable
path/ProductVersion.

No deadline kills a live process. Matching health commits, atomically clears the
active pointer, and permits backup cleanup. Early exit rolls back, records
`RolledBack`, clears the active pointer, and starts the old executable only in
the later user-initiated launch context.

Cleanup runs only for `Committed` or `RolledBack`, recomputes a validated GUID
child beneath the fixed protected root, refuses reparse ancestors, and never
deletes `RecoveryBlocked` evidence. At most one active protected transaction is
allowed; only `ProtectedStaged` may be superseded, while `CloseAuthorized` and
later phases are immutable to staging replacement.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.WindowsUpdate tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "feat: recover update health by process identity"
```

### Task 11: Add the self-contained updater command host

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/UpdaterCommandLine.cs`
- Create: `src/WireguardSplitTunnel.Updater/WireguardSplitTunnel.Updater.csproj`
- Create: `src/WireguardSplitTunnel.Updater/Program.cs`
- Modify: `WireguardSplitTunnel.sln`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/UpdaterCommandLineTests.cs`

- [ ] **Step 1: Write strict command-line tests**

Accept only:

```text
--mode apply-after-exit --transaction <protected-json>
--mode recover-and-launch --transaction <protected-json>
```

Reject duplicate/missing/unknown arguments, relative/UNC transaction paths, and
transaction paths outside the fixed protected root. Recompute the transaction
directory from the parsed record GUID and require it to equal the supplied
canonical protected record path.

Use fixed exit codes:

```csharp
public static class UpdaterExitCodes
{
    public const int Success = 0;
    public const int LaunchHandled = 10;
    public const int ExistingCandidate = 20;
    public const int RecoveryBlocked = 30;
    public const int InvalidArguments = 64;
    public const int Failed = 70;
}
```

- [ ] **Step 2: Run CLI tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~UpdaterCommandLineTests
```

- [ ] **Step 3: Add the updater project**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <Product>Wireguard Split Tunnel Updater</Product>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\WireguardSplitTunnel.WindowsUpdate\WireguardSplitTunnel.WindowsUpdate.csproj" />
  </ItemGroup>
</Project>
```

`Program.Main` parses, calls one service entrypoint, writes only sanitized
status, and maps typed results to the fixed exit codes.

For `apply-after-exit`, the protected record already contains PID, raw creation
FILETIME, and canonical image path. The helper must:

1. acquire the protected system mutex;
2. open and validate the live old-process handle;
3. write and flush exactly `READY <transaction-guid>` to redirected standard
   output;
4. wait on that handle for at most 60 seconds without terminating it;
5. begin no filesystem mutation until the handle signals;
6. on timeout/error, leave `CloseAuthorized` retryable and exit nonzero.

The WPF parent waits for that exact READY line before completing its second-pass
close. A later launcher recovery opens and validates a fresh handle; no handle
value is persisted.

- [ ] **Step 4: Add READY, mutex, and timeout tests**

Use `WireguardSplitTunnel.TestProcess` to prove READY is emitted only after the
handle is held, mutation begins only after process exit, PID/image/creation
mismatch is rejected, open-handle/helper-crash/READY-timeout paths preserve the
install, and the injectable 60-second boundary leaves `CloseAuthorized`
retryable. Prove close-time apply never launches either app version.

The protected mutex uses owner SYSTEM plus Administrators/SYSTEM-only access.
Test close-helper versus launcher recovery, two simultaneous launchers, and an
abandoned mutex. A loser returns a typed busy/existing-candidate result and
performs no journal or filesystem mutation.

- [ ] **Step 5: Add to solution and verify publish**

```powershell
dotnet sln .\WireguardSplitTunnel.sln add .\src\WireguardSplitTunnel.Updater\WireguardSplitTunnel.Updater.csproj
dotnet publish .\src\WireguardSplitTunnel.Updater\WireguardSplitTunnel.Updater.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Expected: `WireguardSplitTunnel.Updater.exe` is produced with the central
ProductVersion.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add WireguardSplitTunnel.sln src/WireguardSplitTunnel.Updater src/WireguardSplitTunnel.WindowsUpdate/UpdaterCommandLine.cs tests/WireguardSplitTunnel.WindowsUpdate.Tests/UpdaterCommandLineTests.cs
git commit -m "feat: add detached Windows updater host"
```

### Task 12: Orchestrate automatic/manual checks, staging, cancellation, and protected preparation

**Files:**
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Staging/WindowsUpdateStatus.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Staging/WindowsUpdateCoordinator.cs`
- Create: `src/WireguardSplitTunnel.WindowsUpdate/Logging/UpdaterFileLogger.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/WindowsUpdateCoordinatorTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/UpdaterFileLoggerTests.cs`

- [ ] **Step 1: Write scheduling/concurrency interleaving tests**

Inject release client, downloader, validator, local store, protected preparer,
`TimeProvider`, and delay boundary. Prove:

- one automatic attempt when due and timestamp persisted before network work;
- a monotonic 24-hour in-process timer schedules the next due attempt while the
  application remains open;
- failures, cancellation, and wall-clock changes do not create a tight retry;
- a timestamp over five minutes in the future becomes due once and is replaced;
- manual check bypasses due time and does not alter it;
- one semaphore excludes automatic/manual overlap;
- disabling cancels automatic work, deletes only `Automatic` LocalAppData
  staging, and deletes an `Automatic` protected `ProtectedStaged` transaction
  when elevated;
- a non-elevated disable records protected-removal-pending for the next elevated
  run;
- `Manual` staging survives disabled preference and remains authorizable;
- disabling never revokes `CloseAuthorized` or any later phase;
- disable racing with close cannot authorize an Automatic transaction;
- failure after persisted `false` remains fail-closed: automatic authorization
  stays disabled even when cleanup must be retried;
- a newer candidate may replace only an unapproved staged transaction, never an
  authorized/applying transaction;
- closing cancels/drains download before protected-stage inspection;
- a developer layout reports availability but never downloads/prepares;
- post-install self-test permits no check/preparation;
- status/logging contains no response body, full staging path, credential,
  browser/account data, or state content;
- updater logging is append-only and preserves every pre-existing log byte as
  an exact prefix.

- [ ] **Step 2: Run coordinator tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~WindowsUpdateCoordinatorTests
```

- [ ] **Step 3: Implement the public coordinator surface**

```csharp
public sealed class WindowsUpdateCoordinator
{
    public event EventHandler<WindowsUpdateStatus>? StatusChanged;
    public Task StartAsync(bool automaticEnabled, CancellationToken cancellationToken);
    public Task CheckNowAsync(CancellationToken cancellationToken);
    public Task SetAutomaticEnabledAsync(bool enabled, CancellationToken cancellationToken);
    public Task StopForCloseAsync(CancellationToken cancellationToken);
    public Task<UpdateCloseAuthorizationResult> TryAuthorizeAndLaunchAsync(
        UpdateCloseAuthorizationContext context,
        CancellationToken cancellationToken);
}
```

Production has no repository/URL override. Developer-build detection requires
the installed root manifest and launcher layout.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 5: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.WindowsUpdate/Staging src/WireguardSplitTunnel.WindowsUpdate/Logging tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "feat: coordinate background Windows updates"
```

### Task 13: Generate and validate Release packages and fix first bootstrap

**Files:**
- Create: `tools/WireguardSplitTunnel.ReleaseTool/WireguardSplitTunnel.ReleaseTool.csproj`
- Create: `tools/WireguardSplitTunnel.ReleaseTool/Program.cs`
- Create: `tools/WireguardSplitTunnel.ReleaseTool/ReleaseToolApplication.cs`
- Modify: `WireguardSplitTunnel.sln`
- Create: `scripts/WindowsRelease.psm1`
- Create: `scripts/lib/release-package.ps1`
- Create: `scripts/package-windows.ps1`
- Create: `scripts/new-release-manifest.ps1`
- Create: `scripts/validate-release-package.ps1`
- Modify: `scripts/install.ps1`
- Modify: `scripts/ensure-prebuilt.ps1`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ReleasePackageScriptTests.cs`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/InstallerBootstrapTests.cs`

- [ ] **Step 1: Write PowerShell process tests**

From xUnit, invoke Windows PowerShell against temporary layouts. Require:

- package assembly starts from a newly empty output directory and copies only
  the explicit root allowlist (`install.cmd`, `start.cmd`, `start-admin.cmd`,
  `start-safe.cmd`, `test.cmd`, `diagnose.cmd`, `fix-dns.cmd`,
  `reset-network.cmd`, `README.md`), the explicitly enumerated Windows runtime
  scripts they call, and clean App/Updater publish outputs—never source
  `bin/obj`, PDBs, test assemblies, state, logs, runtime markers, backups, or
  Mac/build/package-only scripts;
- deterministic manifest sorted by case-insensitive relative path;
- SHA-256/length for every payload, excluding manifest;
- exact version/RID/compatibility/entry/helper/launcher fields;
- validator failure for missing/extra/changed files or ProductVersion mismatch;
- SDK-present Release layout selects `BundledRelease`;
- source checkout selects `PublishSource`;
- `-SkipPublish` selects bundled executable;
- `-ForcePublish` is rejected when source project/props are absent;
- bootstrap uses the fixed repository, strict stable tag, exact ZIP/sidecar,
  exact sidecar grammar, the same redirect allowlist/count, bounded streaming,
  safe ZIP extraction, full manifest validation, and no production repo/URL
  override;
- a source checkout copies only the validated `WireguardSplitTunnel` subtree,
  never the root release manifest that marks a supported installed package;
- a ZIP and sidecar produced by the scripts are accepted end-to-end by the
  production `UpdatePackageValidator`, preventing producer/consumer drift;
- representative `v0.1.9` LocalAppData files remain untouched;
- the bundled installer binds the exact package before UAC, publishes managed
  files only to `%ProgramFiles%\WireguardSplitTunnel`, and executes packaged
  code only after that protected copy and its exact ACL validate;
- a valid bundle outside Program Files cannot auto-elevate or become an
  updater-capable installed root;
- inherited user PATH, caller-controlled elevated log paths, and predictable
  user-TEMP executables are never executed by the bundled installer;
- `-RepairBlockedUpdate` authenticates the fresh source, repairs and fully
  revalidates the protected transaction's exact installation root, records a
  resolution, and only then deactivates the active pointer while retaining the
  blocked transaction/journal/backups as evidence; without the explicit switch
  or with an invalid repair, `RecoveryBlocked` remains active.

- [ ] **Step 2: Run script tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter "FullyQualifiedName~ReleasePackageScriptTests|FullyQualifiedName~InstallerBootstrapTests"
```

- [ ] **Step 3: Implement the deterministic Release tool and package functions**

The cross-platform Release tool references Core and exposes strict commands:

```text
generate-manifest --package-root <path> --props <Directory.Build.props> --expected-tag <tag>
validate-package --package-root <path> --props <Directory.Build.props> --expected-tag <tag>
write-checksum --archive <path> --output <path>
```

It shares the Core manifest/path/version validator instead of duplicating that
contract in workflow YAML. Add the Release tool to the solution; the
deterministic test process was added in Task 6.

`scripts/lib/release-package.ps1` exports:

```powershell
Get-WgstInstallMode
New-WgstReleaseManifest
Test-WgstReleasePackage
Get-WgstSha256
```

`Get-WgstInstallMode` takes explicit booleans for manifest, bundled EXE, source
project, props, SDK, skip, and force. This keeps selection testable without
running installers/UAC.

- [ ] **Step 4: Fix installer and bootstrap downloader**

Add `[switch]$ForcePublish` and forward it through elevation. A valid bundled
Release wins over SDK detection. Publishing requires both source project and
`Directory.Build.props`.

For a bundled Release, bind the exact root and manifest identity in the
initially running script, elevate only a self-contained encoded/in-memory
bootstrap, revalidate the exact bytes after elevation, copy the manifest-managed
package into a protected staging sibling under Program Files, atomically
publish `%ProgramFiles%\WireguardSplitTunnel`, apply the exact installed-root
ACL, and execute only the protected installed script. Shortcuts target that
fixed root. No elevated code imports a module/script by the extracted source
pathname. Bundled mode selects before SDK/tool discovery and never executes an
inherited-PATH `dotnet`/`winget` or a user-TEMP prerequisite installer.

`ensure-prebuilt.ps1` remains a missing-local-executable bootstrap only.
`scripts/WindowsRelease.psm1` owns its fixed endpoint, manual redirect
validation, response/time/size limits, checksum binding, safe extraction, and
manifest/ProductVersion checks. Remove fuzzy ZIP/EXE selection and all runtime
repository/direct-URL overrides. In a source checkout copy only the validated
application publish subtree; do not copy the root manifest or make developer
output updater-capable. The new automatic updater never calls this script.

Add `[switch]$RepairBlockedUpdate` and forward it through the bound bootstrap.
It is an explicit manual recovery action, not normal install behavior. The
repair authenticates the fresh bundled Release, acquires the protected updater
authority, resolves the active record's canonical Program Files installation
root, restores its managed files while preserving unmanaged/user data, and
revalidates the resulting manifest, payload hashes, versions, root authority,
and exact ACLs before deactivating a `RecoveryBlocked` pointer. It writes a
protected repair-resolution record and preserves the transaction, journal, and
backups. Any mismatch/failure or a missing explicit switch leaves the pointer
active.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Use the Step 2 command.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add WireguardSplitTunnel.sln tools/WireguardSplitTunnel.ReleaseTool scripts/WindowsRelease.psm1 scripts/lib/release-package.ps1 scripts/package-windows.ps1 scripts/new-release-manifest.ps1 scripts/validate-release-package.ps1 scripts/install.ps1 scripts/ensure-prebuilt.ps1 tests/WireguardSplitTunnel.WindowsUpdate.Tests
git commit -m "fix: bootstrap validated bundled releases"
```

### Task 14: Integrate protected recovery into the launcher without weakening DryRun

**Files:**
- Create: `scripts/update-launcher.ps1`
- Modify: `scripts/start.ps1`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/LauncherScriptTests.cs`

- [ ] **Step 1: Write launcher process tests**

Temporary protected-state fixtures must prove:

- no transaction continues normal executable selection;
- `LocalStaged` cannot be read as authorization;
- `ProtectedStaged` continues current version;
- `CloseAuthorized` invokes only the helper path inside its protected
  transaction after elevation;
- apply/recovery phases invoke recover-and-launch;
- `RecoveryBlocked` exits nonzero and identifies repair log/guidance;
- helper `LaunchHandled`/`ExistingCandidate` stops a second launch;
- UAC cancellation changes no phase;
- `-DryRun` performs no mutation/process start and still reports selected EXE;
- `-PostInstallSelfTest` never invokes updater recovery.
- a valid bundled Release outside the exact protected Program Files root never
  requests UAC or invokes recovery;
- `start-admin.cmd`, DNS repair, and network reset cannot bypass that guard;
- elevated launchers discard caller-controlled log paths.

- [ ] **Step 2: Run launcher tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~LauncherScriptTests
```

- [ ] **Step 3: Add a narrow PowerShell recovery adapter**

`scripts/update-launcher.ps1` reads only the fixed protected
`active-transaction.json`, treats its GUID as the sole lookup key, recomputes the
transaction/helper paths, and revalidates the owner, ACL, canonical descendants,
helper hash, and helper ProductVersion immediately before process creation. It
then invokes:

```text
WireguardSplitTunnel.Updater.exe
--mode recover-and-launch
--transaction <protected-json>
```

It returns a typed PowerShell object containing `Handled`, `Blocked`,
`ExitCode`, and sanitized `Message`.

- [ ] **Step 4: Reorder start.ps1 safely**

Keep `DryRun` and post-install self-test free of recovery mutations. For a
normal run, acquire the existing launcher elevation, invoke protected recovery,
then continue existing candidate selection only when recovery returns
`ContinueNormalLaunch`. Candidate launch is handled by the helper and includes
only `--update-transaction <guid>` plus `--update-version <normalized-version>`;
ordinary/current-version launch receives neither argument.

Before any elevation, classify the current root. A bundled Release may elevate
and recover only from `%ProgramFiles%\WireguardSplitTunnel` after its protected
authority validates; an extracted bundle directs the user to `install.cmd`.
`-DryRun` remains available against the assembled Release fixture. Direct
`start-admin.cmd` enters this guarded non-elevated path instead of RunAs-opening
the mutable script itself. The packaged DNS/network repair entry points and the
App's direct executable auto-elevation enforce the same boundary.

- [ ] **Step 5: Run focused tests and launcher DryRun**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~LauncherScriptTests
.\scripts\start.ps1 -DryRun
```

Expected: tests pass and DryRun resolves the current matching executable.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add scripts/update-launcher.ps1 scripts/start.ps1 tests/WireguardSplitTunnel.WindowsUpdate.Tests/LauncherScriptTests.cs
git commit -m "feat: recover updates through protected launcher"
```

### Task 15: Replace WPF close handling with serialized, intent-aware authorization

**Files:**
- Create: `src/WireguardSplitTunnel.App/Services/WpfApplicationCloseActions.cs`
- Modify: `src/WireguardSplitTunnel.App/App.xaml.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/IncrementalDnsTimerIntegrationTests.cs`
- Create: `tests/WireguardSplitTunnel.Core.Tests/WindowsUpdateWiringContractTests.cs`

- [ ] **Step 1: Write failing WPF wiring contracts**

Require `App.OnSessionEnding` to mark intent before base handling. Require the
successful unelevated handoff to mark `ElevationHandoff` before `Shutdown()`.
Require sanitized argument logging that records booleans/context presence, not
raw arguments.

Require the close adapter to acquire:

```text
softwareApplySemaphore
then renewSemaphore
```

and release in reverse. Require queued software apply to recheck
`isWindowClosing` after acquiring its gate.

- [ ] **Step 2: Run focused Core lifecycle/wiring tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~ApplicationClose|FullyQualifiedName~WindowsUpdateWiringContractTests|FullyQualifiedName~IncrementalDnsTimerIntegrationTests"
```

- [ ] **Step 3: Make every close a two-pass async close**

First pass:

```text
e.Cancel = true
mark isWindowClosing
stop timers/network subscriptions and cancel CTS objects
resolve default normal intent without overriding special intent
await ApplicationCloseOrchestrator.RunOnceAsync
log typed outcome
set final-close flag
Close()
```

Second `Closing` event returns without repeating work.

Remove the early return when restore-on-exit is disabled. The restore step then
becomes a successful no-op, but state still saves before possible
authorization.

- [ ] **Step 4: Serialize route/software cleanup and save exactly once**

Move `stateStore.Save(state)` out of `RestoreNormalRoutingOnExitAsync`.
`WpfApplicationCloseActions` waits software gate, then runs route restore under
`DomainRouteOperationSerializer.RunAsync(renewSemaphore, RestoreNormalRoutingOnExitAsync)`, saves state
once, releases gates, and lets the Core orchestrator re-read close intent.

Helper launch or READY-handshake failure must not erase or downgrade an already
protected `CloseAuthorized` transaction. The final `Close()` occurs only after
the close participant returns READY success or a typed recoverable launch
failure; it never waits indefinitely.

- [ ] **Step 5: Run focused tests and Windows build**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~ApplicationClose|FullyQualifiedName~WindowsUpdateWiringContractTests|FullyQualifiedName~IncrementalDnsTimerIntegrationTests"
dotnet build .\src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj -c Release
```

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.App/App.xaml.cs src/WireguardSplitTunnel.App/MainWindow.xaml.cs src/WireguardSplitTunnel.App/Services/WpfApplicationCloseActions.cs tests/WireguardSplitTunnel.Core.Tests
git commit -m "fix: serialize close before update authorization"
```

### Task 16: Add WPF update composition, startup health, settings, status, and Check now

**Files:**
- Create: `src/WireguardSplitTunnel.App/Services/WindowsUpdateCompositionRoot.cs`
- Create: `src/WireguardSplitTunnel.App/MainWindow.Update.cs`
- Modify: `src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj`
- Modify: `src/WireguardSplitTunnel.App/App.xaml.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/WindowsUpdateWiringContractTests.cs`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/ApplicationUpdateStartupOrchestratorTests.cs`

- [ ] **Step 1: Write failing UI/startup contracts**

Parse XAML and require:

```xml
<CheckBox x:Name="AutoUpdateEnabledCheckBox"
          Content="Automatically update from GitHub Releases" />
<Button x:Name="CheckForUpdatesButton"
        Content="Check now" />
<TextBlock x:Name="UpdateStatusTextBlock"
           TextWrapping="Wrap" />
```

Startup tests require health after handled routing readiness and before
coordinator start. Handled startup-renew failure still qualifies; unrelated
initialization failure does not. Closing before readiness writes no health.
Post-install self-test suppresses health, checks, manual action, protected
preparation, and close authorization.

- [ ] **Step 2: Run focused tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~ApplicationUpdateStartupOrchestratorTests|FullyQualifiedName~WindowsUpdateWiringContractTests"
```

- [ ] **Step 3: Compose one production update runtime**

`WindowsUpdateCompositionRoot` creates the fixed GitHub client, installed-root
locator, local metadata store, validator, protected preparer, health service,
coordinator, and an append-only logger covered by prefix-preservation tests:

```text
%LOCALAPPDATA%\WireguardSplitTunnel\logs\updater.log
```

The App project references `WireguardSplitTunnel.WindowsUpdate`.

The production installed-root locator accepts updater capability only for the
exact `%ProgramFiles%\WireguardSplitTunnel` root with the expected protected
root/managed-file ACLs. A hash-valid extracted bundle is deliberately reported
as automatic-installation-unavailable.

- [ ] **Step 4: Wire preference and manual status behavior**

`LoadSettingsToUi` assigns `state.AutoUpdateEnabled`.

Checkbox flow:

```text
save new AppState atomically
call SetAutomaticEnabledAsync
on save failure restore old state/UI and do not change coordinator
on coordinator failure after persisted false, keep UI/state false and leave
  automatic authorization fail-closed while showing a retryable cleanup status
```

Manual Check calls `CheckNowAsync` without changing preference. Busy status
disables only Check now. The checkbox stays enabled so it can cancel automatic
download. Status events marshal through `Dispatcher`. Closing disables both
controls and unsubscribes.

- [ ] **Step 5: Put health/checks after routing readiness**

After:

```csharp
await AutoRenewDomainRoutesOnStartAsync();
```

invoke `ApplicationUpdateStartupOrchestrator`. Do not put health in an
unconditional outer `finally`. Pass the sanitized transaction ID/version launch
context from `App` without logging it. Reuse `VersionDisplay.FromAssembly` only
for display; strict version comes from assembly metadata through the update
policy.

- [ ] **Step 6: Run focused tests and build**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName~ApplicationUpdateStartupOrchestratorTests|FullyQualifiedName~WindowsUpdateWiringContractTests"
dotnet build .\src\WireguardSplitTunnel.App\WireguardSplitTunnel.App.csproj -c Release
```

- [ ] **Step 7: Proposed commit boundary**

```powershell
git add src/WireguardSplitTunnel.App tests/WireguardSplitTunnel.Core.Tests
git commit -m "feat: add Windows automatic update UI"
```

### Task 17: Harden the Release workflow and platform test matrix

**Files:**
- Modify: `.github/workflows/release-prebuilt.yml`
- Modify: `Directory.Build.props`
- Modify: `scripts/test.ps1`
- Create: `tests/WireguardSplitTunnel.WindowsUpdate.Tests/ReleaseWorkflowContractTests.cs`

- [ ] **Step 1: Write failing workflow/script contracts**

Require:

- root `permissions: contents: read`;
- Windows job runs non-Mac Core tests and Windows updater tests;
- macOS job runs Mac Core tests;
- tag equals `VersionPrefix`;
- version-controlled `MinimumAutoUpdateVersion`,
  `RollbackCompatibleFromVersion`, and `StateSchemaVersion` are strict, not
  greater than the release version, and feed manifest generation;
- an explicit test proves the expected prior updater-capable version remains
  eligible for the new Release;
- App and Updater publish self-contained `win-x64`;
- manifest generation and validation;
- Release-layout launcher DryRun;
- exact ZIP and `.sha256`;
- Windows/Mac artifact upload;
- one final publish job depending on both builds with `contents: write`;
- every action pinned to a 40-character SHA.

- [ ] **Step 2: Run workflow contract tests and confirm RED**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~ReleaseWorkflowContractTests
```

- [ ] **Step 3: Pin the verified action SHAs**

Use these read-only verified tag resolutions:

```yaml
actions/checkout: 11d5960a326750d5838078e36cf38b85af677262
actions/setup-dotnet: 67a3573c9a986a3f9c594539f4ab511d57bb3ce9
actions/upload-artifact: ea165f8d65b6e75b540449e92b4886f43607fa02
actions/download-artifact: d3f86a106a0bac45b974a628896c90dbdf5c8093
softprops/action-gh-release: 3bb12739c298aeb8a4eeaf626c5b8d85266b0e65
```

Keep readable comments such as `# v4` and `# v2`.

Before the final version bump, add the three compatibility properties to
`Directory.Build.props` at `0.1.9`, `0.1.9`, and schema `1` so Task 17 contracts
can turn green without prematurely changing `VersionPrefix`. Task 18 updates the
version and both floors to the initial updater-capable `0.2.0`. The workflow
allows equality only for that first bootstrap Release; later Releases must prove
a version at the effective compatibility floor is strictly older and selected
as eligible.

- [ ] **Step 4: Implement the gated workflow**

Windows job order:

```text
checkout
setup .NET
non-Mac Core tests
Windows updater tests
Release build
publish App and Updater into WireguardSplitTunnel
assemble package
generate/validate manifest from Directory.Build.props compatibility fields
feed the real ZIP/sidecar to production UpdatePackageValidator
run release-package scripts/start.ps1 -DryRun
ZIP
write "<lowercase sha>  wireguard-split-tunnel-win-x64.zip"
upload Windows artifact
```

macOS job runs Mac Core tests before package creation. The final publish job
downloads both artifacts, reruns exact-name/checksum/package validation, and
uploads them through one Release action. It cannot publish unless the
production-consumer validation test passed in the Windows job.

`scripts/test.ps1` detects host OS and applies the same platform filter rather
than making the 10 known Mac tests fail on Windows.

- [ ] **Step 5: Run contracts and local Windows matrix**

```powershell
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release --filter FullyQualifiedName~ReleaseWorkflowContractTests
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName!~Mac"
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release
```

Expected: every selected Windows test passes.

- [ ] **Step 6: Proposed commit boundary**

```powershell
git add .github/workflows/release-prebuilt.yml Directory.Build.props scripts/test.ps1 tests/WireguardSplitTunnel.WindowsUpdate.Tests/ReleaseWorkflowContractTests.cs
git commit -m "ci: gate and verify Windows update releases"
```

### Task 18: Bump v0.2.0, document rollout, and run final verification

**Files:**
- Modify: `Directory.Build.props`
- Modify: `tests/WireguardSplitTunnel.Core.Tests/ReleaseVersionMetadataTests.cs`
- Modify: `README.md`
- Verify: `docs/superpowers/specs/2026-07-29-windows-github-release-auto-update-design.md`
- Verify: `docs/superpowers/plans/2026-07-29-windows-github-release-auto-update.md`

- [ ] **Step 1: Write the failing release-version expectation**

Change the metadata test to require:

```csharp
ReadCentralVersion().Should().Be("0.2.0");
ReadMinimumAutoUpdateVersion().Should().Be("0.2.0");
ReadRollbackCompatibleFromVersion().Should().Be("0.2.0");
ReadStateSchemaVersion().Should().Be(1);
```

Run:

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter FullyQualifiedName~ReleaseVersionMetadataTests
```

Expected: failure because `Directory.Build.props` is still `0.1.9`.

- [ ] **Step 2: Set the central version and update README**

Set the independently version-controlled Release contract:

```xml
<VersionPrefix>0.2.0</VersionPrefix>
<MinimumAutoUpdateVersion>0.2.0</MinimumAutoUpdateVersion>
<RollbackCompatibleFromVersion>0.2.0</RollbackCompatibleFromVersion>
<StateSchemaVersion>1</StateSchemaVersion>
```

Future version bumps change compatibility floors only when a reviewed state or
updater boundary requires it; they are not automatically set to the new version.

README must explain:

- first updater-capable release requires one manual `install.cmd` bootstrap;
- future stable releases download in the background;
- installation occurs only after an eligible normal close;
- the application does not reopen automatically after close-time apply;
- preference, Check now, ready/error statuses, and 24-hour interval;
- `%LOCALAPPDATA%\WireguardSplitTunnel\logs\updater.log`;
- `RecoveryBlocked` manual repair using a freshly extracted verified Release and
  explicit `install.cmd -RepairBlockedUpdate`, with transaction evidence kept;
- checksum trust protects corruption/mix-ups but is not independent publisher
  signing; Authenticode remains a future hardening option;
- no Mac automatic updater;
- tag/release commands remain manual and require explicit authorization.

- [ ] **Step 3: Run focused and platform-correct automated verification**

```powershell
dotnet test .\tests\WireguardSplitTunnel.Core.Tests\WireguardSplitTunnel.Core.Tests.csproj -c Release --filter "FullyQualifiedName!~Mac"
dotnet test .\tests\WireguardSplitTunnel.WindowsUpdate.Tests\WireguardSplitTunnel.WindowsUpdate.Tests.csproj -c Release
dotnet build .\WireguardSplitTunnel.sln -c Release
```

Expected: all selected tests pass and the solution builds with zero errors.

- [ ] **Step 4: Assemble and validate a local Release fixture**

Publish both executables to a temporary package root, run:

```powershell
.\scripts\package-windows.ps1 -Tag v0.2.0 -OutputRoot <fixture-output>
dotnet run --project .\tools\WireguardSplitTunnel.ReleaseTool\WireguardSplitTunnel.ReleaseTool.csproj -- validate-package --package-root <fixture-output>\package --props .\Directory.Build.props --expected-tag v0.2.0
& <fixture-output>\package\scripts\start.ps1 -DryRun
```

Expected: manifest/package validation succeeds and DryRun selects the packaged
v0.2.0 application. Use an actual temporary path in execution; do not mutate a
live install.

- [ ] **Step 5: Run deterministic update/rollback smoke tests**

Use Windows integration fixtures to verify:

1. representative v0.1.9 state survives bundled manual bootstrap;
2. updater-capable N discovers/stages N+1;
3. crash/session-ending with staging does not authorize;
4. elevated normal close restores routes, saves, then authorizes;
5. close-time apply does not reopen;
6. next start commits healthy N+1;
7. corrupt package is rejected;
8. early candidate exit rolls back;
9. live unconfirmed candidate blocks a second launch;
10. unexpected recovery hash enters `RecoveryBlocked`;
11. explicit verified manual repair clears only the active pointer and preserves
    blocked transaction evidence;
12. `state.json`, applied/temp-list state, WireGuard configs/DPAPI material, and
    custom files remain byte-for-byte equal before candidate launch;
13. every existing log remains either equal or an exact byte prefix.

- [ ] **Step 6: Run local manual Windows security/lifecycle smoke**

With explicit approval before UAC or application shutdown:

- prove a standard user cannot modify the protected ProgramData transaction;
- cancel one real UAC prompt and verify install unchanged;
- verify `SessionEnding` suppression;
- verify helper READY/old-process handle behavior;
- verify post-install self-test performs no update work.

- [ ] **Step 7: Review the final diff and repository state**

```powershell
git status --short
git diff --check -- . ':!logs/*.log'
git diff --stat
```

Confirm only updater source/tests/scripts/workflow/docs/version files are in
scope. Keep existing runtime logs unstaged. Do not tag, publish, close/install,
commit, or push without the corresponding user authorization.

- [ ] **Step 8: Proposed final commit boundary**

```powershell
git add Directory.Build.props README.md WireguardSplitTunnel.sln src tests tools scripts .github/workflows/release-prebuilt.yml docs/superpowers/specs/2026-07-29-windows-github-release-auto-update-design.md docs/superpowers/plans/2026-07-29-windows-github-release-auto-update.md
git commit -m "feat: add secure Windows automatic updates"
```

Expected: one final commit only if the user asks for a squashed commit instead
of the task-level commit series. Never run both strategies.

### Final security-review amendments

The completed implementation and final verification must also cover these
review-driven requirements:

- prepare and validate the inactive protected workspace before an exact active
  pointer publication CAS;
- bind that CAS and every idempotent result to held pointer bytes plus file
  identity, reject pointer ABA, and keep the destination pinned through the
  POSIX-semantics rename;
- treat the pointer CAS as the cancellation commit point, then perform exactly
  two best-effort superseded cleanup attempts and surface
  `superseded_cleanup_pending` without reverting the committed pointer;
- linearize automatic disable with the real `CloseAuthorized` CAS by holding a
  shared commit lease after final record/path revalidation;
- reconcile UI busy state from a lock-linearized latest-status snapshot after
  settings-save generation handoffs;
- pin the protected Program Files parent, install root, and application through
  launch, with the child working directory fixed to the verified app folder;
- authorize privileged DNS mutation from only a canonical Base64 GUID, prove
  active WireGuard/Wintun provenance and stable interface index, write only the
  fixed DNS pair, verify ordered readback, and require cache-flush success;
- run packaged `start.ps1 -DryRun` under both supported PowerShell editions
  using only protected edition-matched module roots, with inherited module
  autoloading disabled.
