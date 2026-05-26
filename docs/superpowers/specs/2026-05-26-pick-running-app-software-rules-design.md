# Pick Running App for Software Rules Design

Date: 2026-05-26

## Goal

Adding a software rule should not require the user to manually find an executable path under `Program Files` or another install directory. The first version will let the user add software rules from currently running applications.

The user workflow should be:

1. Open the target application.
2. Open the Software Rules tab.
3. Click `Pick Running App`.
4. Search or select one or more running applications.
5. Click `Add Selected`.

The app will store both the process name and executable path, so the existing firewall policy apply flow can use the resolved path immediately.

## Current Context

The Windows app currently has a Software Rules tab with:

- `Add Software`, which opens an `.exe` file picker.
- `Toggle Enabled`.
- `Toggle Subprocess`.
- `Delete Selected`.
- `Apply Software`.
- `Software Self Test`.

The model already supports `SoftwareRule.ProcessName`, `SoftwareRule.IncludeSubprocesses`, and `SoftwareRule.ExecutablePath`. The apply flow already attempts to auto-resolve missing paths using `SystemSoftwareExecutableLocator`, then passes rules with valid existing paths into `SoftwareFirewallPolicyService`.

This feature should reuse that existing state model and mutation path. It should not change routing semantics.

## User Experience

Add a new `Pick Running App` button in the Software Rules tab near `Add Software`.

When clicked, the app opens a modal window that lists running processes that have a usable `.exe` path. Each row should show:

- Process name, for example `chrome.exe`.
- Full executable path, for example `C:\Program Files\Google\Chrome\Application\chrome.exe`.
- A checkbox or multi-select state.

The dialog should include a search box that filters by process name and path. Search is case-insensitive.

The dialog has:

- `Add Selected`.
- `Cancel`.
- A short status line such as `12 apps found`.

On `Add Selected`, the app tries to add one software rule per selected executable using:

- `ProcessName`: `Path.GetFileName(executablePath)`.
- `ExecutablePath`: the full executable path.
- `Mode`: `DomainRouteMode.UseWireGuard`.
- `IncludeSubprocesses`: `true`.

Duplicate process names are skipped using the existing duplicate behavior in `SoftwareRuleMutations.TryAddSoftwareRule`.

After adding, the dialog closes and the Software Rules grid refreshes. The app shows a summary message:

- Added count.
- Skipped duplicate count.
- Skipped invalid path count, if any.

The existing `Add Software` file picker remains available as a fallback for apps that are not currently running.

## Discovery Rules

The process discovery service should enumerate currently running processes and return only candidates where:

- `Process.ProcessName` is not empty.
- `Process.MainModule.FileName` can be read.
- The file name ends with `.exe`.
- The file exists on disk.

The service should ignore processes where Windows denies access to `MainModule`, where the path is empty, or where the executable no longer exists.

Candidates should be de-duplicated by executable path first, then ordered by process name and path. If multiple running process instances share the same executable path, show one row.

This means the first version intentionally hides processes without readable executable paths. That keeps the list useful and avoids adding rules that cannot be applied by Windows Firewall.

## Architecture

Add a small core service for process discovery:

- `RunningSoftwareCandidate`
  - `ProcessName`
  - `ExecutablePath`

- `IRunningSoftwareDiscovery`
  - `IReadOnlyList<RunningSoftwareCandidate> DiscoverRunningSoftware()`

- `SystemRunningSoftwareDiscovery`
  - Uses `Process.GetProcesses()`.
  - Safely reads `MainModule.FileName`.
  - Catches access-denied and process-exited errors per process.
  - Returns filtered, de-duplicated candidates.

The WPF app owns the dialog UI and calls the discovery service. This keeps Windows process enumeration testable in the core layer while keeping WPF-specific selection behavior in the app project.

The existing `SoftwareRuleMutations.TryAddSoftwareRule` remains the only write path for adding rules.

## UI Components

Add a new WPF dialog in `src/WireguardSplitTunnel.App`:

- `RunningSoftwarePickerWindow.xaml`
- `RunningSoftwarePickerWindow.xaml.cs`

The dialog should be simple and consistent with the existing WPF app style:

- Search box at the top.
- Data grid in the middle.
- Buttons at the bottom.
- No new external UI dependencies.

The main window should:

- Own one `IRunningSoftwareDiscovery` field.
- Wire `PickRunningAppButton.Click` to open the dialog.
- Add selected candidates through `SoftwareRuleMutations.TryAddSoftwareRule`.
- Save state and refresh the grid.

## Error Handling

If no candidates are found, the dialog should show an empty state message such as `No running apps with readable executable paths found.`

If discovery fails unexpectedly, the app should log the exception and show a message box. Per-process failures should not abort discovery.

If selected candidates become invalid before adding, skip them and report the skipped count.

If every selected candidate is skipped because it already exists, the app should say that nothing new was added.

## Testing

Add core tests for the discovery filtering and de-duplication logic where practical. Because `Process.GetProcesses()` is a system API, the testable part should be factored into a pure helper that accepts raw candidate values and returns normalized candidates.

Test coverage should include:

- Missing or empty paths are skipped.
- Non-`.exe` paths are skipped.
- Duplicate executable paths are collapsed.
- Candidate ordering is stable.
- Existing `SoftwareRuleMutations.TryAddSoftwareRule` behavior still stores executable paths and skips duplicate process names.

Verification commands:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

Manual check:

1. Start a known app such as Chrome or Codex.
2. Click `Pick Running App`.
3. Search for the app.
4. Add it.
5. Confirm the Software Rules grid shows the new process.
6. Click `Apply Software` as Administrator and confirm the rule applies.

## Non-Goals

This first version will not:

- Scan all installed apps.
- Parse Start Menu shortcuts.
- Add drag-and-drop support.
- Add icons to the picker.
- Add rules for Microsoft Store apps without readable `.exe` paths.
- Change firewall policy behavior or routing behavior.

Those can be added later if running-app selection is not enough.

## Decisions

The first implementation defaults `IncludeSubprocesses` to `true` and does not show the current y/n subprocess prompt before opening the picker. Users can still change subprocess behavior afterward with the existing `Toggle Subprocess` button.
