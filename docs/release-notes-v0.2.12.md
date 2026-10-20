# v0.2.12

Fixes the first in-app update on installations without a protected update transaction directory.

- An absent update directory now means there is no pending transaction. Access denied, unsafe links and invalid permissions still stop the update.
- Protected staging now creates the same `UpdateTransactions` directory used by transaction validation and recovery.
- Native staging directory handles permit the updater's own writes while continuing to prevent directory rename and replacement.
- Atomic transaction writes now use native handle-relative rename and verify the retained file handle. Read handles are released at the protected commit boundary so journal and active-pointer replacements do not fail on Windows sharing restrictions.
- Mutation operations retain strict protected directory validation.

Existing 0.2.10 and 0.2.11 executables contain the old updater logic, including the failing close-authorization write. They cannot repair this through their own in-app update flow. Download the Windows ZIP from this Release, extract it, and run its `install.cmd` once. The installer verifies the package, saves settings during maintenance shutdown, upgrades the app and checks startup. It leaves the WireGuard tunnel service running.

Keep WireGuard connected. The installer uses maintenance shutdown, which skips exit route restoration; there is no need to change the **Restore normal routing when app exits** preference. Subsequent in-app updates from 0.2.12 use the corrected transaction implementation.

Regression coverage includes missing roots, unsafe existing directories, access errors, strict mutation rejection, canonical staging paths, atomic file writes and active-pointer replacement/deactivation. Release CI runs elevated native filesystem tests in isolated temporary directories and starts the updater in its isolated single-file layout. Native pointer/store integration uses simulated installed artifacts; it does not stand in for a full live upgrade.
