# Protected first update repair

User-authorized objective: restore the installed 0.2.10 application's update, preserving settings and the running WireGuard tunnel. The user subsequently approved moving directly to corrected 0.2.12 because published 0.2.11 contains the same updater defects. Do not rewrite published releases or relax protected directory ACLs.

## Evidence

The live updater log reports `protected_active`. The ProgramData product/update roots are absent. `ReadActiveSnapshot` requires existing protected roots before it can report no transaction. Native preparation also requests `transactions` while the canonical layout requires `UpdateTransactions`.

## Tasks

1. Add failing behavioral regressions for absent roots, unsafe existing roots and canonical native preparation. Fix absence detection without treating access denied, invalid ACLs or reparse points as absence. Keep mutating transaction paths strict and mutex protected. Use the canonical path constant for preparation.
2. Trace existing 0.2.10's close authorization and route semantics. Native tests identified additional rename and file-sharing defects embedded in old releases, including the close-authorization write. A staging-only bridge cannot repair that code and is excluded. Use the authenticated 0.2.12 Release installer once, with maintenance shutdown and startup verification; do not restart WireGuard.
3. Review specification and security/correctness, run focused and complete updater tests and Release build. Test native filesystem behavior in a temporary protected test location; distinguish simulated tests from live application evidence.
4. After successful tests, merge/push and publish 0.2.12 as authorized. Download and verify the official package, apply the one-time installer repair with elevation, and verify actual app update status/version, saved settings and unchanged VPN service identity. Explain that the old executable cannot update itself through this defect.

Commit/push only scoped source and regression evidence after successful verification. Preserve unrelated user logs, configurations and worktrees.

## Native findings and safeguards

- Directory handles share read/write without delete; new directory handles do not unnecessarily request DELETE. Cleanup releases only its exact target pin, retains ancestors and verifies identity before deletion.
- `SetFileInformationByHandle(FileRenameInfoEx)` returned Windows error 87 for the handle-relative rename. Use `NtSetInformationFile(FileRenameInformationEx = 65)` with normal access checks, pinned directory, bounded leaf name and durable directory flush.
- Verify the renamed file through its retained handle, including final path, identity, ACL and bytes. Reopening while the write/delete handle remains open caused a sharing conflict.
- CAS releases only destination readers after final validation. Protected parent ACLs exclude unprivileged writers; the update mutex serializes authorized writers. The documented threat model excludes already-elevated attackers.
- Active-pointer replacement/deactivation releases the store's additional read snapshot before the identity-and-bytes CAS. Native pointer integration tests use real Windows file operations with simulated installed artifacts; they are not full live upgrade evidence.
