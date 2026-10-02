# Production Deployment Policy

This policy applies to production sing-box instances, including VM107 and VM115.

## Artifact source of truth

- The immutable GitHub Release (tag, commit/revision, asset and SHA-256) or an explicitly approved NAS release directory is the only persistent source for deployable binaries and rollback versions.
- Never retain an old sing-box executable on a VM as a rollback copy. This prohibition includes the application directory, `/tmp`, `/var/tmp`, `/dev/shm`, and staging directories. Do not create timestamped `.bak`, `.before-*`, or `.rollback-*` binaries on the VM.
- A temporary copy of the *new* artifact is allowed only during deployment and must be removed automatically on success, failure, or interruption.

## Replace procedure

1. Resolve the exact target, release tag, commit, architecture/libc, and expected SHA-256. Confirm the rollback artifact is still available from GitHub or the approved NAS; do not begin if it is not.
2. Read-only preflight: verify service health, current revision, configuration path, free bytes/inodes, and required temporary space. The target filesystem must have room for the complete new binary and a small safety margin before stopping the service. If not, stop and reclaim only explicitly identified stale binary backups or use an approved external staging source; never improvise by deleting configs, logs, or unrelated files.
3. Stage only the new binary on the target filesystem. Verify SHA-256, executable format, `sing-box version`, and `sing-box check` against the active runtime configuration before touching the running service.
4. Replace the executable with one same-filesystem atomic rename. Do not copy the old executable aside. Restart and verify service state, revision, listeners/API, and a representative proxy request.
5. On any failure, retrieve the previously recorded release directly from GitHub or the approved NAS, verify its SHA-256, and atomically restore it. Do not rely on a VM-local backup.
6. A cleanup trap must remove all temporary binaries and checksum/staging files on every exit path. After deployment, audit the VM and require exactly one production `sing-box` executable; remove pre-existing historical executable backups by exact path after confirming the current service is healthy.

## Evidence and completion

Record target, old/new revision, release tag, checksums, config-check result, restart result, API/listener checks, proxy smoke-test result, and cleanup audit. A deployment is not complete while a VM-local rollback binary or temporary artifact remains. Keep secrets, subscription URLs, and runtime configuration contents out of deployment logs.
