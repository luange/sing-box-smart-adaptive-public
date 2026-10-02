# Packaging CI reliability audit — 2026-08-31

## Release naming policy

Package and release versions use SemVer only: `MAJOR.MINOR.PATCH` with an
optional prerelease `-alpha.N`, `-beta.N`, or `-rc.N`. Examples are `1.14.1`
and `1.14.0-rc.5`. Capability names such as `smart`, `ebpf`, or `v3.50` must
not be appended to a version. Capabilities remain build tags and release
notes. The `v` prefix is used only on Git tags (`v1.14.1`).

## Failure causes found

- The legacy Linux package workflow assumed an upstream release branch and
  failed on adaptive branches during track detection.
- Signing and Fury publication ran without fork-owned secrets.
- The upstream desktop version updater rejected a custom branch because its
  generated change was not committed.
- Historical gateway tags mixed product features into the version string.

## Durable changes

- `.github/validate-version.sh` rejects feature-suffixed versions before any
  build work starts.
- The gateway release workflow accepts SemVer tags and validates manual input;
  it derives one validated version for every matrix job.
- Legacy Linux packages are manual-only; signing and Fury upload are explicit
  opt-in inputs and fail clearly only when requested without secrets.
- The desktop updater runs only on the supported upstream release branches.
- Custom branches are classified as beta for package metadata without changing
  their version identity.

## Verification

- YAML parsing, shell syntax, and `git diff --check` pass locally.
- The full legacy Linux matrix (11 architectures) passed in GitHub Actions run
  `33363217502` with unsigned packages and Fury publication disabled.
- The dedicated gateway release matrix passed for the four target artifacts
  (amd64/arm64 × glibc/musl) in run `33363693963` using `1.14.1`; the release
  publication step was intentionally disabled for this validation run.
- The same matrix was then published as release `v1.14.1` by run
  `33364862337`; the release is non-draft and non-prerelease. The embedded
  binary revision and the tag both resolve to `eb9caf87`.
