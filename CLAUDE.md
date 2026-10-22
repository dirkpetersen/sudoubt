# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

sudoubt is "sudo with trust issues": a tiny Rust helper that the ProjectVault web app calls through sudo, so the web app does not need to run as root. README.md is the design spec. Keep README.md and the code in step.

## Status

The crate is implemented. Modules: `request.rs` parses and checks the command line (no file system access except NSS name lookups), `path.rs` checks path strings and opens the target one component at a time, `acl.rs` parses setfacl text, `ops.rs` runs the operations on the opened file descriptor, `ratelimit.rs` holds the global rate limit, and `main.rs` holds the constants, exit codes, JSON output and syslog. Add dependencies with `cargo add` and commit `Cargo.lock`.

- Build: `cargo build` (release: `cargo build --release`)
- Test: `cargo test`; one test: `cargo test <name>`
- Lint: `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
- Root tests: `tests/root.rs` runs the real binary as root against `/storage/test` and `/run/sudoubt`. As a normal user each test returns early. They run in CI with `sudo -E env "PATH=$PATH" cargo test --locked --test root -- --test-threads=1`. Do not ask the owner for sudo; push to a branch and let CI run them.
- CI (`.github/workflows/ci.yml`) runs the tests, a release build and the root tests on x86_64 and arm64 for every push to any branch and every pull request.

The ACL crates link against libacl, so building needs its headers: `libacl1-dev` on Ubuntu (CI installs it), `libacl-devel` on RHEL.

README marks the command syntax and the JSON output format as "not final". You may change them, but update README.md in the same change.

## Hard rules (from README)

These are the security model. Do not weaken them without the owner's approval.

- Only these operations: mkdir, chown, chmod, setfacl, getfacl, setfattr, getfattr. Refuse everything else.
- Do the system calls in Rust (`nix`, `posix-acl`, `xattr`). Never run a shell or an external binary.
- Only absolute paths to directories. Refuse relative paths, `..`, an allowed root itself, any path outside the allowed roots, `.snap` components, paths that cross a mount point below the root, and anything that is not a directory (files, symlinks, devices).
- `ALLOWED_ROOTS` is a compiled-in constant, default `["/storage/test"]`. No config file, env var or CLI option may change it.
- Resolve paths from `/` one component at a time, so no symlink is ever followed: `openat` + `O_NOFOLLOW` down to the allowed root (each must be root-owned and not writable by others unless sticky), then `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS` below it. Run every operation on the one opened directory fd.
- One invocation = one path. It can have many operations, but each operation at most once (duplicate = exit 2). Validate all operations before running any (name lookups happen after the rate limit wait, but still before the first operation). Run them in fixed order: mkdir, chown, chmod, setfacl, setfattr, getfacl, getfattr. Stop at the first failure.
- Rate limit: `MAX_CALLS_PER_MINUTE` (default 1) and `MAX_WAITING` (default 25) are compiled-in constants, global for all callers. Only calls with a write operation count; read-only calls (getfacl, getfattr) skip the limit. State lives in `/run/sudoubt/` (root, `0700`), guarded by `flock`. When the limit is reached, print "please wait N seconds" to stderr, wait, then run. Each waiter holds a lock on one of `MAX_WAITING` slot files; no free slot = exit 8.
- mkdir creates only the last component (no `-p`) and succeeds if the directory already exists. setfacl accepts any ACL entry and replaces the ACL like `setfacl --set` (access entries replace the access ACL, `d:` entries the default ACL; a kind not given stays as is; `d:-` removes the default ACL).
- chmod: refuse setuid; allow setgid. chown: `user:group`, names or numeric IDs; look up names, then refuse UIDs and GIDs 1 to 999; allow 0. xattr: only `ALLOWED_XATTRS` = `ceph.quota.max_bytes`, `ceph.quota.max_files`; value must be a decimal integer >= 0; directories only.
- Move (archive into `.deleted`) is an open question. If added: only `renameat2` with `RENAME_NOREPLACE`, both paths inside the allowed roots, alone in its invocation. Never a delete operation.
- Two install modes: sudo (default) and setuid root (`4750`, group with only the web server user). The binary must be safe in both: ignore all env vars, set its own umask, check effective UID 0, reset inherited timers, resource limits and signal mask. Never trust env in setuid mode.
- sudoubt does not check the caller; the sudoers rule or the file mode does. Group management is out of scope (ProjectVault uses an API).
- Output: pretty JSON to stdout always (also on failure, with `ok`, `exit_code`, `error`); plain text to stderr. Log one syslog line per call (caller, path, operations, result). Caller is `SUDO_USER` in sudo mode, real UID in setuid mode.
- Exit codes: 0 success, 1 internal, 2 usage, 3 path refused, 4 operation refused, 5 file system error, 6 rate limit state error, 7 not root, 8 too many waiting. The table in README.md is the reference.
- Targets: Linux x86_64 and arm64, RHEL 10+ and Ubuntu 26.04+.
- Keep the tool small. Avoid dependencies beyond the ones above plus `serde`/`serde_json` for the JSON output.

## Release

Push a tag `vX.Y.Z` that matches the `Cargo.toml` version and points to a commit on `main` (only admins can create `v*` tags; a repository ruleset enforces it). `.github/workflows/release.yml` builds Linux x86_64 and arm64 on native runners and publishes the release. The build uses `--locked`, so commit `Cargo.lock`. Pin every action to a commit SHA. CI runs `cargo test --locked --release` on both architectures before it builds. The runners stay on `ubuntu-24.04` / `ubuntu-24.04-arm` (glibc 2.39) on purpose: a newer runner would link against a newer glibc than RHEL 10 has. `rust-toolchain.toml` pins the Rust version for local builds and both workflows (they run `rustup toolchain install`). To upgrade Rust, change it there and keep `rust-version` in `Cargo.toml` the same.

## Agent workflow

Opus implements. Fable reviews security. Reviewers only read and report; only the implementer edits code.

The Gemini review (`scripts/gemini-security-review.sh`) is paused. Do not run it until the owner turns it back on.

1. **Implement (Opus).** Make the change and its tests. Run `cargo build` and `cargo test` until they pass.
2. **Review.** Run the `fable-security-reviewer` subagent (`.claude/agents/fable-security-reviewer.md`). It uses `prompts/security-review.md`.
3. **Fix (Opus).** Fix every Critical and High finding. For Medium and Low, fix it or say why not. Before you fix a finding, check that it is real; reviewers can be wrong.
4. **Repeat** steps 2 and 3 until no Critical or High findings are left.
5. **Report** to the owner: what changed, what the reviewer found, what you fixed, and what you did not fix and why.

`reviews/` is in `.gitignore`. Do not commit review reports.
