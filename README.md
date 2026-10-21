# sudoubt

sudo with trust issues. A tiny Rust helper that lets your web app create project folders and set owners, ACLs and Ceph quotas, and refuses everything else.

> **Status:** design stage. The crate is a placeholder that does nothing yet. This README describes the planned tool.

## Why

ProjectVault is a web app that lets researchers create and manage POSIX project folders. Today the app runs as root, because it must create folders, change owners and modes, and set ACLs.

A web server that runs as root is a large risk. If an attacker breaks into the web app, the attacker has full root access to the host.

sudoubt removes that risk. The web app runs as a normal user. When it needs a privileged operation, it calls sudoubt. sudoubt does only a small set of folder operations, only under a fixed list of allowed paths, and refuses all other requests.

## What it allows

| Operation | Like       | Type  |
| --------- | ---------- | ----- |
| mkdir     | `mkdir`    | write |
| chown     | `chown`    | write |
| chmod     | `chmod`    | write |
| setfacl   | `setfacl`  | write |
| setfattr  | `setfattr` | write |
| getfacl   | `getfacl`  | read  |
| getfattr  | `getfattr` | read  |

All other requests fail. Group management is not in sudoubt. ProjectVault does it through an API to another system.

## Supported systems

Linux only, on x86_64 and arm64. Supported distributions are RHEL 10 or newer and Ubuntu 26.04 or newer.

## Install

There are two install options. Both give the web server user, and only that user, a way to run sudoubt as root. The examples use `projectvault` as the web server user.

### Option 1: sudo (default)

Install the binary owned by root, and give the web server user one sudoers rule for it and nothing else:

```bash
sudo install -o root -g root -m 0755 sudoubt /usr/local/bin/sudoubt
```

```sudoers
# /etc/sudoers.d/projectvault
projectvault ALL=(root) NOPASSWD: /usr/local/bin/sudoubt
```

The web app calls `sudo /usr/local/bin/sudoubt ...`. sudo removes unsafe environment variables before sudoubt starts, and logs every call.

### Option 2: setuid root

Use this option if the host has no sudo, or if you do not want the web app to depend on it. Install the binary setuid root, with a group that only the web server user is a member of, and no access for other users:

```bash
sudo groupadd --system sudoubt
sudo usermod -aG sudoubt projectvault
sudo install -o root -g sudoubt -m 4750 sudoubt /usr/local/bin/sudoubt
```

Mode `4750` means: setuid root, group `sudoubt` can run it, all other users cannot. The web app calls `/usr/local/bin/sudoubt ...` without sudo.

Make sure that no other user is a member of the `sudoubt` group. Any member can run sudoubt as root.

In setuid mode there is no sudo to clean the environment, so sudoubt does it itself:

- It ignores all environment variables.
- It does not use the current directory (all paths are absolute).
- It sets its own umask.
- It checks that the effective UID is 0.

## Usage

### One invocation, one path, each operation once

One invocation works on exactly one path. It can contain more than one operation, but each operation can occur only once. This lets the web app set up a new folder in one call:

```bash
sudo sudoubt /storage/test/myproject-2026/all \
    --mkdir \
    --chown root:myproject-2026 \
    --chmod 2770 \
    --setfacl d:u::rwx,d:g::rwx,d:o::-
```

Read operations work the same way:

```bash
sudo sudoubt /storage/test/myproject-2026 --getfacl --getfattr ceph.quota.max_bytes
sudo sudoubt /storage/test/myproject-2026 --setfattr ceph.quota.max_bytes=10995116277760
```

Rules:

- The path must be absolute. sudoubt refuses relative paths.
- An operation that occurs two times in one invocation (for example `--chmod 770 --chmod 777`) is a usage error. sudoubt does nothing.
- sudoubt checks all operations before it does the first one. If one operation is not allowed, sudoubt does none of them.
- sudoubt always runs the operations in this fixed order, not in the order on the command line: mkdir, chown, chmod, setfacl, setfattr, getfacl, getfattr.
- If an operation fails, sudoubt stops and does not run the operations after it.
- `--mkdir` succeeds if the directory already exists. This makes it safe to repeat a call. It fails if the path exists but is not a directory, or is a symlink.
- `--setfacl` accepts any ACL entry.
- `--setfattr` and `--getfattr` work only on the Ceph quota attributes. See [Ceph quota](#ceph-quota).

The command syntax is not final.

### Output

sudoubt writes pretty-printed JSON to stdout, also when it fails. It writes plain-text messages (errors and "please wait") to stderr.

Success:

```json
{
  "ok": true,
  "path": "/storage/test/myproject-2026/all",
  "results": {
    "mkdir": "created",
    "chown": "root:myproject-2026",
    "chmod": "2770",
    "setfacl": "d:u::rwx,d:g::rwx,d:o::-"
  }
}
```

`mkdir` is `"created"` or `"exists"`. Read operations put their data in `results`, for example `"getfattr": {"ceph.quota.max_bytes": "10995116277760"}`.

Failure:

```json
{
  "ok": false,
  "path": "/etc/shadow",
  "exit_code": 3,
  "error": "path is outside the allowed roots"
}
```

The JSON format is not final.

## Ceph quota

The only extended attributes that sudoubt reads or writes are the CephFS quota attributes. The list is compiled into the binary:

```rust
const ALLOWED_XATTRS: &[&str] = &["ceph.quota.max_bytes", "ceph.quota.max_files"];
```

- The value must be a decimal integer, 0 or more. `0` removes the quota.
- The path must be a directory.
- sudoubt refuses all other attribute names (exit code 4), including `user.*`, `trusted.*` and `security.*`.
- On a file system that is not CephFS, the operation fails with exit code 5.

## Allowed paths

The list of allowed paths is compiled into the binary. There is no config file, no environment variable and no command line option that can change it. To change the list, edit the source and build again.

The default list has one entry:

```rust
const ALLOWED_ROOTS: &[&str] = &["/storage/test"];
```

sudoubt works only on paths inside one of these roots. It refuses:

- relative paths,
- paths with `..` components,
- paths outside all allowed roots,
- an allowed root itself (for example `/storage/test`), so the caller cannot change the owner or mode of the root,
- paths that go through a symlink (see below).

## Rate limit

To stop denial of service attacks, sudoubt limits how often it makes changes. The limits are compiled into the binary:

```rust
const MAX_CALLS_PER_MINUTE: u32 = 1;
const MAX_WAITING: u32 = 25;
```

- **Write calls.** A call with at least one write operation counts against the limit. The default is one write call per minute, for all callers together. A call with many operations counts as one call.
- **Read calls.** A call with only read operations (getfacl, getfattr) does not count and does not wait.
- **Waiting.** If the limit is reached, sudoubt does not fail. It prints this to stderr, waits, and then runs the operations:

  ```
  sudoubt: rate limit reached, please wait 42 seconds
  ```

- **Too many waiting.** If 25 calls are already waiting, a new write call fails at once with exit code 8. This stops an attacker from queuing a very large number of calls.

sudoubt keeps its state in `/run/sudoubt/`. This directory is on tmpfs, so the state resets at reboot. It is owned by root with mode `0700`, so the web app cannot read or change it. A file lock (`flock`) on the state file makes sure that two calls at the same time cannot both pass the check. Each waiting call holds a lock on one of 25 slot files. If a call stops or is killed, the kernel releases its lock, so a crashed call never keeps a slot.

## Logging

sudoubt writes one line to syslog (journald) for every call, also for refused calls. The line contains the caller, the path, the operations, and the result or exit code.

The caller is the `SUDO_USER` that sudo sets in sudo mode, and the real UID in setuid mode. In setuid mode, sudoubt never reads the caller from the environment, because the caller controls it.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0    | Success. All operations completed. |
| 1    | Internal error that does not fit another code. |
| 2    | Usage error: unknown option, missing value, or an operation that occurs more than once. |
| 3    | Path refused: not absolute, outside the allowed roots, contains `..`, is an allowed root, or goes through a symlink. |
| 4    | Operation refused: for example a setuid mode, a system UID or GID, or an xattr name that is not on the allowlist. |
| 5    | The operation failed on the file system: for example the path does not exist, the mkdir path is not a directory, or no ACL support. |
| 6    | Rate limit state error: sudoubt cannot open or lock its state files in `/run/sudoubt/`. |
| 7    | Not running as root (effective UID is not 0). |
| 8    | Too many waiting: 25 write calls already wait for the rate limit. |

For codes 2, 3, 4, 6, 7 and 8 sudoubt did nothing. For code 5, the operations before the failed one are complete.

## Security model

sudoubt assumes that the caller is hostile. The design must stop a compromised web app from using sudoubt to get root.

- **No shell, no external binaries.** sudoubt makes the system calls directly in Rust (`nix` for mkdir, chmod and chown, `posix-acl` or `exacl` for ACLs, `xattr` for extended attributes). It does not run `/bin/chown` or `setfacl`, so there is no argument injection and no `PATH` attack.
- **Compiled-in limits.** The allowed roots, the rate limits and the xattr allowlist are constants in the source. A caller cannot change them at run time.
- **No symlink tricks.** sudoubt opens each path component with `openat` and `O_NOFOLLOW`, starting from the allowed root. A symlink placed inside a project folder cannot redirect a chown or setfacl to a file outside the root, such as `/etc/shadow`.
- **Xattr allowlist.** sudoubt reads and writes only the two Ceph quota attributes, with integer values. It refuses all other names. This blocks `security.*` attributes, which hold SELinux labels and file capabilities, and `trusted.*` attributes, which only root can see.
- **No setuid bits.** chmod must not set setuid. A setuid binary inside a project folder would give root to any user. ProjectVault uses setgid on directories, so setgid on directories is allowed and setgid on files is refused.
- **Safe owners.** chown must refuse system UIDs and GIDs (1 to 999), so the caller cannot hand a file to a service account. Root (0) is allowed, because ProjectVault makes root the owner of project folders.
- **Caller check.** sudoubt does not check who the caller is. The sudoers rule (option 1) or the file mode and group (option 2) decide who can run it.
- **Clean start in setuid mode.** See [Option 2](#option-2-setuid-root).
- **Rate limit.** A compromised web app cannot flood the file system with changes or queue an unlimited number of calls.
- **Small code.** The tool must stay small enough to read in one sitting.

## Open question: move

ProjectVault archives a project by moving it into `.deleted`, and later deletes it. This needs root. It is not decided whether sudoubt will do this.

If sudoubt gets a move operation, the plan is:

- Only `mv`. No delete.
- No overwrite: sudoubt uses `renameat2` with `RENAME_NOREPLACE`, so the move fails if the target exists.
- The source and the target must both be inside the allowed roots, with the same path rules as above.
- A move needs two paths, so it does not fit the "one invocation, one path" rule. It would be an invocation with only the move in it.

## Build

Use the normal Cargo commands. The ACL support needs the libacl headers (`libacl1-dev` on Ubuntu, `libacl-devel` on RHEL).

```bash
cargo build --release
cargo test
```

## Release

To make a release, set the version in `Cargo.toml` (for example `0.0.1`), then push a matching tag:

```bash
git tag v0.0.1
git push origin v0.0.1
```

`.github/workflows/release.yml` then tests and builds on x86_64 and arm64 and publishes `sudoubt-0.0.1-linux-x86_64.tar.gz` and `sudoubt-0.0.1-linux-arm64.tar.gz`, each with a `.sha256` file. The build runs on Ubuntu 24.04 (glibc 2.39), so the binaries run on RHEL 10 and Ubuntu 26.04.

## License

MIT. See [LICENSE](LICENSE).
