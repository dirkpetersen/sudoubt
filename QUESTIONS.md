# Open questions

Decisions I made on my own while I built 0.0.1. Each one has a default in the code. Answer the ones you want changed. Answers are below each question; lines starting with → say what I did.

## Scope

1. **Files or only directories?** chown, chmod and setfacl (access ACL) also work on regular files. If ProjectVault only manages directories, allowing directories only would remove the hard-link and special-file cases completely. Should files be refused?
Directories only 
→ Done. Files, symlinks, devices, FIFOs and sockets are refused with exit 3. The hard-link check is gone, because directories cannot have hard links.
2. **Move into `.deleted`** is still not implemented (README "Open question: move"). Do you want it in a later version? 
Later
→ Not in 0.0.1.
3. **Removing a default ACL.** `--setfacl` replaces only the kinds of ACL it has entries for, so there is no way to remove a default ACL. Should there be one (for example `--setfacl d:-`)?
OK
→ Done: `--setfacl d:-` removes the default ACL. It can be combined with access entries (`u::rwx,g::rwx,o::-,d:-`) but not with other default entries. Tell me if "OK" meant "no need" and I will take it out.

## Behaviour

4. **The ACL mask is always recalculated.** The `posix-acl` crate recalculates the mask on every write, so a given `m::` entry is overwritten, and a mask entry is added even when the ACL has no named entries (the permissions are the same). `setfacl --set` keeps a given mask. Is that acceptable, or should sudoubt refuse `m::` entries so nobody is surprised?
Acceptable
5. **`--chown` needs both parts.** `user:group` is required; `user:` or `:group` is a usage error. Should one side be optional?
both required 
6. **Hard-linked files are refused** (exit 3), because a hard link could point to a file outside the allowed root on the same file system. If project folders legitimately contain hard-linked files, those cannot be changed with sudoubt.
ok
7. **A refused write call still counts against the rate limit** if it is refused after the wait (for example, the path turns out to be a symlink). Validation that needs the file system runs after the wait, so the result reflects the file system at the time of the change.
yes
8. **JSON key order is alphabetical** (`error`, `exit_code`, `ok`, `path`, `results`), because keeping the README order would add the `indexmap` dependency. The README now says not to depend on the order.
ok
9. **Unset quota attributes** are returned as `null` by `--getfattr`.
ok

## Operations

10. **Syslog** uses facility `authpriv` and level `notice`. Is that what your log collection expects?
ok
11. **The allowed root itself is trusted.** sudoubt opens `/storage/test` normally (following symlinks in `/storage`), and does not check who owns it. Components below the root are never followed. The root and its parents must be owned by root and not writable by others.
Following some links is not allowed Need to only look at the real folder 
→ Done. sudoubt now walks from `/` with `O_NOFOLLOW` on every component, including `/storage` and `/storage/test`. If any of them is a symlink, the call fails with exit 3.

