//! Path rules and safe path resolution.
//!
//! `check` decides from the string alone whether a path is allowed.
//! `open_parent` and `open_target` walk it from `/` one component at a time,
//! so neither a symlink nor a mount point can redirect them. sudoubt works
//! on directories only.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::OwnedFd;

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat, openat2};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat};

use crate::{ALLOWED_ROOTS, EXIT_FS, EXIT_PATH, Fail, Result};

const MAX_PATH: usize = 4096;
const MAX_NAME: usize = 255;
/// The message when the target does not exist.
pub const NOT_FOUND: &str = "path does not exist";

fn refused(msg: impl Into<String>) -> Fail {
    Fail::new(EXIT_PATH, msg)
}

fn fs_error(what: &str, e: Errno) -> Fail {
    Fail::new(EXIT_FS, format!("{what}: {}", e.desc()))
}

/// Check the path string and return its allowed root and the components
/// below the root.
pub fn check(path: &OsStr) -> Result<(&'static str, Vec<String>)> {
    let Some(p) = path.to_str() else {
        return Err(refused("path is not valid UTF-8"));
    };
    if p.len() > MAX_PATH {
        return Err(refused("path is too long"));
    }
    if !p.starts_with('/') {
        return Err(refused("path is not absolute"));
    }
    if p.chars().any(char::is_control) {
        return Err(refused("path contains a control character"));
    }
    let comps: Vec<&str> = p[1..].split('/').collect();
    for c in &comps {
        if c.is_empty() {
            return Err(refused("path has an empty component (// or a trailing /)"));
        }
        if *c == "." || *c == ".." {
            return Err(refused("path contains . or .."));
        }
        // The CephFS snapshot directory: mkdir there creates a snapshot.
        if *c == ".snap" {
            return Err(refused("path contains .snap"));
        }
        if c.len() > MAX_NAME {
            return Err(refused("path component is too long"));
        }
    }
    for root in ALLOWED_ROOTS {
        let rc: Vec<&str> = root[1..].split('/').collect();
        if comps.len() >= rc.len() && comps[..rc.len()] == rc[..] {
            if comps.len() == rc.len() {
                return Err(refused("path is an allowed root"));
            }
            let rel = comps[rc.len()..].iter().map(|c| c.to_string()).collect();
            return Ok((root, rel));
        }
    }
    Err(refused("path is outside the allowed roots"))
}

/// The directory that holds the target, with its status, and the device of
/// the allowed root.
pub struct Parent {
    pub fd: OwnedFd,
    pub st: FileStat,
    pub dev: u64,
}

/// How components below the allowed root are opened: never through a
/// symlink, never across a mount point (refused during lookup, before
/// anything on the other file system is touched), never above `dirfd`.
fn below_root(flags: OFlag) -> OpenHow {
    OpenHow::new().flags(flags | OFlag::O_CLOEXEC).resolve(
        ResolveFlag::RESOLVE_BENEATH
            | ResolveFlag::RESOLVE_NO_SYMLINKS
            | ResolveFlag::RESOLVE_NO_XDEV
            | ResolveFlag::RESOLVE_NO_MAGICLINKS,
    )
}

/// Map an open error below the root to an exit code.
fn open_error(c: &str, e: Errno) -> Fail {
    match e {
        Errno::ENOENT => Fail::new(EXIT_FS, format!("{c:?} does not exist")),
        Errno::ELOOP => refused("path goes through or is a symlink"),
        Errno::EXDEV => refused("path crosses a mount point below the allowed root"),
        Errno::ENOTDIR => refused(format!("{c:?} is not a directory")),
        e => fs_error(&format!("cannot open {c:?}"), e),
    }
}

/// Open the directory that holds the target.
///
/// The allowed root and its ancestors are opened one component at a time
/// with `O_NOFOLLOW` from `/`; each must be a real directory owned by root
/// and not writable by others (unless sticky), so nobody but root can swap
/// the root. Components below the root are opened one at a time with
/// `openat2` and the flags in `below_root`. A component with the same inode
/// as its parent (a snapshot directory such as CephFS `.snap`) is refused.
pub fn open_parent(root: &str, rel: &[String]) -> Result<Parent> {
    let mut dir = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| fs_error("cannot open /", e))?;
    let mut st = fstat(&dir).map_err(|e| fs_error("cannot stat /", e))?;
    check_trusted("/", &st)?;
    for c in root[1..].split('/') {
        let fd = openat(
            &dir,
            c,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| fs_error(&format!("cannot open allowed root component {c:?}"), e))?;
        st = fstat(&fd).map_err(|e| fs_error(&format!("cannot stat {c:?}"), e))?;
        match kind(&st) {
            SFlag::S_IFDIR => {}
            SFlag::S_IFLNK => return Err(refused("the allowed root goes through a symlink")),
            _ => return Err(refused("the allowed root is not a directory")),
        }
        check_trusted(c, &st)?;
        dir = fd;
    }
    let dev = st.st_dev;
    for c in &rel[..rel.len() - 1] {
        let fd = openat2(
            &dir,
            c.as_str(),
            below_root(OFlag::O_PATH | OFlag::O_DIRECTORY),
        )
        .map_err(|e| open_error(c, e))?;
        let st2 = fstat(&fd).map_err(|e| fs_error(&format!("cannot stat {c:?}"), e))?;
        check_below(c, &st, &st2, dev)?;
        dir = fd;
        st = st2;
    }
    Ok(Parent { fd: dir, st, dev })
}

/// The allowed root and its ancestors: owned by root, not writable by group
/// or others unless the sticky bit is set.
fn check_trusted(c: &str, st: &FileStat) -> Result<()> {
    if st.st_uid != 0 || (st.st_mode & 0o022 != 0 && st.st_mode & 0o1000 == 0) {
        return Err(refused(format!(
            "allowed root component {c:?} must be owned by root and not writable by others"
        )));
    }
    Ok(())
}

/// A component below the root: a directory on the root's file system that
/// is not a snapshot view of its parent.
fn check_below(c: &str, parent: &FileStat, st: &FileStat, dev: u64) -> Result<()> {
    if kind(st) != SFlag::S_IFDIR {
        return Err(refused(format!("{c:?} is not a directory")));
    }
    if st.st_dev != dev {
        return Err(refused("path crosses a mount point below the allowed root"));
    }
    if st.st_ino == parent.st_ino {
        return Err(refused(format!("{c:?} is a snapshot directory")));
    }
    Ok(())
}

/// Open the last component in `parent` as a directory, read-only, for every
/// operation. `O_DIRECTORY` makes the kernel refuse anything else before it
/// opens it, so devices and FIFOs are never opened. Returns the directory
/// and its status.
pub fn open_target(parent: &Parent, name: &str) -> Result<(File, FileStat)> {
    let fd = openat2(
        &parent.fd,
        name,
        below_root(OFlag::O_RDONLY | OFlag::O_DIRECTORY),
    )
    .map_err(|e| match e {
        Errno::ENOENT => Fail::new(EXIT_FS, NOT_FOUND),
        Errno::ENOTDIR => refused("path is not a directory"),
        e => open_error(name, e),
    })?;
    let st = fstat(&fd).map_err(|e| fs_error("cannot stat path", e))?;
    check_below(name, &parent.st, &st, parent.dev)?;
    Ok((File::from(fd), st))
}

fn kind(st: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(st.st_mode & SFlag::S_IFMT.bits())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(p: &str) -> u8 {
        check(OsStr::new(p)).err().map_or(0, |f| f.code)
    }

    #[test]
    fn allowed() {
        let (root, rel) = check(OsStr::new("/storage/test/a/b")).unwrap();
        assert_eq!(root, "/storage/test");
        assert_eq!(rel, ["a", "b"]);
        assert_eq!(code("/storage/test/.deleted"), 0);
        assert_eq!(code("/storage/test/a b"), 0);
    }

    #[test]
    fn refused_paths() {
        for p in [
            "",
            "storage/test/a",
            "./a",
            "/storage/test",
            "/storage/test/",
            "/storage/test//a",
            "/storage/test/a/",
            "/storage/test/./a",
            "/storage/test/../test/a",
            "/storage/test/a/..",
            "/storage/testing/a",
            "/storage/tes/a",
            "/storage",
            "/",
            "/etc/shadow",
            "//storage/test/a",
            "/storage/test/a\nb",
            "/storage/test/a\0b",
            "/storage/test/p/.snap",
            "/storage/test/p/.snap/keep",
        ] {
            assert_eq!(code(p), 3, "{p:?}");
        }
        assert_eq!(code(&format!("/storage/test/{}", "a".repeat(256))), 3);
        assert_eq!(code(&format!("/storage/test/{}", "a/".repeat(2100))), 3);
    }

    #[test]
    fn roots_are_not_nested() {
        for a in ALLOWED_ROOTS {
            assert!(
                a.starts_with('/') && !a.ends_with('/') && a.len() > 1,
                "{a}"
            );
            for b in ALLOWED_ROOTS {
                assert!(
                    a == b || !b.starts_with(&format!("{a}/")),
                    "{a} contains {b}"
                );
            }
        }
    }

    #[test]
    fn non_utf8() {
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            check(OsStr::from_bytes(b"/storage/test/\xff"))
                .unwrap_err()
                .code,
            3
        );
    }
}
