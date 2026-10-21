//! Path rules and safe path resolution.
//!
//! `check` decides from the string alone whether a path is allowed.
//! `open_parent` and `open_target` walk it from the allowed root one
//! component at a time with `O_NOFOLLOW`, so a symlink cannot redirect them.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};

use crate::{ALLOWED_ROOTS, EXIT_FS, EXIT_PATH, Fail, Result};

const MAX_PATH: usize = 4096;
const MAX_NAME: usize = 255;

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

/// Open the directory that holds the target. Every component below the
/// root must be a real directory, not a symlink.
pub fn open_parent(root: &str, rel: &[String]) -> Result<OwnedFd> {
    // The root is set by the admin at build time and is trusted.
    let mut dir = open(
        root,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| fs_error(&format!("cannot open allowed root {root}"), e))?;
    for c in &rel[..rel.len() - 1] {
        let fd = openat(
            &dir,
            c.as_str(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| fs_error(&format!("cannot open {c:?}"), e))?;
        let st = fstat(&fd).map_err(|e| fs_error(&format!("cannot stat {c:?}"), e))?;
        match kind(&st) {
            SFlag::S_IFDIR => dir = fd,
            SFlag::S_IFLNK => return Err(refused("path goes through a symlink")),
            _ => return Err(Fail::new(EXIT_FS, format!("{c:?} is not a directory"))),
        }
    }
    Ok(dir)
}

/// The opened target. `file` is opened read-only and used for every operation.
pub struct Target {
    pub file: File,
    pub is_dir: bool,
}

/// Open the last component in `parent`. It must be a directory or a regular
/// file with one link. Symlinks, devices, FIFOs and sockets are refused.
pub fn open_target(parent: &OwnedFd, name: &str) -> Result<Target> {
    let st = match fstatat(parent.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::ENOENT) => return Err(Fail::new(EXIT_FS, "path does not exist")),
        Err(e) => return Err(fs_error("cannot stat path", e)),
    };
    let flags = OFlag::O_RDONLY
        | OFlag::O_NOFOLLOW
        | OFlag::O_NONBLOCK
        | OFlag::O_NOCTTY
        | OFlag::O_CLOEXEC;
    let is_dir = match kind(&st) {
        SFlag::S_IFDIR => true,
        SFlag::S_IFREG => false,
        SFlag::S_IFLNK => return Err(refused("path is a symlink")),
        _ => return Err(refused("path is not a regular file or directory")),
    };
    let flags = if is_dir {
        flags | OFlag::O_DIRECTORY
    } else {
        flags
    };
    let fd = match openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ELOOP) => return Err(refused("path is a symlink")),
        Err(e) => return Err(fs_error("cannot open path", e)),
    };
    let st2 = fstat(&fd).map_err(|e| fs_error("cannot stat path", e))?;
    if st2.st_dev != st.st_dev || st2.st_ino != st.st_ino || kind(&st2) != kind(&st) {
        return Err(refused("path changed while it was opened"));
    }
    // A hard link could point to a file outside the allowed roots.
    if !is_dir && st2.st_nlink > 1 {
        return Err(refused("path is a file with more than one hard link"));
    }
    Ok(Target {
        file: File::from(fd),
        is_dir,
    })
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
        ] {
            assert_eq!(code(p), 3, "{p:?}");
        }
        assert_eq!(code(&format!("/storage/test/{}", "a".repeat(256))), 3);
        assert_eq!(code(&format!("/storage/test/{}", "a/".repeat(2100))), 3);
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
