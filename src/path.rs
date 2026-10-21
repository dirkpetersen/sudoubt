//! Path rules and safe path resolution.
//!
//! `check` decides from the string alone whether a path is allowed.
//! `open_parent` and `open_target` walk it from `/` one component at a time
//! with `O_NOFOLLOW`, so a symlink cannot redirect them. sudoubt works on
//! directories only.

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::OwnedFd;

use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat};

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

/// Open the directory that holds the target. Every component from `/` down,
/// including the allowed root itself, must be a real directory, not a symlink.
pub fn open_parent(root: &str, rel: &[String]) -> Result<OwnedFd> {
    let mut dir = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| fs_error("cannot open /", e))?;
    let root_comps = root[1..].split('/');
    let rel_comps = rel[..rel.len() - 1].iter().map(String::as_str);
    for c in root_comps.chain(rel_comps) {
        let fd = match openat(
            &dir,
            c,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Err(Fail::new(EXIT_FS, format!("{c:?} does not exist"))),
            Err(e) => return Err(fs_error(&format!("cannot open {c:?}"), e)),
        };
        let st = fstat(&fd).map_err(|e| fs_error(&format!("cannot stat {c:?}"), e))?;
        match kind(&st) {
            SFlag::S_IFDIR => dir = fd,
            SFlag::S_IFLNK => return Err(refused("path goes through a symlink")),
            _ => {
                return Err(refused(format!(
                    "path goes through {c:?}, which is not a directory"
                )));
            }
        }
    }
    Ok(dir)
}

/// Open the last component in `parent` as a directory, read-only, for every
/// operation. `O_DIRECTORY` makes the kernel refuse anything else before it
/// opens it, so devices and FIFOs are never opened, and `O_NOFOLLOW` refuses
/// a symlink.
pub fn open_target(parent: &OwnedFd, name: &str) -> Result<File> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let fd = match openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Err(Fail::new(EXIT_FS, "path does not exist")),
        Err(Errno::ELOOP) => return Err(refused("path is a symlink")),
        Err(Errno::ENOTDIR) => return Err(refused("path is not a directory")),
        Err(e) => return Err(fs_error("cannot open path", e)),
    };
    let st = fstat(&fd).map_err(|e| fs_error("cannot stat path", e))?;
    if kind(&st) != SFlag::S_IFDIR {
        return Err(refused("path is not a directory"));
    }
    Ok(File::from(fd))
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
