//! Run the operations of a checked request in the fixed order:
//! mkdir, chown, chmod, setfacl, setfattr, getfacl, getfattr.

use std::os::fd::{AsFd, AsRawFd};

use nix::errno::Errno;
use nix::sys::stat::{Mode, fchmod, mkdirat};
use nix::unistd::{Gid, Uid, fchown};
use posix_acl::{ACLError, PosixACL};
use serde_json::{Map, Value, json};
use xattr::FileExt;

use crate::acl::{build, resolve, to_text};
use crate::path::{open_parent, open_target};
use crate::request::{Request, check_owner_id, resolve_group, resolve_user};
use crate::{EXIT_FS, Fail, Result};

/// The kernel's name for the default ACL. Used only to remove it.
const DEFAULT_ACL_XATTR: &str = "system.posix_acl_default";

fn fs_error(op: &str, e: impl std::fmt::Display) -> Fail {
    Fail::new(EXIT_FS, format!("{op} failed: {e}"))
}

fn acl_error(op: &str, e: ACLError) -> Fail {
    match e.as_io_error() {
        Some(io) => fs_error(op, io),
        None => fs_error(op, e),
    }
}

pub fn run(req: &Request, results: &mut Map<String, Value>) -> Result<()> {
    // Look up names first. This is still checking: nothing has been done yet.
    let owner = match &req.chown {
        Some((text, u, g)) => {
            let uid = check_owner_id("user", resolve_user(u)?)?;
            let gid = check_owner_id("group", resolve_group(g)?)?;
            Some((text, Uid::from_raw(uid), Gid::from_raw(gid)))
        }
        None => None,
    };
    let acl = match &req.setfacl {
        Some((text, spec)) => Some((text, resolve(spec)?)),
        None => None,
    };

    let parent = open_parent(req.root, &req.rel)?;
    let name = req
        .rel
        .last()
        .expect("checked paths have components below the root")
        .as_str();

    let mkdir = if req.mkdir {
        match mkdirat(&parent, name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => Some("created"),
            Err(Errno::EEXIST) => Some("exists"),
            Err(e) => return Err(fs_error("mkdir", e.desc())),
        }
    } else {
        None
    };
    let dir = open_target(&parent, name)?;
    if let Some(r) = mkdir {
        results.insert("mkdir".into(), json!(r));
    }
    // libacl works on paths. This magic link always resolves to the opened directory.
    let proc_path = format!("/proc/self/fd/{}", dir.as_raw_fd());

    if let Some((text, uid, gid)) = owner {
        fchown(dir.as_fd(), Some(uid), Some(gid)).map_err(|e| fs_error("chown", e.desc()))?;
        results.insert("chown".into(), json!(text));
    }
    if let Some((text, mode)) = &req.chmod {
        fchmod(&dir, Mode::from_bits_truncate(*mode)).map_err(|e| fs_error("chmod", e.desc()))?;
        results.insert("chmod".into(), json!(text));
    }
    if let Some((text, spec)) = acl {
        if !spec.access.is_empty() {
            build(&spec.access)
                .write_acl(&proc_path)
                .map_err(|e| acl_error("setfacl", e))?;
        }
        if !spec.default.is_empty() {
            build(&spec.default)
                .write_default_acl(&proc_path)
                .map_err(|e| acl_error("setfacl", e))?;
        }
        if spec.remove_default {
            match dir.remove_xattr(DEFAULT_ACL_XATTR) {
                Err(e) if e.raw_os_error() != Some(libc::ENODATA) => {
                    return Err(fs_error("setfacl", e));
                }
                _ => {}
            }
        }
        results.insert("setfacl".into(), json!(text));
    }
    if let Some(list) = &req.setfattr {
        let mut done = Map::new();
        for (name, value) in list {
            dir.set_xattr(name, value.to_string().as_bytes())
                .map_err(|e| fs_error("setfattr", e))?;
            done.insert(name.to_string(), json!(value.to_string()));
        }
        results.insert("setfattr".into(), Value::Object(done));
    }
    if req.getfacl {
        let access = PosixACL::read_acl(&proc_path).map_err(|e| acl_error("getfacl", e))?;
        let default =
            PosixACL::read_default_acl(&proc_path).map_err(|e| acl_error("getfacl", e))?;
        let default = Some(to_text(&default, "d:")).filter(|s| !s.is_empty());
        results.insert(
            "getfacl".into(),
            json!({"access": to_text(&access, ""), "default": default}),
        );
    }
    if let Some(list) = &req.getfattr {
        let mut got = Map::new();
        for name in list {
            let v = dir.get_xattr(name).map_err(|e| fs_error("getfattr", e))?;
            let v = v.map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_end_matches('\0')
                    .to_string()
            });
            got.insert(name.to_string(), json!(v));
        }
        results.insert("getfattr".into(), Value::Object(got));
    }
    Ok(())
}
