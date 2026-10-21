//! Run the operations of a checked request in the fixed order:
//! mkdir, chown, chmod, setfacl, setfattr, getfacl, getfattr.

use std::os::fd::{AsFd, AsRawFd};

use nix::errno::Errno;
use nix::sys::stat::{Mode, fchmod, mkdirat};
use nix::unistd::fchown;
use posix_acl::{ACLError, PosixACL};
use serde_json::{Map, Value, json};
use xattr::FileExt;

use crate::acl::{build, to_text};
use crate::path::{open_parent, open_target};
use crate::request::Request;
use crate::{EXIT_FS, EXIT_OP, Fail, Result};

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
    let parent = open_parent(req.root, &req.rel)?;
    let name = req
        .rel
        .last()
        .expect("checked paths have components below the root")
        .as_str();

    if req.mkdir {
        let r = match mkdirat(&parent, name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => "created",
            Err(Errno::EEXIST) => "exists",
            Err(e) => return Err(fs_error("mkdir", e.desc())),
        };
        results.insert("mkdir".into(), json!(r));
    }

    let t = open_target(&parent, name)?;
    if req.mkdir && !t.is_dir {
        return Err(Fail::new(
            EXIT_FS,
            "mkdir failed: path exists but is not a directory",
        ));
    }
    if !t.is_dir {
        // With --mkdir the target is a directory, so these never fire after a mkdir.
        let refuse = |msg: &str| Err(Fail::new(EXIT_OP, msg));
        if req.chmod.as_ref().is_some_and(|(_, m)| m & 0o2000 != 0) {
            return refuse("setgid is allowed on directories only");
        }
        if req
            .setfacl
            .as_ref()
            .is_some_and(|(_, s)| !s.default.is_empty())
        {
            return refuse("a default ACL needs a directory");
        }
        if req.setfattr.is_some() || req.getfattr.is_some() {
            return refuse("extended attributes need a directory");
        }
    }
    // libacl works on paths. This magic link always resolves to the opened inode.
    let proc_path = format!("/proc/self/fd/{}", t.file.as_raw_fd());

    if let Some((text, uid, gid)) = &req.chown {
        fchown(t.file.as_fd(), Some(*uid), Some(*gid)).map_err(|e| fs_error("chown", e.desc()))?;
        results.insert("chown".into(), json!(text));
    }
    if let Some((text, mode)) = &req.chmod {
        fchmod(&t.file, Mode::from_bits_truncate(*mode))
            .map_err(|e| fs_error("chmod", e.desc()))?;
        results.insert("chmod".into(), json!(text));
    }
    if let Some((text, spec)) = &req.setfacl {
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
        results.insert("setfacl".into(), json!(text));
    }
    if let Some(list) = &req.setfattr {
        let mut done = Map::new();
        for (name, value) in list {
            t.file
                .set_xattr(name, value.to_string().as_bytes())
                .map_err(|e| fs_error("setfattr", e))?;
            done.insert(name.to_string(), json!(value.to_string()));
        }
        results.insert("setfattr".into(), Value::Object(done));
    }
    if req.getfacl {
        let access = PosixACL::read_acl(&proc_path).map_err(|e| acl_error("getfacl", e))?;
        let default = if t.is_dir {
            let d = PosixACL::read_default_acl(&proc_path).map_err(|e| acl_error("getfacl", e))?;
            Some(to_text(&d, "d:")).filter(|s| !s.is_empty())
        } else {
            None
        };
        results.insert(
            "getfacl".into(),
            json!({"access": to_text(&access, ""), "default": default}),
        );
    }
    if let Some(list) = &req.getfattr {
        let mut got = Map::new();
        for name in list {
            let v = t
                .file
                .get_xattr(name)
                .map_err(|e| fs_error("getfattr", e))?;
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
