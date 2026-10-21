//! Parse and check the command line. Nothing here touches the file system or
//! looks up names; names are resolved later, after the rate limit.

use std::ffi::OsString;

use nix::unistd::{Group, User};

use crate::acl::AclText;
use crate::{ALLOWED_XATTRS, EXIT_OP, EXIT_USAGE, Fail, Result, path};

/// A user or group as given: a numeric ID or a name to look up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Id {
    Num(u32),
    Name(String),
}

/// One checked invocation: one path and each operation at most once.
#[derive(Debug, Default)]
pub struct Request {
    pub root: &'static str,
    /// Path components below the root. Never empty.
    pub rel: Vec<String>,
    pub mkdir: bool,
    pub chown: Option<(String, Id, Id)>,
    pub chmod: Option<(String, u32)>,
    pub setfacl: Option<(String, AclText)>,
    pub setfattr: Option<Vec<(&'static str, u64)>>,
    pub getfacl: bool,
    pub getfattr: Option<Vec<&'static str>>,
}

impl Request {
    /// True if the call changes anything. Only these count for the rate limit.
    pub fn has_write(&self) -> bool {
        self.mkdir
            || self.chown.is_some()
            || self.chmod.is_some()
            || self.setfacl.is_some()
            || self.setfattr.is_some()
    }
}

fn usage(msg: impl Into<String>) -> Fail {
    Fail::new(EXIT_USAGE, msg)
}

fn refused(msg: impl Into<String>) -> Fail {
    Fail::new(EXIT_OP, msg)
}

/// Parse `<path> --op [value] ...`. Usage errors (exit 2) come before path
/// errors (exit 3), which come before refused values (exit 4).
pub fn parse(args: &[OsString]) -> Result<Request> {
    let Some((path_arg, rest)) = args.split_first() else {
        return Err(usage("usage: sudoubt <path> --op [value] ..."));
    };
    if path_arg.to_string_lossy().starts_with("--") {
        return Err(usage("the first argument must be the path"));
    }

    // First pass: option names and raw values only.
    let mut seen: Vec<&str> = Vec::new();
    let mut raw: Vec<(&str, Option<String>)> = Vec::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let Some(arg) = arg.to_str() else {
            return Err(usage("arguments must be valid UTF-8"));
        };
        let (name, takes_value) = match arg {
            "--mkdir" => ("mkdir", false),
            "--getfacl" => ("getfacl", false),
            "--chown" => ("chown", true),
            "--chmod" => ("chmod", true),
            "--setfacl" => ("setfacl", true),
            "--setfattr" => ("setfattr", true),
            "--getfattr" => ("getfattr", true),
            _ => return Err(usage(format!("unknown argument {arg:?}"))),
        };
        if seen.contains(&name) {
            return Err(usage(format!("--{name} occurs more than once")));
        }
        seen.push(name);
        let value = if takes_value {
            let Some(v) = it.next() else {
                return Err(usage(format!("--{name} needs a value")));
            };
            let Some(v) = v.to_str() else {
                return Err(usage("arguments must be valid UTF-8"));
            };
            Some(v.to_string())
        } else {
            None
        };
        raw.push((name, value));
    }
    if raw.is_empty() {
        return Err(usage("no operation given"));
    }

    let (root, rel) = path::check(path_arg)?;
    let mut req = Request {
        root,
        rel,
        ..Request::default()
    };
    for (name, value) in raw {
        let v = value.unwrap_or_default();
        match name {
            "mkdir" => req.mkdir = true,
            "getfacl" => req.getfacl = true,
            "chown" => req.chown = Some(parse_chown(&v)?),
            "chmod" => req.chmod = Some((v.clone(), parse_chmod(&v)?)),
            "setfacl" => req.setfacl = Some((v.clone(), crate::acl::parse(&v)?)),
            "setfattr" => req.setfattr = Some(parse_setfattr(&v)?),
            "getfattr" => req.getfattr = Some(parse_getfattr(&v)?),
            _ => unreachable!("option names are checked above"),
        }
    }
    Ok(req)
}

/// `NNN` or `NNNN` in octal. Setuid is refused. Setgid is allowed, because
/// sudoubt works on directories only.
pub fn parse_chmod(v: &str) -> Result<u32> {
    if !(3..=4).contains(&v.len()) || !v.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(usage(format!(
            "--chmod needs 3 or 4 octal digits, not {v:?}"
        )));
    }
    let mode = u32::from_str_radix(v, 8).map_err(|_| usage("bad mode"))?;
    if mode & 0o4000 != 0 {
        return Err(refused("setuid mode is not allowed"));
    }
    Ok(mode)
}

/// `user:group`, each a name or a numeric ID. Numeric IDs are checked here,
/// names after they are looked up.
fn parse_chown(v: &str) -> Result<(String, Id, Id)> {
    let Some((u, g)) = v.split_once(':') else {
        return Err(usage(format!("--chown needs user:group, not {v:?}")));
    };
    if u.is_empty() || g.is_empty() || g.contains(':') {
        return Err(usage(format!("--chown needs user:group, not {v:?}")));
    }
    let user = parse_id(u)?;
    let group = parse_id(g)?;
    if let Id::Num(n) = user {
        check_owner_id("user", n)?;
    }
    if let Id::Num(n) = group {
        check_owner_id("group", n)?;
    }
    Ok((v.to_string(), user, group))
}

/// Refuse system IDs (1 to 999) and -1, which chown reads as "do not change".
pub fn check_owner_id(kind: &str, id: u32) -> Result<u32> {
    if (1..=999).contains(&id) {
        return Err(refused(format!(
            "{kind} ID {id} is a system account (1 to 999)"
        )));
    }
    if id == u32::MAX {
        return Err(refused(format!("{kind} ID {id} is not allowed")));
    }
    Ok(id)
}

/// A decimal number if all digits, else a name.
pub fn parse_id(s: &str) -> Result<Id> {
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let n = s
            .parse::<u32>()
            .map_err(|_| usage(format!("ID {s:?} is too large")))?;
        Ok(Id::Num(n))
    } else {
        Ok(Id::Name(s.to_string()))
    }
}

/// Look up a user name through NSS. Numeric IDs pass through.
pub fn resolve_user(id: &Id) -> Result<u32> {
    match id {
        Id::Num(n) => Ok(*n),
        Id::Name(s) => match User::from_name(s) {
            Ok(Some(u)) => Ok(u.uid.as_raw()),
            Ok(None) => Err(refused(format!("unknown user {s:?}"))),
            Err(e) => Err(refused(format!("cannot look up user {s:?}: {e}"))),
        },
    }
}

/// Look up a group name through NSS. Numeric IDs pass through.
pub fn resolve_group(id: &Id) -> Result<u32> {
    match id {
        Id::Num(n) => Ok(*n),
        Id::Name(s) => match Group::from_name(s) {
            Ok(Some(g)) => Ok(g.gid.as_raw()),
            Ok(None) => Err(refused(format!("unknown group {s:?}"))),
            Err(e) => Err(refused(format!("cannot look up group {s:?}: {e}"))),
        },
    }
}

fn xattr_name(name: &str) -> Result<&'static str> {
    ALLOWED_XATTRS
        .iter()
        .find(|a| **a == name)
        .copied()
        .ok_or_else(|| refused(format!("extended attribute {name:?} is not allowed")))
}

/// `name=value[,name=value]`. Names from ALLOWED_XATTRS, values decimal integers >= 0.
pub fn parse_setfattr(v: &str) -> Result<Vec<(&'static str, u64)>> {
    let mut out: Vec<(&'static str, u64)> = Vec::new();
    for item in v.split(',') {
        let Some((name, value)) = item.split_once('=') else {
            return Err(usage(format!("--setfattr needs name=value, not {item:?}")));
        };
        let name = xattr_name(name)?;
        if out.iter().any(|(n, _)| *n == name) {
            return Err(usage(format!("{name} occurs more than once")));
        }
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refused(format!(
                "{name} must be a decimal integer >= 0, not {value:?}"
            )));
        }
        let n = value
            .parse::<u64>()
            .map_err(|_| refused(format!("{name} value is too large")))?;
        out.push((name, n));
    }
    Ok(out)
}

/// `name[,name]`. Names from ALLOWED_XATTRS.
pub fn parse_getfattr(v: &str) -> Result<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    for name in v.split(',') {
        let name = xattr_name(name)?;
        if out.contains(&name) {
            return Err(usage(format!("{name} occurs more than once")));
        }
        out.push(name);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    fn code(a: &[&str]) -> u8 {
        parse(&args(a)).err().map_or(0, |f| f.code)
    }

    #[test]
    fn usage_errors() {
        assert_eq!(code(&[]), 2);
        assert_eq!(code(&["/storage/test/p"]), 2);
        assert_eq!(code(&["--mkdir", "/storage/test/p"]), 2);
        assert_eq!(code(&["/storage/test/p", "--mkdir", "--mkdir"]), 2);
        assert_eq!(
            code(&["/storage/test/p", "--chmod", "770", "--chmod", "777"]),
            2
        );
        assert_eq!(code(&["/storage/test/p", "--chmod"]), 2);
        assert_eq!(code(&["/storage/test/p", "--rm"]), 2);
        assert_eq!(code(&["/storage/test/p", "--mkdir", "extra"]), 2);
        assert_eq!(code(&["/storage/test/p", "--chmod=770"]), 2);
        // usage errors win over path errors
        assert_eq!(code(&["relative", "--bogus"]), 2);
    }

    #[test]
    fn path_errors() {
        assert_eq!(code(&["relative", "--mkdir"]), 3);
        assert_eq!(code(&["/etc/shadow", "--getfacl"]), 3);
    }

    #[test]
    fn full_request() {
        let r = parse(&args(&[
            "/storage/test/p/all",
            "--setfacl",
            "d:u::rwx,d:g::rwx,d:o::-",
            "--chmod",
            "2770",
            "--chown",
            "root:5000",
            "--mkdir",
        ]))
        .unwrap();
        assert!(r.mkdir && r.has_write());
        assert_eq!(r.rel, ["p", "all"]);
        assert_eq!(r.chmod.unwrap().1, 0o2770);
        let (_, u, g) = r.chown.unwrap();
        assert_eq!((u, g), (Id::Name("root".into()), Id::Num(5000)));
    }

    #[test]
    fn read_only_is_not_write() {
        let r = parse(&args(&[
            "/storage/test/p",
            "--getfacl",
            "--getfattr",
            "ceph.quota.max_bytes",
        ]))
        .unwrap();
        assert!(!r.has_write());
    }

    #[test]
    fn chmod() {
        assert_eq!(parse_chmod("770").unwrap(), 0o770);
        assert_eq!(parse_chmod("2770").unwrap(), 0o2770);
        assert_eq!(parse_chmod("1777").unwrap(), 0o1777);
        assert_eq!(parse_chmod("4755").unwrap_err().code, 4);
        assert_eq!(parse_chmod("6770").unwrap_err().code, 4);
        for bad in ["", "77", "07770", "778", "+x", "u+s", "-770", " 770"] {
            assert_eq!(parse_chmod(bad).unwrap_err().code, 2, "{bad}");
        }
    }

    #[test]
    fn chown() {
        assert_eq!(parse_chown("0:0").unwrap().1, Id::Num(0));
        assert_eq!(parse_chown("1000:1000").unwrap().2, Id::Num(1000));
        assert_eq!(parse_chown("1:1000").unwrap_err().code, 4);
        assert_eq!(parse_chown("1000:999").unwrap_err().code, 4);
        assert_eq!(parse_chown("4294967295:1000").unwrap_err().code, 4);
        assert_eq!(parse_chown("1000:4294967296").unwrap_err().code, 2);
        // Names are not looked up while parsing.
        assert_eq!(
            parse_chown("no-such-user-xyz:0").unwrap().1,
            Id::Name("no-such-user-xyz".into())
        );
        for bad in ["1000", ":1000", "1000:", "1:2:3", ""] {
            assert_eq!(parse_chown(bad).unwrap_err().code, 2, "{bad}");
        }
    }

    #[test]
    fn resolve() {
        assert_eq!(resolve_user(&Id::Name("root".into())).unwrap(), 0);
        assert_eq!(resolve_group(&Id::Num(5000)).unwrap(), 5000);
        assert_eq!(
            resolve_user(&Id::Name("no-such-user-xyz".into()))
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(
            resolve_group(&Id::Name("no-such-group-xyz".into()))
                .unwrap_err()
                .code,
            4
        );
    }

    #[test]
    fn xattrs() {
        assert_eq!(
            parse_setfattr("ceph.quota.max_bytes=10,ceph.quota.max_files=0").unwrap(),
            [("ceph.quota.max_bytes", 10), ("ceph.quota.max_files", 0)]
        );
        assert_eq!(parse_setfattr("user.x=1").unwrap_err().code, 4);
        assert_eq!(parse_setfattr("security.capability=1").unwrap_err().code, 4);
        assert_eq!(
            parse_setfattr("system.posix_acl_default=1")
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(
            parse_setfattr("ceph.quota.max_bytes=-1").unwrap_err().code,
            4
        );
        assert_eq!(parse_setfattr("ceph.quota.max_bytes=").unwrap_err().code, 4);
        assert_eq!(
            parse_setfattr("ceph.quota.max_bytes=1e3").unwrap_err().code,
            4
        );
        assert_eq!(
            parse_setfattr("ceph.quota.max_bytes=99999999999999999999")
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(parse_setfattr("ceph.quota.max_bytes").unwrap_err().code, 2);
        assert_eq!(
            parse_setfattr("ceph.quota.max_bytes=1,ceph.quota.max_bytes=2")
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            parse_getfattr("ceph.quota.max_files").unwrap(),
            ["ceph.quota.max_files"]
        );
        assert_eq!(parse_getfattr("trusted.x").unwrap_err().code, 4);
        assert_eq!(parse_getfattr("").unwrap_err().code, 4);
    }
}
