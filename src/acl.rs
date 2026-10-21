//! Parse setfacl text and convert ACLs to text.
//!
//! The spec is a comma-separated list of `[d:]tag:qualifier:perms` entries,
//! for example `u::rwx,g::r-x,o::-,u:alice:rwx,d:u::rwx,d:g::rwx,d:o::-`.
//! Tags: `u`/`user`, `g`/`group`, `m`/`mask`, `o`/`other`. A `d:` or
//! `default:` prefix marks a default ACL entry. The given entries replace the
//! whole ACL of their kind, like `setfacl --set`. The mask is always
//! recalculated.

use posix_acl::{ACL_EXECUTE, ACL_READ, ACL_WRITE, PosixACL, Qualifier};

use crate::request::{lookup_group, lookup_user};
use crate::{EXIT_OP, EXIT_USAGE, Fail, Result};

const MAX_ENTRIES: usize = 64;

/// Entries for the access ACL and the default ACL. An empty list means that
/// ACL is left as it is.
#[derive(Debug, Default)]
pub struct AclSpec {
    pub access: Vec<(Qualifier, u32)>,
    pub default: Vec<(Qualifier, u32)>,
}

fn usage(msg: impl Into<String>) -> Fail {
    Fail::new(EXIT_USAGE, msg)
}

pub fn parse(spec: &str) -> Result<AclSpec> {
    let mut out = AclSpec::default();
    let entries: Vec<&str> = spec.split(',').collect();
    if entries.len() > MAX_ENTRIES {
        return Err(usage(format!(
            "--setfacl takes at most {MAX_ENTRIES} entries"
        )));
    }
    for entry in entries {
        let mut parts: Vec<&str> = entry.split(':').collect();
        let default = matches!(parts.first(), Some(&"d") | Some(&"default"));
        if default {
            parts.remove(0);
        }
        let [tag, qual, perm] = parts[..] else {
            return Err(usage(format!(
                "ACL entry {entry:?} must look like [d:]tag:qualifier:perms"
            )));
        };
        let q = match (tag, qual) {
            ("u" | "user", "") => Qualifier::UserObj,
            ("g" | "group", "") => Qualifier::GroupObj,
            ("m" | "mask", "") => Qualifier::Mask,
            ("o" | "other", "") => Qualifier::Other,
            ("u" | "user", name) => Qualifier::User(acl_id("user", lookup_user(name)?)?),
            ("g" | "group", name) => Qualifier::Group(acl_id("group", lookup_group(name)?)?),
            _ => return Err(usage(format!("bad ACL entry {entry:?}"))),
        };
        let list = if default {
            &mut out.default
        } else {
            &mut out.access
        };
        if list.iter().any(|(x, _)| *x == q) {
            return Err(usage(format!("ACL entry {entry:?} occurs more than once")));
        }
        list.push((
            q,
            parse_perm(perm).ok_or_else(|| usage(format!("bad permissions in {entry:?}")))?,
        ));
    }
    for (name, list) in [("access", &out.access), ("default", &out.default)] {
        if list.is_empty() {
            continue;
        }
        for base in [Qualifier::UserObj, Qualifier::GroupObj, Qualifier::Other] {
            if !list.iter().any(|(q, _)| *q == base) {
                return Err(usage(format!(
                    "the {name} ACL needs u::, g:: and o:: entries"
                )));
            }
        }
        let mut acl = build(list);
        acl.fix_mask();
        acl.validate()
            .map_err(|_| usage(format!("the {name} ACL is not valid")))?;
    }
    Ok(out)
}

/// ACL qualifiers accept any ID except -1, which libacl treats as undefined.
fn acl_id(kind: &str, id: u32) -> Result<u32> {
    if id == u32::MAX {
        return Err(Fail::new(EXIT_OP, format!("{kind} ID {id} is not allowed")));
    }
    Ok(id)
}

/// `rwx`, `r-x`, `-` and so on, or one octal digit.
fn parse_perm(p: &str) -> Option<u32> {
    if p.len() == 1 && (b'0'..=b'7').contains(&p.as_bytes()[0]) {
        return Some(u32::from(p.as_bytes()[0] - b'0'));
    }
    if p.is_empty() || p.len() > 3 {
        return None;
    }
    let mut perm = 0;
    for c in p.chars() {
        let bit = match c {
            'r' => ACL_READ,
            'w' => ACL_WRITE,
            'x' => ACL_EXECUTE,
            '-' => 0,
            _ => return None,
        };
        if bit != 0 && perm & bit != 0 {
            return None;
        }
        perm |= bit;
    }
    Some(perm)
}

pub fn build(list: &[(Qualifier, u32)]) -> PosixACL {
    let mut acl = PosixACL::empty();
    for (q, perm) in list {
        acl.set(*q, *perm);
    }
    acl
}

/// Short text form, the same syntax that --setfacl takes.
pub fn to_text(acl: &PosixACL, prefix: &str) -> String {
    let perm = |p: u32| {
        let f = |bit, c| if p & bit != 0 { c } else { '-' };
        format!(
            "{}{}{}",
            f(ACL_READ, 'r'),
            f(ACL_WRITE, 'w'),
            f(ACL_EXECUTE, 'x')
        )
    };
    acl.entries()
        .iter()
        .filter_map(|e| {
            let head = match e.qual {
                Qualifier::UserObj => "u:".to_string(),
                Qualifier::User(id) => format!("u:{id}"),
                Qualifier::GroupObj => "g:".to_string(),
                Qualifier::Group(id) => format!("g:{id}"),
                Qualifier::Mask => "m:".to_string(),
                Qualifier::Other => "o:".to_string(),
                Qualifier::Undefined => return None,
            };
            Some(format!("{prefix}{head}:{}", perm(e.perm)))
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_example() {
        let s = parse("d:u::rwx,d:g::rwx,d:o::-").unwrap();
        assert!(s.access.is_empty());
        assert_eq!(s.default.len(), 3);
        assert_eq!(
            to_text(&build(&s.default), "d:"),
            "d:u::rwx,d:g::rwx,d:o::---"
        );
    }

    #[test]
    fn named_entries() {
        let s =
            parse("u::rwx,g::r-x,o::0,u:5000:rw,g:6000:7,default:user::7,d:group::5,d:other::-")
                .unwrap();
        assert_eq!(s.access.len(), 5);
        assert_eq!(s.default.len(), 3);
        let mut acl = build(&s.access);
        acl.fix_mask();
        assert_eq!(
            to_text(&acl, ""),
            "u::rwx,u:5000:rw-,g::r-x,g:6000:rwx,m::rwx,o::---"
        );
    }

    #[test]
    fn errors() {
        for bad in [
            "",
            "u::rwx",
            "u::rwx,g::rwx",
            "u::rwx,g::rwx,o::rwx,u::r",
            "u::rwx,g::rwx,o::rwX",
            "u::rwx,g::rwx,o::rr",
            "u::rwx,g::rwx,o::8",
            "u::rwx,g::rwx,o::rwxr",
            "u::rwx,g::rwx,o:x:r",
            "u::rwx,g::rwx,o:r",
            "x::rwx",
            "d:d:u::rwx",
            "u:rwx",
        ] {
            assert_eq!(parse(bad).unwrap_err().code, 2, "{bad:?}");
        }
        assert_eq!(
            parse("u::rwx,g::rwx,o::-,u:4294967295:r").unwrap_err().code,
            4
        );
        assert_eq!(
            parse("u::rwx,g::rwx,o::-,u:no-such-user-xyz:r")
                .unwrap_err()
                .code,
            4
        );
        let many = vec!["u:5000:r"; 65].join(",");
        assert_eq!(parse(&many).unwrap_err().code, 2);
    }

    #[test]
    fn system_ids_allowed_in_acl() {
        assert!(parse("u::rwx,g::rwx,o::-,u:0:r,g:5:r").is_ok());
    }
}
