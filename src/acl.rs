//! Parse setfacl text and convert ACLs to text.
//!
//! The spec is a comma-separated list of `[d:]tag:qualifier:perms` entries,
//! for example `u::rwx,g::r-x,o::-,u:alice:rwx,d:u::rwx,d:g::rwx,d:o::-`.
//! Tags: `u`/`user`, `g`/`group`, `m`/`mask`, `o`/`other`. A `d:` or
//! `default:` prefix marks a default ACL entry. The given entries replace the
//! whole ACL of their kind, like `setfacl --set`. The mask is always
//! recalculated. The single entry `d:-` removes the default ACL.
//!
//! `parse` checks the syntax without looking up names. `resolve` looks up
//! names and checks the result, after the rate limit.

use posix_acl::{ACL_EXECUTE, ACL_READ, ACL_WRITE, PosixACL, Qualifier};

use crate::request::{Id, parse_id, resolve_group, resolve_user};
use crate::{EXIT_OP, EXIT_USAGE, Fail, Result};

const MAX_ENTRIES: usize = 64;

/// An entry tag as given, with names not yet looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    UserObj,
    User(Id),
    GroupObj,
    Group(Id),
    Mask,
    Other,
}

/// The parsed spec: entries for the access and the default ACL. An empty
/// list means that ACL is left as it is.
#[derive(Debug, Default)]
pub struct AclText {
    pub access: Vec<(Tag, u32)>,
    pub default: Vec<(Tag, u32)>,
    pub remove_default: bool,
}

/// The resolved spec, ready to write.
#[derive(Debug, Default)]
pub struct AclSpec {
    pub access: Vec<(Qualifier, u32)>,
    pub default: Vec<(Qualifier, u32)>,
    pub remove_default: bool,
}

fn usage(msg: impl Into<String>) -> Fail {
    Fail::new(EXIT_USAGE, msg)
}

pub fn parse(spec: &str) -> Result<AclText> {
    let mut out = AclText::default();
    let entries: Vec<&str> = spec.split(',').collect();
    if entries.len() > MAX_ENTRIES {
        return Err(usage(format!(
            "--setfacl takes at most {MAX_ENTRIES} entries"
        )));
    }
    for entry in entries {
        if entry == "d:-" || entry == "default:-" {
            if out.remove_default {
                return Err(usage(format!("ACL entry {entry:?} occurs more than once")));
            }
            out.remove_default = true;
            continue;
        }
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
        let t = match (tag, qual) {
            ("u" | "user", "") => Tag::UserObj,
            ("g" | "group", "") => Tag::GroupObj,
            ("m" | "mask", "") => Tag::Mask,
            ("o" | "other", "") => Tag::Other,
            ("u" | "user", name) => Tag::User(acl_id(parse_id(name)?)?),
            ("g" | "group", name) => Tag::Group(acl_id(parse_id(name)?)?),
            _ => return Err(usage(format!("bad ACL entry {entry:?}"))),
        };
        let list = if default {
            &mut out.default
        } else {
            &mut out.access
        };
        if list.iter().any(|(x, _)| *x == t) {
            return Err(usage(format!("ACL entry {entry:?} occurs more than once")));
        }
        let perm =
            parse_perm(perm).ok_or_else(|| usage(format!("bad permissions in {entry:?}")))?;
        list.push((t, perm));
    }
    if out.remove_default && !out.default.is_empty() {
        return Err(usage("d:- cannot be combined with other default entries"));
    }
    for (name, list) in [("access", &out.access), ("default", &out.default)] {
        if list.is_empty() {
            continue;
        }
        for base in [Tag::UserObj, Tag::GroupObj, Tag::Other] {
            if !list.iter().any(|(t, _)| *t == base) {
                return Err(usage(format!(
                    "the {name} ACL needs u::, g:: and o:: entries"
                )));
            }
        }
    }
    Ok(out)
}

/// Look up names and check that each ACL is valid.
pub fn resolve(text: &AclText) -> Result<AclSpec> {
    let conv = |list: &[(Tag, u32)]| -> Result<Vec<(Qualifier, u32)>> {
        list.iter()
            .map(|(t, perm)| {
                let q = match t {
                    Tag::UserObj => Qualifier::UserObj,
                    Tag::GroupObj => Qualifier::GroupObj,
                    Tag::Mask => Qualifier::Mask,
                    Tag::Other => Qualifier::Other,
                    Tag::User(id) => Qualifier::User(acl_num(resolve_user(id)?)?),
                    Tag::Group(id) => Qualifier::Group(acl_num(resolve_group(id)?)?),
                };
                Ok((q, *perm))
            })
            .collect()
    };
    let spec = AclSpec {
        access: conv(&text.access)?,
        default: conv(&text.default)?,
        remove_default: text.remove_default,
    };
    for (name, list) in [("access", &spec.access), ("default", &spec.default)] {
        if list.is_empty() {
            continue;
        }
        // Two names for the same ID are only visible after the lookup.
        for (i, (q, _)) in list.iter().enumerate() {
            if list[..i].iter().any(|(x, _)| x == q) {
                return Err(usage(format!("the {name} ACL names the same ID twice")));
            }
        }
        let mut acl = build(list);
        acl.fix_mask();
        acl.validate()
            .map_err(|_| usage(format!("the {name} ACL is not valid")))?;
    }
    Ok(spec)
}

/// ACL qualifiers accept any ID except -1, which libacl treats as undefined.
fn acl_id(id: Id) -> Result<Id> {
    if let Id::Num(n) = id {
        acl_num(n)?;
    }
    Ok(id)
}

fn acl_num(n: u32) -> Result<u32> {
    if n == u32::MAX {
        return Err(Fail::new(
            EXIT_OP,
            format!("ID {n} is not allowed in an ACL"),
        ));
    }
    Ok(n)
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

    fn spec(s: &str) -> Result<AclSpec> {
        resolve(&parse(s)?)
    }

    #[test]
    fn readme_example() {
        let s = spec("d:u::rwx,d:g::rwx,d:o::-").unwrap();
        assert!(s.access.is_empty() && !s.remove_default);
        assert_eq!(s.default.len(), 3);
        assert_eq!(
            to_text(&build(&s.default), "d:"),
            "d:u::rwx,d:g::rwx,d:o::---"
        );
    }

    #[test]
    fn named_entries() {
        let s = spec("u::rwx,g::r-x,o::0,u:5000:rw,g:6000:7,default:user::7,d:group::5,d:other::-")
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
    fn remove_default() {
        let s = spec("d:-").unwrap();
        assert!(s.remove_default && s.access.is_empty() && s.default.is_empty());
        let s = spec("u::rwx,g::rwx,o::-,default:-").unwrap();
        assert!(s.remove_default && s.access.len() == 3);
        assert_eq!(parse("d:-,d:u::rwx,d:g::rwx,d:o::-").unwrap_err().code, 2);
        assert_eq!(parse("d:-,d:-").unwrap_err().code, 2);
        assert_eq!(parse("-").unwrap_err().code, 2);
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
            "u::rwx,g::rwx,o::-,u:4294967296:r",
        ] {
            assert_eq!(parse(bad).unwrap_err().code, 2, "{bad:?}");
        }
        assert_eq!(
            parse("u::rwx,g::rwx,o::-,u:4294967295:r").unwrap_err().code,
            4
        );
        // Names are looked up only in resolve.
        let t = parse("u::rwx,g::rwx,o::-,u:no-such-user-xyz:r").unwrap();
        assert_eq!(resolve(&t).unwrap_err().code, 4);
        // root and 0 are the same user.
        assert_eq!(
            spec("u::rwx,g::rwx,o::-,u:root:r,u:0:r").unwrap_err().code,
            2
        );
        let many = vec!["u:5000:r"; 65].join(",");
        assert_eq!(parse(&many).unwrap_err().code, 2);
    }

    #[test]
    fn system_ids_allowed_in_acl() {
        assert!(spec("u::rwx,g::rwx,o::-,u:0:r,g:5:r").is_ok());
    }
}
