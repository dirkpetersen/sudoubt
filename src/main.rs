//! sudoubt: sudo with trust issues. See README.md for the design.
//!
//! sudoubt runs as root on behalf of a caller that is assumed to be hostile.
//! It does a few folder operations on one path below a compiled-in root.

mod acl;
mod ops;
mod path;
mod ratelimit;
mod request;

use std::ffi::{CString, OsString};
use std::io::Write;
use std::panic::AssertUnwindSafe;
use std::process::ExitCode;

use nix::unistd::{Gid, Uid};
use serde_json::{Map, Value, json};

/// The only directories sudoubt works in. Change by editing the source only.
pub const ALLOWED_ROOTS: &[&str] = &["/storage/test"];
/// The only extended attributes sudoubt reads or writes.
pub const ALLOWED_XATTRS: &[&str] = &["ceph.quota.max_bytes", "ceph.quota.max_files"];
/// Write calls per minute, for all callers together.
pub const MAX_CALLS_PER_MINUTE: u32 = 1;
/// Write calls that may wait for the rate limit at the same time.
pub const MAX_WAITING: u32 = 25;
/// Rate limit state. Root only, on tmpfs.
pub const STATE_DIR: &str = "/run/sudoubt";

const _: () = assert!(MAX_CALLS_PER_MINUTE >= 1 && MAX_WAITING >= 1);

// Exit codes. The table in README.md is the reference.
pub const EXIT_INTERNAL: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_PATH: u8 = 3;
pub const EXIT_OP: u8 = 4;
pub const EXIT_FS: u8 = 5;
pub const EXIT_STATE: u8 = 6;
pub const EXIT_NOT_ROOT: u8 = 7;
pub const EXIT_BUSY: u8 = 8;

/// Why a call failed: the exit code and a message for the caller.
#[derive(Debug)]
pub struct Fail {
    pub code: u8,
    pub msg: String,
}

impl Fail {
    pub fn new(code: u8, msg: impl Into<String>) -> Fail {
        Fail {
            code,
            msg: msg.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Fail>;

fn main() -> ExitCode {
    // In setuid mode the caller controls the environment, so read nothing from it.
    // In sudo mode (real UID 0) sudo has cleaned it and SUDO_USER names the caller.
    let ruid = Uid::current();
    let caller = if ruid.is_root() {
        match std::env::var_os("SUDO_USER") {
            Some(u) => u.to_string_lossy().into_owned(),
            None => "root".to_string(),
        }
    } else {
        format!("uid {ruid}")
    };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // Rust's runtime has already reopened closed fds 0 to 2 on /dev/null, so
    // no file opened below can land on stdout or stderr.
    // SAFETY: no other threads exist yet.
    unsafe { libc::clearenv() };
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    let path = args.first().map(|p| p.to_string_lossy().into_owned());
    let mut results = Map::new();
    // posix-acl panics on allocation failure. Report a panic as an internal error.
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| run(&args, &mut results)))
        .unwrap_or_else(|_| Err(Fail::new(EXIT_INTERNAL, "internal error")));

    // Log before writing to stdout and stderr: the caller can make those block.
    let ops: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let result = match &outcome {
        Ok(()) => "ok".to_string(),
        Err(f) => format!("exit={} error={:?}", f.code, f.msg),
    };
    let (path_log, ops_log) = (clip(&format!("{path:?}")), clip(&format!("{ops:?}")));
    log(&format!(
        "caller={caller:?} path={path_log} ops={ops_log} result={result}"
    ));

    let mut out = Map::new();
    out.insert("ok".into(), json!(outcome.is_ok()));
    out.insert("path".into(), json!(path));
    if let Err(f) = &outcome {
        out.insert("exit_code".into(), json!(f.code));
        out.insert("error".into(), json!(f.msg));
    }
    out.insert("results".into(), Value::Object(results));
    let text = serde_json::to_string_pretty(&Value::Object(out))
        .unwrap_or_else(|_| "{\"ok\": false, \"exit_code\": 1}".to_string());
    // Write errors are ignored: the operations are done, and the exit code still tells.
    let _ = writeln!(std::io::stdout(), "{text}");
    if let Err(f) = &outcome {
        let _ = writeln!(std::io::stderr(), "sudoubt: {}", f.msg);
    }

    ExitCode::from(outcome.err().map_or(0, |f| f.code))
}

fn run(args: &[OsString], results: &mut Map<String, Value>) -> Result<()> {
    if !Uid::effective().is_root() {
        return Err(Fail::new(
            EXIT_NOT_ROOT,
            "not running as root (effective UID is not 0)",
        ));
    }
    become_root()?;
    let req = request::parse(args)?;
    if req.has_write() {
        ratelimit::wait()?;
    }
    ops::run(&req, results)
}

/// Make real, effective and saved IDs root and drop supplementary groups, so the
/// caller can no longer signal or trace the process in setuid mode. Then undo
/// what the caller can pass through exec to stop the process halfway: timers,
/// resource limits and blocked signals.
fn become_root() -> Result<()> {
    let fail = |e: nix::Error| Fail::new(EXIT_INTERNAL, format!("cannot become root: {e}"));
    nix::unistd::setgroups(&[]).map_err(fail)?;
    nix::unistd::setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)).map_err(fail)?;
    nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).map_err(fail)?;
    nix::sys::prctl::set_dumpable(false).map_err(fail)?;

    // SAFETY: plain system calls on local values.
    unsafe {
        let zero: libc::itimerval = std::mem::zeroed();
        for timer in [libc::ITIMER_REAL, libc::ITIMER_VIRTUAL, libc::ITIMER_PROF] {
            if libc::setitimer(timer, &zero, std::ptr::null_mut()) != 0 {
                return Err(fail(nix::Error::last()));
            }
        }
        let unlimited = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        for res in [
            libc::RLIMIT_CPU,
            libc::RLIMIT_FSIZE,
            libc::RLIMIT_AS,
            libc::RLIMIT_DATA,
        ] {
            if libc::setrlimit(res, &unlimited) != 0 {
                return Err(fail(nix::Error::last()));
            }
        }
        let files = libc::rlimit {
            rlim_cur: 1024,
            rlim_max: 1024,
        };
        let mut cur: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) != 0
            || (cur.rlim_cur < 1024 && libc::setrlimit(libc::RLIMIT_NOFILE, &files) != 0)
        {
            return Err(fail(nix::Error::last()));
        }
        // A background job writing to a terminal would be stopped by SIGTTOU.
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        if libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) != 0 {
            return Err(fail(nix::Error::last()));
        }
    }
    Ok(())
}

/// Shorten caller-supplied text for the log, so one call cannot flood it.
fn clip(s: &str) -> String {
    const MAX: usize = 512;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...(truncated)", &s[..end])
}

/// Write a short message to stderr only if that cannot block, so a caller
/// that does not read stderr cannot stall a waiting call.
pub fn note(msg: &str) {
    let line = format!("{msg}\n");
    let mut fds = libc::pollfd {
        fd: libc::STDERR_FILENO,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one valid pollfd; the buffer outlives the write. Writes up to
    // PIPE_BUF bytes are atomic, so POLLOUT means this one fits.
    unsafe {
        if libc::poll(&mut fds, 1, 0) == 1 && fds.revents & libc::POLLOUT != 0 {
            libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len());
        }
    }
}

/// Write one line to syslog (authpriv). The message is built with `{:?}` quoting,
/// so caller-supplied text cannot add lines.
fn log(msg: &str) {
    let msg = CString::new(msg.replace('\0', "\\0")).unwrap_or_default();
    // SAFETY: both strings are NUL-terminated and live for the whole call.
    unsafe {
        libc::openlog(c"sudoubt".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV);
        libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), msg.as_ptr());
        libc::closelog();
    }
}
