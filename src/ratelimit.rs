//! Global rate limit for write calls.
//!
//! The state file holds the start times (CLOCK_BOOTTIME, milliseconds) of the
//! write calls in the last minute. A call locks it, and if fewer than
//! MAX_CALLS_PER_MINUTE calls started in the last minute, it adds its own time
//! and runs. Otherwise it takes one of MAX_WAITING slot locks (exit 8 if none
//! is free), unlocks the state, sleeps and tries again. Only calls that
//! actually start are recorded, so a killed waiter costs nothing, and the
//! kernel releases its slot lock.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::time::{ClockId, clock_gettime};
use nix::unistd::mkdir;

use crate::{EXIT_BUSY, EXIT_STATE, Fail, MAX_CALLS_PER_MINUTE, MAX_WAITING, Result, STATE_DIR};

const WINDOW_MS: u64 = 60_000;

fn state_error(what: &str, e: impl std::fmt::Display) -> Fail {
    Fail::new(EXIT_STATE, format!("rate limit state: {what}: {e}"))
}

/// Wait until this write call may run.
pub fn wait() -> Result<()> {
    let dir = open_dir()?;
    let mut slot: Option<Flock<File>> = None;
    loop {
        let file = open_file(&dir, "state")?;
        let mut state =
            Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| state_error("lock", e))?;
        let mut text = String::new();
        state
            .read_to_string(&mut text)
            .map_err(|e| state_error("read", e))?;
        let now = now_ms()?;
        let mut times = parse(&text, now)?;
        times.retain(|t| t + WINDOW_MS > now);
        if times.len() < MAX_CALLS_PER_MINUTE as usize {
            times.push(now);
            let out: String = times.iter().map(|t| format!("{t}\n")).collect();
            // Write first, then cut off the rest, so a failed write never
            // leaves an empty file behind.
            std::os::unix::fs::FileExt::write_all_at(&*state, out.as_bytes(), 0)
                .map_err(|e| state_error("write", e))?;
            state
                .set_len(out.len() as u64)
                .map_err(|e| state_error("write", e))?;
            return Ok(());
        }
        let oldest = times.iter().min().copied().unwrap_or(now);
        let wait = (oldest + WINDOW_MS).saturating_sub(now).max(1);
        if slot.is_none() {
            slot = Some(take_slot(&dir)?);
            drop(state);
            // Only once: another call may start first, and then this one waits again.
            let _ = writeln!(
                std::io::stderr(),
                "sudoubt: rate limit reached, please wait {} seconds",
                wait.div_ceil(1000)
            );
        } else {
            drop(state);
        }
        std::thread::sleep(std::time::Duration::from_millis(wait));
    }
}

/// One start time per line. Times in the future mean the file is broken.
fn parse(text: &str, now: u64) -> Result<Vec<u64>> {
    let mut times = Vec::new();
    for line in text.lines() {
        let t: u64 = line
            .parse()
            .map_err(|_| state_error("state file", "bad line"))?;
        if t > now {
            return Err(state_error("state file", "time in the future"));
        }
        times.push(t);
        if times.len() > 1000 {
            return Err(state_error("state file", "too many lines"));
        }
    }
    Ok(times)
}

fn now_ms() -> Result<u64> {
    let t = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|e| state_error("clock", e))?;
    Ok(t.tv_sec() as u64 * 1000 + t.tv_nsec() as u64 / 1_000_000)
}

/// Open the state directory, creating it if needed. It must be a real
/// directory owned by root with no access for group or others.
fn open_dir() -> Result<OwnedFd> {
    match mkdir(STATE_DIR, Mode::from_bits_truncate(0o700)) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(e) => return Err(state_error(STATE_DIR, e.desc())),
    }
    let fd = open(
        STATE_DIR,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| state_error(STATE_DIR, e.desc()))?;
    let st = fstat(&fd).map_err(|e| state_error(STATE_DIR, e.desc()))?;
    if st.st_uid != 0 || st.st_mode & 0o077 != 0 {
        return Err(state_error(
            STATE_DIR,
            "must be owned by root with mode 0700",
        ));
    }
    Ok(fd)
}

fn open_file(dir: &OwnedFd, name: &str) -> Result<File> {
    let fd = openat(
        dir,
        name,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|e| state_error(name, e.desc()))?;
    let st = fstat(&fd).map_err(|e| state_error(name, e.desc()))?;
    if st.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() || st.st_uid != 0 {
        return Err(state_error(name, "must be a regular file owned by root"));
    }
    Ok(File::from(fd))
}

/// Lock a free slot file. The lock is held until the returned value is dropped.
fn take_slot(dir: &OwnedFd) -> Result<Flock<File>> {
    for i in 0..MAX_WAITING {
        let file = open_file(dir, &format!("slot.{i}"))?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(lock),
            Err((_, Errno::EWOULDBLOCK)) => continue,
            Err((_, e)) => return Err(state_error("slot lock", e)),
        }
    }
    Err(Fail::new(
        EXIT_BUSY,
        format!("too many waiting: {MAX_WAITING} write calls already wait"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_state() {
        assert_eq!(parse("", 10).unwrap(), Vec::<u64>::new());
        assert_eq!(parse("1\n5\n", 10).unwrap(), [1, 5]);
        assert_eq!(parse("11\n", 10).unwrap_err().code, 6);
        assert_eq!(parse("x\n", 10).unwrap_err().code, 6);
        assert_eq!(parse("-1\n", 10).unwrap_err().code, 6);
    }
}
