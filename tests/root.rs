//! End-to-end tests that run the real binary as root against /storage/test.
//!
//! They need root, ACL support and the right to create /storage/test, so they
//! run in CI only (`sudo ... cargo test --test root`). As a normal user every
//! test returns early.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

use nix::fcntl::{Flock, FlockArg};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_sudoubt");
const ROOT: &str = "/storage/test";
const STATE: &str = "/run/sudoubt";

static LOCK: Mutex<()> = Mutex::new(());

/// Serialize the tests and give each one a clean directory and rate limit.
/// None when not running as root.
fn setup(name: &str) -> Option<(MutexGuard<'static, ()>, String)> {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("skipped: needs root");
        return None;
    }
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = format!("{ROOT}/{name}");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(ROOT).unwrap();
    reset_rate_limit();
    Some((guard, dir))
}

fn reset_rate_limit() {
    let _ = fs::remove_file(format!("{STATE}/state"));
}

struct Out {
    code: i32,
    json: Value,
    stderr: String,
}

fn run(args: &[&str]) -> Out {
    reset_rate_limit();
    run_keep_state(args)
}

fn run_keep_state(args: &[&str]) -> Out {
    let o = Command::new(BIN).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    Out {
        code: o.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("bad JSON {e}: {stdout}")),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn mode(p: &str) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

fn boot_ms() -> u64 {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).unwrap();
    t.tv_sec() as u64 * 1000 + t.tv_nsec() as u64 / 1_000_000
}

#[test]
fn create_project_folder() {
    let Some((_g, dir)) = setup("create") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    let p = format!("{dir}/all");
    let o = run(&[
        &p,
        "--mkdir",
        "--chown",
        "root:5000",
        "--chmod",
        "2770",
        "--setfacl",
        "u::rwx,g::rwx,o::-,g:6000:r-x,d:u::rwx,d:g::rwx,d:o::-",
    ]);
    assert_eq!(o.code, 0, "{}", o.json);
    assert_eq!(o.json["ok"], true);
    assert_eq!(o.json["results"]["mkdir"], "created");
    let md = fs::metadata(&p).unwrap();
    assert!(md.is_dir());
    assert_eq!((md.uid(), md.gid()), (0, 5000));
    assert_eq!(mode(&p), 0o2770);

    let o = run(&[&p, "--getfacl"]);
    assert_eq!(o.code, 0, "{}", o.json);
    assert_eq!(
        o.json["results"]["getfacl"]["access"],
        "u::rwx,g::rwx,g:6000:r-x,m::rwx,o::---"
    );
    assert_eq!(
        o.json["results"]["getfacl"]["default"],
        "d:u::rwx,d:g::rwx,d:o::---"
    );

    // Repeating the call is safe.
    let o = run(&[&p, "--mkdir"]);
    assert_eq!(o.code, 0, "{}", o.json);
    assert_eq!(o.json["results"]["mkdir"], "exists");
}

#[test]
fn file_operations() {
    let Some((_g, dir)) = setup("files") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    let f = format!("{dir}/file");
    fs::write(&f, "x").unwrap();
    let o = run(&[
        &f,
        "--chown",
        "1000:1000",
        "--chmod",
        "0640",
        "--setfacl",
        "u::rw,g::r,o::-,u:1001:r",
    ]);
    assert_eq!(o.code, 0, "{}", o.json);
    let md = fs::metadata(&f).unwrap();
    assert_eq!((md.uid(), md.gid()), (1000, 1000));
    let o = run(&[&f, "--getfacl"]);
    assert_eq!(
        o.json["results"]["getfacl"]["access"],
        "u::rw-,u:1001:r--,g::r--,m::r--,o::---"
    );
    assert_eq!(o.json["results"]["getfacl"]["default"], Value::Null);

    // Refused on files, and nothing is done.
    for args in [
        vec!["--chmod", "2770"],
        vec!["--chown", "0:0", "--setfacl", "d:u::rwx,d:g::rwx,d:o::-"],
        vec!["--getfattr", "ceph.quota.max_bytes"],
        vec!["--setfattr", "ceph.quota.max_bytes=1"],
    ] {
        let mut a = vec![f.as_str()];
        a.extend(args);
        let o = run(&a);
        assert_eq!(o.code, 4, "{a:?} {}", o.json);
    }
    assert_eq!(fs::metadata(&f).unwrap().uid(), 1000);
    assert_eq!(run(&[&f, "--mkdir"]).code, 5);
}

#[test]
fn refused_paths() {
    let Some((_g, dir)) = setup("paths") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    let outside = format!("{ROOT}-outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(format!("{outside}/secret"), "x").unwrap();
    fs::set_permissions(
        format!("{outside}/secret"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink(&outside, format!("{dir}/dirlink")).unwrap();
    symlink(format!("{outside}/secret"), format!("{dir}/filelink")).unwrap();
    fs::write(format!("{dir}/plain"), "x").unwrap();
    fs::hard_link(format!("{dir}/plain"), format!("{dir}/hardlink")).unwrap();
    nix::unistd::mkfifo(
        format!("{dir}/fifo").as_str(),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();

    for p in [
        ROOT.to_string(),
        format!("{ROOT}/"),
        "relative/path".to_string(),
        format!("{dir}/../paths"),
        format!("{dir}//x"),
        format!("{outside}/secret"),
        format!("{dir}/dirlink/secret"),
        format!("{dir}/dirlink"),
        format!("{dir}/filelink"),
        format!("{dir}/hardlink"),
        format!("{dir}/fifo"),
    ] {
        let o = run(&[&p, "--chmod", "0777"]);
        assert_eq!(o.code, 3, "{p} {}", o.json);
        assert_eq!(o.json["ok"], false);
    }
    // mkdir on a symlink is refused and does not follow it.
    assert_eq!(run(&[&format!("{dir}/dirlink"), "--mkdir"]).code, 3);
    assert_eq!(run(&[&format!("{dir}/dirlink/new"), "--mkdir"]).code, 3);
    assert!(!Path::new(&format!("{outside}/new")).exists());
    assert_eq!(mode(&format!("{outside}/secret")), 0o600);
    assert_eq!(mode(&format!("{dir}/plain")), 0o644);
    fs::remove_dir_all(&outside).unwrap();
}

#[test]
fn refused_operations() {
    let Some((_g, dir)) = setup("ops") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    for args in [
        vec!["--chmod", "4755"],
        vec!["--chmod", "6770"],
        vec!["--chown", "1:1000"],
        vec!["--chown", "1000:999"],
        vec!["--chown", "daemon:1000"],
        vec!["--chown", "4294967295:1000"],
        vec!["--setfattr", "user.x=1"],
        vec!["--setfattr", "security.capability=1"],
        vec!["--setfattr", "ceph.quota.max_bytes=-1"],
        vec!["--getfattr", "trusted.x"],
        // Checked before anything runs: the mkdir must not happen.
        vec!["--mkdir", "--chown", "0:0", "--chmod", "4777"],
    ] {
        let p = format!("{dir}/new");
        let mut a = vec![p.as_str()];
        a.extend(args);
        let o = run(&a);
        assert_eq!(o.code, 4, "{a:?} {}", o.json);
        assert!(!Path::new(&p).exists());
    }
}

#[test]
fn usage_errors() {
    let Some((_g, dir)) = setup("usage") else {
        return;
    };
    for a in [
        vec![],
        vec![dir.as_str()],
        vec![dir.as_str(), "--mkdir", "--mkdir"],
        vec![dir.as_str(), "--chmod", "770", "--chmod", "777"],
        vec![dir.as_str(), "--rm"],
        vec![dir.as_str(), "--chmod"],
        vec![dir.as_str(), "--setfacl", "u::rwx"],
    ] {
        let o = run(&a);
        assert_eq!(o.code, 2, "{a:?} {}", o.json);
    }
    assert!(!Path::new(&dir).exists());
}

#[test]
fn file_system_errors() {
    let Some((_g, dir)) = setup("fserr") else {
        return;
    };
    // Parent does not exist: mkdir has no -p.
    assert_eq!(run(&[&format!("{dir}/a/b"), "--mkdir"]).code, 5);
    assert_eq!(run(&[&format!("{dir}/missing"), "--chmod", "0700"]).code, 5);
    fs::create_dir(&dir).unwrap();
    // Not CephFS: the quota xattr fails on the file system, after mkdir ran.
    let o = run(&[
        &format!("{dir}/q"),
        "--mkdir",
        "--setfattr",
        "ceph.quota.max_bytes=100",
    ]);
    assert_eq!(o.code, 5, "{}", o.json);
    assert_eq!(o.json["results"]["mkdir"], "created");
}

#[test]
fn not_root() {
    let Some((_g, dir)) = setup("notroot") else {
        return;
    };
    // The build directory may not be readable for nobody.
    let bin = "/tmp/sudoubt-not-root-test";
    fs::copy(BIN, bin).unwrap();
    fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
    let o = Command::new("setpriv")
        .args([
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            bin,
            &dir,
            "--mkdir",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(7));
    assert!(!Path::new(&dir).exists());
}

#[test]
fn read_only_calls_skip_the_rate_limit() {
    let Some((_g, dir)) = setup("readonly") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    fs::write(format!("{STATE}/state"), format!("{}\n", boot_ms())).unwrap();
    let start = std::time::Instant::now();
    let o = run_keep_state(&[&dir, "--getfacl"]);
    assert_eq!(o.code, 0, "{}", o.json);
    assert!(start.elapsed().as_secs() < 5);
    assert!(o.stderr.is_empty(), "{}", o.stderr);
}

#[test]
fn write_calls_wait() {
    let Some((_g, dir)) = setup("wait") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    // The last write call was 58 seconds ago, so this one waits about 2 seconds.
    fs::write(
        format!("{STATE}/state"),
        format!("{}\n", boot_ms() - 58_000),
    )
    .unwrap();
    let start = std::time::Instant::now();
    let o = run_keep_state(&[&dir, "--chmod", "0750"]);
    assert_eq!(o.code, 0, "{}", o.json);
    assert!(o.stderr.contains("please wait"), "{}", o.stderr);
    assert!(start.elapsed().as_millis() >= 1500);
    assert_eq!(mode(&dir), 0o750);
    // The state now holds this call, so the next write must wait too.
    let state = fs::read_to_string(format!("{STATE}/state")).unwrap();
    assert_eq!(state.lines().count(), 1);
}

#[test]
fn too_many_waiting() {
    let Some((_g, dir)) = setup("busy") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    // Run one call so the state directory exists, then hold every slot.
    assert_eq!(run(&[&dir, "--chmod", "0700"]).code, 0);
    let slots: Vec<_> = (0..25)
        .map(|i| {
            let f = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(format!("{STATE}/slot.{i}"))
                .unwrap();
            Flock::lock(f, FlockArg::LockExclusiveNonblock)
                .map_err(|(_, e)| e)
                .unwrap()
        })
        .collect();
    fs::write(format!("{STATE}/state"), format!("{}\n", boot_ms())).unwrap();
    let o = run_keep_state(&[&dir, "--chmod", "0755"]);
    assert_eq!(o.code, 8, "{}", o.json);
    assert_eq!(mode(&dir), 0o700);
    drop(slots);
}

#[test]
fn bad_state_directory() {
    let Some((_g, dir)) = setup("state") else {
        return;
    };
    fs::create_dir(&dir).unwrap();
    assert_eq!(run(&[&dir, "--chmod", "0700"]).code, 0);
    fs::set_permissions(STATE, fs::Permissions::from_mode(0o755)).unwrap();
    let o = run(&[&dir, "--chmod", "0755"]);
    fs::set_permissions(STATE, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(o.code, 6, "{}", o.json);
    assert_eq!(mode(&dir), 0o700);
    // A broken state file is an error, not a reset.
    fs::write(format!("{STATE}/state"), "garbage\n").unwrap();
    assert_eq!(run_keep_state(&[&dir, "--chmod", "0755"]).code, 6);
    reset_rate_limit();
}
