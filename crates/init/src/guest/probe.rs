use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use guest_contract::paths::{TENANT_GID, TENANT_UID};
use guest_contract::probe::{FRAME_PREFIX, MAX_BINARY_BYTES, MAX_OUTPUT_BYTES};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::mount::{mount, MsFlags};

pub(super) fn run(length: Option<u64>) {
    // An interrupted host worker can leave a VMM alive. PID 1 bounds its lifetime independently.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(15));
        unsafe { libc::reboot(libc::RB_AUTOBOOT) };
    });
    let result = match inspect(length, Instant::now() + Duration::from_secs(12)) {
        Ok(Some(output)) => format!("ok {} {}", output.len(), hex::encode(output)),
        Ok(None) => "invalid".into(),
        Err(_) => "unavailable".into(),
    };
    let mut console = io::stdout().lock();
    let _ = writeln!(console, "{FRAME_PREFIX}{result}");
    let _ = console.flush();
    unsafe { libc::tcdrain(libc::STDOUT_FILENO) };
}

fn inspect(length: Option<u64>, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let length = length
        .filter(|n| (1..=MAX_BINARY_BYTES).contains(n))
        .ok_or_else(|| io::Error::other("invalid probe length"))?;
    mount(
        Some("tmpfs"),
        Path::new("/tmp"),
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Some("size=100M,mode=0755"),
    )?;
    let device = guest_contract::paths::CONFIG_DEVICE;
    super::mounts::wait_for_device(device).map_err(io::Error::other)?;
    let mut payload = File::open(device)?.take(length);
    let destination = "/tmp/binary";
    if io::copy(&mut payload, &mut File::create(destination)?)? != length {
        return Err(io::Error::other("incomplete probe input"));
    }
    std::fs::set_permissions(destination, Permissions::from_mode(0o555))?;
    let mut command = Command::new("/binary");
    command
        .arg("--drop-manifest")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // The tenant must not inherit a console, device, supplementary group or path to its parent.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0
                || libc::chroot(c"/tmp".as_ptr()) < 0
                || libc::chdir(c"/".as_ptr()) < 0
                || libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(TENANT_GID) < 0
                || libc::setuid(TENANT_UID) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(libc::ENOEXEC) => return Ok(None),
        Err(error) => return Err(error),
    };
    collect_output(child, deadline.min(Instant::now() + Duration::from_secs(4)))
}

fn collect_output(mut child: Child, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    let mut pipe = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing probe output pipe"))?;
    fcntl(&pipe, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    let mut output = Vec::new();
    let mut eof = false;
    loop {
        if Instant::now() >= deadline || output.len() > MAX_OUTPUT_BYTES {
            let _ = child.kill();
            return Ok(None);
        }
        if !eof {
            let remaining = (MAX_OUTPUT_BYTES + 1 - output.len()) as u64;
            match pipe.by_ref().take(remaining).read_to_end(&mut output) {
                Ok(_) if output.len() > MAX_OUTPUT_BYTES => continue,
                Ok(_) => eof = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Ok(None);
            }
            if eof {
                return Ok(Some(output));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_running_nonmanifest_application_produces_a_definitive_result() {
        let child = Command::new("sleep")
            .arg("10")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let now = Instant::now();
        assert_eq!(
            collect_output(child, now + Duration::from_millis(40)).unwrap(),
            None
        );
        assert!(now.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_signal_after_successful_spawn_is_a_definitive_probe_result() {
        let mut child = Command::new("sleep")
            .arg("10")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.kill().unwrap();
        assert_eq!(
            collect_output(child, Instant::now() + Duration::from_secs(3)).unwrap(),
            None
        );
    }

    #[test]
    fn a_finished_manifest_still_returns_its_output() {
        let child = Command::new("echo")
            .arg("manifest")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        assert_eq!(
            collect_output(child, Instant::now() + Duration::from_secs(3)).unwrap(),
            Some(b"manifest\n".to_vec())
        );
    }
}
