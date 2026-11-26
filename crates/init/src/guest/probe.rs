use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use guest_contract::paths::{TENANT_GID, TENANT_UID};
use guest_contract::probe::{FRAME_PREFIX, MAX_BINARY_BYTES, MAX_OUTPUT_BYTES};
use nix::mount::{mount, MsFlags};

pub(super) fn run(length: Option<u64>) {
    // An interrupted host worker can leave a VMM alive. PID 1 bounds its lifetime independently.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(15));
        unsafe { libc::reboot(libc::RB_AUTOBOOT) };
    });
    let result = match inspect(length) {
        Ok(Some(output)) => format!("ok {} {}", output.len(), hex::encode(output)),
        Ok(None) => "invalid".into(),
        Err(_) => "unavailable".into(),
    };
    let mut console = io::stdout().lock();
    let _ = writeln!(console, "{FRAME_PREFIX}{result}");
    let _ = console.flush();
    unsafe { libc::tcdrain(libc::STDOUT_FILENO) };
}

fn inspect(length: Option<u64>) -> io::Result<Option<Vec<u8>>> {
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
    let mut payload = File::open("/dev/vdb")?.take(length);
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
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(libc::ENOEXEC) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing probe output pipe"))?
        .take(MAX_OUTPUT_BYTES as u64 + 1)
        .read_to_end(&mut output)?;
    if output.len() > MAX_OUTPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Ok(None);
    }
    match child.wait()?.code() {
        Some(0) => Ok(Some(output)),
        Some(_) => Ok(None),
        None => Err(io::Error::other("probe child was interrupted")),
    }
}
