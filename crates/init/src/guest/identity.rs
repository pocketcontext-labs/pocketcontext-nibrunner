use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use guest_contract::instance_env::InstanceConfig;
use guest_contract::vsock::{IDENTITY_PORT, MAX_IDENTITY_BYTES};
use nix::mount::{mount, MsFlags};
use nix::sys::socket::{connect, setsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::sys::time::{TimeVal, TimeValLike};

const DIRECTORY: &str = "/run/drop-identity";
const FILE: &str = "/run/drop-identity/token";
const STAGED: &str = "/run/drop-identity/.next";
static ROLE: OnceLock<String> = OnceLock::new();
pub(super) const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

pub(super) fn enabled() -> bool {
    ROLE.get().is_some()
}

fn receive() -> io::Result<(String, String)> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let timeout = TimeVal::milliseconds(1200);
    setsockopt(&fd, sockopt::ReceiveTimeout, &timeout)?;
    setsockopt(&fd, sockopt::SendTimeout, &timeout)?;
    connect(
        fd.as_raw_fd(),
        &VsockAddr::new(super::vsock::CID_HOST, IDENTITY_PORT),
    )?;
    let mut wire = BufReader::new(File::from(fd)).take(MAX_IDENTITY_BYTES as u64);
    let mut role = String::new();
    let mut token = String::new();
    wire.read_line(&mut role)?;
    wire.read_line(&mut token)?;
    if !role.ends_with('\n') || !token.ends_with('\n') || role.trim().is_empty() || token.trim().is_empty() {
        return Err(io::Error::other("workload identity unavailable"));
    }
    Ok((role.trim().to_owned(), token.trim().to_owned()))
}

fn install_token(token: &str) -> io::Result<()> {
    std::fs::write(STAGED, token)?;
    std::fs::rename(STAGED, FILE)
}

pub(super) fn prepare(config: &mut InstanceConfig) -> io::Result<()> {
    if !config
        .environment
        .iter()
        .any(|(key, value)| key == "AWS_WORKLOAD_IDENTITY" && value == "1")
    {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let (role, token) = loop {
        match receive() {
            Ok(frame) => break frame,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error),
        }
    };

    std::fs::create_dir(DIRECTORY)?;
    install_token(&token)?;
    let view = super::in_root(DIRECTORY);
    std::fs::create_dir(&view)?;
    mount(
        Some(DIRECTORY),
        Path::new(&view),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    let flags = MsFlags::MS_BIND
        | MsFlags::MS_REMOUNT
        | MsFlags::MS_RDONLY
        | MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV
        | MsFlags::MS_NOEXEC;
    mount(None::<&str>, Path::new(&view), None::<&str>, flags, None::<&str>)?;
    config
        .environment
        .retain(|(key, _)| key != "AWS_WEB_IDENTITY_TOKEN_FILE" && key != "AWS_ROLE_ARN");
    config
        .environment
        .push(("AWS_WEB_IDENTITY_TOKEN_FILE".into(), FILE.into()));
    config.environment.push(("AWS_ROLE_ARN".into(), role.clone()));
    ROLE.set(role)
        .map_err(|_| io::Error::other("workload identity already configured"))?;
    super::log("workload identity installed before tenant start");
    Ok(())
}

pub(super) fn refresh() -> io::Result<()> {
    let Some(expected) = ROLE.get() else {
        return Ok(());
    };
    let (role, token) = receive()?;
    if &role != expected {
        return Err(io::Error::other(
            "workload identity role changed during deployment",
        ));
    }
    install_token(&token)
}
