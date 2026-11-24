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
struct Identity {
    role: String,
    background: bool,
}

static IDENTITY: OnceLock<Identity> = OnceLock::new();
pub(super) const REFRESH_INTERVAL: Duration = Duration::from_secs(15);

pub(super) fn synchronous() -> bool {
    IDENTITY.get().is_some_and(|id| !id.background)
}

pub(super) fn asynchronous() -> bool {
    IDENTITY.get().is_some_and(|id| id.background)
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
    let mode = config
        .environment
        .iter()
        .find(|(key, _)| key == "AWS_WORKLOAD_IDENTITY")
        .map(|(_, value)| value.as_str());
    let (role, token) = match mode {
        Some("async") => {
            let role = config
                .workload_role
                .clone()
                .ok_or_else(|| io::Error::other("missing configured workload role"))?;
            (role, None)
        }
        Some("1") => {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match receive() {
                    Ok((role, token)) => break (role, Some(token)),
                    Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                    Err(error) => return Err(error),
                }
            }
        }
        _ => return Ok(()),
    };

    std::fs::create_dir(DIRECTORY)?;
    if let Some(token) = &token {
        install_token(token)?;
    }
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
    let background = token.is_none();
    IDENTITY
        .set(Identity { role, background })
        .map_err(|_| io::Error::other("workload identity already configured"))?;
    if background {
        super::log("workload identity delivery is asynchronous");
    } else {
        super::log("workload identity installed before tenant start");
    }
    Ok(())
}

pub(super) fn refresh() -> io::Result<()> {
    let Some(expected) = IDENTITY.get() else {
        return Ok(());
    };
    let (role, token) = receive()?;
    if role != expected.role {
        return Err(io::Error::other(
            "workload identity role changed during deployment",
        ));
    }
    install_token(&token)
}

pub(super) fn before_release() -> io::Result<()> {
    if asynchronous() {
        // A restored file could predate a long sleep. The broker exchange runs in the
        // identity worker and never holds the clock or tenant-release handshake.
        if let Err(error) = std::fs::remove_file(FILE) {
            if error.kind() != io::ErrorKind::NotFound {
                super::log("the previous workload token could not be removed");
            }
        }
    } else if synchronous() {
        refresh()?;
        super::log("workload identity refreshed before tenant release");
    }
    Ok(())
}

pub(super) fn serve() -> ! {
    let mut next = Instant::now();
    loop {
        if Instant::now() >= next || !Path::new(FILE).exists() {
            let delay = if refresh().is_ok() {
                REFRESH_INTERVAL
            } else {
                Duration::from_secs(1)
            };
            next = Instant::now() + delay;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
