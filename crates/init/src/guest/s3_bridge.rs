use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use guest_contract::instance_env::InstanceConfig;
use guest_contract::vsock::{
    HOST_SERVICES_PORT, S3_BRIDGE_ACCESS_KEY_ID, S3_BRIDGE_ADDRESS, S3_BRIDGE_ENDPOINT,
    S3_BRIDGE_SECRET_ACCESS_KEY,
};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::unistd::{ForkResult, Pid};

const MAX_CONNECTIONS: usize = 64;

// Every way the tenant could name another credential or endpoint is replaced, so the SDK's chain
// can only find the bridge and its placeholder keys.
const REPLACED: [&str; 10] = [
    "AWS_WORKLOAD_IDENTITY",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_S3",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
];

pub(super) fn prepare(config: &mut InstanceConfig) {
    if !config.host_s3 {
        return;
    }
    config
        .environment
        .retain(|(key, _)| !REPLACED.contains(&key.as_str()));
    config.environment.extend([
        ("AWS_ENDPOINT_URL_S3".to_string(), S3_BRIDGE_ENDPOINT.to_string()),
        (
            "AWS_ACCESS_KEY_ID".to_string(),
            S3_BRIDGE_ACCESS_KEY_ID.to_string(),
        ),
        (
            "AWS_SECRET_ACCESS_KEY".to_string(),
            S3_BRIDGE_SECRET_ACCESS_KEY.to_string(),
        ),
    ]);
    super::log("S3 goes through the host's services; the guest holds no AWS credential");
}

fn vsock_to_host() -> io::Result<OwnedFd> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    connect(
        fd.as_raw_fd(),
        &VsockAddr::new(super::vsock::CID_HOST, HOST_SERVICES_PORT),
    )?;
    Ok(fd)
}

// The listener is bound before the tenant starts, so its first request finds the bridge there.
pub(super) fn start(config: &InstanceConfig) -> Option<Pid> {
    if !config.host_s3 {
        return None;
    }
    let listener = match TcpListener::bind(S3_BRIDGE_ADDRESS) {
        Ok(listener) => listener,
        Err(error) => {
            super::log(&format!(
                "the S3 bridge could not listen on {S3_BRIDGE_ADDRESS}: {error}"
            ));
            return None;
        }
    };
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Parent { child }) => Some(child),
        Ok(ForkResult::Child) => {
            let _ = nix::sys::signal::SigSet::all().thread_unblock();
            serve(&listener, vsock_to_host)
        }
        Err(error) => {
            super::log(&format!("the S3 bridge could not be started: {error}"));
            None
        }
    }
}

fn serve(listener: &TcpListener, upstream: fn() -> io::Result<OwnedFd>) -> ! {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let Ok((client, _)) = listener.accept() else {
            continue;
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let active = active.clone();
        std::thread::spawn(move || {
            if let Ok(host) = upstream() {
                let _ = relay(client, host);
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

fn relay(client: TcpStream, host: OwnedFd) -> io::Result<()> {
    let mut to_host = File::from(host);
    let mut from_host = to_host.try_clone()?;
    let mut from_client = client.try_clone()?;
    let mut to_client = client;
    let upstream = std::thread::spawn(move || {
        let _ = copy(&mut from_client, &mut to_host);
        let _ = nix::sys::socket::shutdown(to_host.as_raw_fd(), nix::sys::socket::Shutdown::Write);
    });
    let _ = copy(&mut from_host, &mut to_client);
    let _ = to_client.shutdown(Shutdown::Write);
    let _ = upstream.join();
    Ok(())
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<u64> {
    io::copy(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::OnceLock;

    static HOST: OnceLock<std::path::PathBuf> = OnceLock::new();

    fn unix_host() -> io::Result<OwnedFd> {
        Ok(OwnedFd::from(UnixStream::connect(
            HOST.get().expect("host path set"),
        )?))
    }

    fn config(host_s3: bool, environment: &[(&str, &str)]) -> InstanceConfig {
        InstanceConfig {
            http_port: 3000,
            layers: 1,
            program: "/app/server".into(),
            working_directory: "/app".into(),
            hostname: None,
            workload_role: None,
            host_s3,
            max_restarts: 1,
            initial_backoff_ms: 1,
            max_backoff_ms: 1,
            backoff_factor: 2.0,
            reset_after_ms: 1,
            nameservers: vec![],
            arguments: vec![],
            environment: environment
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn host_s3_replaces_every_credential_and_endpoint_the_tenant_named() {
        let mut host = config(
            true,
            &[
                ("AWS_ACCESS_KEY_ID", "AKIAREALKEY"),
                ("AWS_ENDPOINT_URL", "https://elsewhere.example"),
                ("AWS_WORKLOAD_IDENTITY", "async"),
                ("AWS_REGION", "eu-north-1"),
            ],
        );
        prepare(&mut host);
        let named = |key: &str| {
            host.environment
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(named("AWS_ACCESS_KEY_ID"), vec![S3_BRIDGE_ACCESS_KEY_ID]);
        assert_eq!(named("AWS_ENDPOINT_URL_S3"), vec![S3_BRIDGE_ENDPOINT]);
        assert!(named("AWS_ENDPOINT_URL").is_empty());
        assert!(named("AWS_WORKLOAD_IDENTITY").is_empty());
        assert_eq!(named("AWS_REGION"), vec!["eu-north-1"]);
        let mut plain = config(false, &[("AWS_ACCESS_KEY_ID", "kept")]);
        prepare(&mut plain);
        assert_eq!(
            plain.environment,
            vec![("AWS_ACCESS_KEY_ID".into(), "kept".into())]
        );
    }

    #[test]
    fn the_bridge_relays_both_ways_and_passes_on_each_half_close() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.sock");
        HOST.set(path.clone()).unwrap();
        let host = UnixListener::bind(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(&listener, unix_host));
        let service = std::thread::spawn(move || {
            let (mut stream, _) = host.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(b"reply to ").unwrap();
            stream.write_all(&request).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "reply to request");
        service.join().unwrap();
    }
}
