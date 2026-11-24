use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use protocol::{
    AppId, DeploymentId, GuestPort, HookEvent, HookOutcome, Ipv4Address, ReportedHook, SecretString,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::process::VmProcesses;
use crate::clock::now_timestamp;
use crate::json_store::{read_json, write_json};
use crate::ports::VmError;
use crate::state::SharedState;

#[derive(Deserialize, Serialize)]
pub(super) struct LaunchHooks {
    pub(super) port: GuestPort,
    pub(super) token: SecretString,
    deployment: DeploymentId,
}

const FILE: &str = "lifecycle-hooks.json";

impl LaunchHooks {
    pub(super) fn stage(
        directory: &Path,
        deployment: &DeploymentId,
        port: Option<GuestPort>,
    ) -> Result<Option<Self>, VmError> {
        let path = directory.join(FILE);
        let Some(port) = port else {
            match std::fs::remove_file(path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(VmError::Host(e.to_string())),
            }
            return Ok(None);
        };
        let previous: Option<Self> = read_json(&path).map_err(|e| VmError::Host(e.to_string()))?;
        let token = previous.map_or_else(
            || SecretString::parse(uuid::Uuid::new_v4().simple().to_string()).expect("a UUID fits a secret"),
            |previous| previous.token,
        );
        let hooks = Self {
            deployment: deployment.clone(),
            port,
            token,
        };
        write_json(&path, &hooks).map_err(|e| VmError::Host(e.to_string()))?;
        Ok(Some(hooks))
    }
}

pub(crate) struct HookClient {
    http: reqwest::Client,
    timeout: Duration,
    active: Mutex<BTreeMap<AppId, Weak<AsyncMutex<()>>>>,
}

impl HookClient {
    pub(crate) fn new(timeout: Duration) -> Self {
        crate::install_crypto_provider();
        Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .pool_max_idle_per_host(0)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()
                .expect("a direct HTTP client"),
            timeout,
            active: Mutex::default(),
        }
    }

    async fn sequence(&self, app: &AppId) -> OwnedMutexGuard<()> {
        let lock = {
            let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
            active.retain(|_, lock| lock.strong_count() != 0);
            let entry = active.entry(app.clone()).or_default();
            entry.upgrade().unwrap_or_else(|| {
                let lock = Arc::new(AsyncMutex::new(()));
                *entry = Arc::downgrade(&lock);
                lock
            })
        };
        lock.lock_owned().await
    }

    pub(super) async fn call(
        &self,
        app: &AppId,
        event: HookEvent,
        directory: &Path,
        processes: &VmProcesses,
        state: &SharedState,
    ) {
        let hooks = match read_json::<LaunchHooks>(&directory.join(FILE)) {
            Ok(Some(hooks)) => hooks,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%app, %error, "could not read the guest lifecycle hook binding");
                return;
            }
        };
        let guard = self.sequence(app).await;
        let Some(record) = state.record(app).await else {
            return;
        };
        if record.deployment_id != hooks.deployment
            || processes.running_deployment(app).as_ref() != Some(&hooks.deployment)
        {
            return;
        }
        let Some(address) = record.guest_ipv4 else { return };
        let http = self.http.clone();
        let timeout = self.timeout;
        let state = state.clone();
        let app = app.clone();
        let send = async move {
            let _guard = guard;
            let result = send(&http, timeout, &address, &hooks, event).await;
            state
                .update_record(&app, |record| {
                    if record.deployment_id == hooks.deployment {
                        record.last_hook = Some(result);
                    }
                })
                .await;
            state.signal_report();
        };
        if event == HookEvent::Resume {
            tokio::spawn(send);
        } else {
            send.await;
        }
    }
}

async fn send(
    http: &reqwest::Client,
    timeout: Duration,
    address: &Ipv4Address,
    hooks: &LaunchHooks,
    event: HookEvent,
) -> ReportedHook {
    let name = match event {
        HookEvent::Suspend => "suspend",
        HookEvent::Resume => "resume",
        HookEvent::Terminate => "terminate",
    };
    let url = format!("http://{address}:{}/hooks/{name}", hooks.port);
    let started = Instant::now();
    let response = http
        .post(url)
        .bearer_auth(hooks.token.expose())
        .timeout(timeout)
        .send()
        .await;
    let outcome = match response {
        Ok(response) if response.status().is_success() => HookOutcome::Ok,
        Ok(_) => HookOutcome::Error,
        Err(error) if error.is_timeout() => HookOutcome::Timeout,
        Err(_) => HookOutcome::Unreachable,
    };
    ReportedHook {
        time: now_timestamp(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        event,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vm::process::VmRecord;
    use crate::state::HostState;
    use crate::test_support::{app_config, app_id, deployment_id, instance_record};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn a_private_hook_port_never_enters_the_relay_and_cannot_overlap_a_public_port() {
        let mut config = app_config(|_| {});
        let port = GuestPort::new(8081).unwrap();
        config.hooks = Some(protocol::LifecycleHooks { port });
        assert!(config.validate_ports().is_ok());
        assert!(config.all_ports().iter().all(|p| p.guest_port != port));
        config.ports.push(protocol::InstancePort {
            name: protocol::PortName::parse("extra").unwrap(),
            guest_port: port,
        });
        assert!(config.validate_ports().is_err());
        config.ports.clear();
        config.hooks = Some(protocol::LifecycleHooks {
            port: GuestPort::new(config.http_port.get()).unwrap(),
        });
        assert!(config.validate_ports().is_err());
    }

    #[tokio::test]
    async fn hooks_use_the_launch_bearer_and_report_outcomes_only_for_the_applied_deployment() {
        let dir = tempfile::tempdir().unwrap();
        let process = VmProcesses::new(dir.path().into());
        let app = app_id();
        let deployment = deployment_id();
        process
            .write_record(&VmRecord {
                app_id: app.clone(),
                deployment_id: Some(deployment.clone()),
                pid: std::process::id() as i32,
                host_boot_id: process.boot_id().to_owned(),
                started_at_ms: 0,
                guest_image_version: None,
                exit_code: None,
                signal: None,
                stop_requested: false,
                jail_root: None,
                jail_uid: None,
            })
            .unwrap();
        let state = HostState::shared();
        state
            .put_record(instance_record(|r| {
                r.guest_ipv4 = Some(Ipv4Address::parse("127.0.0.1").unwrap())
            }))
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = GuestPort::new(listener.local_addr().unwrap().port()).unwrap();
        let hooks = LaunchHooks::stage(dir.path(), &deployment, Some(port))
            .unwrap()
            .unwrap();
        let repeated = LaunchHooks::stage(dir.path(), &deployment, Some(port))
            .unwrap()
            .unwrap();
        assert_eq!(hooks.token, repeated.token);
        assert_eq!(
            std::fs::metadata(dir.path().join(FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let client = HookClient::new(Duration::from_millis(300));
        let server = tokio::spawn(async move {
            for (name, status) in [("suspend", 503), ("resume", 204), ("terminate", 0)] {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = BufReader::new(socket);
                let mut request = String::new();
                connection.read_line(&mut request).await.unwrap();
                assert_eq!(request, format!("POST /hooks/{name} HTTP/1.1\r\n"));
                let mut authenticated = false;
                loop {
                    let mut line = String::new();
                    let count = connection.read_line(&mut line).await.unwrap();
                    assert_ne!(count, 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("Authorization") {
                            authenticated = value.trim() == format!("Bearer {}", hooks.token.expose());
                        }
                    }
                }
                assert!(authenticated);
                if status == 0 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    connection.get_mut().write_all(format!("HTTP/1.1 {status} response\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                }
            }
        });
        for (event, expected) in [
            (HookEvent::Suspend, HookOutcome::Error),
            (HookEvent::Resume, HookOutcome::Ok),
            (HookEvent::Terminate, HookOutcome::Timeout),
        ] {
            client.call(&app, event, dir.path(), &process, &state).await;
            let _completed = client.sequence(&app).await;
            let report = state.record(&app).await.unwrap().last_hook.unwrap();
            assert_eq!((report.event, report.outcome), (event, expected));
        }
        server.await.unwrap();
        client
            .call(&app, HookEvent::Suspend, dir.path(), &process, &state)
            .await;
        assert_eq!(
            state.record(&app).await.unwrap().last_hook.unwrap().outcome,
            HookOutcome::Unreachable
        );
        state
            .update_record(&app, |r| {
                r.deployment_id = DeploymentId::parse("replaced").unwrap();
                r.last_hook = None;
            })
            .await;
        client
            .call(&app, HookEvent::Terminate, dir.path(), &process, &state)
            .await;
        assert!(state.record(&app).await.unwrap().last_hook.is_none());
    }
}
