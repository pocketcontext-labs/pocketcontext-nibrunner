use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use guest_contract::vsock::{
    GUEST_VSOCK_FILENAME, HOST_SERVICES_PORT, MAX_SIGN_IN_EMAIL_FRAME, SIGN_IN_EMAIL_PORT,
};
use protocol::{AppId, DeploymentId, DesiredInstance, HostDesiredState};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::process::VmProcesses;
use crate::desired::DesiredStateCache;

const CONNECTIONS_PER_APP: usize = 32;
const CONNECTIONS_PER_HOST: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Service {
    S3,
    SignInEmail,
}

impl Service {
    fn socket_path(self, jail: &Path) -> PathBuf {
        let port = match self {
            Self::S3 => HOST_SERVICES_PORT,
            Self::SignInEmail => SIGN_IN_EMAIL_PORT,
        };
        jail.join(format!("{GUEST_VSOCK_FILENAME}_{port}"))
    }

    fn bind(self, jail: &Path, uid: u32, gid: u32) -> io::Result<UnixListener> {
        let path = self.socket_path(jail);
        let listener = crate::unix_socket::bind(&path)?;
        crate::unix_socket::own(&path, uid, gid)?;
        Ok(listener)
    }

    // The listener and jail supply all three fields; none come from guest bytes.
    fn header(self, app: &AppId, deployment: &DeploymentId) -> String {
        let verb = match self {
            Self::S3 => "CONNECT",
            Self::SignInEmail => "CONNECT-MAIL",
        };
        format!("{verb} {app} {deployment}\n")
    }

    async fn refuse(self, socket: &mut UnixStream, status: &str) {
        if self == Self::SignInEmail {
            // Closing a Unix stream with unread request bytes resets the peer after the reply.
            let mut request = Vec::new();
            let mut reader = BufReader::new((&mut *socket).take(MAX_SIGN_IN_EMAIL_FRAME as u64));
            let _ = timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut request)).await;
            let response = format!("{{\"status\":\"{status}\"}}\n");
            let _ = timeout(Duration::from_secs(1), socket.write_all(response.as_bytes())).await;
        }
    }
}

struct Relay {
    service: PathBuf,
    cache: Arc<Mutex<DesiredStateCache>>,
    host: Arc<Semaphore>,
}

struct Guest {
    app: AppId,
    deployment: DeploymentId,
    processes: VmProcesses,
    connections: Arc<Semaphore>,
    grants: std::sync::Mutex<Grants>,
}

#[derive(Clone, Copy, Default)]
struct Grants {
    s3: bool,
    sign_in_email: bool,
}

impl Grants {
    fn of(instance: &DesiredInstance) -> Self {
        Self {
            s3: instance.host_s3(),
            sign_in_email: instance.sign_in_email.is_some(),
        }
    }

    fn allow(self, service: Service) -> bool {
        match service {
            Service::S3 => self.s3,
            Service::SignInEmail => self.sign_in_email,
        }
    }
}

enum DesiredGuest {
    Same(Grants),
    Replaced,
    Removed,
}

impl DesiredGuest {
    fn in_document(desired: Option<&HostDesiredState>, app: &AppId, deployment: &DeploymentId) -> Self {
        let instance = desired.and_then(|desired| desired.instances.iter().find(|i| i.app_id == *app));
        match instance {
            Some(instance) if instance.deployment_id == *deployment => Self::Same(Grants::of(instance)),
            Some(_) => Self::Replaced,
            None => Self::Removed,
        }
    }
}

impl Guest {
    // A stopped or removed instance keeps its grants until its VM stops, so the terminate hook
    // can finish a final sync through the services; `detach` after the hook ends them. A
    // replacement revokes them for good, even if the app is removed afterwards.
    fn follow(&self, desired: Option<&HostDesiredState>) -> Grants {
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match DesiredGuest::in_document(desired, &self.app, &self.deployment) {
            DesiredGuest::Same(current) => *grants = current,
            DesiredGuest::Replaced => *grants = Grants::default(),
            DesiredGuest::Removed => {}
        }
        *grants
    }
}

impl Relay {
    async fn enabled(&self, guest: &Guest, service: Service) -> bool {
        if guest.processes.running_deployment(&guest.app).as_ref() != Some(&guest.deployment) {
            return false;
        }
        guest.follow(self.cache.lock().await.latest()).allow(service)
    }

    fn permits(&self, guest: &Guest) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let app = guest.connections.clone().try_acquire_owned().ok()?;
        let host = self.host.clone().try_acquire_owned().ok()?;
        Some((app, host))
    }

    async fn serve(self: Arc<Self>, guest: Arc<Guest>, kind: Service, mut socket: UnixStream) {
        let Some(permits) = self.permits(&guest) else {
            tracing::debug!(app_id = %guest.app, "host service connection refused: too many open");
            if kind == Service::SignInEmail {
                let _ = socket.try_write(b"{\"status\":\"throttled\"}\n");
            }
            return;
        };
        if !self.enabled(&guest, kind).await {
            tracing::debug!(app_id = %guest.app, "host service connection refused: not enabled for the running deployment");
            kind.refuse(&mut socket, "disabled").await;
            return;
        }
        let Ok(Ok(mut service)) = timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.service)).await else {
            tracing::warn!(app_id = %guest.app, "the host service socket could not be reached");
            kind.refuse(&mut socket, "temporarily_unavailable").await;
            return;
        };
        if service
            .write_all(kind.header(&guest.app, &guest.deployment).as_bytes())
            .await
            .is_err()
        {
            kind.refuse(&mut socket, "temporarily_unavailable").await;
            return;
        }
        let transfer = tokio::io::copy_bidirectional(&mut socket, &mut service);
        match kind {
            Service::S3 => {
                let _ = transfer.await;
            }
            Service::SignInEmail => {
                let _ = timeout(Duration::from_secs(12), transfer).await;
            }
        }
        drop(permits);
    }
}

pub(crate) struct HostServicesForwarder {
    relay: Option<Arc<Relay>>,
    listeners: Mutex<BTreeMap<AppId, JoinHandle<()>>>,
}

impl HostServicesForwarder {
    pub(crate) fn disabled() -> Self {
        Self {
            relay: None,
            listeners: Mutex::default(),
        }
    }

    pub(crate) fn new(service: Option<PathBuf>, cache: Arc<Mutex<DesiredStateCache>>) -> Self {
        let Some(service) = service else {
            return Self::disabled();
        };
        Self {
            relay: Some(Arc::new(Relay {
                service,
                cache,
                host: Arc::new(Semaphore::new(CONNECTIONS_PER_HOST)),
            })),
            listeners: Mutex::default(),
        }
    }

    pub(super) async fn attach(
        &self,
        app: &AppId,
        deployment: &DeploymentId,
        jail: &Path,
        uid: u32,
        gid: u32,
        processes: VmProcesses,
    ) -> io::Result<()> {
        let Some(relay) = self.relay.clone() else {
            return Ok(());
        };
        let mut listeners = self.listeners.lock().await;
        if let Some(previous) = listeners.remove(app) {
            previous.abort();
            let _ = previous.await;
        }
        let s3 = Service::S3.bind(jail, uid, gid)?;
        let mail = Service::SignInEmail.bind(jail, uid, gid)?;
        let guest = Arc::new(Guest {
            app: app.clone(),
            deployment: deployment.clone(),
            processes,
            connections: Arc::new(Semaphore::new(CONNECTIONS_PER_APP)),
            grants: std::sync::Mutex::default(),
        });
        let mut changes = {
            let cache = relay.cache.lock().await;
            guest.follow(cache.latest());
            cache.watch()
        };
        let task = tokio::spawn(async move {
            loop {
                let (kind, connection) = tokio::select! {
                    connection = s3.accept() => (Service::S3, connection),
                    connection = mail.accept() => (Service::SignInEmail, connection),
                    Ok(()) = changes.changed() => {
                        guest.follow(relay.cache.lock().await.latest());
                        continue;
                    }
                };
                let Ok((socket, _)) = connection else { break };
                tokio::spawn(relay.clone().serve(guest.clone(), kind, socket));
            }
        });
        listeners.insert(app.clone(), task);
        Ok(())
    }

    pub(super) async fn detach(&self, app: &AppId) {
        if let Some(task) = self.listeners.lock().await.remove(app) {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for HostServicesForwarder {
    fn drop(&mut self) {
        for task in self.listeners.get_mut().values() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
