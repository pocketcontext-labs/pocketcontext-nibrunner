use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use guest_contract::vsock::{GUEST_VSOCK_FILENAME, HOST_SERVICES_PORT};
use protocol::{AppId, DeploymentId, DesiredInstanceState};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::process::VmProcesses;
use crate::desired::DesiredStateCache;

const CONNECTIONS_PER_APP: usize = 32;
const CONNECTIONS_PER_HOST: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn socket_path(jail: &Path) -> PathBuf {
    jail.join(format!("{GUEST_VSOCK_FILENAME}_{HOST_SERVICES_PORT}"))
}

// The service learns the app and deployment from this line alone. Both come from the jail the
// guest connected through, never from the guest.
pub(crate) fn header(app: &AppId, deployment: &DeploymentId) -> String {
    format!("CONNECT {app} {deployment}\n")
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
}

impl Relay {
    async fn enabled(&self, guest: &Guest) -> bool {
        if guest.processes.running_deployment(&guest.app).as_ref() != Some(&guest.deployment) {
            return false;
        }
        let cache = self.cache.lock().await;
        cache.latest().is_some_and(|desired| {
            desired.instances.iter().any(|i| {
                i.app_id == guest.app
                    && i.deployment_id == guest.deployment
                    && i.desired_state != DesiredInstanceState::Stopped
                    && i.host_s3()
            })
        })
    }

    fn permits(&self, guest: &Guest) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let app = guest.connections.clone().try_acquire_owned().ok()?;
        let host = self.host.clone().try_acquire_owned().ok()?;
        Some((app, host))
    }

    async fn serve(self: Arc<Self>, guest: Arc<Guest>, mut socket: UnixStream) {
        let Some(permits) = self.permits(&guest) else {
            tracing::debug!(app_id = %guest.app, "host service connection refused: too many open");
            return;
        };
        if !self.enabled(&guest).await {
            tracing::debug!(app_id = %guest.app, "host service connection refused: not enabled for the running deployment");
            return;
        }
        let Ok(Ok(mut service)) = timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.service)).await else {
            tracing::warn!(app_id = %guest.app, "the host service socket could not be reached");
            return;
        };
        if service
            .write_all(header(&guest.app, &guest.deployment).as_bytes())
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut socket, &mut service).await;
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
        let path = socket_path(jail);
        let listener = crate::unix_socket::bind(&path)?;
        crate::unix_socket::own(&path, uid, gid)?;
        let guest = Arc::new(Guest {
            app: app.clone(),
            deployment: deployment.clone(),
            processes,
            connections: Arc::new(Semaphore::new(CONNECTIONS_PER_APP)),
        });
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(relay.clone().serve(guest.clone(), socket));
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
