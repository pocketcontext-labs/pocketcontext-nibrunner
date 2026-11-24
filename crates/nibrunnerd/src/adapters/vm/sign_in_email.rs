use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guest_contract::vsock::{GUEST_VSOCK_FILENAME, MAX_SIGN_IN_EMAIL_FRAME, SIGN_IN_EMAIL_PORT};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{AsyncSmtpConnection, Certificate, TlsParameters};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::response::Severity;
use lettre::Message;
use protocol::{AppId, DeploymentId, DesiredInstanceState, SignInMailbox};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::process::VmProcesses;
use crate::desired::DesiredStateCache;

const SMTP_TIMEOUT: Duration = Duration::from_secs(8);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT: usize = 5;
const MAX_RATE_KEYS: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpCredential {
    host: String,
    #[serde(default = "implicit_tls_port")]
    port: u16,
    username: String,
    password: String,
    sender: SignInMailbox,
    ca_file: Option<PathBuf>,
}

fn implicit_tls_port() -> u16 {
    465
}

struct Smtp {
    host: String,
    port: u16,
    credentials: Credentials,
    sender: Mailbox,
    tls: TlsParameters,
}

impl Smtp {
    fn from_file(path: &Path) -> Result<Self, ()> {
        let mut contents = String::new();
        let file = std::fs::File::open(path).map_err(|_| ())?;
        std::io::Read::read_to_string(&mut std::io::Read::take(file, 16385), &mut contents)
            .map_err(|_| ())?;
        if contents.len() > 16384 {
            return Err(());
        }
        let config: SmtpCredential = toml::from_str(&contents).map_err(|_| ())?;
        if config.host.is_empty()
            || config.port == 0
            || config.username.is_empty()
            || config.password.is_empty()
        {
            return Err(());
        }
        let mut tls = TlsParameters::builder(config.host.clone());
        if let Some(file) = config.ca_file {
            tls = tls.add_root_certificate(
                Certificate::from_pem(&std::fs::read(file).map_err(|_| ())?).map_err(|_| ())?,
            );
        }
        Ok(Self {
            sender: config.sender.as_str().parse().map_err(|_| ())?,
            host: config.host,
            port: config.port,
            credentials: Credentials::new(config.username, config.password),
            tls: tls.build().map_err(|_| ())?,
        })
    }

    async fn connect(&self) -> Result<AsyncSmtpConnection, ()> {
        let mut connection = AsyncSmtpConnection::connect_tokio1(
            (self.host.as_str(), self.port),
            Some(SMTP_TIMEOUT),
            &ClientId::default(),
            Some(self.tls.clone()),
            None,
        )
        .await
        .map_err(|_| ())?;
        if !connection
            .auth(&[Mechanism::Plain], &self.credentials)
            .await
            .map_err(|_| ())?
            .has_code(235)
        {
            return Err(());
        }
        Ok(connection)
    }

    fn message(&self, recipient: &SignInMailbox, code: &str) -> Result<Message, ()> {
        Message::builder()
            .from(self.sender.clone())
            .to(recipient.as_str().parse().map_err(|_| ())?)
            .subject("Your sign-in code")
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(format!(
                "Your sign-in code is {code}.\r\n\r\nEnter this code in the app to sign in."
            ))
            .map_err(|_| ())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    code: String,
}

async fn read_code(socket: &mut UnixStream) -> Option<String> {
    let mut frame = Vec::new();
    let mut reader = BufReader::new(socket.take(MAX_SIGN_IN_EMAIL_FRAME as u64));
    reader.read_until(b'\n', &mut frame).await.ok()?;
    if frame.last() != Some(&b'\n') || frame.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let request: Request = serde_json::from_slice(&frame).ok()?;
    (request.code.len() == 6 && request.code.bytes().all(|c| c.is_ascii_digit())).then_some(request.code)
}

#[derive(Default)]
struct RateLimits {
    apps: BTreeMap<AppId, Vec<Instant>>,
    recipients: BTreeMap<String, Vec<Instant>>,
}

impl RateLimits {
    fn admit(&mut self, app: &AppId, recipient: &SignInMailbox, now: Instant) -> bool {
        fn expire<K: Ord>(map: &mut BTreeMap<K, Vec<Instant>>, now: Instant) {
            map.retain(|_, times| {
                times.retain(|time| now.duration_since(*time) < RATE_WINDOW);
                !times.is_empty()
            });
        }
        expire(&mut self.apps, now);
        expire(&mut self.recipients, now);
        let address = recipient.as_str().to_ascii_lowercase();
        if self
            .apps
            .get(app)
            .map_or(self.apps.len() >= MAX_RATE_KEYS, |v| v.len() >= RATE_LIMIT)
            || self
                .recipients
                .get(&address)
                .map_or(self.recipients.len() >= MAX_RATE_KEYS, |v| v.len() >= RATE_LIMIT)
        {
            return false;
        }
        self.apps.entry(app.clone()).or_default().push(now);
        self.recipients.entry(address).or_default().push(now);
        true
    }
}

struct Delivery {
    smtp: Smtp,
    cache: Arc<Mutex<DesiredStateCache>>,
    rates: Mutex<RateLimits>,
    submissions: Semaphore,
}

struct Guest {
    app: AppId,
    deployment: DeploymentId,
    processes: VmProcesses,
}

impl Delivery {
    async fn recipient(&self, guest: &Guest) -> Option<SignInMailbox> {
        if guest.processes.running_deployment(&guest.app).as_ref() != Some(&guest.deployment) {
            return None;
        }
        let cache = self.cache.lock().await;
        let instance = cache.latest()?.instances.iter().find(|i| {
            i.app_id == guest.app
                && i.deployment_id == guest.deployment
                && i.desired_state != DesiredInstanceState::Stopped
        })?;
        Some(instance.sign_in_email.as_ref()?.recipient.clone())
    }

    async fn submit(&self, guest: &Guest, code: &str) -> &'static str {
        let Some(recipient) = self.recipient(guest).await else {
            return "disabled";
        };
        let Ok(_permit) = self.submissions.try_acquire() else {
            return "throttled";
        };
        if !self
            .rates
            .lock()
            .await
            .admit(&guest.app, &recipient, Instant::now())
        {
            return "throttled";
        }
        let Ok(message) = self.smtp.message(&recipient, code) else {
            return "temporarily_unavailable";
        };
        let Ok(mut smtp) = self.smtp.connect().await else {
            return "temporarily_unavailable";
        };
        if self.recipient(guest).await.as_ref() != Some(&recipient) {
            return "disabled";
        }
        if smtp
            .send(message.envelope(), &message.formatted())
            .await
            .is_ok_and(|reply| reply.code().severity == Severity::PositiveCompletion)
        {
            "accepted"
        } else {
            "temporarily_unavailable"
        }
    }

    async fn serve(&self, guest: &Guest, mut socket: UnixStream) {
        let result = match timeout(Duration::from_secs(2), read_code(&mut socket)).await {
            Ok(Some(code)) => timeout(SMTP_TIMEOUT, self.submit(guest, &code))
                .await
                .unwrap_or("temporarily_unavailable"),
            _ => "invalid_request",
        };
        if result == "accepted" || result == "temporarily_unavailable" {
            tracing::info!(app_id = %guest.app, deployment_id = %guest.deployment, outcome = result, "sign-in email submission");
        } else {
            tracing::debug!(app_id = %guest.app, deployment_id = %guest.deployment, outcome = result, "sign-in email request");
        }
        let reply = format!("{{\"status\":\"{result}\"}}\n");
        let _ = timeout(Duration::from_secs(1), socket.write_all(reply.as_bytes())).await;
    }
}

pub(crate) struct SignInEmailService {
    delivery: Option<Arc<Delivery>>,
    listeners: Mutex<BTreeMap<AppId, JoinHandle<()>>>,
}

impl SignInEmailService {
    pub(crate) fn disabled() -> Self {
        Self {
            delivery: None,
            listeners: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn from_service_credentials(cache: Arc<Mutex<DesiredStateCache>>) -> Self {
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Self::disabled();
        };
        let path = PathBuf::from(directory).join("sign-in-email.toml");
        Self::from_file(&path, cache)
    }

    pub(super) fn from_file(path: &Path, cache: Arc<Mutex<DesiredStateCache>>) -> Self {
        if !path.exists() {
            return Self::disabled();
        }
        let Ok(smtp) = Smtp::from_file(path) else {
            tracing::error!("the sign-in email service credential could not be loaded");
            return Self::disabled();
        };
        Self {
            delivery: Some(Arc::new(Delivery {
                smtp,
                cache,
                rates: Mutex::default(),
                submissions: Semaphore::new(16),
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
        let Some(delivery) = self.delivery.clone() else {
            return Ok(());
        };
        let mut listeners = self.listeners.lock().await;
        if let Some(previous) = listeners.remove(app) {
            previous.abort();
            let _ = previous.await;
        }
        let path = jail.join(format!("{GUEST_VSOCK_FILENAME}_{SIGN_IN_EMAIL_PORT}"));
        let listener = crate::unix_socket::bind(&path)?;
        crate::unix_socket::own(&path, uid, gid)?;
        let guest = Guest {
            app: app.clone(),
            deployment: deployment.clone(),
            processes,
        };
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                delivery.serve(&guest, socket).await;
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

impl Drop for SignInEmailService {
    fn drop(&mut self) {
        for task in self.listeners.get_mut().values() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
