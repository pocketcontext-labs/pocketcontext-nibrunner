use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use protocol::AppId;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use guest_contract::vsock::{GUEST_VSOCK_FILENAME, IDENTITY_PORT, MAX_IDENTITY_BYTES};

pub(crate) struct Identities {
    sources: PathBuf,
    roles: PathBuf,
    listeners: Mutex<BTreeMap<AppId, JoinHandle<()>>>,
}

pub(super) fn socket_path(jail: &Path) -> PathBuf {
    jail.join(format!("{GUEST_VSOCK_FILENAME}_{IDENTITY_PORT}"))
}

impl Identities {
    pub(crate) fn new(sources: PathBuf, roles: PathBuf) -> Self {
        Self {
            sources,
            roles,
            listeners: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn role_for(&self, app: &AppId) -> io::Result<String> {
        read_field(&self.roles.join(app.as_str()).join("role-arn"), 2048)
    }

    pub(crate) async fn attach(&self, app: &AppId, jail: &Path) -> io::Result<()> {
        let source = self.sources.join(app.as_str());
        let mut listeners = self.listeners.lock().await;
        if let Some(previous) = listeners.remove(app) {
            previous.abort();
        }
        let socket = socket_path(jail);
        if !source.join("role-arn").try_exists()?
            && !self.roles.join(app.as_str()).join("role-arn").try_exists()?
        {
            return Ok(());
        }
        let listener = crate::unix_socket::bind(&socket)?;
        let owner = std::fs::metadata(jail)?;
        crate::unix_socket::own(&socket, owner.uid(), owner.gid())?;
        // The jail's listener fixes the app identity before the guest connects. There is no
        // guest-supplied path, role or subject in the protocol.
        let task = tokio::spawn(async move {
            while let Ok((mut connection, _)) = listener.accept().await {
                if let Ok(frame) = credential_frame(&source) {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), connection.write_all(frame.as_bytes()))
                            .await;
                }
            }
        });
        listeners.insert(app.clone(), task);
        Ok(())
    }

    pub(crate) async fn detach(&self, app: &AppId) {
        if let Some(task) = self.listeners.lock().await.remove(app) {
            task.abort();
        }
    }
}

fn read_field(path: &Path, limit: usize) -> io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_string(&mut text)?;
    if text.len() > limit || text.trim().is_empty() || text.trim().contains(char::is_whitespace) {
        return Err(io::Error::other("invalid workload identity field"));
    }
    Ok(text.trim().to_owned())
}

fn credential_frame(source: &Path) -> io::Result<String> {
    let role = read_field(&source.join("role-arn"), 2048)?;
    let token = read_field(&source.join("token"), MAX_IDENTITY_BYTES - 2049)?;
    let invalid = || io::Error::other("missing or expired workload identity");
    let payload = token
        .split('.')
        .nth(1)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
        .ok_or_else(invalid)?;
    // STS verifies the signature. This expiry check prevents a stalled host issuer from
    // releasing a restored guest with the same expired file it had when it fell asleep.
    let exp = serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()
        .and_then(|claims| claims.get("exp").and_then(serde_json::Value::as_u64))
        .ok_or_else(invalid)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if exp <= now + 10 {
        return Err(invalid());
    }
    Ok(format!("{role}\n{token}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn each_jail_reads_only_its_own_current_token() {
        use tokio::io::AsyncReadExt;
        let root = tempfile::tempdir().unwrap();
        let sources = root.path().join("credentials");
        let identities = Identities::new(sources.clone(), root.path().join("roles"));
        for name in ["app-a", "app-b"] {
            let source = sources.join(name);
            std::fs::create_dir_all(&source).unwrap();
            let claims = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
            std::fs::write(source.join("token"), format!("header.{claims}.{name}")).unwrap();
            std::fs::write(
                source.join("role-arn"),
                format!("arn:aws:iam::123456789012:role/{name}"),
            )
            .unwrap();
            let jail = root.path().join(name);
            std::fs::create_dir(&jail).unwrap();
            identities
                .attach(&AppId::parse(name).unwrap(), &jail)
                .await
                .unwrap();
        }
        let read = |name: &str| {
            let socket = socket_path(&root.path().join(name));
            async move {
                let mut client = tokio::net::UnixStream::connect(socket).await.unwrap();
                let mut frame = String::new();
                client.read_to_string(&mut frame).await.unwrap();
                frame
            }
        };
        assert!(read("app-a").await.ends_with(".app-a\n"));
        assert!(read("app-b").await.ends_with(".app-b\n"));
        let source = sources.join("app-a");
        let fresh = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444801}"#);
        std::fs::write(source.join("next"), format!("header.{fresh}.rotated")).unwrap();
        std::fs::rename(source.join("next"), source.join("token")).unwrap();
        assert!(read("app-a").await.ends_with(".rotated\n"));
        std::fs::remove_file(source.join("token")).unwrap();
        assert!(read("app-a").await.is_empty());
    }

    #[tokio::test]
    async fn a_static_role_keeps_its_jail_listener_through_a_broker_outage() {
        use tokio::io::AsyncReadExt;
        let root = tempfile::tempdir().unwrap();
        let app = AppId::parse("app-a").unwrap();
        let sources = root.path().join("tokens");
        let roles = root.path().join("roles");
        let role_dir = roles.join(app.as_str());
        std::fs::create_dir_all(&role_dir).unwrap();
        let role = "arn:aws:iam::123456789012:role/app-a";
        std::fs::write(role_dir.join("role-arn"), role).unwrap();
        let jail = root.path().join("jail");
        std::fs::create_dir(&jail).unwrap();
        let identities = Identities::new(sources.clone(), roles);
        assert_eq!(identities.role_for(&app).unwrap(), role);
        identities.attach(&app, &jail).await.unwrap();
        let read = || async {
            let mut socket = tokio::net::UnixStream::connect(socket_path(&jail)).await.unwrap();
            let mut result = String::new();
            socket.read_to_string(&mut result).await.unwrap();
            result
        };
        assert!(read().await.is_empty());
        let source = sources.join(app.as_str());
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("role-arn"), role).unwrap();
        let claims = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        std::fs::write(source.join("token"), format!("header.{claims}.token")).unwrap();
        assert!(read().await.ends_with(".token\n"));
    }

    #[test]
    fn an_expired_host_token_cannot_release_a_guest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("role-arn"), "arn:aws:iam::123456789012:role/demo").unwrap();
        for (expiry, allowed) in [(0_u64, false), (u64::MAX, true)] {
            let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{expiry}}}"#));
            std::fs::write(dir.path().join("token"), format!("header.{claims}.sig")).unwrap();
            assert_eq!(credential_frame(dir.path()).is_ok(), allowed);
        }
    }
}
