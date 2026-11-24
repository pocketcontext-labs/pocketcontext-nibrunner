use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::*;
use crate::adapters::vm::process::VmRecord;
use crate::test_support::{deployment_id, desired_instance, desired_state};

const CERT: &[u8] = include_bytes!("../../../test_support/jwt/jwks-server-cert.pem");
const KEY: &[u8] = include_bytes!("../../../test_support/jwt/jwks-server-key.pem");

struct MailboxCapture {
    recipient: String,
    message: String,
}

struct Sink {
    messages: mpsc::Receiver<MailboxCapture>,
    connections: Arc<AtomicUsize>,
    port: u16,
}

async fn smtp_sink() -> Sink {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs = rustls_pemfile::certs(&mut &CERT[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut &KEY[..]).unwrap().unwrap();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    ));
    let (sender, messages) = mpsc::channel(16);
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::Relaxed);
            let sender = sender.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                let mut socket = BufReader::new(tls.accept(socket).await.unwrap());
                socket.write_all(b"220 test\r\n").await.unwrap();
                let mut line = String::new();
                let mut recipient = String::new();
                loop {
                    line.clear();
                    if socket.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let reply = if line.starts_with("EHLO ") {
                        "250-test\r\n250 AUTH PLAIN"
                    } else if line.trim_end() == "AUTH PLAIN AGZpeHR1cmUAcGFzcw==" {
                        "235 authenticated"
                    } else if line.trim_end() == "MAIL FROM:<sign-in@example.org>" {
                        "250 ok"
                    } else if let Some(address) = line
                        .trim_end()
                        .strip_prefix("RCPT TO:<")
                        .and_then(|s| s.strip_suffix('>'))
                    {
                        recipient = address.to_owned();
                        "250 ok"
                    } else if line.trim_end() == "DATA" {
                        socket.write_all(b"354 send\r\n").await.unwrap();
                        let mut message = String::new();
                        loop {
                            line.clear();
                            if socket.read_line(&mut line).await.unwrap() == 0 {
                                return;
                            }
                            if line == ".\r\n" {
                                break;
                            }
                            message.push_str(&line);
                        }
                        let reply = if message.contains("code is 222222.") {
                            "550 rejected"
                        } else if message.contains("code is 444444.") {
                            "timeout"
                        } else if message.contains("code is 333333.") {
                            ""
                        } else if message.contains("code is 555555.") {
                            "354 continue"
                        } else {
                            "250 accepted"
                        };
                        sender
                            .send(MailboxCapture {
                                recipient: recipient.clone(),
                                message,
                            })
                            .await
                            .unwrap();
                        if reply == "timeout" {
                            tokio::time::sleep(SMTP_TIMEOUT + Duration::from_secs(2)).await;
                            return;
                        }
                        if reply.is_empty() {
                            return;
                        }
                        reply
                    } else if line.trim_end() == "QUIT" {
                        "221 bye"
                    } else {
                        "500 invalid"
                    };
                    socket.write_all(format!("{reply}\r\n").as_bytes()).await.unwrap();
                }
            });
        }
    });
    Sink {
        port,
        messages,
        connections,
    }
}

async fn request(jail: &Path, bytes: &[u8]) -> String {
    let path = jail.join(format!("{GUEST_VSOCK_FILENAME}_{SIGN_IN_EMAIL_PORT}"));
    let mut socket = UnixStream::connect(path).await.unwrap();
    socket.write_all(bytes).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).await.unwrap();
    serde_json::from_str::<serde_json::Value>(&reply).unwrap()["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn jail_and_applied_deployment_select_the_only_mailbox_and_submission_is_never_replayed() {
    let mut trace = tempfile::tempfile().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(trace.try_clone().unwrap())
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let cache = Arc::new(Mutex::new(DesiredStateCache::new()));
    let mut sink = smtp_sink().await;
    let ca = root.path().join("ca.pem");
    std::fs::write(&ca, CERT).unwrap();
    let config = root.path().join("credential");
    std::fs::write(&config, format!("host='localhost'\nport={}\nusername='fixture'\npassword='pass'\nsender='sign-in@example.org'\nca_file='{}'\n", sink.port, ca.display())).unwrap();
    let service = SignInEmailService {
        delivery: Some(Arc::new(Delivery {
            smtp: Smtp::from_file(&config).unwrap(),
            cache: cache.clone(),
            rates: Mutex::default(),
            submissions: Semaphore::new(16),
        })),
        listeners: Mutex::default(),
    };
    let processes = VmProcesses::new(root.path().to_owned());
    let mut desired = desired_state(|s| s.instances.clear());
    for name in ["alpha", "beta"] {
        let app = AppId::parse(name).unwrap();
        let jail = root.path().join(name);
        std::fs::create_dir(&jail).unwrap();
        let owner = std::fs::metadata(&jail).unwrap();
        processes
            .write_record(&VmRecord {
                app_id: app.clone(),
                deployment_id: Some(deployment_id()),
                pid: std::process::id() as i32,
                host_boot_id: processes.boot_id().to_owned(),
                started_at_ms: 0,
                guest_image_version: None,
                exit_code: None,
                signal: None,
                stop_requested: false,
                jail_root: Some(jail.clone()),
                jail_uid: Some(owner.uid()),
            })
            .unwrap();
        service
            .attach(
                &app,
                &deployment_id(),
                &jail,
                owner.uid(),
                owner.gid(),
                processes.clone(),
            )
            .await
            .unwrap();
        desired.instances.push(desired_instance(|instance| {
            instance.app_id = app;
            instance.sign_in_email =
                Some(serde_json::from_value(json!({"recipient": format!("{name}@example.org")})).unwrap());
        }));
    }
    cache.lock().await.accept(desired.clone());
    let a = root.path().join("alpha");
    let b = root.path().join("beta");
    for line in [
        r#"{"code":123456}"#,
        r#"{"code":"１２３４５６"}"#,
        r#"{"code":"012345","recipient":"b@example.org"}"#,
        r#"{"code":"012345","code":"012345"}"#,
        r#"{"code":"012345","subject":"hi"}"#,
        r#"{"code":"012345","body":"hi"}"#,
        r#"{"code":"012345","header":"X"}"#,
        r#"["012345"]"#,
        "broken",
    ] {
        assert_eq!(
            request(&a, format!("{line}\n").as_bytes()).await,
            "invalid_request"
        );
    }
    assert_eq!(
        request(&a, &[b' '; MAX_SIGN_IN_EMAIL_FRAME]).await,
        "invalid_request"
    );
    assert_eq!(sink.connections.load(Ordering::Relaxed), 0);
    let (one, two) = tokio::join!(
        request(&a, b"{\"code\":\"012345\"}\n"),
        request(&b, b"{\"code\":\"111111\"}\n")
    );
    assert_eq!((one.as_str(), two.as_str()), ("accepted", "accepted"));
    for _ in 0..2 {
        let mail = sink.messages.recv().await.unwrap();
        let code = match mail.recipient.as_str() {
            "alpha@example.org" => "012345",
            "beta@example.org" => "111111",
            _ => panic!("wrong envelope recipient"),
        };
        assert!(mail.message.contains(&format!("To: {}\r\n", mail.recipient)));
        assert!(mail.message.contains("From: sign-in@example.org\r\n"));
        assert!(mail.message.contains("Subject: Your sign-in code\r\n"));
        assert!(mail.message.contains(&format!(
            "Your sign-in code is {code}.\r\n\r\nEnter this code in the app to sign in."
        )));
        assert!(!mail.message.contains("http"));
    }
    for code in ["222222", "333333", "444444", "555555"] {
        assert_eq!(
            request(&a, format!("{{\"code\":\"{code}\"}}\n").as_bytes()).await,
            "temporarily_unavailable"
        );
        assert!(sink.messages.recv().await.unwrap().message.contains(code));
    }
    let submitted = sink.connections.load(Ordering::Relaxed);
    assert_eq!(submitted, 6);
    desired.instances[0].sign_in_email = None;
    desired.instances[1].deployment_id = DeploymentId::parse("replaced").unwrap();
    cache.lock().await.accept(desired.clone());
    for jail in [&a, &b] {
        assert_eq!(request(jail, b"{\"code\":\"012345\"}\n").await, "disabled");
    }
    desired.instances[1].deployment_id = deployment_id();
    desired.instances[1].desired_state = DesiredInstanceState::Stopped;
    cache.lock().await.accept(desired);
    assert_eq!(request(&b, b"{\"code\":\"012345\"}\n").await, "disabled");
    assert_eq!(sink.connections.load(Ordering::Relaxed), submitted);
    service.detach(&AppId::parse("alpha").unwrap()).await;
    assert!(
        UnixStream::connect(a.join(format!("{GUEST_VSOCK_FILENAME}_{SIGN_IN_EMAIL_PORT}")))
            .await
            .is_err()
    );
    use std::io::{Read, Seek};
    trace.rewind().unwrap();
    let mut logs = String::new();
    trace.read_to_string(&mut logs).unwrap();
    assert!(logs.contains("sign-in email submission"));
    for private in [
        "012345",
        "Your sign-in code",
        "AGZpeHR1cmUAcGFzcw==",
        "alpha@example.org",
    ] {
        assert!(
            !logs.contains(private),
            "a sign-in secret or message reached tracing"
        );
    }
}

#[test]
fn the_send_limit_counts_both_apps_and_recipients_and_expires_old_requests() {
    let mut rate = RateLimits::default();
    let a = AppId::parse("a").unwrap();
    let b = AppId::parse("b").unwrap();
    let first = SignInMailbox::parse("a@example.org").unwrap();
    let second = SignInMailbox::parse("b@example.org").unwrap();
    let now = Instant::now();
    for _ in 0..RATE_LIMIT {
        assert!(rate.admit(&a, &first, now));
    }
    assert!(!rate.admit(&b, &first, now));
    assert!(!rate.admit(&a, &second, now));
    assert!(rate.admit(&b, &second, now));
    assert!(rate.admit(&a, &first, now + RATE_WINDOW));
}
