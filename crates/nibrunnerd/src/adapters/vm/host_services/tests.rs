use std::os::unix::fs::MetadataExt;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::UnixListener;

use protocol::DesiredInstanceState;

use super::*;
use crate::adapters::vm::process::VmRecord;
use crate::test_support::{deployment_id, desired_instance, desired_state};

struct Fixture {
    root: tempfile::TempDir,
    forwarder: HostServicesForwarder,
    cache: Arc<Mutex<DesiredStateCache>>,
    service: UnixListener,
    processes: VmProcesses,
}

async fn fixture(apps: &[(&str, bool)]) -> Fixture {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let service_path = root.path().join("service.sock");
    let service = UnixListener::bind(&service_path).unwrap();
    let cache = Arc::new(Mutex::new(DesiredStateCache::new()));
    let forwarder = HostServicesForwarder::new(Some(service_path), cache.clone());
    let processes = VmProcesses::new(root.path().to_owned());
    let mut desired = desired_state(|s| s.instances.clear());
    for (name, enabled) in apps {
        let enabled = *enabled;
        desired.instances.push(desired_instance(|instance| {
            instance.app_id = AppId::parse(*name).unwrap();
            instance.host_services = enabled.then_some(protocol::HostServices { s3: true });
        }));
    }
    cache.lock().await.accept(desired);
    for (name, _) in apps {
        let app = AppId::parse(*name).unwrap();
        let jail = root.path().join(name);
        std::fs::create_dir(&jail).unwrap();
        let owner = std::fs::metadata(&jail).unwrap();
        processes
            .write_record(&running_record(&app, &jail, &processes))
            .unwrap();
        forwarder
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
    }
    Fixture {
        root,
        forwarder,
        cache,
        service,
        processes,
    }
}

fn running_record(app: &AppId, jail: &Path, processes: &VmProcesses) -> VmRecord {
    VmRecord {
        app_id: app.clone(),
        deployment_id: Some(deployment_id()),
        pid: std::process::id() as i32,
        host_boot_id: processes.boot_id().to_owned(),
        started_at_ms: 0,
        guest_image_version: None,
        exit_code: None,
        signal: None,
        stop_requested: false,
        jail_root: Some(jail.to_owned()),
        jail_uid: Some(std::fs::metadata(jail).unwrap().uid()),
    }
}

impl Fixture {
    async fn change_desired(&self, change: impl FnOnce(&mut HostDesiredState)) {
        let mut desired = self.cache.lock().await.latest().unwrap().clone();
        change(&mut desired);
        self.cache.lock().await.accept(desired);
    }

    async fn reaches_the_service(&self, app: &str) -> bool {
        let mut client = guest(&self.root.path().join(app)).await;
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let Ok(accepted) = tokio::time::timeout(Duration::from_secs(2), self.service.accept()).await else {
            return false;
        };
        let (service, _) = accepted.unwrap();
        let mut line = String::new();
        BufReader::new(service).read_line(&mut line).await.unwrap();
        line == format!("CONNECT {app} {}\n", deployment_id())
    }
}

async fn guest(jail: &Path) -> UnixStream {
    UnixStream::connect(Service::S3.socket_path(jail)).await.unwrap()
}

async fn closed_unanswered(mut socket: UnixStream) -> bool {
    let mut byte = [0; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn a_guest_reaches_the_service_under_its_jails_app_and_running_deployment() {
    let f = fixture(&[("alpha", true)]).await;
    let mut client = guest(&f.root.path().join("alpha")).await;
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let (service, _) = f.service.accept().await.unwrap();
    let mut service = BufReader::new(service);
    let mut line = String::new();
    service.read_line(&mut line).await.unwrap();
    assert_eq!(line, format!("CONNECT alpha {}\n", deployment_id()));
    let mut request = [0; 18];
    service.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET / HTTP/1.1\r\n\r\n");
    service.get_mut().write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
    let mut reply = [0; 17];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"HTTP/1.1 200 OK\r\n");
    f.forwarder.detach(&AppId::parse("alpha").unwrap()).await;
}

#[tokio::test]
async fn a_guest_without_host_services_or_with_a_replaced_deployment_reaches_nothing() {
    let f = fixture(&[("alpha", false), ("beta", true)]).await;
    assert!(closed_unanswered(guest(&f.root.path().join("alpha")).await).await);
    let mut desired = f.cache.lock().await.latest().unwrap().clone();
    desired.instances[1].deployment_id = DeploymentId::parse("replaced").unwrap();
    f.cache.lock().await.accept(desired);
    assert!(closed_unanswered(guest(&f.root.path().join("beta")).await).await);
    let accepted = tokio::time::timeout(Duration::from_millis(200), f.service.accept()).await;
    assert!(accepted.is_err(), "the service was reached");
}

#[tokio::test]
async fn a_stopping_guest_reaches_the_service_until_its_vm_stops() {
    let f = fixture(&[("alpha", true)]).await;
    let alpha = AppId::parse("alpha").unwrap();
    let jail = f.root.path().join("alpha");
    f.change_desired(|desired| desired.instances[0].desired_state = DesiredInstanceState::Stopped)
        .await;
    assert!(f.reaches_the_service("alpha").await);
    let mut stopping = running_record(&alpha, &jail, &f.processes);
    stopping.stop_requested = true;
    f.processes.write_record(&stopping).unwrap();
    assert!(closed_unanswered(guest(&jail).await).await);
    f.forwarder.detach(&alpha).await;
    assert!(UnixStream::connect(Service::S3.socket_path(&jail)).await.is_err());
}

#[tokio::test]
async fn a_guest_removed_from_the_desired_state_reaches_the_service_until_its_vm_stops() {
    let f = fixture(&[("alpha", true)]).await;
    let alpha = AppId::parse("alpha").unwrap();
    let jail = f.root.path().join("alpha");
    f.change_desired(|desired| desired.instances.clear()).await;
    assert!(f.reaches_the_service("alpha").await);
    let mut exited = running_record(&alpha, &jail, &f.processes);
    exited.exit_code = Some(0);
    f.processes.write_record(&exited).unwrap();
    assert!(closed_unanswered(guest(&jail).await).await);
}

#[tokio::test]
async fn a_removed_guest_whose_host_services_were_never_enabled_reaches_nothing() {
    let f = fixture(&[("alpha", false)]).await;
    f.change_desired(|desired| desired.instances.clear()).await;
    assert!(closed_unanswered(guest(&f.root.path().join("alpha")).await).await);
}

#[tokio::test]
async fn a_stopping_guest_whose_deployment_was_replaced_reaches_nothing() {
    let f = fixture(&[("alpha", true)]).await;
    f.change_desired(|desired| {
        desired.instances[0].deployment_id = DeploymentId::parse("replaced").unwrap();
        desired.instances[0].desired_state = DesiredInstanceState::Stopped;
    })
    .await;
    assert!(closed_unanswered(guest(&f.root.path().join("alpha")).await).await);
    f.change_desired(|desired| desired.instances.clear()).await;
    assert!(closed_unanswered(guest(&f.root.path().join("alpha")).await).await);
    let accepted = tokio::time::timeout(Duration::from_millis(200), f.service.accept()).await;
    assert!(accepted.is_err(), "the service was reached");
}

#[tokio::test]
async fn a_guest_replaced_then_removed_between_connections_reaches_nothing() {
    let f = fixture(&[("alpha", true)]).await;
    f.change_desired(|desired| desired.instances[0].deployment_id = DeploymentId::parse("replaced").unwrap())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    f.change_desired(|desired| desired.instances.clear()).await;
    assert!(closed_unanswered(guest(&f.root.path().join("alpha")).await).await);
}

#[tokio::test]
async fn a_disabled_forwarder_listens_on_no_jail() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let forwarder = HostServicesForwarder::disabled();
    let app = AppId::parse("alpha").unwrap();
    forwarder
        .attach(
            &app,
            &deployment_id(),
            root.path(),
            0,
            0,
            VmProcesses::new(root.path().to_owned()),
        )
        .await
        .unwrap();
    assert!(!Service::S3.socket_path(root.path()).exists());
}

#[test]
fn the_header_names_the_app_and_deployment_on_one_line() {
    assert_eq!(
        Service::S3.header(
            &AppId::parse("d-000000000000001").unwrap(),
            &DeploymentId::parse("d-000000000000001-dep-7").unwrap()
        ),
        "CONNECT d-000000000000001 d-000000000000001-dep-7\n"
    );
}

#[tokio::test]
async fn a_mail_only_guest_reaches_the_agent_on_its_own_mail_channel() {
    let f = fixture(&[("alpha", false)]).await;
    let jail = f.root.path().join("alpha");
    let mut desired = f.cache.lock().await.latest().unwrap().clone();
    desired.instances[0].sign_in_email = Some(protocol::SignInEmail {
        recipient: protocol::SignInMailbox::parse("owner@example.org").unwrap(),
    });
    f.cache.lock().await.accept(desired);
    assert!(closed_unanswered(guest(&jail).await).await);
    let mut client = UnixStream::connect(Service::SignInEmail.socket_path(&jail))
        .await
        .unwrap();
    client.write_all(b"{\"code\":\"012345\"}\n").await.unwrap();
    let (service, _) = timeout(CONNECT_TIMEOUT, f.service.accept())
        .await
        .unwrap()
        .unwrap();
    let mut service = BufReader::new(service);
    let mut line = String::new();
    service.read_line(&mut line).await.unwrap();
    assert_eq!(line, format!("CONNECT-MAIL alpha {}\n", deployment_id()));
    line.clear();
    service.read_line(&mut line).await.unwrap();
    assert_eq!(line, "{\"code\":\"012345\"}\n");
    service
        .get_mut()
        .write_all(b"{\"status\":\"accepted\"}\n")
        .await
        .unwrap();
    service.get_mut().shutdown().await.unwrap();
    line.clear();
    client.read_to_string(&mut line).await.unwrap();
    assert_eq!(line, "{\"status\":\"accepted\"}\n");
}
