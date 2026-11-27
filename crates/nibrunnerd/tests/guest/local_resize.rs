//! Exercise the local-file maintenance protocol on a real guest with persistent data.
use nibrunnerd::test_support::machine::{RunningHost, Tenant};
use protocol::{InstanceState, LocalResize, ResizeOutcome};

const MIB: u64 = 1 << 20;

async fn resize(
    host: &RunningHost,
    app: &mut Tenant,
    peer: &Tenant,
    id: &str,
    size: u64,
    outcome: ResizeOutcome,
) {
    let original = app.volume.size_bytes;
    app.volume.local_resize = Some(LocalResize {
        request_id: id.to_owned(),
        from_bytes: original,
    });
    app.volume.size_bytes = size;
    host.deploy(&[app.clone(), peer.clone()]).await;
    host.until("matching terminal disk receipt", |report| {
        report.volumes.iter().any(|v| {
            v.volume_id == app.volume_id
                && v.size_bytes
                    == if outcome == ResizeOutcome::Applied {
                        size
                    } else {
                        original
                    }
                && v.local_resize
                    .as_ref()
                    .is_some_and(|r| r.request_id == id && r.outcome == outcome)
        })
    })
    .await;

    let fenced = host
        .get(app, "/read?path=sentinel")
        .await
        .expect("request through fenced route");
    assert_ne!(fenced.status, 200);
    let other = host
        .get(peer, "/write?path=available&body=yes")
        .await
        .expect("unrelated guest remains writable");
    assert_eq!(other.status, 200);
    if outcome == ResizeOutcome::Refused {
        app.volume.size_bytes = original;
    }
    app.volume.local_resize = None;
    *app = app.clone().redeployed(id);
    host.deploy(&[app.clone(), peer.clone()]).await;
    host.until_state(&app.app_id, InstanceState::Running).await;
    host.until_routed(app).await;
    let response = host
        .get(app, "/read?path=sentinel")
        .await
        .expect("read through guest");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "preserve-me");
}

#[tokio::test(flavor = "multi_thread")]
async fn sleeping_guest_keeps_files_through_growth_shrink_and_refusal() {
    let Some(host) = crate::host_with(|config| {
        config.host_security.allow_active_smt =
            std::env::var("NIBRUNNER_TEST_ALLOW_ACTIVE_SMT").as_deref() == Ok("1");
    })
    .await
    else {
        return;
    };
    let mut app = host.tenant(1).on_request(60_000);
    let peer = host.tenant(2);
    host.deploy(&[app.clone(), peer.clone()]).await;
    host.until_state(&peer.app_id, InstanceState::Running).await;
    host.until_routed(&peer).await;
    host.until_state(&app.app_id, InstanceState::Running).await;
    host.until_routed(&app).await;
    let written = host
        .get(&app, "/write?path=sentinel&body=preserve-me")
        .await
        .expect("guest write");
    assert_eq!(written.status, 200);
    host.let_sleep(&app).await;
    resize(
        &host,
        &mut app,
        &peer,
        "11111111111111111111111111111111",
        128 * MIB,
        ResizeOutcome::Applied,
    )
    .await;
    resize(
        &host,
        &mut app,
        &peer,
        "22222222222222222222222222222222",
        64 * MIB,
        ResizeOutcome::Applied,
    )
    .await;
    resize(
        &host,
        &mut app,
        &peer,
        "33333333333333333333333333333333",
        MIB,
        ResizeOutcome::Refused,
    )
    .await;
    host.stop().await;
}
