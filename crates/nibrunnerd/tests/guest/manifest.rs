#[tokio::test(flavor = "multi_thread")]
async fn a_manifest_requires_an_isolated_clean_exit_and_releases_its_jail() {
    use nibrunnerd::adapters::vm::probe;
    use sha2::Digest;

    let Some(host) = crate::host().await else {
        return;
    };
    let tenant =
        std::fs::read(std::path::Path::new(&host.host.config.artifact_store_url).join("tenant")).unwrap();
    let area = tempfile::tempdir().unwrap();
    let binary = area.path().join("tenant");
    for (suffix, expected) in [
        ("", 0),
        (":probe-fail", 3),
        (":probe-flood", 3),
        (":probe-hang", 3),
        ("", 0),
    ] {
        let bytes = [tenant.as_slice(), suffix.as_bytes()].concat();
        std::fs::write(&binary, &bytes).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(&bytes));
        let result = probe::run(&host.host.config, &binary, &digest).await;
        if expected == 0 {
            assert_eq!(result.unwrap(), b"{\"app\":\"test-tenant\"}\n");
        } else {
            assert_eq!(result.unwrap_err().exit_code(), expected);
        }
        assert!(!host.host.config.state_dir.join("manifest-probe").exists());
    }
    host.stop().await;
}
