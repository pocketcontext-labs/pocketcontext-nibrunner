use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

use protocol::{
    AppId, DesiredPresence, DesiredVolume, HostDesiredState, LocalResizeReport, ResizeOutcome, VolumeId,
};

use crate::adapters::volumes::local_file::{resize, resize_transaction};
use crate::host::Host;

pub fn capable(host: &Host) -> bool {
    host.config.volumes == crate::config::VolumeBackend::LocalFile && resize::tools_available()
}

pub fn requested(desired: &HostDesiredState) -> BTreeSet<&AppId> {
    desired
        .volumes
        .iter()
        .filter(|volume| volume.local_resize.is_some())
        .map(|volume| &volume.app_id)
        .collect()
}

// A VM may have detached from the daemon before its Firecracker process has released the
// original disk inode. A kernel read lease can only be acquired after the last writer closes.
// The per-app transition and desired-document fence exclude new writers after this check.
#[allow(unsafe_code, reason = "Linux file leases have no standard-library wrapper")]
fn check_writers(source: &Path) -> io::Result<()> {
    let file = File::open(source)?;
    // Linux F_SETSIG on the supported x86_64 and aarch64 ABIs. A competing open must
    // not wake the daemon with the default action for SIGIO while the lease is held.
    const F_SETSIG: libc::c_int = 10;
    // SAFETY: both fcntl calls use a live descriptor and integer-only arguments.
    if unsafe { libc::fcntl(file.as_raw_fd(), F_SETSIG, libc::SIGURG) } == -1
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sync(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

async fn quiesce(host: &Host, vol: &DesiredVolume, source: &Path, dir: &Path) -> Result<(), String> {
    let ioerr = |e: io::Error| e.to_string();
    let app = &vol.app_id;
    let record = host.state.record(app).await;
    if record
        .as_ref()
        .is_some_and(|record| record.volume_id != vol.volume_id)
    {
        return Err("source owner does not match instance record".into());
    }
    host.cron_runs.stop(app).await;
    host.cron_execution.stop(app).await.map_err(|e| e.to_string())?;
    host.close_http_connections_to(app).await;
    host.activator.close_connections_to(app).await;
    let statuses = host.vms.statuses(std::slice::from_ref(app)).await;
    let running = statuses.get(app).ok_or("source VM status unavailable")?.active;
    let paths = crate::adapters::vm::snapshot::snapshot_paths(&host.config.snapshot_dir, app);
    let sleeping = !running && paths.stamp_path.try_exists().map_err(ioerr)?;
    if !running
        && !sleeping
        && (paths.memory_path.try_exists().map_err(ioerr)? || paths.state_path.try_exists().map_err(ioerr)?)
    {
        return Err("source snapshot is incomplete".into());
    }
    let freeze_needed = dir.join("needs-guest-freeze");
    let _freeze = if running || sleeping {
        File::create(&freeze_needed)
            .and_then(|file| file.sync_all())
            .map_err(ioerr)?;
        sync(dir).map_err(ioerr)?;
        if sleeping {
            let record = record.ok_or("sleeping guest has no deployment record")?;
            let slot = host
                .slot_of(app)
                .await
                .ok_or("sleeping guest has no device slot")?;
            host.vms
                .wake(crate::ports::SuspendRequest {
                    app_id: app.clone(),
                    deployment_id: record.deployment_id,
                    slot,
                })
                .await
                .map_err(|e| e.to_string())?;
        }
        let socket = crate::domain::filesystem::reader::guest_vsock_path(host, app);
        let lease = crate::domain::exports::freeze::frozen(app, &socket)
            .await
            .map_err(|e| e.message())?;
        lease.require_running_guest().map_err(|e| e.message())?;
        std::fs::remove_file(&freeze_needed).map_err(ioerr)?;
        sync(dir).map_err(ioerr)?;
        Some(lease)
    } else {
        if freeze_needed.try_exists().map_err(ioerr)? {
            return Err("the source guest must be recovered before resizing".into());
        }
        None
    };
    host.vms.stop(app).await.map_err(|e| e.to_string())?;
    crate::adapters::vm::limits::release_stopped_cgroup(app)
        .await
        .map_err(ioerr)?;
    check_writers(source).map_err(ioerr)?;
    host.vms.discard(app).await.map_err(|e| e.to_string())?;
    for path in [&paths.memory_path, &paths.state_path, &paths.stamp_path] {
        if path.try_exists().map_err(ioerr)? {
            return Err("source snapshot has not been discarded".into());
        }
    }
    if paths.directory.try_exists().map_err(ioerr)? {
        sync(&paths.directory).map_err(ioerr)?;
    }
    if host.config.snapshot_dir.try_exists().map_err(ioerr)? {
        sync(&host.config.snapshot_dir).map_err(ioerr)?;
    }
    host.state.drop_record(app).await;
    host.persist().await;
    Ok(())
}

fn validate_request(host: &Host, desired: &HostDesiredState, vol: &DesiredVolume) -> Result<(), String> {
    let Some(request) = &vol.local_resize else {
        return Err("missing resize request".into());
    };
    if !capable(host)
        || vol.storage.is_some()
        || vol.desired_state != DesiredPresence::Present
        || desired
            .volumes
            .iter()
            .filter(|v| v.app_id == vol.app_id || v.volume_id == vol.volume_id)
            .count()
            != 1
        || desired
            .exports
            .iter()
            .any(|e| e.volume_id == vol.volume_id && e.desired_state == DesiredPresence::Present)
        || desired
            .checkpoints
            .iter()
            .any(|c| c.volume_id == vol.volume_id && c.desired_state == DesiredPresence::Present)
        || request.request_id.len() != 32
        || !request
            .request_id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || desired
            .instances
            .iter()
            .filter(|vm| vm.volume_id == vol.volume_id || vm.app_id == vol.app_id)
            .map(|vm| (&vm.app_id, &vm.volume_id))
            .collect::<Vec<_>>()
            != [(&vol.app_id, &vol.volume_id)]
    {
        return Err("unsupported or invalid local volume resize".into());
    }
    Ok(())
}

pub async fn validate_change(host: &Host, desired: &HostDesiredState) -> Result<(), String> {
    for vol in desired.volumes.iter().filter(|v| v.local_resize.is_some()) {
        validate_request(host, desired, vol)?;
    }
    let previous = host
        .repositories
        .accepted_document
        .read()
        .await
        .map_err(|e| e.message())?;
    for vol in desired.volumes.iter().filter(|v| v.local_resize.is_some()) {
        let prior = previous
            .as_ref()
            .and_then(|doc| doc.desired.volumes.iter().find(|v| v.volume_id == vol.volume_id));
        if prior == Some(vol) {
            continue;
        }
        let request = vol.local_resize.as_ref().ok_or("missing resize request")?;
        let metadata = std::fs::symlink_metadata(host.config.volumes_dir().join(vol.volume_id.as_str()))
            .map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.len() != request.from_bytes
            || request.from_bytes == vol.size_bytes
            || prior.is_some_and(|old| old.app_id != vol.app_id)
        {
            return Err("local resize source must match the existing volume and physical size".into());
        }
    }
    let Some(previous) = previous else { return Ok(()) };
    for old in previous
        .desired
        .volumes
        .iter()
        .filter(|v| v.local_resize.is_some())
    {
        let new = desired.volumes.iter().find(|v| v.volume_id == old.volume_id);
        if new == Some(old) {
            continue;
        }
        let root = host.config.volumes_dir();
        let state = root.join(".local-resize").join(old.volume_id.as_str());
        let source = root.join(old.volume_id.as_str());
        let outcome = resize_transaction::completed(&state, &source, old).map_err(|e| e.to_string())?;
        let bytes = match outcome {
            Some(ResizeOutcome::Applied) => old.size_bytes,
            Some(ResizeOutcome::Refused) => {
                old.local_resize
                    .as_ref()
                    .ok_or("missing resize request")?
                    .from_bytes
            }
            _ => return Err("pending volume resize must finish before its request can be replaced".into()),
        };
        if let Some(new) = new {
            let from = new.local_resize.as_ref().map_or(new.size_bytes, |r| r.from_bytes);
            if new.app_id != old.app_id || (new.desired_state == DesiredPresence::Present && from != bytes) {
                return Err("acknowledgement does not match the completed volume resize".into());
            }
        }
    }
    Ok(())
}

async fn process(host: &Host, vol: &DesiredVolume) -> Result<ResizeOutcome, String> {
    let _guard = host.state.transition(&vol.app_id).await;
    let root = host.config.volumes_dir();
    let source = root.join(vol.volume_id.as_str());
    let ledger = root.join(".local-resize");
    let dir = ledger.join(vol.volume_id.as_str());
    for (path, parent) in [(&ledger, &root), (&dir, &ledger)] {
        crate::json_store::make_directory(path, 0o700)
            .and_then(|()| sync(parent))
            .map_err(|e| e.to_string())?;
    }
    if let Some(done) = resize_transaction::completed(&dir, &source, vol).map_err(|e| e.to_string())? {
        return Ok(done);
    }
    quiesce(host, vol, &source, &dir).await?;
    resize_transaction::apply(&dir, &source, vol, &*host.commands)
        .await
        .map_err(|e| e.to_string())
}

pub async fn run(host: &Host, desired: &HostDesiredState) -> BTreeMap<VolumeId, LocalResizeReport> {
    let mut reports = BTreeMap::new();
    for vol in &desired.volumes {
        let Some(request) = &vol.local_resize else {
            continue;
        };
        let outcome = process(host, vol).await.unwrap_or_else(|error| {
            tracing::warn!(volume_id=%vol.volume_id, %error, "local volume resize remains pending");
            ResizeOutcome::Pending
        });
        reports.insert(
            vol.volume_id.clone(),
            LocalResizeReport {
                request_id: request.request_id.clone(),
                outcome,
            },
        );
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        accepted_document, desired_instance, desired_state, desired_volume, test_host,
    };

    #[tokio::test]
    async fn a_pending_resize_survives_replacement_or_withdrawal_of_the_request() {
        let host = test_host().await;
        let wanted = desired_state(|doc| {
            doc.instances = vec![desired_instance(|_| {})];
            doc.volumes = vec![desired_volume(|v| {
                v.local_resize = Some(protocol::LocalResize {
                    request_id: "0".repeat(32),
                    from_bytes: v.size_bytes / 2,
                })
            })];
        });
        host.remember_accepted_document(&accepted_document(wanted.clone()))
            .await
            .unwrap();
        let mut withdrawn = wanted;
        withdrawn.volumes[0].local_resize = None;
        assert!(validate_change(&host, &withdrawn)
            .await
            .unwrap_err()
            .contains("must finish"));
        withdrawn.volumes.clear();
        withdrawn.instances.clear();
        assert!(validate_change(&host, &withdrawn)
            .await
            .unwrap_err()
            .contains("must finish"));
    }

    #[test]
    fn an_open_writer_prevents_publication_even_when_the_vm_record_is_absent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk");
        let writer = File::create(&path).unwrap();
        assert!(check_writers(&path).is_err());
        drop(writer);
        assert!(check_writers(&path).is_ok());
    }
}
