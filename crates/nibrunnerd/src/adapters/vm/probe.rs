use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use guest_contract::probe::{FRAME_PREFIX, MAX_BINARY_BYTES, MAX_OUTPUT_BYTES};
use protocol::AppId;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::{jailer, jailer_inputs, manager, process};
use crate::config::HostConfig;
use crate::install::jailer_identities;

const PROBE_DIRECTORY: &str = "/run/nibrunner-manifest";
const CGROUP_PARENT: &str = "nibrunner-manifest";
const MAX_CONSOLE: u64 = 96 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the manifest probe is unavailable: {0}")]
    Unavailable(#[from] io::Error),
    #[error("the executable did not produce a supported manifest")]
    Invalid,
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Unavailable(_) => 1,
            Self::Invalid => 3,
        }
    }
}

fn staged_binary(binary: &Path, digest: &str, image: &Path) -> io::Result<u64> {
    let input = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(binary)?;
    if !input.metadata()?.is_file() {
        return Err(io::Error::other("the probe input must be a regular file"));
    }
    let mut staged = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(image)?;
    let length = io::copy(&mut input.take(MAX_BINARY_BYTES + 1), &mut staged)?;
    if !(1..=MAX_BINARY_BYTES).contains(&length) {
        return Err(io::Error::other(
            "probe input exceeds the supported size or is empty",
        ));
    }
    staged.rewind()?;
    let mut hash = Sha256::new();
    io::copy(&mut staged, &mut hash)?;
    if hex::encode(hash.finalize()) != digest {
        return Err(io::Error::other(
            "staged executable differs from the approved digest",
        ));
    }
    // Virtio block devices expose whole sectors. PID 1 copies exactly the approved length.
    staged.set_len(length.next_multiple_of(512))?;
    staged.set_permissions(fs::Permissions::from_mode(0o444))?;
    Ok(length)
}

fn completed(console: &[u8]) -> Result<Vec<u8>, Error> {
    let text = String::from_utf8_lossy(console);
    let mut frames = text.lines().filter_map(|line| line.strip_prefix(FRAME_PREFIX));
    let frame = frames
        .next()
        .ok_or_else(|| io::Error::other("the guest returned no completion frame"))?;
    if frames.next().is_some() {
        return Err(io::Error::other("the guest returned conflicting completion frames").into());
    }
    if frame == "invalid" {
        return Err(Error::Invalid);
    }
    let (_, hex) = frame
        .strip_prefix("ok ")
        .and_then(|value| value.split_once(' '))
        .and_then(|(length, hex)| length.parse::<usize>().ok().map(|length| (length, hex)))
        .filter(|(length, hex)| *length <= MAX_OUTPUT_BYTES && hex.len() == length * 2)
        .ok_or_else(|| io::Error::other("the guest could not complete inspection"))?;
    let output = hex::decode(hex).map_err(io::Error::other)?;
    if !serde_json::from_slice::<serde_json::Value>(&output).is_ok_and(|json| json.is_object()) {
        return Err(Error::Invalid);
    }
    Ok(output)
}

async fn clear_group(group: &Path) -> io::Result<()> {
    match fs::write(group.join("cgroup.kill"), "1") {
        Err(e) if e.kind() == io::ErrorKind::NotFound && !group.exists() => return Ok(()),
        result => result?,
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match fs::remove_dir(group) {
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
}

pub async fn run(config: &HostConfig, binary: &Path, digest: &str) -> Result<Vec<u8>, Error> {
    crate::host_security::check(&config.host_security).map_err(io::Error::other)?;
    let root = Path::new(PROBE_DIRECTORY);
    crate::json_store::make_directory(root, 0o700)?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(root.join("lock"))?;
    lock.try_lock().map_err(io::Error::from)?;
    // No ordinary slot can reach this identity, even after a host capacity change.
    let identities =
        jailer_identities::read(nft_render::most_apps_the_ports_fit() + 1).map_err(io::Error::other)?;
    let app = AppId::parse("manifest-probe").map_err(io::Error::other)?;
    let group = Path::new("/sys/fs/cgroup")
        .join(CGROUP_PARENT)
        .join(jailer::jail_id(&app));
    clear_group(&group).await?;
    let directory = root.join("work");
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    crate::json_store::make_directory(&directory, 0o700)?;
    let result = inspect(config, binary, digest, &directory, &app, identities).await;
    clear_group(&group).await?;
    fs::remove_dir_all(directory)?;
    result
}

async fn inspect(
    config: &HostConfig,
    binary: &Path,
    digest: &str,
    work: &Path,
    app: &AppId,
    identities: jailer_identities::Identities,
) -> Result<Vec<u8>, Error> {
    let image = work.join("payload");
    let length = staged_binary(binary, digest, &image)?;
    manager::verify_guest_image(&config.guest_image_dir).map_err(io::Error::other)?;
    let kernel = config.guest_image_dir.join(manager::GUEST_KERNEL_FILENAME);
    let rootfs = config.guest_image_dir.join(manager::GUEST_ROOTFS_FILENAME);
    let machine = guest_contract::firecracker::render_manifest_probe(
        kernel.display().to_string(),
        &rootfs.display().to_string(),
        &image.display().to_string(),
        length,
    );
    jailer_inputs::stage(work, nft_render::most_apps_the_ports_fit(), None, machine)
        .map_err(io::Error::other)?;
    let binary = process::extract_firecracker(work)?;
    let jailer = jailer::Jailer::new(process::extract_jailer(work)?, identities);
    let base: PathBuf = work.join("jails");
    let jail = jailer.prepare(
        work,
        &base,
        &work.join("snapshots"),
        app,
        &process::read_host_boot_id()?,
    )?;
    let mut command = jail.command(&jailer, &binary, app, &base, CGROUP_PARENT);
    command
        .arg("--")
        .arg("--no-api")
        .arg("--config-file")
        .arg("/firecracker.json");
    command
        .env_clear()
        .current_dir(&jail.root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    jail.configure_command(&mut command)?;
    let mut child = command.spawn()?;
    let pipe = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing guest console"))?;
    let mut console = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(25), async {
        pipe.take(MAX_CONSOLE + 1).read_to_end(&mut console).await?;
        if console.len() > MAX_CONSOLE as usize {
            return Err(io::Error::other("guest console exceeded its limit"));
        }
        if !child.wait().await?.success() {
            return Err(io::Error::other("the probe microVM did not shut down cleanly"));
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err(io::Error::other("manifest probe timed out")));
    if let Err(error) = result {
        let _ = child.kill().await;
        return Err(error.into());
    }
    completed(&console)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_covers_the_staged_bytes_before_sector_padding() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("binary");
        fs::write(&file, b"abc").unwrap();
        let path = dir.path().join("image");
        assert_eq!(
            staged_binary(&file, &hex::encode(Sha256::digest(b"abc")), &path).unwrap(),
            3
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 512);
        fs::write(&file, b"abcd").unwrap();
        assert!(staged_binary(
            &file,
            &hex::encode(Sha256::digest(b"abc")),
            &dir.path().join("mismatch")
        )
        .is_err());
        std::os::unix::fs::symlink(&file, dir.path().join("link")).unwrap();
        assert!(staged_binary(&dir.path().join("link"), "", &dir.path().join("unread")).is_err());
    }

    #[test]
    fn a_complete_guest_frame_distinguishes_invalid_output_from_a_lost_vm() {
        assert_eq!(
            completed(b"boot\r\nNIBRUNNER-MANIFEST/1 ok 3 7b7d0a\r\n").unwrap(),
            b"{}\n"
        );
        assert_eq!(
            completed(b"NIBRUNNER-MANIFEST/1 invalid\r\n")
                .unwrap_err()
                .exit_code(),
            3
        );
        assert_eq!(
            completed(b"NIBRUNNER-MANIFEST/1 ok 1 7b\r\n")
                .unwrap_err()
                .exit_code(),
            3
        );
        for console in [
            "",
            "NIBRUNNER-MANIFEST/1 unavailable",
            "NIBRUNNER-MANIFEST/1 ok 3 7b7d",
            "NIBRUNNER-MANIFEST/1 invalid\nNIBRUNNER-MANIFEST/1 ok 2 7b7d",
        ] {
            assert_eq!(completed(console.as_bytes()).unwrap_err().exit_code(), 1);
        }
    }
}
