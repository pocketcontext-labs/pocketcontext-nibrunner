//! Preparing a replacement never opens the source for writing. The caller
//! holds the offline/wake fence through preparation, verification and cutover.
use std::fmt::Display;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use tempfile::NamedTempFile;

use crate::adapters::volumes::{filesystem_uuid, VolumeError};
use crate::ports::{CommandRequest, CommandRunner, CommandRunnerExt};

const MIB: u64 = 1 << 20;
const TOOL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SPACE_MARGIN: u64 = 128 * MIB;

fn unusable(error: impl Display) -> VolumeError {
    VolumeError::Unusable(format!("offline disk resize: {error}"))
}

fn filesystem_bytes(file: &std::fs::File) -> Result<u64, VolumeError> {
    // ext4 stores its block count across the low and high superblock fields.
    let field = |offset: u64| {
        let mut value = [0; 4];
        file.read_exact_at(&mut value, 1024 + offset).map_err(unusable)?;
        Ok::<_, VolumeError>(u32::from_le_bytes(value))
    };
    let blocks = u64::from(field(0x04)?) | (u64::from(field(0x150)?) << 32);
    let block_size = 1024_u64
        .checked_shl(field(0x18)?)
        .ok_or_else(|| unusable("invalid ext4 block size"))?;
    blocks
        .checked_mul(block_size)
        .ok_or_else(|| unusable("invalid ext4 block count"))
}

fn text(path: &Path) -> Result<&str, VolumeError> {
    path.to_str().ok_or_else(|| unusable("non-UTF-8 image path"))
}

async fn run_tool(
    commands: &dyn CommandRunner,
    image: &Path,
    tool: &str,
    flags: &[&str],
    max_bytes: u64,
) -> Result<(), VolumeError> {
    // The ext4 metadata is tenant-controlled. Limit the parser to a copy of
    // that one image, read-only runtime libraries and its own namespaces.
    let size_limit = format!("--fsize={max_bytes}");
    let mut request = CommandRequest::new(&[
        "prlimit",
        &size_limit,
        "--as=1073741824",
        "--nproc=16",
        "--nofile=64",
        "--core=0",
        "--",
        "bwrap",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--dir",
        "/usr",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--ro-bind-try",
        "/usr/lib64",
        "/usr/lib64",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--ro-bind",
        tool,
        "/tool",
        "--bind",
        text(image)?,
        "/image",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--remount-ro",
        "/",
        "--",
        "/tool",
    ]);
    request.command.extend(flags.iter().map(ToString::to_string));
    request.discard_output = true;
    request.timeout = TOOL_TIMEOUT;
    let result = commands.run(request).await.map_err(unusable)?;
    // e2fsck returns one after a successful automatic repair on the staged copy.
    if result.code == 0 || (flags == ["-fp", "/image"] && result.code == 1) {
        Ok(())
    } else {
        Err(unusable(format!("{tool} failed with status {}", result.code)))
    }
}

pub(crate) fn tools_available() -> bool {
    [
        "cp",
        "prlimit",
        "bwrap",
        "/usr/sbin/e2fsck",
        "/usr/sbin/resize2fs",
    ]
    .iter()
    .all(|name| crate::install::prerequisites::on_path(name).is_some())
}

pub(crate) async fn stage_resized_copy(
    source: &Path,
    staging_directory: &Path,
    target_bytes: u64,
    commands: &dyn CommandRunner,
) -> Result<NamedTempFile, VolumeError> {
    let src = source.symlink_metadata().map_err(unusable)?;
    if !src.is_file() || src.len() == 0 || target_bytes == 0 || !target_bytes.is_multiple_of(MIB) {
        return Err(unusable(
            "expected a regular disk image and a positive whole-MiB target",
        ));
    }
    if src.dev() != staging_directory.metadata().map_err(unusable)?.dev() {
        return Err(unusable("staging must be on the volume filesystem"));
    }
    let uuid = filesystem_uuid(text(source)?).ok_or_else(|| unusable("source has no ext filesystem UUID"))?;
    let stats = nix::sys::statvfs::statvfs(staging_directory).map_err(unusable)?;
    let available = stats.blocks_available().saturating_mul(stats.fragment_size());
    let max_bytes = src.len().max(target_bytes);
    if available < max_bytes.saturating_add(SPACE_MARGIN) {
        return Err(unusable(
            "insufficient free space for a replacement and recovery margin",
        ));
    }
    let staged = NamedTempFile::new_in(staging_directory).map_err(unusable)?;
    let mut copy = CommandRequest::new(&[
        "cp",
        "--sparse=always",
        "--reflink=auto",
        "--",
        text(source)?,
        text(staged.path())?,
    ]);
    copy.timeout = TOOL_TIMEOUT;
    commands.stdout_of(copy).await.map_err(unusable)?;
    let image = staged.path();
    let fsck = "/usr/sbin/e2fsck";
    run_tool(commands, image, fsck, &["-fp", "/image"], max_bytes).await?;
    if target_bytes > src.len() {
        staged.as_file().set_len(target_bytes).map_err(unusable)?;
    }
    let size = format!("{}M", target_bytes / MIB);
    run_tool(
        commands,
        image,
        "/usr/sbin/resize2fs",
        &["/image", &size],
        max_bytes,
    )
    .await?;
    if target_bytes < src.len() {
        staged.as_file().set_len(target_bytes).map_err(unusable)?;
    }
    run_tool(commands, image, fsck, &["-fn", "/image"], max_bytes).await?;
    if filesystem_bytes(staged.as_file())? != target_bytes
        || filesystem_uuid(text(image)?) != Some(uuid)
        || staged.as_file().metadata().map_err(unusable)?.len() != target_bytes
    {
        return Err(unusable("resized image failed identity or size verification"));
    }
    staged.as_file().sync_all().map_err(unusable)?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::exec::HostCommands;
    use std::fs::{read_dir, File};
    use std::os::unix::fs::symlink;
    use std::process::Command;

    #[tokio::test]
    async fn an_unformatted_or_symlinked_source_is_never_staged() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        File::create(&source).unwrap().set_len(MIB).unwrap();
        let linked = root.path().join("link");
        symlink(&source, &linked).unwrap();
        for candidate in [&source, &linked] {
            assert!(stage_resized_copy(candidate, root.path(), 2 * MIB, &HostCommands)
                .await
                .is_err());
        }
        assert_eq!(read_dir(root.path()).unwrap().count(), 2);
    }

    fn tool(program: &str, args: &[&str]) -> String {
        let output = Command::new(program).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[tokio::test]
    async fn offline_resizes_preserve_files_and_leave_the_source_intact_even_when_a_shrink_fails() {
        if std::env::var("NIBRUNNER_INTEGRATION").as_deref() != Ok("1") {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let payload = root.path().join("payload");
        let source = root.path().join("source");
        let mut random = File::open("/dev/urandom").unwrap();
        let mut data = vec![0; 5 * MIB as usize];
        std::io::Read::read_exact(&mut random, &mut data).unwrap();
        std::fs::write(&payload, &data).unwrap();
        File::create(&source).unwrap().set_len(96 * MIB).unwrap();
        tool("mke2fs", &["-q", "-F", "-t", "ext4", text(&source).unwrap()]);
        tool(
            "debugfs",
            &[
                "-w",
                "-R",
                &format!("write {} /payload", payload.display()),
                text(&source).unwrap(),
            ],
        );
        let original_checksum = tool("sha256sum", &[text(&source).unwrap()]);
        for size in [48, 192] {
            let stage = stage_resized_copy(&source, root.path(), size * MIB, &HostCommands)
                .await
                .unwrap();
            assert!(stage.as_file().metadata().unwrap().blocks() * 512 < size * MIB);
            let dump = root.path().join("dump");
            tool(
                "debugfs",
                &[
                    "-R",
                    &format!("dump /payload {}", dump.display()),
                    text(stage.path()).unwrap(),
                ],
            );
            assert_eq!(std::fs::read(&dump).unwrap(), data);
            std::fs::remove_file(dump).unwrap();
            let header = tool("dumpe2fs", &["-h", text(stage.path()).unwrap()]);
            let field = |name: &str| {
                header
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .unwrap()
            };
            assert_eq!(field("Block count:") * field("Block size:"), size * MIB);
        }
        assert!(stage_resized_copy(&source, root.path(), MIB, &HostCommands)
            .await
            .is_err());
        assert_eq!(tool("sha256sum", &[text(&source).unwrap()]), original_checksum);
        assert_eq!(read_dir(root.path()).unwrap().count(), 2);
    }
}
