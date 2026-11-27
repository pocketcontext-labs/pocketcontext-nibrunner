//! Publication runs under the caller's offline per-volume fence.
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use protocol::{DesiredVolume, ResizeOutcome};
use serde::{Deserialize, Serialize};

use super::resize::stage_resized_copy;
use crate::adapters::volumes::VolumeError;
use crate::ports::CommandRunner;

type Result<T> = std::result::Result<T, VolumeError>;

fn fail(e: impl std::fmt::Display) -> VolumeError {
    VolumeError::Unusable(format!("local resize: {e}"))
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Image {
    dev: u64,
    ino: u64,
    bytes: u64,
}

fn image(path: &Path) -> Result<Image> {
    let m = fs::symlink_metadata(path).map_err(fail)?;
    if !m.is_file() {
        return Err(fail("expected a regular image"));
    }
    Ok(Image {
        dev: m.dev(),
        ino: m.ino(),
        bytes: m.len(),
    })
}

fn sync(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(fail)
}

fn directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(fail(e)),
    }
    let m = fs::symlink_metadata(path).map_err(fail)?;
    if !m.is_dir() || m.mode() & 0o077 != 0 {
        return Err(fail("expected private transaction directory"));
    }
    sync(path.parent().ok_or_else(|| fail("directory has no parent"))?)
}

#[derive(Serialize, Deserialize)]
enum Phase {
    Preparing,
    Prepared(Image),
    Applied(Image),
    Refused,
}
#[derive(Serialize, Deserialize)]
struct Journal {
    source: Image,
    target: u64,
    phase: Phase,
}

fn store(dir: &Path, j: &Journal) -> Result<()> {
    let mut f = tempfile::NamedTempFile::new_in(dir).map_err(fail)?;
    serde_json::to_writer(&mut f, j).map_err(fail)?;
    f.as_file().sync_all().map_err(fail)?;
    f.persist(dir.join("journal.json")).map_err(fail)?;
    sync(dir)
}

fn attempt(dir: &Path, vol: &DesiredVolume) -> Result<(PathBuf, u64)> {
    let r = vol
        .local_resize
        .as_ref()
        .ok_or_else(|| fail("missing resize request"))?;
    if r.request_id.len() != 32
        || !r
            .request_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail("invalid request id"));
    }
    Ok((dir.join(&r.request_id), r.from_bytes))
}

fn load(dir: &Path, from: u64, target: u64) -> Result<Option<Journal>> {
    let f = match File::open(dir.join("journal.json")) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(e)),
    };
    let j: Journal = serde_json::from_reader(f).map_err(fail)?;
    if j.target != target || j.source.bytes != from {
        return Err(fail("request id reused with different geometry"));
    }
    Ok(Some(j))
}

fn terminal(dir: &Path, source: &Path, j: &Journal) -> Result<Option<ResizeOutcome>> {
    match &j.phase {
        Phase::Applied(active) if image(source)? == *active => {
            let backup = dir.join("original");
            if backup.try_exists().map_err(fail)? {
                if image(&backup)? != j.source {
                    return Err(fail("unexpected backup identity"));
                }
                fs::remove_file(backup).map_err(fail)?;
                sync(dir)?;
            }
            Ok(Some(ResizeOutcome::Applied))
        }
        Phase::Refused if image(source)? == j.source => Ok(Some(ResizeOutcome::Refused)),
        Phase::Applied(_) | Phase::Refused => Err(fail("receipt does not match active image")),
        _ => Ok(None),
    }
}

pub(crate) fn completed(dir: &Path, source: &Path, vol: &DesiredVolume) -> Result<Option<ResizeOutcome>> {
    let (op, from) = attempt(dir, vol)?;
    match load(&op, from, vol.size_bytes)? {
        Some(j) => terminal(&op, source, &j),
        None => Ok(None),
    }
}

fn publish(op: &Path, source: &Path, j: &mut Journal) -> Result<ResizeOutcome> {
    let Phase::Prepared(staged) = &j.phase else {
        return Err(fail("missing prepared image"));
    };
    let backup = op.join("original");
    let candidate = op.join("candidate");
    if image(&backup)? != j.source {
        return Err(fail("original image identity changed"));
    }
    let active = image(source)?;
    if active == j.source {
        if image(&candidate)? != *staged {
            return Err(fail("candidate identity changed"));
        }
        fs::rename(&candidate, source).map_err(fail)?;
    } else if active != *staged {
        return Err(fail("unexpected active image"));
    }
    sync(source.parent().ok_or_else(|| fail("image has no parent"))?)?;
    sync(op)?;
    let published = image(source)?;
    if published != *staged || published.bytes != j.target {
        return Err(fail("published image did not match prepared image"));
    }
    j.phase = Phase::Applied(published);
    store(op, j)?;
    terminal(op, source, j)?.ok_or_else(|| fail("missing publication receipt"))
}

pub(crate) async fn apply(
    dir: &Path,
    source: &Path,
    vol: &DesiredVolume,
    commands: &dyn CommandRunner,
) -> Result<ResizeOutcome> {
    let (op, from) = attempt(dir, vol)?;
    directory(dir)?;
    directory(&op)?;
    let mut j = match load(&op, from, vol.size_bytes)? {
        Some(j) => j,
        None => {
            let original = image(source)?;
            if original.bytes != from {
                return Err(fail("source size changed"));
            }
            let j = Journal {
                source: original,
                target: vol.size_bytes,
                phase: Phase::Preparing,
            };
            store(&op, &j)?;
            j
        }
    };
    if let Some(outcome) = terminal(&op, source, &j)? {
        return Ok(outcome);
    }
    if matches!(j.phase, Phase::Prepared(_)) {
        return publish(&op, source, &mut j);
    }
    if image(source)? != j.source {
        return Err(fail("active image changed before staging"));
    }
    // Staging can leave an incomplete disposable image after process or power loss.
    for entry in fs::read_dir(&op).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name();
        if name == "candidate" || name.to_string_lossy().starts_with(".tmp") {
            fs::remove_file(entry.path()).map_err(fail)?;
        }
    }
    let backup = op.join("original");
    if backup.try_exists().map_err(fail)? {
        if image(&backup)? != j.source {
            return Err(fail("unexpected backup during staging"));
        }
        fs::remove_file(&backup).map_err(fail)?;
        sync(&op)?;
    }
    let staged = match stage_resized_copy(source, &op, j.target, commands).await {
        Ok(f) => f,
        Err(e) => {
            if image(source)? != j.source {
                return Err(fail("source changed while staging"));
            }
            tracing::warn!(error=%e,"refused offline volume resize");
            j.phase = Phase::Refused;
            store(&op, &j)?;
            return Ok(ResizeOutcome::Refused);
        }
    };
    let mode = fs::metadata(source).map_err(fail)?;
    std::os::unix::fs::chown(staged.path(), Some(mode.uid()), Some(mode.gid())).map_err(fail)?;
    staged
        .as_file()
        .set_permissions(mode.permissions())
        .map_err(fail)?;
    for key in xattr::list(source).map_err(fail)? {
        let value = xattr::get(source, &key)
            .map_err(fail)?
            .ok_or_else(|| fail("image attributes changed"))?;
        if xattr::get(staged.path(), &key).map_err(fail)?.as_ref() != Some(&value) {
            xattr::set(staged.path(), &key, &value).map_err(fail)?;
        }
    }
    staged.as_file().sync_all().map_err(fail)?;
    let candidate = op.join("candidate");
    staged.persist_noclobber(&candidate).map_err(fail)?;
    fs::hard_link(source, &backup).map_err(fail)?;
    if image(&backup)? != j.source {
        return Err(fail("backup identity changed"));
    }
    sync(&backup)?;
    sync(&op)?;
    j.phase = Phase::Prepared(image(&candidate)?);
    store(&op, &j)?;
    publish(&op, source, &mut j)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn retries_replay_success_and_refusal_on_real_ext4() {
        if std::env::var("NIBRUNNER_INTEGRATION").as_deref() != Ok("1") {
            return;
        }
        use crate::adapters::exec::HostCommands;
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("volume");
        let dir = tmp.path().join("transactions");
        const MIB: u64 = 1024 * 1024;
        File::create(&source).unwrap().set_len(32 * MIB).unwrap();
        assert!(std::process::Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4"])
            .arg(&source)
            .status()
            .unwrap()
            .success());
        xattr::set(&source, "user.resize-test", b"keep me").unwrap();
        let mut vol:DesiredVolume=serde_json::from_value(serde_json::json!({
            "volumeId":"test-volume","appId":"test-app","sizeBytes":64*MIB,"desiredState":"present","storage":null,
            "localResize":{"requestId":"11111111111111111111111111111111","fromBytes":32*MIB}
        })).unwrap();
        for outcome in [ResizeOutcome::Applied, ResizeOutcome::Refused] {
            assert_eq!(completed(&dir, &source, &vol).unwrap(), None);
            assert_eq!(apply(&dir, &source, &vol, &HostCommands).await.unwrap(), outcome);
            let active = image(&source).unwrap();
            assert_eq!(active.bytes, 64 * MIB);
            assert_eq!(apply(&dir, &source, &vol, &HostCommands).await.unwrap(), outcome);
            assert_eq!(completed(&dir, &source, &vol).unwrap(), Some(outcome));
            assert_eq!(image(&source).unwrap(), active);
            assert_eq!(
                xattr::get(&source, "user.resize-test").unwrap().unwrap(),
                b"keep me"
            );
            vol.size_bytes = MIB;
            vol.local_resize = Some(protocol::LocalResize {
                request_id: "22222222222222222222222222222222".into(),
                from_bytes: 64 * MIB,
            });
        }
    }

    #[test]
    fn recover_cutover_from_either_side_of_rename() {
        for already_published in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let active = tmp.path().join("active");
            let op = tmp.path().join("resize");
            directory(&op).unwrap();
            fs::write(&active, b"original").unwrap();
            fs::hard_link(&active, op.join("original")).unwrap();
            let candidate = op.join("candidate");
            fs::write(&candidate, b"resized image").unwrap();
            let mut journal = Journal {
                source: image(&active).unwrap(),
                target: 13,
                phase: Phase::Prepared(image(&candidate).unwrap()),
            };
            store(&op, &journal).unwrap();
            if already_published {
                fs::rename(candidate, &active).unwrap();
            }
            assert_eq!(
                publish(&op, &active, &mut journal).unwrap(),
                ResizeOutcome::Applied
            );
            let loaded = load(&op, 8, 13).unwrap().unwrap();
            assert_eq!(
                terminal(&op, &active, &loaded).unwrap(),
                Some(ResizeOutcome::Applied)
            );
            assert_eq!(fs::read(active).unwrap(), b"resized image");
            assert!(!op.join("original").exists());
            assert!(load(&op, 8, 99).is_err());
        }
    }
    #[test]
    fn refuse_cutover_over_unexpected_active_image() {
        let tmp = tempfile::tempdir().unwrap();
        let op = tmp.path();
        let active = op.join("active");
        fs::write(&active, b"old").unwrap();
        fs::hard_link(&active, op.join("original")).unwrap();
        let candidate = op.join("candidate");
        fs::write(&candidate, b"newer").unwrap();
        let mut journal = Journal {
            source: image(&active).unwrap(),
            target: 5,
            phase: Phase::Prepared(image(&candidate).unwrap()),
        };
        fs::remove_file(&active).unwrap();
        fs::write(&active, b"???").unwrap();
        assert!(publish(op, &active, &mut journal).is_err());
        assert_eq!(fs::read(active).unwrap(), b"???");
        assert_eq!(fs::read(op.join("original")).unwrap(), b"old");
    }
}
