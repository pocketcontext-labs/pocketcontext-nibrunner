use std::sync::LazyLock;

use nix::sys::time::TimeValLike;
use nix::time::{clock_gettime, ClockId};
use serde::{Deserialize, Serialize};

static BOOT_ID: LazyLock<String> = LazyLock::new(crate::adapters::vm::process::host_boot_id_or_session);

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AwakeMeter {
    measured_ms: u64,
    billable_ms: u64,
    checkpoint: Option<Checkpoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Checkpoint {
    boot: String,
    monotonic_ms: u64,
    billable: bool,
}

impl AwakeMeter {
    pub(crate) fn reported(&self) -> protocol::AwakeCounter {
        protocol::AwakeCounter {
            measured_seconds: self.measured_ms / 1000,
            billable_seconds: self.billable_ms / 1000,
        }
    }

    pub(crate) fn observe(&mut self, awake: bool, billable: bool) {
        if let Ok(time) = clock_gettime(ClockId::CLOCK_MONOTONIC) {
            self.sample(&BOOT_ID, time.num_milliseconds() as u64, awake, billable);
        }
    }

    pub(crate) fn set_billable(&mut self, billable: bool) {
        if self.checkpoint.is_some() {
            self.observe(true, billable);
        }
    }

    fn sample(&mut self, boot: &str, now: u64, awake: bool, billable: bool) {
        if let Some(previous) = &self.checkpoint {
            if previous.boot == boot {
                let elapsed = now.saturating_sub(previous.monotonic_ms);
                self.measured_ms = self.measured_ms.saturating_add(elapsed);
                if previous.billable {
                    self.billable_ms = self.billable_ms.saturating_add(elapsed);
                }
            }
        }
        self.checkpoint = awake.then(|| Checkpoint {
            boot: boot.to_owned(),
            monotonic_ms: now,
            billable,
        });
    }

    pub(crate) fn lost(&mut self) {
        // An observed exit supplies no monotonic exit timestamp. The last positive
        // checkpoint fences billing, including when the daemon was down for the exit.
        self.checkpoint = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restart_resumes_the_same_boot_clock_and_excludes_sleep_and_suspend_work() {
        let mut meter = AwakeMeter::default();
        meter.sample("a", 1000, true, true);
        meter.sample("a", 3400, true, true);
        let saved = serde_json::to_vec(&meter).unwrap();
        let mut reopened: AwakeMeter = serde_json::from_slice(&saved).unwrap();
        reopened.sample("a", 6500, true, false);
        reopened.sample("a", 8000, false, false);
        reopened.sample("a", 48000, true, true);
        reopened.sample("a", 50600, true, true);
        reopened.sample("b", 900, true, true);
        reopened.lost();
        assert_eq!(reopened.reported().measured_seconds, 9);
        assert_eq!(reopened.reported().billable_seconds, 8);
    }
    #[tokio::test]
    async fn a_reopened_host_database_retains_the_deployments_partial_second() {
        use crate::repositories::instances_repository::{InstanceRepository, SqliteInstances};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.sqlite");
        let pool = crate::domain::store::open(&path).await.unwrap();
        let mut record = crate::test_support::instance_record(|_| {});
        record.awake_meter.sample("boot", 100, true, true);
        record.awake_meter.sample("boot", 850, true, true);
        SqliteInstances::new(pool.clone())
            .replace_all(&[record])
            .await
            .unwrap();
        pool.close().await;

        let pool = crate::domain::store::open(&path).await.unwrap();
        let mut records = SqliteInstances::new(pool).all().await.unwrap();
        let mut recovered = records.pop().unwrap();
        recovered.awake_meter.sample("boot", 1200, false, false);
        let reported = super::super::build_report::to_reported_instance(&recovered);
        assert_eq!(reported.awake_counter.unwrap().billable_seconds, 1);
    }
}
