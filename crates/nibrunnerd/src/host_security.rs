use std::path::{Path, PathBuf};

use crate::config::HostSecurityConfig;

mod ksm;
mod vulnerabilities;

const CPU_DIRECTORY: &str = "/sys/devices/system/cpu";
const KSM_DIRECTORY: &str = "/sys/kernel/mm/ksm";
const SECURITY_DOCS: &str = "https://nibrunner.dev/docs/guides/host-security";

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecurityError {
    #[error("host SMT is active; disable it before starting nibrunner; see {SECURITY_DOCS}#host-smt")]
    SmtActive,
    #[error("host SMT status could not be verified from {path}: {reason}; see {SECURITY_DOCS}#host-smt")]
    SmtUnknown { path: PathBuf, reason: String },
    #[error("host KSM is active; disable it and unmerge retained pages before starting nibrunner; see {SECURITY_DOCS}#kernel-samepage-merging")]
    KsmActive,
    #[error("host KSM retains {pages} shared pages; unmerge them before starting nibrunner; see {SECURITY_DOCS}#kernel-samepage-merging")]
    KsmShared { pages: u64 },
    #[error("host KSM status could not be verified from {path}: {reason}; see {SECURITY_DOCS}#kernel-samepage-merging")]
    KsmUnknown { path: PathBuf, reason: String },
}

/// What the checks found on a host they accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostSecurityStatus {
    pub(crate) smt_active: bool,
}

pub(crate) fn check(policy: &HostSecurityConfig) -> Result<HostSecurityStatus, SecurityError> {
    let smt_active = check_smt(Path::new(CPU_DIRECTORY), policy)?;
    ksm::check(Path::new(KSM_DIRECTORY))?;
    Ok(HostSecurityStatus { smt_active })
}

pub(crate) fn report_cpu_vulnerabilities() {
    vulnerabilities::report(&Path::new(CPU_DIRECTORY).join("vulnerabilities"));
}

fn check_smt(cpu_directory: &Path, policy: &HostSecurityConfig) -> Result<bool, SecurityError> {
    let active = smt_active(cpu_directory)?;
    if active {
        if !policy.allow_active_smt {
            return Err(SecurityError::SmtActive);
        }
        tracing::warn!(
            "host SMT is active and host_security.allow_active_smt accepts it: sibling threads can observe each other's data, so run only apps that trust each other; see {SECURITY_DOCS}#host-smt"
        );
    }
    Ok(active)
}

fn smt_active(cpu_directory: &Path) -> Result<bool, SecurityError> {
    let path = cpu_directory.join("smt/active");
    let active = std::fs::read_to_string(&path).map_err(|error| SecurityError::SmtUnknown {
        path: path.clone(),
        reason: error.to_string(),
    })?;
    match active.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        status => Err(SecurityError::SmtUnknown {
            path,
            reason: format!("unexpected status {status:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforced() -> HostSecurityConfig {
        HostSecurityConfig::default()
    }

    fn accepting_active_smt() -> HostSecurityConfig {
        HostSecurityConfig {
            allow_active_smt: true,
        }
    }

    fn cpu_directory(active: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("smt")).unwrap();
        std::fs::write(directory.path().join("smt/active"), active).unwrap();
        directory
    }

    #[test]
    fn a_host_with_no_active_smt_siblings_meets_the_requirement() {
        let directory = cpu_directory("0\n");
        assert!(check_smt(directory.path(), &enforced()).is_ok());
    }

    #[test]
    fn active_smt_is_refused_with_remediation_instructions() {
        let directory = cpu_directory("1\n");
        let error = check_smt(directory.path(), &enforced()).unwrap_err();
        assert!(matches!(error, SecurityError::SmtActive));
        assert!(error.to_string().contains(SECURITY_DOCS));
    }

    #[test]
    fn a_host_that_accepts_active_smt_starts_and_says_so() {
        let directory = cpu_directory("1\n");
        assert!(check_smt(directory.path(), &accepting_active_smt()).unwrap());
    }

    #[test]
    fn accepting_active_smt_still_reports_inactive_smt_as_inactive() {
        let directory = cpu_directory("0\n");
        assert!(!check_smt(directory.path(), &accepting_active_smt()).unwrap());
    }

    #[test]
    fn accepting_active_smt_does_not_accept_an_unknown_status() {
        let missing = tempfile::tempdir().unwrap();
        assert!(matches!(
            check_smt(missing.path(), &accepting_active_smt()),
            Err(SecurityError::SmtUnknown { .. })
        ));
        let unexpected = cpu_directory("2");
        assert!(matches!(
            check_smt(unexpected.path(), &accepting_active_smt()),
            Err(SecurityError::SmtUnknown { .. })
        ));
    }

    #[test]
    fn absent_smt_status_is_not_evidence_that_smt_is_disabled() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            check_smt(directory.path(), &enforced()),
            Err(SecurityError::SmtUnknown { .. })
        ));
    }

    #[test]
    fn unreadable_smt_status_is_not_evidence_that_smt_is_disabled() {
        let directory = cpu_directory("0");
        let path = directory.path().join("smt/active");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(path).unwrap();
        assert!(matches!(
            check_smt(directory.path(), &enforced()),
            Err(SecurityError::SmtUnknown { .. })
        ));
    }

    #[test]
    fn unexpected_smt_status_is_refused() {
        for active in ["", "2", "off", "0\n1", "unknown"] {
            let directory = cpu_directory(active);
            assert!(matches!(
                check_smt(directory.path(), &enforced()),
                Err(SecurityError::SmtUnknown { .. })
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_integration_host_meets_the_smt_requirement() {
        if std::env::var("NIBRUNNER_INTEGRATION").is_ok_and(|value| value == "1") {
            check(&enforced()).expect("disable host SMT before running integration tests");
        }
    }
}
