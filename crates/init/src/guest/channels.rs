use nix::unistd::{ForkResult, Pid};

use guest_contract::instance_env::InstanceConfig;

use crate::guest::{control, cron, filesystem, identity, log, memory, s3_bridge};

pub(crate) struct Channels {
    identity: Option<Pid>,
    control: Option<Pid>,
    files: Option<Pid>,
    cron: Option<Pid>,
    s3_bridge: Option<Pid>,
}

pub(crate) fn start(config: &InstanceConfig, ceiling: &memory::Ceiling) -> Channels {
    Channels {
        identity: if identity::asynchronous() {
            fork_channel("workload identity", identity::serve)
        } else {
            None
        },
        control: fork_channel("control", control::serve),
        files: fork_channel("filesystem", filesystem::serve),
        cron: cron::start(config, ceiling),
        s3_bridge: s3_bridge::start(config),
    }
}

impl Channels {
    pub(crate) fn stop(&self) {
        if let Some(pid) = self.cron {
            cron::stop(pid);
        }
        for pid in [self.control, self.files, self.identity, self.s3_bridge]
            .into_iter()
            .flatten()
        {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
        }
        control::thaw_quietly();
        for pid in [self.control, self.files, self.identity, self.s3_bridge]
            .into_iter()
            .flatten()
        {
            let _ = nix::sys::wait::waitpid(pid, None);
        }
    }
}

fn fork_channel(what: &'static str, serve: fn() -> !) -> Option<Pid> {
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Parent { child }) => Some(child),
        Ok(ForkResult::Child) => {
            // The guest blocks SIGTERM before forking us; left blocked, Channels::stop() would
            // SIGTERM this child and then waitpid on it forever, so the guest never reboots.
            let _ = nix::sys::signal::SigSet::all().thread_unblock();
            serve()
        }
        Err(error) => {
            log(&format!("the {what} channel could not be started: {error}"));
            None
        }
    }
}
