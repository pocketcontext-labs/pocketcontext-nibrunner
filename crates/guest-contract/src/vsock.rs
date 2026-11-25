pub const TENANT_LOG_VSOCK_PORT: u32 = 51000;

pub const GUEST_CONTROL_VSOCK_PORT: u32 = 51001;

pub const GUEST_FILESYSTEM_VSOCK_PORT: u32 = 51002;

pub const CRON_REGISTRATION_PORT: u32 = 51003;

pub const CRON_EXECUTION_PORT: u32 = 51004;

pub const IDENTITY_PORT: u32 = 51005;
pub const SIGN_IN_EMAIL_PORT: u32 = 51006;
pub const MAX_SIGN_IN_EMAIL_FRAME: usize = 128;
pub const MAX_IDENTITY_BYTES: usize = 16 * 1024;
pub const HOST_SERVICES_PORT: u32 = 51007;

// The guest's S3 endpoint and its placeholder keys: the host ignores the signature they make and
// signs again with the app's own session, so nothing secret is in the guest.
pub const S3_BRIDGE_ADDRESS: &str = "127.0.0.1:9000";
pub const S3_BRIDGE_ENDPOINT: &str = "http://127.0.0.1:9000";
pub const S3_BRIDGE_ACCESS_KEY_ID: &str = "nibrunner-host-services";
pub const S3_BRIDGE_SECRET_ACCESS_KEY: &str = "signed-again-by-the-host";

pub const GUEST_VSOCK_FILENAME: &str = "logs.vsock";

pub fn tenant_log_socket_name() -> String {
    format!("{GUEST_VSOCK_FILENAME}_{TENANT_LOG_VSOCK_PORT}")
}

pub fn connect_request(port: u32) -> String {
    format!("CONNECT {port}\n")
}

const CONNECT_ACCEPTED: &str = "OK ";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("nothing in the guest answered vsock port {port}: {reply}")]
pub struct GuestPortUnreachable {
    pub port: u32,
    pub reply: String,
}

pub fn read_connect_reply(reply: &str, port: u32) -> Result<(), GuestPortUnreachable> {
    if reply.starts_with(CONNECT_ACCEPTED) {
        Ok(())
    } else {
        Err(GuestPortUnreachable {
            port,
            reply: reply.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_handshake_asks_for_the_control_port_by_number() {
        assert_eq!(connect_request(GUEST_CONTROL_VSOCK_PORT), "CONNECT 51001\n");
        assert_eq!(tenant_log_socket_name(), "logs.vsock_51000");
    }

    #[test]
    fn only_a_reply_naming_the_bound_port_is_accepted() {
        assert!(read_connect_reply("OK 1234", GUEST_CONTROL_VSOCK_PORT).is_ok());
        for reply in ["FAILED", "", "OK", "NOT OK 1234"] {
            assert!(read_connect_reply(reply, GUEST_CONTROL_VSOCK_PORT).is_err());
        }
    }
}
