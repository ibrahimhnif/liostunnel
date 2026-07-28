use std::io;

/// The single error type for the whole core. Spec §11.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("config error at `{field}`: {reason}")]
    Config { field: String, reason: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("host key verification failed: {0}")]
    HostKey(String),

    #[error("transport error: {0}")]
    Transport(#[from] io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("{0} is not supported in this build")]
    Unsupported(&'static str),

    #[error("dns error: {0}")]
    Dns(String),

    #[error("route error: {0}")]
    Route(String),

    #[error("tun device error: {0}")]
    Tun(String),
}

impl TunnelError {
    /// Convenience constructor so call sites stay readable.
    pub fn config(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Config {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_names_the_offending_field() {
        let e = TunnelError::Config {
            field: "dns.servers".into(),
            reason: "must not be empty".into(),
        };
        assert_eq!(
            e.to_string(),
            "config error at `dns.servers`: must not be empty"
        );
    }

    #[test]
    fn unsupported_error_names_the_feature() {
        let e = TunnelError::Unsupported("wireguard");
        assert_eq!(e.to_string(), "wireguard is not supported in this build");
    }

    #[test]
    fn io_errors_convert_into_transport() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let e: TunnelError = io.into();
        assert!(matches!(e, TunnelError::Transport(_)));
    }
}
