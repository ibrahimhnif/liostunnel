use std::path::Path;

use liostunnel_core::TunnelError;
use liostunnel_core::config::portable::PortableProfile;
use liostunnel_core::config::profile::ServerProfile;

/// Accepts either representation (spec §6.3). Tries the ref-bearing form first,
/// then the portable form, importing its secrets onto disk.
pub fn load(path: &Path, secret_dir: &Path) -> Result<ServerProfile, TunnelError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        TunnelError::config(path.display().to_string(), format!("cannot read: {e}"))
    })?;

    if let Ok(p) = serde_json::from_str::<ServerProfile>(&raw) {
        return Ok(p);
    }

    match serde_json::from_str::<PortableProfile>(&raw) {
        Ok(p) => p.import(secret_dir),
        Err(e) => Err(TunnelError::config(
            path.display().to_string(),
            format!("not a valid profile in either format: {e}"),
        )),
    }
}

/// `~/.liostunnel`, or `$LIOSTUNNEL_HOME` when set.
pub fn home() -> std::path::PathBuf {
    std::env::var_os("LIOSTUNNEL_HOME")
        .map(Into::into)
        .unwrap_or_else(|| {
            let base = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            base.join(".liostunnel")
        })
}
