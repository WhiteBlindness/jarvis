use std::time::Instant;

use jarvis_protocol::{ProtocolVersion, SystemInfo};

/// Describe the runtime the Core is running in.
///
/// Only values from the Rust standard library are reported. Hostname,
/// username, environment variables and paths are left out on purpose: they
/// identify the user and say nothing useful about the runtime.
pub fn collect(core_version: &str, started: Instant) -> SystemInfo {
    let logical_cpus = std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
        .unwrap_or(1);
    SystemInfo {
        os: std::env::consts::OS.to_owned(),
        os_family: std::env::consts::FAMILY.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        logical_cpus,
        core_version: core_version.to_owned(),
        protocol_version: ProtocolVersion::CURRENT,
        core_uptime_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_build_target() {
        let info = collect("9.9.9", Instant::now());
        assert_eq!(info.os, std::env::consts::OS);
        assert_eq!(info.arch, std::env::consts::ARCH);
        assert!(info.logical_cpus >= 1);
        assert_eq!(info.core_version, "9.9.9");
        assert_eq!(info.protocol_version, ProtocolVersion::CURRENT);
    }

    #[test]
    fn does_not_leak_identity() {
        let rendered = format!("{:?}", collect("0", Instant::now())).to_lowercase();
        for key in ["host", "user", "home", "path", "env"] {
            assert!(
                !rendered.contains(key),
                "unexpected field containing `{key}`"
            );
        }
    }
}
