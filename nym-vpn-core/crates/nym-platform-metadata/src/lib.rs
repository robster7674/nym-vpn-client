// Copyright 2016-2025 Mullvad VPN AB. All Rights Reserved.
// Copyright 2025 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use std::{collections::HashMap, env, fmt::Display};

use sha2::{Digest, Sha256};
use sysinfo::System;

#[cfg(target_os = "android")]
mod android;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod command;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(feature = "user-agent-macro")]
pub mod user_agent;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::AppleVersion;

#[derive(Debug, Clone)]
pub struct SysInfo {
    /// The name of the operating system.
    pub system_name: String,
    /// The version of the operating system including its name
    pub os_version: String,
    /// CPU architecture
    pub arch: String,
    /// Extra metadata
    pub extra: Vec<String>,
}

impl SysInfo {
    pub fn new() -> Self {
        // Some platforms report values with trailing whitespace. FreeBSD ends the kernel version
        // with a newline, which is not valid in an HTTP header.
        let system_name = System::name()
            .unwrap_or("unknown".to_owned())
            .trim()
            .to_owned();
        let os_version = System::long_os_version()
            .unwrap_or_else(|| env::consts::OS.into())
            .trim()
            .to_owned();
        let arch = System::cpu_arch().trim().to_owned();
        let extra_metadata = Self::extra_metadata()
            .into_iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>();

        SysInfo {
            system_name,
            os_version,
            arch,
            extra: extra_metadata,
        }
    }

    /// Generates a hash identifier based on the OS version, architecture, extra metadata, and host name.
    /// Returns a hexadecimal string representation of the hash.
    /// This identifier is used to identify the system in a way that is consistent across runs,
    /// without revealing sensitive information.
    pub fn hash_identifier(&self) -> String {
        let parts = [
            self.os_version.clone(),
            self.arch.clone(),
            self.extra.to_vec().join(" "),
            sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string()),
        ];

        let os_name = parts.join(" ");
        let hash = Sha256::digest(os_name.as_bytes());
        hex::encode(hash)
    }

    fn extra_metadata() -> HashMap<String, String> {
        #[cfg(target_os = "android")]
        {
            android::extra_metadata()
        }

        #[cfg(target_os = "linux")]
        {
            linux::extra_metadata()
        }

        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            HashMap::new()
        }
    }
}

impl Display for SysInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.os_version, self.arch)?;
        if !self.extra.is_empty() {
            write!(f, ", {}", self.extra.join(", "))?;
        }
        Ok(())
    }
}

impl Default for SysInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values end up in the `User-Agent` header, so they must be printable ASCII.
    #[test]
    fn sys_info_is_valid_in_a_header() {
        let sys_info = SysInfo::new();
        for value in [&sys_info.system_name, &sys_info.os_version, &sys_info.arch] {
            assert!(
                value.bytes().all(|byte| (0x20..0x7f).contains(&byte)),
                "not printable ASCII: {value:?}"
            );
        }
    }
}
