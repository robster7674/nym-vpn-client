// Copyright 2026 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! FreeBSD DNS monitor using resolvconf(8).
//!
//! The DNS servers are registered as an exclusive record, so that resolv.conf only lists the
//! servers of the tunnel while it is up. Removing the record restores the previous servers.

use std::{collections::HashSet, io, path::Path, process::Stdio};

use tokio::{io::AsyncWriteExt, process::Command};

use super::DnsConfig;

const RESOLVCONF: &str = "/sbin/resolvconf";

pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can happen in the FreeBSD DNS monitor.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// resolvconf(8) is not installed.
    #[error("{RESOLVCONF} was not found")]
    NoResolvconf,

    /// Failed to run resolvconf(8).
    #[error("failed to run resolvconf")]
    RunResolvconf(#[source] io::Error),

    /// resolvconf(8) failed to add a record.
    #[error("using resolvconf to add a record failed: {stderr}")]
    AddRecord { stderr: String },

    /// resolvconf(8) failed to delete a record.
    #[error("using resolvconf to delete a record failed: {stderr}")]
    DeleteRecord { stderr: String },
}

pub struct DnsMonitor {
    record_names: HashSet<String>,
}

impl super::DnsMonitorT for DnsMonitor {
    type Error = Error;

    fn new() -> Result<Self> {
        if !Path::new(RESOLVCONF).exists() {
            return Err(Error::NoResolvconf);
        }
        Ok(DnsMonitor {
            record_names: HashSet::new(),
        })
    }

    async fn set(&mut self, interface: &str, config: DnsConfig) -> Result<()> {
        let record_name = format!("{interface}.nym");
        let record_contents: String = config
            .addresses
            .iter()
            .map(|address| format!("nameserver {address}\n"))
            .collect();

        let mut child = Command::new(RESOLVCONF)
            .args(["-x", "-a", &record_name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(Error::RunResolvconf)?;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(record_contents.as_bytes())
            .await
            .map_err(Error::RunResolvconf)?;
        let output = child
            .wait_with_output()
            .await
            .map_err(Error::RunResolvconf)?;

        if !output.status.success() {
            return Err(Error::AddRecord {
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        self.record_names.insert(record_name);
        Ok(())
    }

    async fn reset(&mut self) -> Result<()> {
        let mut result = Ok(());

        for record_name in self.record_names.drain() {
            let output = Command::new(RESOLVCONF)
                .args(["-d", &record_name, "-f"])
                .stdin(Stdio::null())
                .output()
                .await
                .map_err(Error::RunResolvconf)?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                tracing::error!("Failed to delete resolvconf record '{record_name}': {stderr}");
                result = Err(Error::DeleteRecord { stderr });
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnsMonitorT;

    /// Registers DNS servers with resolvconf, requires root.
    #[tokio::test]
    #[ignore = "changes /etc/resolv.conf, requires root"]
    async fn sets_and_resets_dns() {
        let before = std::fs::read_to_string("/etc/resolv.conf").unwrap();

        let mut monitor = DnsMonitor::new().unwrap();
        monitor
            .set(
                "tun9",
                DnsConfig {
                    addresses: vec!["127.1.2.3".parse().unwrap()],
                    port: 53,
                },
            )
            .await
            .unwrap();

        let during = std::fs::read_to_string("/etc/resolv.conf").unwrap();
        assert!(during.contains("nameserver 127.1.2.3"), "{during}");
        // The record is exclusive, so the servers of other interfaces are not used.
        assert_eq!(during.matches("nameserver").count(), 1, "{during}");

        monitor.reset().await.unwrap();

        let after = std::fs::read_to_string("/etc/resolv.conf").unwrap();
        assert_eq!(after, before);
    }
}
