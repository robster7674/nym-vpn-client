// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

#[cfg(target_os = "freebsd")]
use std::net::{IpAddr, Ipv4Addr};
use std::{io, net::Ipv6Addr, process::Command};

#[cfg(target_os = "linux")]
pub fn set_ipv6_addr(device_name: &str, ipv6_addr: Ipv6Addr) -> io::Result<()> {
    Command::new("ip")
        .args([
            "-6",
            "addr",
            "add",
            &ipv6_addr.to_string(),
            "dev",
            device_name,
        ])
        .output()?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
pub fn set_ipv6_addr(device_name: &str, ipv6_addr: Ipv6Addr) -> io::Result<()> {
    Command::new("ifconfig")
        .args([
            device_name,
            "inet6",
            &ipv6_addr.to_string(),
            "prefixlen",
            "128",
        ])
        .output()?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn set_ipv6_addr(device_name: &str, ipv6_addr: Ipv6Addr) -> io::Result<()> {
    Command::new("ifconfig")
        .args([device_name, "inet6", "add", &ipv6_addr.to_string()])
        .output()?;
    Ok(())
}

/// Set the IPv4 address, destination and MTU of a tun device and bring it up.
///
/// The tun crate cannot configure a new device on FreeBSD: it first tries to delete an address that
/// does not exist yet. A tun device is point-to-point there and needs a destination, so the address
/// itself is used when there is none.
#[cfg(target_os = "freebsd")]
pub fn set_ipv4_addr(
    device_name: &str,
    ipv4_addr: Ipv4Addr,
    destination: Option<IpAddr>,
    mtu: u16,
) -> io::Result<()> {
    let destination = destination.unwrap_or(IpAddr::V4(ipv4_addr));
    let output = Command::new("ifconfig")
        .args([
            device_name,
            "inet",
            &format!("{ipv4_addr}/32"),
            &destination.to_string(),
            "mtu",
            &mtu.to_string(),
            "up",
        ])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "ifconfig {device_name} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}
