// Copyright 2016-2025 Mullvad VPN AB. All Rights Reserved.
// Copyright 2026 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! FreeBSD firewall implemented with pf(4).
//!
//! The rules of a policy are rendered as pf.conf text and loaded into the `nym` anchor with
//! pfctl(8). The anchor is referenced from the main ruleset, which this module replaces while a
//! policy is active. When the policy is reset, the main ruleset is restored from `/etc/pf.conf`
//! if pf was enabled before, and pf is disabled again if it was not.
//!
//! Not supported yet: split tunnelling and a main ruleset that is not loaded from `/etc/pf.conf`.

use std::{
    fmt::Write as _,
    io,
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
};

use ipnetwork::IpNetwork;
use nym_firewall_config::{ALLOWED_LAN_MULTICAST_NETS, ALLOWED_LAN_NETS};

use super::{
    FirewallArguments, FirewallPolicy,
    net::{
        AllowedEndpoint, AllowedTunnelTraffic, Endpoint, TransportProtocol, TunnelInterface,
    },
};

const ANCHOR_NAME: &str = "nym";
const PFCTL: &str = "/sbin/pfctl";
const KLDLOAD: &str = "/sbin/kldload";
const PF_CONF: &str = "/etc/pf.conf";


#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to run pfctl(8).
    #[error("failed to run pfctl")]
    Spawn(#[source] io::Error),
    /// pfctl(8) exited with an error.
    #[error("pfctl failed: {0}")]
    Pfctl(String),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Firewall {
    /// Whether pf was enabled before this firewall first enabled it.
    pf_was_enabled: Option<bool>,
}

impl Firewall {
    pub fn from_args(_args: FirewallArguments) -> Result<Self> {
        Self::new()
    }

    pub fn new() -> Result<Self> {
        // Loading the module fails if it is already loaded or compiled in, which is fine.
        let _ = Command::new(KLDLOAD)
            .args(["-n", "pf"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        Ok(Firewall {
            pf_was_enabled: None,
        })
    }

    pub fn apply_policy(&mut self, policy: FirewallPolicy) -> Result<()> {
        if self.pf_was_enabled.is_none() {
            self.pf_was_enabled = Some(is_enabled()?);
        }

        pfctl_load(&[], &main_ruleset())?;
        pfctl_load(&["-a", ANCHOR_NAME], &generate_rules(&policy))?;
        enable()?;

        // States that were approved by an earlier policy would otherwise stay valid.
        pfctl(&["-F", "states"])?;
        Ok(())
    }

    pub fn reset_policy(&mut self) -> Result<()> {
        // Run all steps even if one of them fails, and return the first error.
        let flush = pfctl(&["-a", ANCHOR_NAME, "-F", "all"]).map(|_| ());
        let restore = self.restore_state();
        flush.and(restore)
    }

    fn restore_state(&mut self) -> Result<()> {
        match self.pf_was_enabled.take() {
            Some(true) => {
                if Path::new(PF_CONF).exists() {
                    pfctl(&["-f", PF_CONF])?;
                } else {
                    pfctl_load(&[], "")?;
                }
                Ok(())
            }
            Some(false) => {
                pfctl_load(&[], "")?;
                pfctl(&["-d"]).map(|_| ())
            }
            None => Ok(()),
        }
    }
}

/// The main ruleset that evaluates the anchor.
fn main_ruleset() -> String {
    format!("set skip on lo0\nscrub in all fragment reassemble\nanchor \"{ANCHOR_NAME}\"\n")
}

fn is_enabled() -> Result<bool> {
    let output = pfctl(&["-s", "info"])?;
    Ok(output
        .lines()
        .any(|line| line.trim_start().starts_with("Status: Enabled")))
}

fn enable() -> Result<()> {
    match pfctl(&["-e"]) {
        Ok(_) => Ok(()),
        // pfctl reports an error if pf is already enabled.
        Err(Error::Pfctl(message)) if message.contains("already enabled") => Ok(()),
        Err(error) => Err(error),
    }
}

fn pfctl(args: &[&str]) -> Result<String> {
    let output = Command::new(PFCTL)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(Error::Spawn)?;
    check_output(args, output)
}

/// Load `rules` with `pfctl <args> -f -`.
fn pfctl_load(args: &[&str], rules: &str) -> Result<()> {
    use std::io::Write;

    let mut child = Command::new(PFCTL)
        .args(args)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(Error::Spawn)?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(rules.as_bytes())
        .map_err(Error::Spawn)?;
    let output = child.wait_with_output().map_err(Error::Spawn)?;
    check_output(args, output).map(|_| ())
}

fn check_output(args: &[&str], output: std::process::Output) -> Result<String> {
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::Pfctl(format!(
            "`pfctl {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Restricts a rule to processes of the root user.
fn root_user() -> String {
    format!("user {}", super::ROOT_UID)
}

fn proto(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Udp => "udp",
        TransportProtocol::Tcp => "tcp",
    }
}

/// `flags S/SA` only applies to TCP rules.
fn state_options(protocol: Option<TransportProtocol>) -> &'static str {
    match protocol {
        Some(TransportProtocol::Udp) => "keep state",
        _ => "flags S/SA keep state",
    }
}

fn to_endpoint(endpoint: &Endpoint) -> String {
    format!(
        "to {} port {}",
        endpoint.address.ip(),
        endpoint.address.port()
    )
}

/// Render the rules of the policy as the content of the `nym` anchor.
fn generate_rules(policy: &FirewallPolicy) -> String {
    let mut rules = String::new();

    allow_dhcp_client(&mut rules);
    allow_ndp(&mut rules);

    match policy {
        FirewallPolicy::Connecting {
            peer_endpoints,
            tunnel,
            allow_lan,
            dns_config,
            allowed_endpoints,
            allowed_entry_tunnel_traffic,
            allowed_exit_tunnel_traffic,
        } => {
            for dns in dns_config.non_tunnel_dns() {
                // Only root may use the non-tunnel DNS servers while connecting.
                let _ = writeln!(
                    rules,
                    "pass out quick proto {} {} {} {}",
                    proto(dns.protocol),
                    to_endpoint(dns),
                    state_options(Some(dns.protocol)),
                    root_user(),
                );
            }
            for endpoint in peer_endpoints.iter().chain(allowed_endpoints) {
                allow_endpoint(&mut rules, endpoint);
            }

            // Block DNS after the relay rules (the relay may use port 53) but before the LAN rules,
            // so that DNS does not leak to the LAN.
            block_dns(&mut rules);

            if let Some(tunnel) = tunnel {
                match tunnel {
                    TunnelInterface::One(exit) => {
                        allow_tunnel(&mut rules, &exit.interface, allowed_exit_tunnel_traffic);
                    }
                    TunnelInterface::Two { entry, exit } => {
                        allow_tunnel(&mut rules, &entry.interface, allowed_entry_tunnel_traffic);
                        allow_tunnel(&mut rules, &exit.interface, allowed_exit_tunnel_traffic);
                    }
                }
            }

            if *allow_lan {
                allow_lan_rules(&mut rules);
            }
        }
        FirewallPolicy::Connected {
            peer_endpoints,
            tunnel,
            allow_lan,
            dns_config,
        } => {
            let (entry, exit) = match tunnel {
                TunnelInterface::One(exit) => (None, exit),
                TunnelInterface::Two { entry, exit } => (Some(entry), exit),
            };

            // Only port 53 is allowed, since "block DNS" targets port 53 specifically.
            for dns in dns_config.tunnel_dns() {
                if dns.address.port() == 53 {
                    let _ = writeln!(
                        rules,
                        "pass out quick on {} proto {} {} {}",
                        exit.interface,
                        proto(dns.protocol),
                        to_endpoint(dns),
                        state_options(Some(dns.protocol)),
                    );
                }
            }
            for dns in dns_config.non_tunnel_dns() {
                // Requests to a local DNS server must not go through the tunnel.
                for protocol in ["tcp", "udp"] {
                    let _ = writeln!(
                        rules,
                        "block return out quick on {} proto {protocol} {}",
                        exit.interface,
                        to_endpoint(dns)
                    );
                }
                for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
                    let _ = writeln!(
                        rules,
                        "pass out quick proto {} {} {}",
                        proto(protocol),
                        to_endpoint(dns),
                        state_options(Some(protocol)),
                    );
                }
            }

            for endpoint in peer_endpoints {
                allow_endpoint(&mut rules, endpoint);
            }

            // Block DNS before allowing the tunnel and the LAN, so that it cannot leak to the
            // wrong addresses in the tunnel or on the LAN.
            block_dns(&mut rules);

            if *allow_lan {
                allow_lan_rules(&mut rules);
            }

            if let Some(entry) = entry {
                allow_tunnel(&mut rules, &entry.interface, &AllowedTunnelTraffic::All);
            }
            allow_tunnel(&mut rules, &exit.interface, &AllowedTunnelTraffic::All);
        }
        FirewallPolicy::Blocked {
            allow_lan,
            allowed_endpoints,
        } => {
            for endpoint in allowed_endpoints {
                allow_endpoint(&mut rules, endpoint);
            }
            if *allow_lan {
                // Block DNS before allowing the LAN, so that it does not leak to the LAN.
                block_dns(&mut rules);
                allow_lan_rules(&mut rules);
            }
        }
    }

    rules.push_str("block return out quick all\n");
    rules.push_str("block drop quick all\n");
    rules
}

/// Allow traffic to an endpoint, for the root user only unless all clients are allowed.
fn allow_endpoint(rules: &mut String, endpoint: &AllowedEndpoint) {
    let user = if endpoint.clients.allow_all() {
        String::new()
    } else {
        root_user()
    };
    let _ = writeln!(
        rules,
        "pass out quick proto {} {} {} {user}",
        proto(endpoint.endpoint.protocol),
        to_endpoint(&endpoint.endpoint),
        state_options(Some(endpoint.endpoint.protocol)),
    );
}

fn block_dns(rules: &mut String) {
    rules.push_str("block return out quick proto tcp to port 53\n");
    rules.push_str("block return out quick proto udp to port 53\n");
}

fn allow_tunnel(rules: &mut String, interface: &str, traffic: &AllowedTunnelTraffic) {
    let endpoints = match traffic {
        AllowedTunnelTraffic::None => return,
        AllowedTunnelTraffic::All => {
            let _ = writeln!(rules, "pass quick on {interface} {}", state_options(None));
            return;
        }
        AllowedTunnelTraffic::One(endpoint) => vec![endpoint],
        AllowedTunnelTraffic::Two(first, second) => vec![first, second],
    };
    for endpoint in endpoints {
        let _ = writeln!(
            rules,
            "pass quick on {interface} proto {} {} {}",
            proto(endpoint.protocol),
            to_endpoint(endpoint),
            state_options(Some(endpoint.protocol)),
        );
    }
}

fn allow_lan_rules(rules: &mut String) {
    for net in ALLOWED_LAN_NETS {
        let _ = writeln!(rules, "pass out quick from any to {net} keep state");
        let _ = writeln!(rules, "pass in quick from {net} to any keep state");
    }
    for net in ALLOWED_LAN_MULTICAST_NETS {
        let _ = writeln!(rules, "pass out quick to {net}");
    }

    let _ = writeln!(
        rules,
        "pass out quick inet proto udp from port {} to port {}",
        super::DHCPV4_SERVER_PORT,
        super::DHCPV4_CLIENT_PORT
    );
    let _ = writeln!(
        rules,
        "pass in quick proto udp from port {} to {} port {}",
        super::DHCPV4_CLIENT_PORT,
        Ipv4Addr::BROADCAST,
        super::DHCPV4_SERVER_PORT
    );
}

fn allow_dhcp_client(rules: &mut String) {
    let _ = writeln!(
        rules,
        "pass out quick inet proto udp from port {} to {} port {}",
        super::DHCPV4_CLIENT_PORT,
        Ipv4Addr::BROADCAST,
        super::DHCPV4_SERVER_PORT
    );
    let _ = writeln!(
        rules,
        "pass in quick inet proto udp from port {} to port {}",
        super::DHCPV4_SERVER_PORT,
        super::DHCPV4_CLIENT_PORT
    );

    for server in super::DHCPV6_SERVER_ADDRS {
        let _ = writeln!(
            rules,
            "pass out quick inet6 proto udp from {} port {} to {server} port {}",
            super::IPV6_LINK_LOCAL,
            super::DHCPV6_CLIENT_PORT,
            super::DHCPV6_SERVER_PORT
        );
    }
    let _ = writeln!(
        rules,
        "pass in quick inet6 proto udp from {} port {} to {} port {}",
        super::IPV6_LINK_LOCAL,
        super::DHCPV6_SERVER_PORT,
        super::IPV6_LINK_LOCAL,
        super::DHCPV6_CLIENT_PORT
    );
}

fn allow_ndp(rules: &mut String) {
    let link_local = IpNetwork::V6(super::IPV6_LINK_LOCAL);
    // pf expects the ICMPv6 type after the addresses.
    let _ = writeln!(
        rules,
        "pass out quick inet6 proto icmp6 from any to {} icmp6-type routersol",
        super::ROUTER_SOLICITATION_OUT_DST_ADDR
    );
    let _ = writeln!(
        rules,
        "pass in quick inet6 proto icmp6 from {link_local} to any icmp6-type routeradv"
    );
    let _ = writeln!(
        rules,
        "pass in quick inet6 proto icmp6 from {link_local} to any icmp6-type redir"
    );
    let _ = writeln!(
        rules,
        "pass out quick inet6 proto icmp6 from any to {} icmp6-type neighbrsol",
        super::SOLICITED_NODE_MULTICAST
    );
    let _ = writeln!(
        rules,
        "pass out quick inet6 proto icmp6 from any to {link_local} icmp6-type neighbrsol"
    );
    let _ = writeln!(
        rules,
        "pass in quick inet6 proto icmp6 from {link_local} to any icmp6-type neighbrsol"
    );
    let _ = writeln!(
        rules,
        "pass out quick inet6 proto icmp6 from any to {link_local} icmp6-type neighbradv"
    );
    let _ = writeln!(
        rules,
        "pass in quick inet6 proto icmp6 from any to any icmp6-type neighbradv"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{AllowedClients, AllowedDns, TunnelMetadata};
    use std::net::IpAddr;

    fn tunnel() -> TunnelInterface {
        TunnelInterface::One(TunnelMetadata {
            interface: "tun0".to_owned(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            ipv4_gateway: None,
            ipv6_gateway: None,
        })
    }

    fn peer() -> AllowedEndpoint {
        AllowedEndpoint::new(
            Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 51820, TransportProtocol::Udp),
            AllowedClients::Root,
        )
    }

    #[test]
    fn blocked_policy_drops_everything_else() {
        let rules = generate_rules(&FirewallPolicy::Blocked {
            allow_lan: false,
            allowed_endpoints: vec![peer()],
        });
        assert!(rules.contains(
            "pass out quick proto udp to 203.0.113.7 port 51820 keep state user 0"
        ));
        assert!(!rules.contains("10.0.0.0/8"));
        assert!(rules.ends_with("block return out quick all\nblock drop quick all\n"));
    }

    #[test]
    fn connected_policy_allows_tunnel_and_blocks_dns() {
        let rules = generate_rules(&FirewallPolicy::Connected {
            peer_endpoints: vec![peer()],
            tunnel: tunnel(),
            allow_lan: true,
            dns_config: AllowedDns::new(vec![], vec![]),
        });
        let block_dns = rules.find("block return out quick proto udp to port 53").unwrap();
        let allow_tunnel = rules.find("pass quick on tun0 flags S/SA keep state").unwrap();
        let allow_lan = rules.find("pass out quick from any to 10.0.0.0/8").unwrap();
        assert!(block_dns < allow_lan, "DNS must be blocked before the LAN is allowed");
        assert!(block_dns < allow_tunnel);
    }

    #[test]
    fn connecting_policy_limits_tunnel_traffic() {
        let endpoint = Endpoint::new(Ipv4Addr::new(10, 1, 0, 1), 8080, TransportProtocol::Tcp);
        let rules = generate_rules(&FirewallPolicy::Connecting {
            peer_endpoints: vec![peer()],
            tunnel: Some(tunnel()),
            allow_lan: false,
            dns_config: AllowedDns::new(vec![], vec![]),
            allowed_endpoints: vec![],
            allowed_entry_tunnel_traffic: AllowedTunnelTraffic::None,
            allowed_exit_tunnel_traffic: AllowedTunnelTraffic::One(endpoint),
        });
        assert!(rules.contains(
            "pass quick on tun0 proto tcp to 10.1.0.1 port 8080 flags S/SA keep state"
        ));
        assert!(!rules.contains("pass quick on tun0 flags"));
    }

    /// Check the generated rulesets with the pf parser, without loading them.
    #[test]
    #[ignore = "requires pfctl and the pf kernel module"]
    fn generated_rules_parse_with_pfctl() {
        let dns = Endpoint::new(Ipv4Addr::new(10, 0, 0, 1), 53, TransportProtocol::Udp);
        let policies = [
            FirewallPolicy::Blocked {
                allow_lan: true,
                allowed_endpoints: vec![peer()],
            },
            FirewallPolicy::Connecting {
                peer_endpoints: vec![peer()],
                tunnel: Some(tunnel()),
                allow_lan: true,
                dns_config: AllowedDns::new(vec![], vec![dns]),
                allowed_endpoints: vec![peer()],
                allowed_entry_tunnel_traffic: AllowedTunnelTraffic::None,
                allowed_exit_tunnel_traffic: AllowedTunnelTraffic::All,
            },
            FirewallPolicy::Connected {
                peer_endpoints: vec![peer()],
                tunnel: tunnel(),
                allow_lan: true,
                dns_config: AllowedDns::new(
                    vec![Endpoint::new(
                        Ipv4Addr::new(10, 64, 0, 1),
                        53,
                        TransportProtocol::Udp,
                    )],
                    vec![dns],
                ),
            },
        ];

        for policy in policies {
            let rules = generate_rules(&policy);
            let mut child = Command::new(PFCTL)
                .args(["-n", "-a", ANCHOR_NAME, "-f", "-"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            std::io::Write::write_all(&mut child.stdin.take().unwrap(), rules.as_bytes()).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "pfctl rejected the rules of `{policy}`: {}\n{rules}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Resets the firewall when the test ends, also when it fails.
    struct ResetOnDrop(Firewall);

    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            let _ = self.0.reset_policy();
        }
    }

    /// Loads a policy into pf and removes it again. This blocks all network traffic for the
    /// duration of the test, including an SSH session to the machine.
    #[test]
    #[ignore = "changes the pf configuration of the machine, requires root"]
    fn applies_and_resets_policy() {
        let was_enabled = is_enabled().unwrap();
        let mut firewall = ResetOnDrop(Firewall::new().unwrap());

        firewall
            .0
            .apply_policy(FirewallPolicy::Blocked {
                allow_lan: false,
                allowed_endpoints: vec![peer()],
            })
            .unwrap();

        assert!(is_enabled().unwrap());
        let anchor_rules = pfctl(&["-a", ANCHOR_NAME, "-s", "rules"]).unwrap();
        assert!(anchor_rules.contains("203.0.113.7"), "{anchor_rules}");
        assert!(anchor_rules.contains("block drop quick all"), "{anchor_rules}");
        assert!(pfctl(&["-s", "rules"]).unwrap().contains("anchor \"nym\""));

        firewall.0.reset_policy().unwrap();

        assert_eq!(is_enabled().unwrap(), was_enabled);
        assert!(pfctl(&["-a", ANCHOR_NAME, "-s", "rules"]).unwrap().trim().is_empty());
    }
}
