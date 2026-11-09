// Copyright 2026 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! FreeBSD route manager.
//!
//! Routes are installed and removed by running route(8), and the system default routes are read
//! from `route -n get`. Changes to the default routes are detected by polling. A native `PF_ROUTE`
//! implementation can replace this later without changing the public API.

use std::{
    collections::HashSet,
    ffi::CString,
    net::IpAddr,
    process::Stdio,
    time::Duration,
};

use ipnetwork::IpNetwork;
use tokio::{process::Command, sync::mpsc};

use super::{DefaultRouteEvent, RouteManagerCommand};
use crate::{AddressFamily, DefaultRouteInterfaces, NetNode, RequiredRoute};

const ROUTE_BINARY: &str = "/sbin/route";

/// How often the system default routes are compared against the last observed ones.
const DEFAULT_ROUTE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Interface name prefixes that are treated as tunnels rather than physical interfaces.
const TUNNEL_INTERFACE_PREFIXES: &[&str] = &["tun", "tap", "wg", "ipsec", "gif", "gre", "ovpn"];

/// Route manager error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to run route(8).
    #[error("failed to run route(8)")]
    Spawn(#[source] std::io::Error),
    /// route(8) exited with an error.
    #[error("route(8) failed: {0}")]
    Route(String),
    /// There is no system default route to resolve a default node with.
    #[error("no default route found")]
    NoDefaultRoute,
}

/// The system default route for one address family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// Interface name.
    pub interface: String,

    /// Interface index.
    pub interface_index: u16,

    /// Router IP, if the default route has a gateway.
    pub router_ip: Option<IpAddr>,
}

/// A route that has been installed by this manager.
#[derive(Debug)]
struct InstalledRoute {
    prefix: IpNetwork,
}

pub struct RouteManagerImpl {
    required: HashSet<RequiredRoute>,
    installed: Vec<InstalledRoute>,
    listeners: Vec<mpsc::UnboundedSender<DefaultRouteEvent>>,
    default_routes: (Option<DefaultRoute>, Option<DefaultRoute>),
}

impl RouteManagerImpl {
    pub async fn new() -> Result<Self, Error> {
        let default_routes = (
            get_default_route(AddressFamily::Ipv4).await,
            get_default_route(AddressFamily::Ipv6).await,
        );
        Ok(Self {
            required: HashSet::new(),
            installed: Vec::new(),
            listeners: Vec::new(),
            default_routes,
        })
    }

    pub(crate) async fn run(mut self, mut manage_rx: mpsc::UnboundedReceiver<RouteManagerCommand>) {
        let mut poll = tokio::time::interval(DEFAULT_ROUTE_POLL_INTERVAL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                command = manage_rx.recv() => {
                    let Some(command) = command else { break };
                    if self.handle_command(command).await {
                        break;
                    }
                }
                _ = poll.tick() => {
                    self.poll_default_routes().await;
                }
            }
        }

        self.remove_installed().await;
    }

    /// Handle a command. Returns `true` if the manager should shut down.
    async fn handle_command(&mut self, command: RouteManagerCommand) -> bool {
        match command {
            RouteManagerCommand::AddRoutes(routes, result_tx) => {
                let result = self.add_routes(routes).await;
                let _ = result_tx.send(result);
            }
            RouteManagerCommand::ClearRoutes => {
                self.required.clear();
                self.remove_installed().await;
            }
            RouteManagerCommand::RefreshRoutes => {
                self.default_routes = (
                    get_default_route(AddressFamily::Ipv4).await,
                    get_default_route(AddressFamily::Ipv6).await,
                );
                self.reapply_routes().await;
            }
            RouteManagerCommand::NewDefaultRouteListener(response_tx) => {
                let (tx, rx) = mpsc::unbounded_channel();
                self.listeners.push(tx);
                let _ = response_tx.send(rx);
            }
            RouteManagerCommand::GetDefaultRoutes(response_tx) => {
                let _ = response_tx.send(self.default_routes.clone());
            }
            RouteManagerCommand::Shutdown(done_tx) => {
                self.remove_installed().await;
                let _ = done_tx.send(());
                return true;
            }
        }
        false
    }

    async fn add_routes(&mut self, routes: HashSet<RequiredRoute>) -> Result<(), Error> {
        for route in routes {
            if let Err(error) = self.install(&route).await {
                self.required.remove(&route);
                self.remove_installed().await;
                return Err(error);
            }
            self.required.insert(route);
        }
        Ok(())
    }

    /// Install a single route and record it so that it is removed again later.
    async fn install(&mut self, route: &RequiredRoute) -> Result<(), Error> {
        let (gateway, interface) = self.resolve_node(route)?;
        let args = route_args("add", route, gateway, interface.as_deref());

        if let Err(error) = run_route(&args).await {
            // The route may already be there, for example if the daemon crashed earlier.
            let change_args = route_args("change", route, gateway, interface.as_deref());
            if run_route(&change_args).await.is_err() {
                return Err(error);
            }
        }

        tracing::debug!("Added route {}", route.prefix);
        self.installed.push(InstalledRoute {
            prefix: route.prefix,
        });
        Ok(())
    }

    fn resolve_node(&self, route: &RequiredRoute) -> Result<(Option<IpAddr>, Option<String>), Error> {
        match &route.node {
            NetNode::RealNode(node) => Ok((node.get_address(), node.get_device().map(String::from))),
            NetNode::DefaultNode => {
                let default_route = if route.prefix.is_ipv4() {
                    &self.default_routes.0
                } else {
                    &self.default_routes.1
                };
                let default_route = default_route.as_ref().ok_or(Error::NoDefaultRoute)?;
                Ok((default_route.router_ip, Some(default_route.interface.clone())))
            }
        }
    }

    async fn remove_installed(&mut self) {
        for route in self.installed.drain(..) {
            let args = delete_args(&route.prefix);
            if let Err(error) = run_route(&args).await {
                tracing::warn!("Failed to remove route {}: {error}", route.prefix);
            }
        }
    }

    /// Remove all installed routes and add them again, resolving default nodes anew.
    async fn reapply_routes(&mut self) {
        self.remove_installed().await;
        for route in self.required.clone() {
            if let Err(error) = self.install(&route).await {
                tracing::error!("Failed to re-add route {}: {error}", route.prefix);
            }
        }
    }

    async fn poll_default_routes(&mut self) {
        let current = (
            get_default_route(AddressFamily::Ipv4).await,
            get_default_route(AddressFamily::Ipv6).await,
        );
        if current == self.default_routes {
            return;
        }

        let mut events = Vec::new();
        match (&self.default_routes.0, &current.0) {
            (_, Some(_)) if self.default_routes.0 != current.0 => {
                events.push(DefaultRouteEvent::AddedOrChangedV4)
            }
            (Some(_), None) => events.push(DefaultRouteEvent::RemovedV4),
            _ => (),
        }
        match (&self.default_routes.1, &current.1) {
            (_, Some(_)) if self.default_routes.1 != current.1 => {
                events.push(DefaultRouteEvent::AddedOrChangedV6)
            }
            (Some(_), None) => events.push(DefaultRouteEvent::RemovedV6),
            _ => (),
        }

        self.default_routes = current;

        if self
            .required
            .iter()
            .any(|route| matches!(route.node, NetNode::DefaultNode))
        {
            self.reapply_routes().await;
        }

        self.listeners
            .retain(|listener| events.iter().all(|event| listener.send(*event).is_ok()));
    }
}

/// Get every interface currently holding a default route for the given address family.
pub async fn get_default_route_interfaces(
    family: AddressFamily,
) -> Result<DefaultRouteInterfaces, super::Error> {
    let mut result = DefaultRouteInterfaces::default();

    // `route get default` only reports the route that matches a lookup of the default route, so
    // this does not see a default route that is shadowed by another one on a second interface.
    if let Some(route) = get_default_route(family).await {
        if is_tunnel_like_interface(&route.interface) {
            result.virtual_.insert(route.interface);
        } else {
            result.physical.insert(route.interface);
        }
    }

    Ok(result)
}

fn is_tunnel_like_interface(name: &str) -> bool {
    TUNNEL_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit())))
}

fn family_flag(is_ipv4: bool) -> &'static str {
    if is_ipv4 { "-inet" } else { "-inet6" }
}

fn route_args(
    operation: &str,
    route: &RequiredRoute,
    gateway: Option<IpAddr>,
    interface: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "-n".to_owned(),
        operation.to_owned(),
        family_flag(route.prefix.is_ipv4()).to_owned(),
    ];
    push_destination(&mut args, &route.prefix);

    match (gateway, interface) {
        (Some(gateway), Some(interface)) => {
            args.extend([gateway.to_string(), "-ifp".to_owned(), interface.to_owned()]);
        }
        (Some(gateway), None) => args.push(gateway.to_string()),
        (None, Some(interface)) => args.extend(["-interface".to_owned(), interface.to_owned()]),
        (None, None) => (),
    }

    if let Some(mtu) = route.mtu {
        args.extend(["-mtu".to_owned(), mtu.to_string()]);
    }
    args
}

fn delete_args(prefix: &IpNetwork) -> Vec<String> {
    let mut args = vec![
        "-n".to_owned(),
        "delete".to_owned(),
        family_flag(prefix.is_ipv4()).to_owned(),
    ];
    push_destination(&mut args, prefix);
    args
}

fn push_destination(args: &mut Vec<String>, prefix: &IpNetwork) {
    let host_prefix = if prefix.is_ipv4() { 32 } else { 128 };
    if prefix.prefix() == host_prefix {
        args.extend(["-host".to_owned(), prefix.ip().to_string()]);
    } else {
        args.extend(["-net".to_owned(), format!("{}/{}", prefix.network(), prefix.prefix())]);
    }
}

async fn run_route(args: &[String]) -> Result<(), Error> {
    let output = Command::new(ROUTE_BINARY)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(Error::Spawn)?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Route(format!(
            "`route {}`: {}",
            args.join(" "),
            stderr.trim()
        )))
    }
}

/// Look up the default route for the address family, or `None` if there is none.
async fn get_default_route(family: AddressFamily) -> Option<DefaultRoute> {
    let family = match family {
        AddressFamily::Ipv4 => "-inet",
        AddressFamily::Ipv6 => "-inet6",
    };
    let output = Command::new(ROUTE_BINARY)
        .args(["-n", "get", family, "default"])
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_route_get(&String::from_utf8_lossy(&output.stdout))
}

fn parse_route_get(output: &str) -> Option<DefaultRoute> {
    let mut interface = None;
    let mut router_ip = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "interface" => interface = Some(value.to_owned()),
            "gateway" => {
                // An IPv6 link-local gateway carries a zone, such as `fe80::1%em0`.
                let address = value.split('%').next().unwrap_or(value);
                router_ip = address.parse::<IpAddr>().ok();
            }
            _ => (),
        }
    }

    let interface = interface?;
    let interface_index = interface_index(&interface)?;
    Some(DefaultRoute {
        interface,
        interface_index,
        router_ip,
    })
}

fn interface_index(name: &str) -> Option<u16> {
    let name = CString::new(name).ok()?;
    // SAFETY: `name` is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    u16::try_from(index).ok().filter(|index| *index != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_default_route() {
        let output = "   route to: 0.0.0.0\n\
            destination: 0.0.0.0\n       mask: 0.0.0.0\n    gateway: 10.164.0.1\n        fib: 0\n  \
            interface: lo0\n      flags: <UP,GATEWAY,DONE,STATIC>\n";
        let route = parse_route_get(output).unwrap();
        assert_eq!(route.interface, "lo0");
        assert_eq!(route.router_ip, Some("10.164.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_link_local_gateway_zone() {
        let output = "    gateway: fe80::1%lo0\n  interface: lo0\n";
        let route = parse_route_get(output).unwrap();
        assert_eq!(route.router_ip, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn tunnel_interfaces() {
        assert!(is_tunnel_like_interface("tun0"));
        assert!(is_tunnel_like_interface("wg1"));
        assert!(!is_tunnel_like_interface("vtnet0"));
        assert!(!is_tunnel_like_interface("tunnel"));
    }

    #[test]
    fn host_and_net_destinations() {
        let mut args = Vec::new();
        push_destination(&mut args, &"192.0.2.1/32".parse().unwrap());
        assert_eq!(args, ["-host", "192.0.2.1"]);

        let mut args = Vec::new();
        push_destination(&mut args, &"10.0.0.0/8".parse().unwrap());
        assert_eq!(args, ["-net", "10.0.0.0/8"]);

        let mut args = Vec::new();
        push_destination(&mut args, &"2001:db8::/32".parse().unwrap());
        assert_eq!(args, ["-net", "2001:db8::/32"]);
    }

    fn route_get(destination: &str) -> String {
        let output = std::process::Command::new(ROUTE_BINARY)
            .args(["-n", "get", destination])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Adds routes to the system routing table, requires root.
    #[tokio::test]
    #[ignore = "changes the routing table of the machine, requires root"]
    async fn adds_and_removes_routes() {
        use crate::{Node, RouteManagerHandle};

        let ifconfig = |args: &[&str]| {
            assert!(
                std::process::Command::new("/sbin/ifconfig")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        ifconfig(&["tun9", "create"]);
        ifconfig(&["tun9", "inet", "10.9.9.1", "10.9.9.2", "up"]);

        let default_route = get_default_route(AddressFamily::Ipv4)
            .await
            .expect("the test needs a default route");

        let manager = RouteManagerHandle::spawn().await.unwrap();
        let routes = HashSet::from([
            // Through a node on the tunnel.
            RequiredRoute::new(
                "198.51.100.0/24".parse().unwrap(),
                Node::new("10.9.9.2".parse().unwrap(), "tun9".to_owned()),
            ),
            // Through the current default route, and with an MTU.
            RequiredRoute::new("203.0.113.5/32".parse().unwrap(), NetNode::DefaultNode).mtu(1400),
        ]);
        manager.add_routes(routes).await.unwrap();

        let tunnel_route = route_get("198.51.100.7");
        assert!(tunnel_route.contains("interface: tun9"), "{tunnel_route}");
        let default_node_route = route_get("203.0.113.5");
        assert!(
            default_node_route.contains(&format!("interface: {}", default_route.interface)),
            "{default_node_route}"
        );
        assert!(default_node_route.contains("1400"), "{default_node_route}");

        manager.clear_routes().unwrap();
        manager.stop().await;

        let cleared = route_get("198.51.100.7");
        assert!(!cleared.contains("interface: tun9"), "{cleared}");
        assert!(!route_get("203.0.113.5").contains("1400"));

        ifconfig(&["tun9", "destroy"]);
    }
}
