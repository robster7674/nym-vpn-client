// Copyright 2026 Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Offline monitor that follows the presence of the system default routes.

use std::sync::Arc;

use nym_routing::RouteManagerHandle;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

use crate::Connectivity;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to initialize route monitor")]
    StartRouteMonitor(#[from] nym_routing::Error),
}

pub struct ConnectivityHandle {
    state: Arc<Mutex<Connectivity>>,
}

impl ConnectivityHandle {
    /// Returns host connectivity status.
    pub async fn connectivity(&self) -> Connectivity {
        *self.state.lock().await
    }
}

pub async fn spawn_monitor(
    notify_tx: watch::Sender<Connectivity>,
    route_manager: RouteManagerHandle,
    shutdown_token: CancellationToken,
) -> Result<ConnectivityHandle, Error> {
    // note: begin observing before initializing the state
    let mut route_listener = route_manager.default_route_listener().await?;

    let initial = match route_manager.get_default_routes().await {
        Ok((v4_route, v6_route)) => Connectivity::Status {
            ipv4: v4_route.is_some(),
            ipv6: v6_route.is_some(),
        },
        Err(error) => {
            tracing::warn!("Failed to initialize offline monitor: {error}");
            // Fail open: assume that we have connectivity if we cannot determine the existence of
            // a default route, since we don't want to block the user from connecting.
            Connectivity::PresumeOnline
        }
    };
    tracing::info!(
        "Initial connectivity: {}",
        if initial.is_online() {
            "Connected"
        } else {
            "Offline"
        }
    );

    let state = Arc::new(Mutex::new(initial));
    let shared_state = state.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = route_listener.recv() => {
                    if event.is_none() {
                        break;
                    }
                    let connectivity = match route_manager.get_default_routes().await {
                        Ok((v4_route, v6_route)) => Connectivity::Status {
                            ipv4: v4_route.is_some(),
                            ipv6: v6_route.is_some(),
                        },
                        Err(_) => break,
                    };
                    let mut state = shared_state.lock().await;
                    if *state != connectivity {
                        *state = connectivity;
                        if notify_tx.send(connectivity).is_err() {
                            break;
                        }
                    }
                }
                _ = shutdown_token.cancelled() => break,
            }
        }

        tracing::debug!("Offline monitor exiting");
    });

    Ok(ConnectivityHandle { state })
}
