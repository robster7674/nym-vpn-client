// Copyright 2026 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Authentication of local clients on FreeBSD.
//!
//! The peer credentials of the Unix domain socket identify the client. Root and members of the
//! nym-vpn group are allowed. There is no interactive prompt, so other users are denied.

use std::ffi::CString;

use nix::unistd::{Gid, Uid, User, getgrouplist};
use tokio_stream::Stream;

use crate::{
    AuthenticationMaterial,
    authentication::{AuthenticationLayer, error::AuthenticationError},
    uds::Uds,
};

pub(crate) type Transport = tokio::net::UnixStream;

pub(crate) async fn is_authenticated(
    stream: &mut Transport,
    auth_material: AuthenticationMaterial,
) -> Result<(), AuthenticationError> {
    let cred = stream
        .peer_cred()
        .map_err(AuthenticationError::PeerCredentials)?;
    if user_in_group(Uid::from_raw(cred.uid()), auth_material.nym_vpn_gid) {
        Ok(())
    } else {
        Err(AuthenticationError::AuthorizationDenied)
    }
}

fn user_in_group(uid: Uid, gid: Option<Gid>) -> bool {
    if uid.is_root() {
        tracing::trace!("User is root");
        return true;
    }

    let Ok(Some(user)) = User::from_uid(uid) else {
        tracing::debug!("User {uid} could not be parsed or it disappeared");
        return false;
    };
    let Some(gid) = gid else {
        tracing::debug!("No nym-vpn group");
        return false;
    };
    if user.gid == gid {
        tracing::trace!("User is primary of the group");
        return true;
    }

    let Ok(name) = CString::new(user.name.as_bytes()) else {
        tracing::warn!("User name could not be parsed into CString");
        return false;
    };
    let Ok(group_list) = getgrouplist(&name, user.gid)
        .inspect_err(|err| tracing::warn!("Could not get the group list: {err:?}"))
    else {
        return false;
    };

    let in_group = group_list.contains(&gid);
    if !in_group {
        tracing::info!("Connecting user is not in the nym-vpn UNIX group");
    }
    in_group
}

fn skip_authentication_checks(disable_client_verification: bool) -> bool {
    cfg!(debug_assertions) || disable_client_verification
}

pub(crate) fn incoming(
    uds: Uds,
    auth_material: AuthenticationMaterial,
) -> impl Stream<Item = std::io::Result<Transport>> {
    let shutdown_token = auth_material.shutdown_token.clone();
    let auth_material = if skip_authentication_checks(auth_material.disable_client_verification) {
        None
    } else {
        Some(auth_material)
    };
    let auth_layer = AuthenticationLayer::new(uds, auth_material, shutdown_token);
    auth_layer.stream()
}
