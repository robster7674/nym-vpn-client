# NymVPN daemon on FreeBSD

Status: proof of concept, see `docs/freebsd-port-prd.md`.

## Build

```sh
pkg install git protobuf go127 cmake pkgconf gmake bash rust
export PATH=/usr/local/go127/bin:$PATH
./wireguard/build-wireguard-go.sh        # from the repository root
cd nym-vpn-core && cargo build --release -p nym-vpnd -p nym-vpnc
```

`wireguard-go` needs `-buildmode=c-archive`, which Go does not support on FreeBSD/arm64, so the
daemon can only be linked on amd64 for now.

## Install

```sh
install -m 755 target/release/nym-vpnd target/release/nym-vpnc /usr/local/bin/
install -m 755 crates/nym-vpnd/freebsd/nym_vpnd /usr/local/etc/rc.d/
pw groupadd nym-vpn
pw groupmod nym-vpn -m "$USER"
sysrc nym_vpnd_enable=YES
service nym_vpnd start
nym-vpnc status
```

## Notes

- The kill switch uses pf. While a policy is active the daemon replaces the main pf ruleset with
  one that only evaluates the `nym` anchor, and restores `/etc/pf.conf` (or disables pf) when the
  policy is removed.
- DNS is set through `resolvconf(8)`.
- Routes are managed with `route(8)`.
- Split tunnelling is not supported.
