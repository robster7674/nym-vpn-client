# NymVPN daemon on FreeBSD

Status: proof of concept, see `docs/freebsd-port-prd.md`.

## Build

```sh
pkg install git protobuf go127 cmake pkgconf gmake bash rust
export PATH=/usr/local/go127/bin:$PATH
./wireguard/build-wireguard-go.sh        # from the repository root
cd nym-vpn-core && cargo build --release -p nym-vpnd -p nym-vpnc
```

`wireguard-go` needs `-buildmode=c-archive`. Go lists it for FreeBSD/amd64 only, so on arm64 the
build script builds the Go tools from a patched copy of GOROOT (`libwg/goplatform-freebsd-arm64.diff`).

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

- The kill switch uses pf. The rules go into the `nym` anchor. If `/etc/pf.conf` already has
  `anchor "nym"` as its first filter rule, your own rules stay active and only the anchor is
  changed. Without it, the daemon replaces the main ruleset with one that only evaluates the anchor
  while a policy is active, and restores `/etc/pf.conf` (or disables pf) afterwards. Custom rules,
  for example NAT, are suspended in that case.
- DNS is set through `resolvconf(8)`.
- Routes are managed with `route(8)`.
- Split tunnelling is not supported.
