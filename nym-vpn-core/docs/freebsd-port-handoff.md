# FreeBSD port: handoff

Written for: an engineer (or agent) taking the FreeBSD port from "daemon builds and a tunnel comes up" to a client that
carries traffic, cleans up after itself and is fit for an upstream PR.

Tracking issue: robster7674/nym-vpn-client#1. PRD: [freebsd-port-prd.md](freebsd-port-prd.md). Branch
`freebsd-port-poc` (draft PR #11). Fork only: nothing goes upstream without Rob's explicit approval (#10).

## Where it stands (2026-11-09, FreeBSD 15.1 amd64)

Works, verified on the test VM:
- `nym-vpnd` and `nym-vpnc` build, run as an rc.d service and talk to each other.
- Account is added and reads `ReadyToConnect`. Gateways list.
- WireGuard two-hop connect (after #12 and the tun address fix): `tun0` (entry) and `tun1` (exit) come up with IPv4 and
  IPv6 addresses, the default route moves to `tun1`, and the pf `nym` anchor loads the kill switch.
- Error state keeps traffic blocked; `disconnect` from the error state restores routes, `resolv.conf` and pf.

Not working, seen in the second retest (`~/wg1.log` on the VM):
1. **No traffic through the tunnel.** `curl https://ipinfo.io/ip` returned nothing. Inconclusive on its own because DNS
   also failed. Retest with an IP literal (`curl http://1.1.1.1`, `ping 1.1.1.1`, and over IPv6) and check the WireGuard
   handshake on both hops.
2. **DNS.** `resolv.conf` is not changed on connect (still the GCP metadata resolver). The anchor has
   `block return out quick proto {tcp,udp} ... port = domain` ahead of `pass quick on tun0/tun1 all`, so port 53 is
   blocked inside the tunnel as well. Decide what the design is (resolver on the tunnel, or a local forwarder) and make
   `nym-dns` and the pf rules agree. Phase 2 is not done.
3. **`nym-vpnc disconnect` hangs in `Disconnecting`.** After 8 s the state was still `Disconnecting`, the default route
   (`10.164.0.1`) was still missing, `tun0`/`tun1` host routes were still present, and 29 anchor rules were still
   loaded. Something later cleared it (DHCP renewed at 16:40, 27 minutes after) but SSH never came back and the VM
   needed a reset. Find what blocks teardown (`wgTurnOff`, tun device destroy, or the route restore). The daemon log is
   not in `/var/log/daemon.log` in a useful form, so first make the rc.d `daemon -S` logging reach a file you can read.
4. **A daemon crash leaves the host without a default route** (#13). Nothing repairs it on the next start.

Not tested yet: mixnet mode, reconnect, network-change handling, IPv6 leak checks, anything on arm64 (the daemon builds
and starts there, see #2, but no connect was tried).

Not done: the two `unused` warnings in `nym-vpn-lib` (`let mut tun_config` at `lib.rs:1977`) and the clippy pass.

## Bugs found on the way, all fixed on the branch

- `tun` crate FreeBSD backend deletes an address that does not exist before setting one (`EADDRNOTAVAIL`): the address is
  now set with `ifconfig` (003f30116).
- `wgTurnOn` was declared and called without `mtu` on FreeBSD, shifting all FFI arguments and crashing the daemon with a
  Go nil-pointer panic (#12, 6dcbcb118). Linux/macOS code is unchanged. Upstream `nymtech/nym-vpn-client` has the same
  `cfg(any(linux, macos))` gate, so any FreeBSD build needs this change; it is not in any Nym release.

## Test environment

- amd64: GCP `nym-freebsd-poc-1`, europe-west4-a, project `project-8b2d4704-2d55-4abc-910`.
  `gcloud compute ssh nym-freebsd-poc-1 --zone europe-west4-a --project project-8b2d4704-2d55-4abc-910`.
  SSH is allowed only from 144.91.118.138 (firewall `nym-freebsd-poc-ssh`).
- arm64: `nym-freebsd-poc-arm1` (t2a). Stop both VMs when idle.
- Source is `~/src/nym-vpn-client` on the VM. Build with `cargo build -p nym-vpnd -p nym-vpnc` in `nym-vpn-core`
  (debug build, about 3 minutes, binaries are 3 GB), then `sudo install` into `/usr/local/bin` and
  `sudo service nym_vpnd restart`. rc.d script: `crates/nym-vpnd/freebsd/nym_vpnd`.
- Test run: [freebsd-e2e.sh](freebsd-e2e.sh) in this directory is the script used (copy to `~/e2e2.sh`).
  Start it detached with `daemon -f -o /tmp/e2e.out sh /home/rob/e2e2.sh <name>`; `nohup ... &` over SSH did not start it.

### Things that cost hours

- **The kill switch cuts your SSH session** as soon as the tunnel is up (inbound replies go out through the blocked
  interface). Always start a watchdog first, and never `kill` it unless disconnect has verifiably finished. In the second
  run the script killed its own watchdog after `disconnect` hung, which is why the VM stayed dark.
- If the VM is unreachable and the serial log (`gcloud compute instances get-serial-port-output`) shows dhclient
  `No route to host`, a reset is the only way back (`gcloud compute instances reset`). The disk survives.
- Do not trust `grep nym /var/log/messages`: the hostname contains `nym`.
- The core dump from the crash is `/nym-vpnd.core` (346 MB, ELF64 `ET_CORE`, OSABI FreeBSD). Cores contain the account
  and WireGuard keys; treat them as secrets.

## Suggested order

1. Fix the three not-working items above, in this order: disconnect hang (3), then traffic (1), then DNS (2). Each needs a
   log line you can read; add logging first if the daemon is silent.
2. Make the daemon repair its own mess (#13): on start, remove a stale `nym` anchor and restore saved routes and DNS.
3. Mixnet mode, then reconnect and network change (the checklist in #4).
4. arm64 connect.
5. Clean up: warnings and clippy, run the other platforms' `cargo check` (#9), then decide on #3 (pf anchor), #5
   (peer credentials on a release build), #6 (`if_wg` instead of wireguard-go), #7 (routing socket instead of `route(8)`)
   and #8 (split tunnelling).

## DumpTriage and FreeBSD

The crash core was uploaded to DumpTriage as a test (dump `8fcc987f-8573-4bc6-b35c-f8c94299d68f`). It was accepted and
classified `linux_user_mode`. `dumptriage-tools` has no FreeBSD support, so proper handling needs:

- **Detection**: `linux/dumptriage-agent/dumptriage_agent.py` classifies any ELF `ET_CORE` as `LinuxUserCore`. FreeBSD cores
  carry `EI_OSABI` = 9 (`ELFOSABI_FREEBSD`) and FreeBSD-specific notes (`NT_PRSTATUS`, `NT_PROCSTAT_*`). Add a
  `FreeBSDUserCore` kind and a `freebsd_user_mode` dump type end to end (agent, API, schemas, report).
- **Capture**: `configure-dumps.sh` equivalent for FreeBSD: `kern.corefile` (default `%N.core` in the cwd, so `/nym-vpnd.core`
  for a daemon), `kern.coredump`, `kern.sugid_coredump` for setuid processes, and `/var/crash` plus `savecore`/`dumpon`
  for kernel dumps. An rc.d-friendly agent: the Linux agent is a single Python 3 file, and FreeBSD has `python3` in ports,
  so it may only need path defaults and detection.
- **Analysis**: the analyser must use FreeBSD's debugger (`lldb` or FreeBSD `gdb`) and, for symbolication, the matching
  binary and the FreeBSD libc. Go and cgo cores need Go's runtime tables (`GOTRACEBACK=crash` prints the goroutine
  stacks to the log, which is often more useful than the core). Without the binary a core is close to useless, so the
  upload should accept a binary or build id alongside it.
- **Test fixture**: the core above is a ready sample (Rust plus Go, debug build, signal 6, nil dereference in a cgo call).
