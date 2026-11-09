# PRD: FreeBSD support for the NymVPN headless client (`nym-vpnd` / `nym-vpnc`)

Status: draft, PoC in progress
Branch: `freebsd-port-poc` (fork: robster7674/nym-vpn-client)
Upstream context: nymtech/nym-vpn-client#2307 was closed in March 2025 as a
packaging request. Maintainers said they would reconsider with evidence of
demand. This work is a porting effort, not a packaging request, and is meant
to be offered upstream as PRs.

## 1. Goal

A FreeBSD build of the headless client that can connect in mixnet mode,
route traffic through the tunnel, apply DNS settings, and enforce a
kill-switch, with a clean upstreamable diff (`target_os = "freebsd"` gates,
no behaviour change on existing platforms).

Out of scope for this PRD: the Tauri desktop app, split tunnelling, packaging
(FreshPorts), exit-gateway/`nym-node` operation.

## 2. Evidence base

Measured, not assumed (see section 6 for the log of results):

- `nym-vpn-core` has zero `target_os = "freebsd"` gates today. The only
  occurrence of "freebsd" is a doc link in `nym-split-tunnel/src/macos/bpf.rs`.
- Platform crates pick `mod imp` per OS with no fallback, so an unsupported OS
  fails to compile rather than degrading. Seen in `nym-routing`, `nym-firewall`,
  `nym-dns`, `nym-offline-monitor` and `nym-ifconfig`.
- `wireguard/build-wireguard-go.sh` `unix_target_triple` only knows Linux and
  Darwin. `libwg_default.go` and `netstack_default.go` carry
  `//go:build (darwin || linux ...)` tags.
- The code descends from Mullvad's `talpid-*` crates. Mullvad has no FreeBSD
  port either, so there is no upstream-of-upstream to copy from.

The FreeBSD test machine for the compile loop is GCP `nym-freebsd-poc-1`
(FreeBSD 15.1-RELEASE amd64, europe-west4-a, project
project-8b2d4704-2d55-4abc-910, toolkittribe billing). A second target is
FreeBSD 15.1-RELEASE aarch64 in UTM on an Apple Silicon Mac, for manual testing.

## 3. Approach

Phased, each phase a separately reviewable PR, each leaving Linux, macOS and
Windows builds untouched.

### Phase 0: baseline and CI-less compile loop

- Record the exact compile errors of `cargo check -p nym-vpnd -p nym-vpnc
  -p nym-socks5-proxy` on FreeBSD (section 6).
- Establish the loop: edit on rob-dev in the worktree, push the branch,
  `git pull && cargo check` on the VM. Cross `cargo check --target
  x86_64-unknown-freebsd` on rob-dev if the toolchain can be installed there.
- Acceptance: error list committed to this document.

### Phase 1: compile on FreeBSD, mixnet mode, no firewall/DNS/split-tunnel

- `nym-wg-go` / `wireguard`: add FreeBSD to the build script triple and to
  the Go build tags (amneziawg-go already ships `tun_freebsd.go`).
- `nym-split-tunnel`, `nym-exclude`: compile out on FreeBSD (feature or cfg).
- `nym-offline-monitor`: first cut is a polling "default route exists" monitor;
  a routing-socket `RTM_IFINFO`/`RTM_NEWADDR` watcher can follow.
- `nym-platform-metadata`: FreeBSD metadata.
- `nym-ifconfig`: tun device creation and address assignment. The `tun` crate
  used in the mixnet path supports FreeBSD; addressing via `ifconfig` or
  `SIOCAIFADDR`.
- `nym-routing`: FreeBSD `imp`, starting from the macOS `PF_ROUTE` routing
  socket code. Strip the `SystemConfiguration` dependency. Verify
  `rt_msghdr`/`sockaddr` layouts against FreeBSD headers.
- `nym-vpn-lib`: add FreeBSD to the target lists; find FreeBSD equivalents for
  the `cfg(linux)` pieces (fwmark and routing table id: `SO_USER_COOKIE` /
  `setfib`).
- Acceptance: `cargo build -p nym-vpnd -p nym-vpnc` succeeds on FreeBSD
  amd64; `nym-vpnd` starts and answers `nym-vpnc status`.

### Phase 2: DNS

- `nym-dns`: FreeBSD `imp` based on the existing `resolvconf` and static
  `resolv.conf` backends (FreeBSD ships `resolvconf(8)`).
- Acceptance: DNS servers are set on connect and restored on disconnect.

### Phase 3: firewall and kill-switch

- `nym-firewall`: FreeBSD `imp`. Decision needed: port `pfctl-rs` (macOS-only
  today, FreeBSD `pfvar.h` ioctl structures differ) or drive `pfctl -a
  <anchor> -f -` with generated rulesets. Default plan: shell out to
  `pfctl` anchors, because it is the smaller and more reviewable change.
- Acceptance: with the tunnel up, traffic that bypasses it is blocked; on
  disconnect the anchor is flushed and the host returns to its prior pf state.

### Phase 4: daemon integration and IPC

- `nym-ipc`: FreeBSD local-socket auth. Keep the Unix domain socket server;
  replace polkit with `getpeereid()` plus a group check.
- `nym-vpnd`: rc.d script and install layout.
- Acceptance: `nym-vpnd` runs as a service via `service nym-vpnd start` and
  `nym-vpnc connect` works as a non-root user in the allowed group.

### Phase 5: WireGuard (2-hop) mode

- Verify `nym-wg-go` / `libwg` end to end on FreeBSD.
- Acceptance: 2-hop connect passes traffic.

### Phase 6: upstream engagement

- Open a FreeBSD-only issue upstream with the real compile-error list and a
  crate-by-crate plan, and ask: accept `target_os = "freebsd"` gates; accept a
  FreeBSD CI job or keep it community-maintained; `pfctl-rs` port versus
  shelling out. Do this once Phase 1 compiles, so the offer comes with code.
  Rob approves this before anything is posted upstream.

## 4. Risks

- Maintainers may decline FreeBSD in the main tree. Mitigation: keep each phase
  small, gated, and free of behaviour change elsewhere, and ask before Phase 3.
- The routing-socket reuse from macOS is untested on FreeBSD until Phase 1.
- Newer FreeBSD moves some pf operations toward netlink; the anchor-based
  approach avoids binding to that.
- Fast-moving upstream: rebase often, keep the branch narrow.

## 5. Test plan

- GCP `nym-freebsd-poc-1`: FreeBSD 15.1-RELEASE amd64, compile and headless
  tests. Stop the VM when idle.
- UTM VM (aarch64) on Apple Silicon Mac: manual connect, routing, DNS and
  kill-switch tests; also exercises a second architecture.
- Every PR: existing Linux `cargo check` and unit tests unchanged.

## 6. Results log

### Phase 0 baseline (FreeBSD 15.1 amd64, rustc 1.98.1, f1550c660)

`cargo check -p nym-vpnd -p nym-vpnc -p nym-socks5-proxy --keep-going` fails in
two crates; every other dependency compiles unchanged:

- `nym-routing`: 8 errors, all from the missing `imp` module
  (`unresolved import imp`, `cannot find type RouteManagerCommand`).
- `nym-wg-go` `build.rs`: `Unsupported platform: freebsd`.

Dependents of those two (`nym-vpn-lib`, `nym-vpnd`, ...) are blocked, so more
errors are expected as these clear. Tracking issue: robster7674/nym-vpn-client#1.

### Decisions so far

- Routing: shell out to `route(8)` for add/delete/change and `route -n get`
  for the default routes, poll for default-route changes. Follows the macOS
  model (`NetNode::DefaultNode`, no fwmark/table). A native `PF_ROUTE`
  implementation is a later optimisation. Verified route(8) forms by hand on
  FreeBSD 15.1 (`-interface`, `-ifp`, `-mtu`, `change`, `delete`).
- Go toolchain: `go.mod` requires Go 1.27; FreeBSD has `go127` as a package
  (default `go` is 1.26).
