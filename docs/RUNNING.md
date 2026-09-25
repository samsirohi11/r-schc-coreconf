# Running the four-process demo

The demo runs an application client, SCHC core, SCHC device, and application
server. The core and device carry packets between the client and server; the
server is a separate process from the device. The logical application
addresses are `2001:db8::2` (client) and `2001:db8::1` (server), using UDP
port `5683`. The demonstrated raw core-to-device link and management traffic
use UDP port `8724`; raw link addresses are configurable process arguments.

## One Linux machine

For the noninteractive proof, run this from the repository root:

```sh
./tools/run_demo.sh
```

It builds as the invoking user, creates three temporary network namespaces,
runs all four processes, checks the logs, and cleans up. Use
`./tools/run_demo.sh --check` for preflight only, `--no-build` to reuse the
binaries, or `--keep-logs` to preserve logs. Linux, `/dev/net/tun`, `ip`,
`sysctl`, and the listed script dependencies are required. Namespace, veth,
TUN, route, and sysctl setup needs root or `CAP_NET_ADMIN`; the script uses
`sudo` when needed.

To use interactive role windows instead, run:

```sh
./tools/run_demo_interactive.sh
```

It opens device, core, server, and client in separate terminals. Ghostty is
the default when installed; GNOME Terminal is the fallback. Select one with
`DEMO_TERMINAL=ghostty` or `DEMO_TERMINAL=gnome-terminal`. The launcher asks
for sudo once for setup; role terminals can still show separate sudo prompts
if the sudo timestamp expires. The application client and server run as the
invoking user where supported.

## Manual setup

Manual setup is useful when placing the processes on separate machines or
when inspecting every network command. Build the binaries as the normal user
on each machine that runs them, unless deploying equivalent prebuilt
binaries. See the [fixture index](../fixtures/README.md) for fixture details.
The namespace setup matches the demonstrated local topology; the physical
three-machine arrangement is an adaptation and has not been tested here.

```sh
export ROOT=/absolute/path/to/r-schc-coreconf
cd "$ROOT"
cargo build -p schc-coreconf --bins
```

The demo rules elide the IPv6 flow label, so set automatic flow labels to
zero on the client and server hosts (or the corresponding client and device
namespaces below). This is a property of this demo context, not a general
SCHC requirement. On separate machines, record the existing sysctl value
first so it can be restored at cleanup.

### One-machine namespaces

Do not put all roles in one network namespace: local routing could bypass the
core and device TUN path. Create `schc-client`, `schc-core`, and
`schc-device` namespaces with loopback up. Connect client to core with a veth
pair named `cli0` and `ccli0`, and core to device with a pair named `cdev0`
and `dev0`; bring the links up:

```sh
sudo ip netns add schc-client
sudo ip netns add schc-core
sudo ip netns add schc-device
sudo ip netns exec schc-client ip link set lo up
sudo ip netns exec schc-core ip link set lo up
sudo ip netns exec schc-device ip link set lo up
sudo ip link add cli-veth type veth peer name ccli-veth
sudo ip link set cli-veth netns schc-client
sudo ip link set ccli-veth netns schc-core
sudo ip netns exec schc-client ip link set cli-veth name cli0
sudo ip netns exec schc-core ip link set ccli-veth name ccli0
sudo ip link add cdev-veth type veth peer name dev-veth
sudo ip link set cdev-veth netns schc-core
sudo ip link set dev-veth netns schc-device
sudo ip netns exec schc-core ip link set cdev-veth name cdev0
sudo ip netns exec schc-device ip link set dev-veth name dev0
sudo ip netns exec schc-client ip link set cli0 up
sudo ip netns exec schc-core ip link set ccli0 up
sudo ip netns exec schc-core ip link set cdev0 up
sudo ip netns exec schc-device ip link set dev0 up
```

Then configure addresses, forwarding, routes, and flow labels:

```sh
sudo ip netns exec schc-client ip -6 addr add fd00:1::2/64 dev cli0 nodad
sudo ip netns exec schc-core ip -6 addr add fd00:1::1/64 dev ccli0 nodad
sudo ip netns exec schc-core ip addr add 192.0.2.1/30 dev cdev0
sudo ip netns exec schc-device ip addr add 192.0.2.2/30 dev dev0
sudo ip netns exec schc-client ip -6 addr add 2001:db8::2/128 dev lo nodad
sudo ip netns exec schc-device ip -6 addr add 2001:db8::1/128 dev lo nodad
sudo ip netns exec schc-core sysctl -q -w net.ipv6.conf.all.forwarding=1
sudo ip netns exec schc-client ip -6 route add 2001:db8::1/128 via fd00:1::1 dev cli0
sudo ip netns exec schc-core ip -6 route add 2001:db8::2/128 via fd00:1::2 dev ccli0
sudo ip netns exec schc-client sysctl -q -w net.ipv6.auto_flowlabels=0
sudo ip netns exec schc-device sysctl -q -w net.ipv6.auto_flowlabels=0
```

### Three-machine placement

Use connected Linux hosts with these roles:

| Host | Processes | Physical link |
| --- | --- | --- |
| 1 | client | `<m1-client-if>` to host 2 |
| 2 | core | `<m2-client-if>` to host 1; `<m2-device-if>` to host 3 |
| 3 | device and server | `<m3-device-if>` to host 2 |

Replace interface placeholders and documentation addresses if they conflict
with the real network. The core host must forward IPv6. Configure the
physical links, logical loopback addresses, and client-facing routes:
Before changing sysctls, record `sysctl -n net.ipv6.auto_flowlabels` on hosts
1 and 3 and `sysctl -n net.ipv6.conf.all.forwarding` on host 2; restore those
values during cleanup. The `2001:db8::/32`, `192.0.2.0/24`, and `fd00::/8`
addresses are examples and must be replaced if they conflict with the
connected network.

```sh
# Host 1
sudo ip link set <m1-client-if> up
sudo ip -6 addr add fd00:1::2/64 dev <m1-client-if> nodad
sudo ip -6 addr add 2001:db8::2/128 dev lo nodad
sudo ip -6 route add 2001:db8::1/128 via fd00:1::1 dev <m1-client-if>
sudo sysctl -w net.ipv6.auto_flowlabels=0

# Host 2
sudo ip link set <m2-client-if> up
sudo ip link set <m2-device-if> up
sudo ip -6 addr add fd00:1::1/64 dev <m2-client-if> nodad
sudo ip addr add 192.0.2.1/30 dev <m2-device-if>
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip -6 route add 2001:db8::2/128 via fd00:1::2 dev <m2-client-if>

# Host 3
sudo ip link set <m3-device-if> up
sudo ip addr add 192.0.2.2/30 dev <m3-device-if>
sudo ip -6 addr add 2001:db8::1/128 dev lo nodad
sudo sysctl -w net.ipv6.auto_flowlabels=0
```

### Start the four processes

Build as the normal user on each host. Start the device, then the core;
wait for both to print `READY` before installing the TUN routes. The
application roles can start after those routes exist. In the commands below,
run each command in the indicated namespace on one machine, or on the
indicated host across machines. Set `ROOT` to the checkout's absolute path
in each terminal on every machine.

```sh
# Device: local namespace schc-device, or host 3 (with sudo).
sudo ip netns exec schc-device "$ROOT/target/debug/schc-coreconf-device" \
  --debug --link-bind 192.0.2.2:8724 --link-peer 192.0.2.1:8724 \
  --tun-name schc-device --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-09-22.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" --device-id demo-device

# Core: local namespace schc-core, or host 2 (with sudo).
sudo ip netns exec schc-core "$ROOT/target/debug/schc-coreconf-core" \
  --debug --link-bind 192.0.2.1:8724 --link-peer 192.0.2.2:8724 \
  --tun-name schc-core --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-09-22.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" --device-id demo-device

# After both print READY:
sudo ip netns exec schc-core ip -6 route add 2001:db8::1/128 dev schc-core
sudo ip netns exec schc-device ip -6 route add 2001:db8::2/128 dev schc-device

# Server: local namespace schc-device, or host 3 (normal user).
sudo ip netns exec schc-device "$ROOT/target/debug/schc-data-server" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --data "$ROOT/fixtures/demo/app-data.json" \
  --bind '[2001:db8::1]:5683' --path c

# Client: local namespace schc-client, or host 1 (normal user).
sudo ip netns exec schc-client "$ROOT/target/debug/schc-data-client" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --server '[2001:db8::1]:5683' --bind '[2001:db8::2]:5683' --path c
```

For multi-machine use, omit `sudo ip netns exec <namespace>` from each
command. Prefix the device/core commands with `sudo`; run server/client as
the normal user. Install the core route on host 2 and the device route on
host 3 after their respective processes print `READY`:

```sh
# Host 2
sudo ip -6 route add 2001:db8::1/128 dev schc-core
# Host 3
sudo ip -6 route add 2001:db8::2/128 dev schc-device
```

The client prompt accepts `discover`, `schema demo-data`, `fetch
/demo-data:config/count`, `set /demo-data:config/count 42`, `delete
/demo-data:config/count`, `help`, and `quit`. At the core prompt, inspect with
`context status`, `context check`, `rule list core`, `rule list device`, and
`rule get core 20/8` / `rule get device 20/8`. The tested update sequence is:

```text
rule update 20/8 entry=9 tv=6 --if-match
context check
rule duplicate 20/8 22/8 entry=9 tv=2
context check
rule get core 22/8
rule get device 22/8
```

`rule duplicate` is intentionally one-way and has no response; the following
context check verifies both contexts match. Fetch again from the client to
observe traffic through the duplicated rule. `--debug` on core and device
prints structured traffic reports and can be omitted for concise output.

## Stop and clean up

Enter `quit` at the client and core prompts; stop the server and device with
Ctrl-C. For the local setup, delete the three namespaces after all processes
stop; this removes their links, addresses, routes, and sysctls:

```sh
sudo ip netns del schc-client
sudo ip netns del schc-core
sudo ip netns del schc-device
```

For separate machines, remove the TUN routes while core and device are still
running, then stop them. Remove only addresses and routes added for the demo,
and restore each recorded sysctl value. Do not reset host-managed interfaces;
firewall and physical-link cleanup depends on the environment.

```sh
# Host 2, while core is running
sudo ip -6 route del 2001:db8::1/128 dev schc-core
# Host 3, while device is running
sudo ip -6 route del 2001:db8::2/128 dev schc-device

# Host 1
sudo ip -6 route del 2001:db8::1/128 via fd00:1::1 dev <m1-client-if>
sudo ip -6 addr del 2001:db8::2/128 dev lo
sudo ip -6 addr del fd00:1::2/64 dev <m1-client-if>
sudo sysctl -w net.ipv6.auto_flowlabels=<m1-old-auto-flowlabels>

# Host 2
sudo ip -6 route del 2001:db8::2/128 via fd00:1::2 dev <m2-client-if>
sudo ip -6 addr del fd00:1::1/64 dev <m2-client-if>
sudo ip addr del 192.0.2.1/30 dev <m2-device-if>
sudo sysctl -w net.ipv6.conf.all.forwarding=<m2-old-forwarding>

# Host 3
sudo ip -6 addr del 2001:db8::1/128 dev lo
sudo ip addr del 192.0.2.2/30 dev <m3-device-if>
sudo sysctl -w net.ipv6.auto_flowlabels=<m3-old-auto-flowlabels>
```
