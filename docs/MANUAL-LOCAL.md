# Manual local namespace demonstration

This guide runs the four processes interactively on one Linux machine with three network namespaces.
The automated `tools/run_demo.sh` script uses the same namespace topology but drives the processes noninteractively for its proof.

## Why three namespaces

Do not run all four processes in one network namespace for this demonstration.
If the client and server share one namespace, local routing can deliver application packets directly and bypass the core and device TUN path.
The three namespaces force the application packets through the routed core and device endpoints.

Use these roles:

- `schc-client` runs `schc-data-client`.
- `schc-core` runs `schc-coreconf-core`.
- `schc-device` runs `schc-coreconf-device` and the separate `schc-data-server` process.

The namespace and interface names below are stable and are all shorter than Linux's 15-character interface-name limit.
The commands use `sudo ip netns exec`, which runs the contained command with privilege while preserving its standard input and output.

## Build

Build before creating namespaces and do so without root privileges.

```sh
export ROOT=/path/to/r-schc-coreconf
cd "$ROOT"
cargo build -p schc-coreconf --bins
```

The process commands below use the checked-in paths explicitly.

## Create the namespaces and links

Run the following setup commands once in a terminal.

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

The first veth pair connects the client namespace to the core namespace.
The second veth pair connects the core namespace to the device namespace.

## Configure addresses and routes

The example uses `fd00:1::2` and `fd00:1::1` on the client-to-core IPv6 link.
It uses `192.0.2.1` and `192.0.2.2` for the raw core-to-device IPv4 link.
The logical application client address is `2001:db8::2`, and the logical application server address is `2001:db8::1`.
Logical application UDP uses port `5683`.
Logical management packets and the demonstrated raw core-to-device link use port `8724`, while the raw link bind and peer addresses remain configurable.
The logical addresses are packet endpoints carried through the TUN path and are not the raw-link addresses.

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
```

The core namespace forwards routed application packets between the client-facing interface and its TUN interface.

The demo context expects zero IPv6 flow labels because its rules deliberately elide that field.
This is a property of this demonstration context, not a general SCHC requirement.
Apply the setting in the two namespaces that produce application UDP packets.

```sh
sudo ip netns exec schc-client sysctl -q -w net.ipv6.auto_flowlabels=0
sudo ip netns exec schc-device sysctl -q -w net.ipv6.auto_flowlabels=0
```

## Start the processes

Use four separate terminals so the core and client prompts remain interactive.
Run `export ROOT=/absolute/path/to/r-schc-coreconf` in each process terminal before using the commands below.
Start the device first in the `schc-device` namespace.
The device process creates the `schc-device` TUN interface in that namespace.

```sh
sudo ip netns exec schc-device "$ROOT/target/debug/schc-coreconf-device" \
  --debug \
  --link-bind 192.0.2.2:8724 \
  --link-peer 192.0.2.1:8724 \
  --tun-name schc-device \
  --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-05-07.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" \
  --device-id demo-device
```

Start the core second in the `schc-core` namespace after the device prints `READY`.
The core process creates the `schc-core` TUN interface in that namespace.

```sh
sudo ip netns exec schc-core "$ROOT/target/debug/schc-coreconf-core" \
  --debug \
  --link-bind 192.0.2.1:8724 \
  --link-peer 192.0.2.2:8724 \
  --tun-name schc-core \
  --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-05-07.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" \
  --device-id demo-device
```

The `--debug` flags can be removed for concise traffic reports.
After both processes print `READY`, add the routes that require their newly created TUN interfaces.

```sh
sudo ip netns exec schc-core ip -6 route add 2001:db8::1/128 dev schc-core
sudo ip netns exec schc-device ip -6 route add 2001:db8::2/128 dev schc-device
```

Start the standalone application server in a separate terminal in the `schc-device` namespace.

```sh
sudo ip netns exec schc-device "$ROOT/target/debug/schc-data-server" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --data "$ROOT/fixtures/demo/app-data.json" \
  --bind '[2001:db8::1]:5683' \
  --path c
```

Start the application client in a separate terminal in the `schc-client` namespace.

```sh
sudo ip netns exec schc-client "$ROOT/target/debug/schc-data-client" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --server '[2001:db8::1]:5683' \
  --bind '[2001:db8::2]:5683' \
  --path c
```

The application server is a separate process from the SCHC device.
Management traffic remains internal to the core and device and does not go through the application server.

## Interactive client commands

Enter these commands at the client prompt in the `schc-client` terminal.

```text
discover d=0
schema demo-data
get /demo-data:config/count
fetch /demo-data:config/count
set /demo-data:config/count 42
get /demo-data:config/count
delete /demo-data:config/count
fetch /demo-data:config/count
set /demo-data:config/count 42
reload
help
quit
```

## Interactive core commands

Enter the inspection commands at the core prompt in the `schc-core` terminal.

```text
context status
context check
rule list core
rule list device
rule get core 20/8
rule get device 20/8
```

The tested management sequence is:

```text
rule update 20/8 entry=9 tv=6 --if-match
context check
rule duplicate 20/8 22/8 entry=9 tv=2
context check
rule get core 22/8
rule get device 22/8
```

The duplicate command is intentionally one-way and produces no response.
The following `context check` verifies equality after the local installation.
Repeat `fetch /demo-data:config/count` in the client terminal after the checks to observe the application result through the duplicated rule.

Add `--debug` to the core and device commands to include structured IPv6, UDP, CoAP, RPC, and SCHC accounting in traffic reports.
The debug option does not change the client or server commands.

## Cleanup

Enter `quit` in the client terminal and the core terminal.
Stop the application server and device with `Ctrl-C`.
Delete the namespaces only after all four processes have stopped.
Namespace deletion removes the namespace-local veths, addresses, routes, and sysctls without requiring restoration of host sysctls.

```sh
sudo ip netns del schc-client
sudo ip netns del schc-core
sudo ip netns del schc-device
```

Set `ROOT` in the terminal used for the automated alternative before running `sudo "$ROOT/tools/run_demo.sh" --no-build`.
It drives the same namespace topology noninteractively and runs the dynamic proof parser.
