# Manual multi-machine demonstration

This guide describes the three-machine topology equivalent to the tested namespace setup.
It is an adaptation for separate Linux machines, not a claim that physical deployment has already been tested.

## Placement and names

Use three machines with these roles:

- Machine 1 runs `schc-data-client`.
- Machine 2 runs `schc-coreconf-core`.
- Machine 3 runs `schc-coreconf-device` and the separate `schc-data-server` process.

Set `ROOT` in every terminal on each machine, not merely once per machine, and replace interface placeholders with the actual connected interfaces.

```sh
export ROOT=/path/to/r-schc-coreconf
```

The example uses `fd00:1::2` for the client-side physical address and `fd00:1::1` for the core-side physical address.
It uses `192.0.2.1` for the core raw-link address and `192.0.2.2` for the device raw-link address.
These example addresses are documentation-network values and must be replaced when they conflict with the real network.

The logical application addresses are `2001:db8::2` for the client and `2001:db8::1` for the server.
They are IPv6 packet endpoints carried through the TUN interfaces, not the raw-link bind addresses.
Application UDP uses logical port `5683`.
Logical management packets use UDP port `8724`.
The demonstrated raw core-to-device UDP link also uses port `8724`, but its bind and peer addresses are configurable process arguments.
Management traffic stays inside the core/device pair and is not sent to the application server.

## Build

Build from the checkout as the normal owner on each machine that runs one or more binaries, unless equivalent prebuilt binaries have deliberately been deployed there.

```sh
cd "$ROOT"
cargo build -p schc-coreconf --bins
```

Core and device TUN creation and the interface, address, route, and forwarding setup require root or the corresponding `CAP_NET_ADMIN` capability.
The application client and server do not need those network-configuration privileges.

## Network setup

The following commands describe the tested-example addressing.
Run the commands on the indicated machine after connecting the physical interfaces.

On machine 1, configure the client-facing interface and logical client address.

```sh
sudo ip link set <m1-client-if> up
sudo ip -6 addr add fd00:1::2/64 dev <m1-client-if> nodad
sudo ip -6 addr add 2001:db8::2/128 dev lo nodad
sudo ip -6 route add 2001:db8::1/128 via fd00:1::1 dev <m1-client-if>
```

On machine 2, configure both physical links, enable IPv6 forwarding, and add the route back to the logical client.
Before changing forwarding, run `sysctl -n net.ipv6.conf.all.forwarding` on machine 2 and record the result as `<m2-old-forwarding>`.

```sh
sudo ip link set <m2-client-if> up
sudo ip link set <m2-device-if> up
sudo ip -6 addr add fd00:1::1/64 dev <m2-client-if> nodad
sudo ip addr add 192.0.2.1/30 dev <m2-device-if>
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip -6 route add 2001:db8::2/128 via fd00:1::2 dev <m2-client-if>
```

On machine 3, configure the raw-link interface and logical server address.

```sh
sudo ip link set <m3-device-if> up
sudo ip addr add 192.0.2.2/30 dev <m3-device-if>
sudo ip -6 addr add 2001:db8::1/128 dev lo nodad
```

The core forwards routed application packets from the client-facing interface to its TUN interface.
The device-side route to the logical client is installed only after the device TUN interface exists.

The demo context expects zero IPv6 flow labels on application packets because its rules deliberately elide that field.
This is a property of this demonstration context, not a general SCHC requirement.
Before changing auto flow labels, run `sysctl -n net.ipv6.auto_flowlabels` separately on machines 1 and 3 and record the results as `<m1-old-auto-flowlabels>` and `<m3-old-auto-flowlabels>`.
Then set `net.ipv6.auto_flowlabels=0` separately on machines 1 and 3, which produce the application UDP packets.

```sh
sudo sysctl -w net.ipv6.auto_flowlabels=0
```

## Start the processes

Use separate terminals for the device, core, server, and client commands.
Start the device first on machine 3.
Run it with root or equivalent TUN capability.

```sh
sudo "$ROOT/target/debug/schc-coreconf-device" \
  --link-bind 192.0.2.2:8724 \
  --link-peer 192.0.2.1:8724 \
  --tun-name schc-device \
  --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-05-07.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" \
  --device-id demo-device
```

Start the core second on machine 2.
Run it with root or equivalent TUN capability.

```sh
sudo "$ROOT/target/debug/schc-coreconf-core" \
  --link-bind 192.0.2.1:8724 \
  --link-peer 192.0.2.2:8724 \
  --tun-name schc-core \
  --tun-mtu 1280 \
  --sid "$ROOT/fixtures/demo/ietf-schc@2026-05-07.sid" \
  --sor "$ROOT/fixtures/demo/initial.sor" \
  --device-id demo-device
```

After both processes print `READY`, install the routes that depend on their TUN interfaces.
Use the actual interface names shown by the `READY` lines if the kernel changed the requested names.

```sh
# Machine 2.
sudo ip -6 route add 2001:db8::1/128 dev schc-core

# Machine 3.
sudo ip -6 route add 2001:db8::2/128 dev schc-device
```

Start the application server in a separate terminal on machine 3.
It is an independent process from the SCHC device.

```sh
"$ROOT/target/debug/schc-data-server" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --data "$ROOT/fixtures/demo/app-data.json" \
  --bind '[2001:db8::1]:5683' \
  --path c
```

Start the application client in a separate terminal on machine 1.

```sh
"$ROOT/target/debug/schc-data-client" \
  --sid "$ROOT/fixtures/demo/demo-data.sid" \
  --server '[2001:db8::1]:5683' \
  --bind '[2001:db8::2]:5683' \
  --path c
```

## Client commands

Enter these commands at the client prompt.

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

The `discover`, `schema`, `get`, `fetch`, `set`, `delete`, `reload`, `help`, and `quit` commands are listed by `schc-data-client --help`.

## Core management commands

Enter these commands at the core prompt after the client has completed an initial application operation.
The list and get commands are read-only inspection operations.

```text
context status
context check
rule list core
rule list device
rule get core 20/8
rule get device 20/8
```

The tested update and duplicate sequence is:

```text
rule update 20/8 entry=9 tv=6 --if-match
context check
rule duplicate 20/8 22/8 entry=9 tv=2
context check
rule get core 22/8
rule get device 22/8
```

The duplicate command is intentionally one-way and produces no response.
The following `context check` verifies that the core and device contexts are equal after the local installation.
After the checks, repeat `fetch /demo-data:config/count` in the client terminal to observe the application result through the duplicated rule.

## Debug output and shutdown

Add `--debug` to the core and device launch commands to include structured IPv6, UDP, CoAP, RPC, and SCHC accounting in traffic reports.
The debug option does not change the application client or server command lines.

For a clean shutdown, enter `quit` in the client terminal first and stop the application server with `Ctrl-C` when finished.
While the core and device are still running, run the first two route-delete commands below from separate administrative shells if explicit cleanup is desired.
Then enter `quit` in the core terminal and stop the device with `Ctrl-C`.
If the core and device were already stopped, their TUN interfaces and dependent routes are already gone, so skip those route-delete commands.
After process shutdown, run the remaining machine-specific cleanup commands and restore each sysctl to the value recorded before setup.

```sh
# Machine 2: remove the core TUN route while core is still running.
sudo ip -6 route del 2001:db8::1/128 dev schc-core

# Machine 3: remove the device TUN route while device is still running.
sudo ip -6 route del 2001:db8::2/128 dev schc-device

# Machine 1: remove its route, addresses, and flow-label setting.
sudo ip -6 route del 2001:db8::1/128 via fd00:1::1 dev <m1-client-if>
sudo ip -6 addr del 2001:db8::2/128 dev lo
sudo ip -6 addr del fd00:1::2/64 dev <m1-client-if>
sudo sysctl -w net.ipv6.auto_flowlabels=<m1-old-auto-flowlabels>

# Machine 2: remove its route, addresses, and forwarding setting.
sudo ip -6 route del 2001:db8::2/128 via fd00:1::2 dev <m2-client-if>
sudo ip -6 addr del fd00:1::1/64 dev <m2-client-if>
sudo ip addr del 192.0.2.1/30 dev <m2-device-if>
sudo sysctl -w net.ipv6.conf.all.forwarding=<m2-old-forwarding>

# Machine 3: remove its addresses and flow-label setting.
sudo ip -6 addr del 2001:db8::1/128 dev lo
sudo ip addr del 192.0.2.2/30 dev <m3-device-if>
sudo sysctl -w net.ipv6.auto_flowlabels=<m3-old-auto-flowlabels>
```

Do not delete or reset interfaces owned by the host or its network manager.
The exact physical interface cleanup and any inter-machine firewall rules remain environment-specific.
