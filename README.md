# SCHC CORECONF localhost demonstration

This repository contains a three-process SCHC and CORECONF prototype.
The demonstration uses real IPv6, UDP, CoAP, CORECONF, SCHC, and localhost UDP link bytes.
It does not require root privileges or a TUN interface.

## Architecture

`schc-data-client` is the application-facing client.
It discovers resources and displays schema paths.
Its `get` command uses a root CORECONF GET, its `fetch` command uses a root FETCH with identifier payloads, and its `set` and `delete` commands use root iPATCH mutations.

`schc-coreconf-core` is the application and management core.
It receives application CoAP datagrams, constructs logical IPv6 and UDP packets, compresses ordinary traffic, and sends raw SCHC frames to the device.
Its console supports context inspection and targeted ordinary-rule updates.

`schc-coreconf-device` is the device-side process.
It decodes raw SCHC frames, dispatches protected management traffic by exact RuleID, serves the sample application datastore, and returns compressed responses.

The internal link carries only padded SCHC frame bytes.
IPv6, UDP, and CoAP headers are reconstructed at the receiving SCHC endpoint rather than being sent as an outer link envelope.

The repository currently composes source-pinned development dependencies.
The target release boundary uses versioned `r-schc` and `rustconf` crates, keeps those repositories independently usable, and separates the application server from the SCHC device as a fourth process.
See [the composition contract](docs/COMPOSITION.md) for dependency ownership, the four-role target, replaceable inputs, synchronization invariants, and the rule lifecycle profile.

The protected management RuleIDs are `16/8` (context FETCH), `17/8` (responses), `26/8` (inspection FETCH), `27/8` (default iPATCH), `28/8` (If-Match iPATCH), and `29/8` (NON POST duplicate-rule).
All logical management packets use UDP port `8724` at both endpoints.
Rule `20/8` is the ordinary optimized FETCH request rule.
Rule `21/8` is the ordinary response rule.
Rule `25/8` is the ordinary header-compression fallback used before the Rule 20 update.

The initial Rule 20 target for `IPV6.APP_IID` is `::5`.
The updated target is `::2`, which matches the application/core source address in the sample request.
The device remains the request destination at `2001:db8::1`, while the application/core source address is `2001:db8::2`.
The logical request bytes remain identical before and after the update.
Only the selected SCHC representation changes.

## Prerequisites

- Rust and Cargo 1.93.1 or newer.
- Python 3 for fixture checking.
- A Linux or Unix environment with localhost UDP support.
- No root privileges are required.

The pinned `rule2sor` package is needed only to regenerate or verify the checked-in SoR fixtures.
See `fixtures/demo/README.md` for the package hash and installation commands.

## Build

Run the following command from the repository root:

```sh
cargo build -p schc-coreconf --bins
```

Run the complete automated test suite with:

```sh
cargo test --workspace --all-targets --all-features
```

## Direct-TUN demonstration

The direct-TUN endpoint processes require Linux, a usable `/dev/net/tun`, and permission to create the requested interface.
A privileged namespace end-to-end harness is not included here.
Use the deterministic Rust tests for packet, SCHC, management, and reporting coverage.

## Interactive CLI use

Run the core and data client from a terminal, not through a pipe, to get a visible prompt.
The core prompt is `core>` and the data client prompt is `data>`.
Both processes print one `READY` line and accept `help` at any time.
The device is a background service and includes its peer address on its `READY` line while it waits for frames.

Traffic reports are concise by default and use one deterministic line such as `RX APP   20/8  63 B -> 11 B`.
The line contains direction, traffic class, RuleID, original packet bytes, and padded transmitted bytes.
Pass `--debug` to `schc-coreconf-core` or `schc-coreconf-device` for the same line followed by a structured IPv6, UDP, CoAP, RPC, and SCHC accounting block.
Debug output is plain ASCII and intentionally omits raw packet and frame hexadecimal.

Successful management actions use concise results such as `OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged` and `OK update 20/8 entry=9  device=changed  local=changed`.
Context status is reported as `CONTEXT generation=2  rules=9` in regular mode.

The core command list is:

```text
context status
context check
rule list <core|device>
rule get <core|device> <value>/<bits>
rule duplicate <source>/<bits> <destination>/<bits> [entry=<index> tv=<value> mo=<identity> cda=<identity> ...]
rule update <value>/<bits> entry=<index> tv=<value> [--if-match]
rule update <value>/<bits> fid=<field> [fp=<position>] [di=<direction>] tv=<value> [--if-match]
help
quit
```

Each `entry=<index>` starts one override group, followed by one or more of `tv=<value>`, `mo=<identity>`, and `cda=<identity>`.
Duplicate target replacements accept unsigned decimal values only when replacing an existing fixed-width binary target, preserving that target's width.
The `mo=` and `cda=` arguments accept only the currently supported identity names.

The data client command list is:

```text
discover [query]
schema [filter]
get <path>
fetch <path>
set <path> <json-value>
delete <path>
reload
help
quit
```

## Duplicate-rule measurement

The dedicated duplicate-rule request uses protected M Rule `29/8`.
For `rule duplicate 20/8 22/8 entry=9 tv=2`, the complete modeled RPC payload is 43 bytes.
The fixed payload with only source and destination selectors is 19 bytes.
The one override's inner CORECONF instance map is 22 bytes, comprising 14 bytes of selector/structure and 8 encoded target-value bytes.
The complete logical IPv6/UDP/CoAP packet is 103 bytes.
Its meaningful SCHC frame is 371 bits and its padded link frame is 47 bytes.
The decoded RPC cost is 43 bytes: fixed 19 bytes, variable framing 16 bytes, and target-value contents 8 bytes.
The breakdown is 8 RuleID bits, 7 MID residue bits, zero method/type/path/content-format residue bits, 12 payload-length bits, 344 payload bits, and 5 padding bits.
The fixed management transport overhead is therefore 15 bits.
A successful duplicate management measurement must account for all meaningful residue bits; unaccounted residue is an error.

The application request is 128 meaningful SCHC bits and 16 padded bytes with fallback Rule `25/8`.
After duplication it is 82 meaningful bits and 11 padded bytes with Rule `22/8`.
The saving is 46 meaningful bits per packet.
The management break-even count is `ceil(371 / 46) = 9` application packets.
Rust packet/link tests verify exact logical packet and frame bytes where those bytes are directly available, along with application delivery, source immutability, idempotent replay, and no duplicate-rule response.

## Manual process commands

The endpoint processes now require Linux TUN interfaces and are intended for a privileged namespace harness.
The standalone data client and server remain separate application processes; they are not UDP proxy endpoints of these SCHC processes.
The equivalent process arguments are shown below for inspection.

Start the device first:

```sh
target/debug/schc-coreconf-device \
  --link-bind 127.0.0.1:41081 \
  --link-peer 127.0.0.1:41082 \
  --tun-name schc-device \
  --tun-mtu 1280
```

Start the core in another terminal:

```sh
target/debug/schc-coreconf-core \
  --link-bind 127.0.0.1:41082 \
  --link-peer 127.0.0.1:41081 \
  --tun-name schc-core \
  --tun-mtu 1280
```

Once the interfaces are connected to IPv6 application processes, send these commands to the core console:

```text
context check
rule list device
rule get device 20/8
rule update 20/8 fid=ipv6.app-iid tv=2 --if-match
context check
rule get core 20/8
rule get device 20/8
```


## Limitations

This prototype uses one core endpoint and one device endpoint with fixed logical IPv6 application orientations.
The standalone data client and server remain separate application processes.
It does not implement SCHC fragmentation, OSCORE, QUIC, TCP, or remote administration.
It does not provide automatic RuleID allocation, context epochs, retries, rollback, replay journals, or concurrent multi-device routing.
The core sends duplicate-rule once as a NON POST and does not wait for or require a response.
It then applies the exact same operation locally and reports `remote=unacknowledged`.
A local failure after sending reports possible divergence and requires an operator to run `context check`.
An identical installed duplicate is idempotent with no new publication; a conflicting destination is rejected without mutation.
The management rule inventory is intentionally small and uses exact protected RuleID policy rather than generalized M-Rule creation.

## Troubleshooting

If a process fails before printing `READY`, run `cargo build -p schc-coreconf --bins` and verify that the fixture paths exist.
The device is expected to remain running while idle; its short receive polling interval treats normal `TimedOut` or `WouldBlock` results as no frame rather than a fatal error.
Unexpected socket errors remain fatal.

If the update is rejected with a stale If-Match value, the core and device contexts started from different SoRs.
Restart both processes with the same initial context before retrying.

If fixture regeneration fails, install `rule2sor==0.1.0` and verify the wheel SHA-256 documented in `fixtures/demo/README.md`.
Then run `python3 tools/generate_demo_fixtures.py --check --rule2sor /path/to/rule2sor`.

## Validation

The repository validation contract is formatting, strict Clippy, full workspace tests, rustdoc with warnings denied, deterministic fixture regeneration, and diff checks.

## License

Licensed under either of the Apache License, Version 2.0 or the MIT license, at your option.
See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
