# SCHC CORECONF namespace demonstration

This repository contains a four-process SCHC and CORECONF prototype.
The demonstration uses real IPv6, UDP, CoAP, CORECONF, SCHC, Linux TUN devices, and a raw UDP SCHC link.
The reproducible namespace demonstration requires Linux, `/dev/net/tun`, `ip`, and interactive sudo access.

## Architecture

`schc-data-client` is the application-facing client.
It discovers resources and displays schema paths.
Its `get` command uses a root CORECONF GET, its `fetch` command uses a root FETCH with identifier payloads, and its `set` and `delete` commands use root iPATCH mutations.

`schc-coreconf-core` is the application and management core.
It receives complete routed IPv6/UDP/CoAP application packets through its TUN interface, compresses them, and sends raw SCHC frames to the device.
Its console supports context inspection and targeted ordinary-rule updates.

`schc-coreconf-device` is the device-side process.
It decodes raw SCHC frames, dispatches protected management traffic by exact RuleID, writes ordinary packets to its TUN device, and returns compressed responses.

`schc-data-server` is the standalone application server.
It owns the sample datastore and binds the logical server address inside the device namespace.

The internal link carries only padded SCHC frame bytes.
IPv6, UDP, and CoAP headers are reconstructed at the receiving SCHC endpoint rather than being sent as an outer link envelope.

The repository currently composes source-pinned development dependencies.
The application server is a separate process from the SCHC device.
See [the composition contract](docs/COMPOSITION.md) for dependency ownership and synchronization invariants.

The protected management RuleIDs are `16/8` (context FETCH), `17/8` (responses), `26/8` (inspection FETCH), `27/8` (default iPATCH), `28/8` (If-Match iPATCH), and `29/8` (NON POST duplicate-rule).
All logical management packets use UDP port `8724` at both endpoints.
Rule `20/8` is the ordinary optimized FETCH request rule.
Rule `21/8` is the ordinary response rule.
Rule `25/8` is the ordinary header-compression fallback when no specialized application request rule matches.

## Prerequisites

- Rust and Cargo 1.93.1 or newer.
- Python 3 for fixture checking and proof parsing.
- Linux with `/dev/net/tun`, `ip`, and `stdbuf`.
- Interactive sudo access for the namespace phase.

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

## Namespace demonstration

Build and check the harness without privilege:

```sh
cargo build -p schc-coreconf --bins
bash tools/run_demo.sh --check --no-build
```

Run the three-namespace demonstration with:

```sh
sudo tools/run_demo.sh --no-build
```

The harness creates one client namespace, one core namespace, and one device namespace connected by two temporary veth pairs.
The four processes are the application client, SCHC core, SCHC device, and standalone application server.
Application UDP uses logical port `5683`.
The raw core-to-device SCHC link uses IPv4 UDP port `8724`.
The harness removes temporary namespaces, links, FIFOs, and logs on success.
It prints the log directory on failure, or when `--keep-logs` is supplied.
The proof parser validates endpoint agreement, one-way management, application isolation, and selection of the duplicated rule.
It calculates packet measurements from the endpoint logs.

For interactive one-machine namespace use, see [the local manual guide](docs/MANUAL-LOCAL.md).
For equivalent multi-machine placement, see [the multi-machine manual guide](docs/MANUAL-MULTI.md).

## Interactive CLI use

Run the core and data client from a terminal, not through a pipe, to get a visible prompt.
The core prompt is `core>` and the data client prompt is `data>`.
Both processes print one `READY` line and accept `help` at any time.
The device is a background service and includes its peer address on its `READY` line while it waits for frames.

Traffic reports are concise by default and show direction, traffic class, RuleID, original packet bytes, and padded transmitted bytes.
The proof parser derives and prints the measurements from the endpoint logs.
Pass `--debug` to `schc-coreconf-core` or `schc-coreconf-device` for the same line followed by a structured IPv6, UDP, CoAP, RPC, and SCHC accounting block.
Debug output is plain ASCII and intentionally omits raw packet and frame hexadecimal.

Successful management actions use concise results such as `OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged` and `OK update 20/8 entry=9  device=changed  local=changed`.
Context status reports the current generation and rule count in regular mode.

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

## Adaptive rule demonstration

The core sends the duplicate-rule request once and installs the same derived rule locally.
The harness sends the same application operation before and after duplication and verifies that the duplicated rule is selected while preserving the application operation and result.
The final proof output reports measurements calculated from that run.

## Operational notes

The demonstration uses one core endpoint and one device endpoint with fixed logical IPv6 application orientations.
The standalone data client and server remain separate application processes.
The core sends the duplicate-rule operation once as a NON POST and verifies synchronization with `context check`.
The management rule inventory uses exact protected RuleID policy.

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
