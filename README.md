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

The protected management RuleIDs are `16/8` and `17/8`.
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

## Final demonstration

The executable demonstration builds the checked-out source binaries by default on every run, launches all three real processes, and cleans up processes, FIFOs, and temporary logs on every exit.
Run it with:

```sh
bash tools/run_demo.sh
```

The default high localhost ports are `41081` for the device link, `41082` for the core link, and `41083` for the application endpoint.
Override them when another process owns a port:

```sh
DEMO_DEVICE_LINK_PORT=42081 DEMO_CORE_LINK_PORT=42082 DEMO_CORE_APP_PORT=42083 bash tools/run_demo.sh
```

The script performs discovery, schema inspection, and a FETCH before the update.
It inspects the initial context and confirms Rule 20 has `IPV6.APP_IID` value `0x0000000000000005`.
It applies `rule update 20/8 fid=ipv6.app-iid tv=2 --if-match` through the protected management link.
It verifies equal compact context tags and repeats the exact same FETCH afterward.
It compares packet bytes, SCHC bit counts, RuleIDs, and sender-to-receiver raw frame bytes from both directions.

A successful run prints proof lines similar to:

```text
DEMO PROOF request_packet_identical=yes
DEMO PROOF response_packet_identical=yes
DEMO PROOF request_rule_before=25/8 request_rule_after=20/8
DEMO PROOF request_schc_bits_before=... request_schc_bits_after=...
DEMO PROOF response_rule=21/8
DEMO PROOF context_tags_equal=yes tag=...
DEMO PROOF context_tag_changed=yes
DEMO PROOF raw_padded_frames_sender_receiver_match=yes
DEMO COMPLETE localhost_udp=yes root_required=no
```

The exact bit counts and compact tag depend on the checked-in fixture bytes and implementation version.
The script exits nonzero if any proof condition fails.
By default, the script builds from the checked-out source on every run.
Set `DEMO_BUILD=0` to explicitly skip the build and use existing binaries.
When `DEMO_BUILD=0`, `DEMO_BIN_DIR` may point to a directory containing the three binaries.

## Interactive CLI use

Run the core and data client from a terminal, not through a pipe, to get startup help and a visible prompt.
The core prompt is `core>` and the data client prompt is `data>`.
Both processes also accept `help` at any time.
The device is a background service and prints `WAITING role=device` while it waits for frames.

Traffic reports are concise by default and include the selected RuleID, packet size, SCHC bit count, padded frame size, and compression ratio.
Pass `--debug` to `schc-coreconf-core` or `schc-coreconf-device` when full `packet_hex` and `frame_hex` fields are needed for wire-level diagnosis.
The final demonstration script enables this mode automatically for its proof checks.

The core command list is:

```text
context status
context check
rule list core|device
rule get core|device <value>/<bits>
rule update <value>/<bits> entry=<index> tv=<value> [--if-match]
rule update <value>/<bits> fid=<field> [fp=<position>] [di=<direction>] tv=<value> [--if-match]
help
quit
```

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

## Manual process commands

The automated script is the recommended user-facing command because it reserves no fixed external files and performs all assertions.
The equivalent process arguments are shown below for inspection.

Start the device first:

```sh
target/debug/schc-coreconf-device \
  --link-bind 127.0.0.1:41081 \
  --link-peer 127.0.0.1:41082 \
  --app-sid fixtures/demo/demo-data.sid \
  --app-data fixtures/demo/app-data.json
```

Start the core in another terminal:

```sh
target/debug/schc-coreconf-core \
  --link-bind 127.0.0.1:41082 \
  --link-peer 127.0.0.1:41081 \
  --app-bind 127.0.0.1:41083
```

Run the data client in a third terminal:

```sh
printf '%s\n' \
  'discover d=0' \
  'schema demo-data' \
  'fetch /demo-data:config/count' \
  'quit' | target/debug/schc-data-client \
  --sid fixtures/demo/demo-data.sid \
  --server 127.0.0.1:41083 \
  --path c
```

Send these commands to the core console to inspect and update the context:

```text
context check
rule list device
rule get device 20/8
rule update 20/8 fid=ipv6.app-iid tv=2 --if-match
context check
rule get core 20/8
rule get device 20/8
```

Repeat the client FETCH after the update:

```sh
printf '%s\n' \
  'fetch /demo-data:config/count' \
  'quit' | target/debug/schc-data-client \
  --sid fixtures/demo/demo-data.sid \
  --server 127.0.0.1:41083 \
  --path c
```

## Limitations

This prototype uses one device, fixed localhost UDP endpoints, and three processes.
The application CORECONF server and datastore are still embedded in the SCHC device process.
It does not implement Linux TUN integration, kernel-routed IPv6, SCHC fragmentation, OSCORE, QUIC, TCP, or remote administration.
It does not provide automatic RuleID allocation, context epochs, retries, rollback, replay journals, or concurrent multi-device routing.
The core applies an update locally only after the device acknowledges it.
A local failure after device success reports possible divergence and requires an operator to run `context check`.
The management rule inventory is intentionally small and uses exact protected RuleID policy rather than generalized M-Rule creation.

## Troubleshooting

If the script reports that a port is busy, select three unused high localhost ports with `DEMO_DEVICE_LINK_PORT`, `DEMO_CORE_LINK_PORT`, and `DEMO_CORE_APP_PORT`.
If a previous manual run is still alive, stop the three processes before retrying.

If a process fails before printing `READY`, run `cargo build -p schc-coreconf --bins` and verify that the fixture paths exist.
The script prints captured temporary logs when it fails.
The device is expected to remain running while idle; its short receive polling interval treats normal `TimedOut` or `WouldBlock` results as no frame rather than a fatal error.
Unexpected socket errors remain fatal.

If the data client prints an application error, confirm that the core and device use the same initial SoR and the sample application SID and datastore.
The expected FETCH result is the exact output line `7`.

If the update is rejected with a stale If-Match value, the core and device contexts started from different SoRs.
Restart both processes with the same initial context before retrying.

If fixture regeneration fails, install `rule2sor==0.1.0` and verify the wheel SHA-256 documented in `fixtures/demo/README.md`.
Then run `python3 tools/generate_demo_fixtures.py --check --rule2sor /path/to/rule2sor`.

## Validation

The repository validation contract is formatting, strict Clippy, full workspace tests, rustdoc with warnings denied, deterministic fixture regeneration, and diff checks.
The final acceptance E2E is also available as `cargo test -p schc-coreconf --test link final_real_process_demo_reuses_logical_request_and_shrinks_raw_frame`.

## License

Licensed under either of the Apache License, Version 2.0 or the MIT license, at your option.
See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
