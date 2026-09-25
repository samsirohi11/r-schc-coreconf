# SCHC CORECONF prototype

This repository integrates [r-schc](deps/r-schc/README.md) and
[rustconf](deps/rustconf/README.md) in a four-process IPv6 demonstration. It is
a research prototype, not a claim of full SCHC or CORECONF conformance.

## Repository map

| Path | Responsibility |
| --- | --- |
| `crates/schc-coreconf` | Integration library and four demo binaries: application client/server, SCHC core, and SCHC device. |
| `deps/r-schc` | `schc-core` packet and SCHC codecs; `schc-runtime` endpoint and transport runtime; `schc-cli` standalone CLI. |
| `deps/rustconf` | `coreconf-model` YANG/SID and JSON/CBOR model; `coreconf-runtime` CORECONF operations and datastore; `coreconf-cli` standalone CLI. |
| `fixtures` | Checked-in application and SCHC contexts used by the demo. |
| `tools/run_demo.sh` | Builds and runs the namespace demo and checks its end-to-end proof. |

The root crate owns integration, managed-context synchronization, and the
demonstration. Packet/SCHC behavior belongs to `r-schc`; CORECONF model and
datastore behavior belongs to `rustconf`. See the
[composition contract](docs/COMPOSITION.md).

## Standards and prototype policy

The implementation uses SCHC behavior from [RFC 8724](https://www.rfc-editor.org/rfc/rfc8724.html),
an [RFC 9363](https://www.rfc-editor.org/rfc/rfc9363.html)-derived SCHC YANG
model, [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) CBOR encoding,
and a focused subset of [CORECONF draft 21](https://datatracker.ietf.org/doc/html/draft-ietf-core-comi-21).
These references describe sources for implemented behavior; they do not imply
complete conformance.

The model uses ordered universal entries, marks management Rules with
`nature-management`, and keeps management guard data at context scope. These
are distinct from local demo choices: four processes and three Linux network
namespaces, fixed demo endpoints, zero application flow labels, and a
duplicate-rule request that installs locally without a response. The core
checks context synchronization explicitly. These choices are not general
SCHC requirements.

## Build and run

Requirements: Rust and Cargo 1.93.1 or newer. The namespace demo also needs
Linux, `/dev/net/tun`, `ip`, and interactive `sudo` access.

From the repository root, build the demo binaries:

```sh
cargo build -p schc-coreconf --bins
```

Run the automated root workspace suite:

```sh
cargo test --workspace --all-targets --all-features
```

Run the four-process end-to-end demonstration:

```sh
./tools/run_demo.sh
```

It starts the application client, SCHC core, SCHC device, and application
server across three temporary network namespaces. Success ends with
`DEMO COMPLETE namespaces=3 processes=4 management_internal=yes application_e2e=yes`.
Use `./tools/run_demo.sh --check` for an unprivileged preflight. To open the
four roles in separate terminals, run `./tools/run_demo_interactive.sh`.
For manual setup, see the
[running guide](docs/RUNNING.md) for one-machine namespaces or multi-machine placement.

See the [fixture index](fixtures/README.md) for retained artifacts and
validation or regeneration commands. Normal build, test, and demo use the
checked-in SoRs; `rule2sor` is optional.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at
your option. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
