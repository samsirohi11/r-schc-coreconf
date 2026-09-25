# Composition and demo boundaries

## Dependency and ownership boundaries

The dependency direction is one-way:

```text
r-schc-coreconf -> r-schc
r-schc-coreconf -> rustconf
```

The lower repositories stay independent. `r-schc` owns IPv6/UDP/CoAP packet
construction and parsing, SCHC rules and codecs, frames, and endpoint runtime.
`rustconf` owns CORECONF/YANG/SID model handling, generic request semantics,
operation dispatch, and datastores. The root crate composes these APIs for
managed SCHC contexts, management protection and synchronization, and the
demonstration. Its `packet.rs` only re-exports `schc-core` packet types;
`link.rs` connects logical packets to SCHC frames and rule-derived routes.

The root workspace excludes the source submodules and uses path dependencies
under `deps/`. Gitlinks identify the recorded submodule commits; local changes
inside either submodule also affect builds from a dirty checkout.

## Management boundary

The loaded SoR's `nature-management` marks protected management rules. The
matched RuleID, including its bit length, determines the traffic class and
route; packet addresses, ports, or CoAP shape alone do not authorize
management. Loaded RuleID values are capped at uint32. The model permits an
implicit length-0 RuleID, but this prototype intentionally supports only
explicit lengths 1..=32.
Protected rules cannot be changed or removed from a candidate context.
Management entries use the model's ordered universal-entry structure; the
guard period belongs to the whole context.

The root management handler supports reads, explicit context checks, one
targeted iPATCH shape, and the `duplicate-rule` operation. A targeted iPATCH
replaces one target value in an existing ordinary rule. The device validates
and publishes a detached candidate before replying `2.04 Changed`. The core then applies the same request
locally and checks that it published once. `context check` separately compares
the core and device ContextTags. Other generic create, delete, or iPATCH shapes
are not part of this root management profile.

The duplicate-rule profile is a local policy: Rule `29/8` carries a CoAP NON
POST, the device applies it atomically without a response, and the core applies
the same deterministic operation locally. It copies only ordinary rules;
identical replays are no-op success. This one-way exchange is not an
acknowledged synchronization step. The four-process topology, fixed demo
endpoints, and zero application flow labels are also demonstration policy,
not general SCHC requirements.

The management exchange API supports empty or generated opaque CoAP tokens.
Current management Rules encode zero-length tokens, so the running profile
uses empty tokens.

## Demonstration packet invariant

When a context change only changes the selected SCHC representation, the
reconstructed application packet remains byte-identical. Link tests compare
packet and frame bytes. The demo correlates endpoint reports and prints
selected RuleIDs, meaningful SCHC bit lengths, and padded byte counts.
