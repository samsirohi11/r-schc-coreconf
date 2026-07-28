# Composition and demo boundaries

## Dependency direction

The intended dependency graph is one-way:

```text
r-schc-coreconf
  |-> r-schc
  `-> rustconf
```

The two lower repositories remain independent.
`r-schc` must not depend on CORECONF, application datastore behavior, or this integration repository.
`rustconf` must not depend on SCHC, SCHC rules, or this integration repository.
`r-schc-coreconf` owns only the behavior that combines the two libraries.

The current checkout uses source submodules and path dependencies while the library APIs are stabilized.
The submodule Gitlinks and `Cargo.lock` are the source of truth for this transitional development composition.
Hand-maintained abbreviated commit comments are intentionally avoided because they become stale independently of Gitlinks.

The release composition must use versioned crate dependencies and must not commit dependency source trees.
Each integration release will record a dependency tuple containing the `schc-core`, `schc-runtime`, `coreconf-model`, and `coreconf-runtime` crate versions.
A release is valid only when that tuple passes the integration test suite and the real-process demonstration.

## Ownership by repository

| Repository | Owns | Does not own |
| --- | --- | --- |
| `r-schc` | SCHC packets, rules, compression, decompression, frames, endpoint roles, and transport plugin boundaries. | CORECONF semantics, generic datastores, and application models. |
| `rustconf` | CORECONF model handling, request semantics, datastore boundaries, operation bindings, and CoAP integration. | SCHC compression, SCHC RuleIDs, and SCHC context synchronization. |
| `r-schc-coreconf` | Managed SCHC contexts, protected management routing, context synchronization, and the executable demonstration. | Forked copies of generic SCHC or CORECONF functionality. |

The integration crate must reuse the public packet and CORECONF client, server, and datastore boundaries from the independent repositories.
Duplicate packet builders, generic request codecs, and generic datastore clients are migration targets and must not become new public APIs here.

## Current and target process topology

The current executable demonstration has three processes.
The application CORECONF server and datastore are embedded in the SCHC device process.
This topology remains the acceptance baseline until the reusable boundaries required by the four-process topology are available.

The target demonstration has four independently replaceable roles:

| Role | Responsibility |
| --- | --- |
| Application client | Sends ordinary application CORECONF requests and verifies logical responses. |
| SCHC core | Compresses outbound application traffic, decompresses replies, initiates protected context management, and maintains the synchronized core-side context. |
| SCHC device | Decompresses ordinary traffic, forwards reconstructed packets to the application server, compresses replies, handles protected management commands, and maintains the device-side context. |
| Application CORECONF server and datastore | Serves an application SID and datastore without depending on SCHC or SCHC management. |

The application client and server are demonstration consumers of `rustconf`.
The SCHC core and device are the reusable managed-endpoint contribution of this repository.
The target boundaries must permit replacement of the application SID, SCHC SID registry, SoR, datastore backend, and link transport without editing protocol internals.

## Management invariants

Protected management authorization is based on an exact RuleID and RuleID width, not only on a URI, port, or rule value.
An update is prepared and validated against a detached context before either active context is published.
The device acknowledgment must identify the expected old and new context tags before the core publishes the prepared context.
A successful update must leave the core and device with the same canonical context tag.

Ordinary application packet bytes must remain identical when a context update changes only the selected SCHC representation.
The demonstration must compare sender and receiver packet bytes, selected RuleIDs, meaningful SCHC bit lengths, and raw padded link frames.

## Rule lifecycle profile

Generic create, update, and delete operations use CORECONF iPATCH against the SCHC rule datastore.
The SCHC `duplicate-rule` operation is modeled as a POST RPC because it has operation semantics beyond a generic datastore edit.
An optional patch applied during duplication addresses list entries by their explicit `entry-index` key rather than by vector position.
Custom create-rule and delete-rule RPCs are not part of the initial profile because they would duplicate standard datastore mutation semantics.
