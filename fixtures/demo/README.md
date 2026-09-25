# Deterministic demonstration context

The OpenSCHC JSON document is the user-facing rule source for the final demonstration.

`initial-rules.json` contains these exact rules:

- `16/8`: protected payload-bearing context FETCH request with a fixed method and URI path.
- `17/8`: protected response rule for payload-bearing Content/error and payloadless Changed responses, with a fifteen-entry response-code mapping.
- `26/8`: protected payload-bearing inspection FETCH request with Content-Format 141.
- `27/8`: protected default iPATCH request with Content-Format 142.
- `28/8`: protected iPATCH request with an eight-byte If-Match value.
- `29/8`: protected fixed NON POST duplicate-rule request with a variable modeled RPC payload.
- `20/8`: ordinary application FETCH request for the current public rustconf root FETCH shape, with an intentionally nonmatching application IID of `::5`.
- `21/8`: ordinary application FETCH response on UDP port 5683 with CBOR Content-Format option value 142 and a format-142 instance-sequence payload carried as residue.
- `25/8`: ordinary header-compression fallback that carries the remaining packet bytes.

Application request rules `20/8` and `25/8` map hop limits 63 and 64 with one residue bit.
This covers packets forwarded once by the core namespace as well as locally constructed packets without fixing the research topology to one kernel forwarding behavior.

The protected management rules compress the fixed IPv6, UDP, CoAP, URI, and Content-Format fields.
Rule `29/8` fixes CoAP NON POST and code 0.02, uses the same seven-bit MID residue, and carries only the modeled duplicate-rule payload as the final variable field.
They use zero-length CoAP tokens and encode CoAP MID with MSB(9)/LSB, which carries seven MID bits for the bounded range 0..=127.
The payload field is modeled as `PAYLOAD` and r-schc reconstructs the CoAP `0xff` payload marker rather than sending it as residue.
The default iPATCH rule and the If-Match iPATCH rule are separate so the optional dynamic option remains exact.
The SoR marks Rules `16/8`, `17/8`, `26/8`, `27/8`, `28/8`, and `29/8` with `nature-management`; the runtime derives protection from that nature.
The ordinary Rule `25/8` fallback remains a header-only compression rule with the remaining packet carried as suffix.

The fixed logical addresses are `2001:db8::1` for the device and `2001:db8::2` for the application/core.
Application traffic uses UDP port 5683.
Protected management requests and responses use UDP port 8724 at both logical endpoints.
The outer raw SCHC-link UDP ports remain configurable process arguments.
The data client uses the public rustconf root FETCH shape to fetch `/demo-data:config/count`.
The resulting CoAP FETCH request has code 5, one Uri-Path option `c`, one Content-Format option with numeric value `141`, and an identifier-sequence payload selecting `/demo-data:config/count`.
Management requests use path `schc`.
The protected request rules carry fixed current methods, while the response rule maps 2.01, 2.02, 2.04, 2.05, 4.00, 4.01, 4.02, 4.04, 4.05, 4.08, 4.09, 4.12, 4.13, 4.15, and 5.00 codes using four mapping bits.
The management request and response MIDs are correlated by endpoint and the bounded seven-bit MID residue.
The core reuses MIDs modulo 128 only after each synchronous exchange completes; this is a bounded stateless transport window, not a loss-recovery scheme.
The fixture entries use `BI` direction indicators so each rule is a complete bidirectional field path.
Exact request, response, management, and application separation comes from fixed field values and the matched RuleID.
Dispatch uses the exact matched RuleID and does not authorize management by URI or port alone.
The checked-in `initial.sor` is the encoded fixture used by the repository.
Build, tests, demo, and fixture checks use it directly; alternate test trees
are derived in memory. See the [fixture index](../README.md) for the artifact
inventory and the optional `rule2sor` validation and regeneration commands.
