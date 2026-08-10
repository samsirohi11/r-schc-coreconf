# Deterministic demonstration context

The two OpenSCHC JSON documents are the user-facing rule sources for the final demonstration.
They are not YANG datastore JSON.

`initial-rules.json` contains these exact rules:

- `16/8`: protected payload-bearing context FETCH request with a fixed method and URI path.
- `17/8`: protected response rule for payload-bearing Content/error and payloadless Changed responses, with a fifteen-entry response-code mapping.
- `26/8`: protected payload-bearing inspection FETCH request with Content-Format 141.
- `27/8`: protected default iPATCH request with Content-Format 142.
- `28/8`: protected iPATCH request with an eight-byte If-Match value.
- `20/8`: ordinary application FETCH request for the current public rustconf root FETCH shape, with an intentionally nonmatching application IID of `::5`.
- `21/8`: ordinary application FETCH response on UDP port 5683 with CBOR Content-Format option value 142 and a format-142 instance-sequence payload carried as residue.
- `25/8`: ordinary header-compression fallback that carries the remaining packet bytes.

`updated-rules.json` is identical except that rule `20/8` changes the `IPV6.APP_IID` target from `::5` to `::2`.
The fixed data-client request uses `2001:db8::2` as its application/core source address and `2001:db8::1` as its device destination.
It is handled by rule `25/8` before the update and rule `20/8` after it.
The optimized rule carries only the request residue, so the demonstration can prove fewer SCHC bits without changing the logical request.

The protected management rules compress the fixed IPv6, UDP, CoAP, URI, and Content-Format fields.
They use zero-length CoAP tokens and encode CoAP MID with MSB(9)/LSB, which carries seven MID bits for the bounded range 0..=127.
The payload field is modeled as `PAYLOAD` and r-schc reconstructs the CoAP `0xff` payload marker rather than sending it as residue.
The default iPATCH rule and the If-Match iPATCH rule are separate so the optional dynamic option remains exact.
The integration policy protects the exact rule identities `16/8`, `17/8`, `26/8`, `27/8`, and `28/8`.
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

`rule2sor` 0.1.0 from <https://github.com/ltn22/rule2sor> emits `nature-compression` for OpenSCHC `Compression` entries.
It does not expose management nature in its JSON grammar.
The generated `initial.sor` and `updated.sor` files must be regenerated with the real documented CLI through the repository checker.
The expected PyPI wheel SHA-256 is `8893b4cd5d9f2008cc6a8eb484ff241d84631f5e224ab1b861fc104f6e3631d7`.

Install the pinned package in an isolated environment, then run:

```text
python3 -m venv /tmp/rule2sor-venv
/tmp/rule2sor-venv/bin/python -m pip download --only-binary=:all: --no-deps --dest /tmp/rule2sor-wheel rule2sor==0.1.0
test "$(sha256sum /tmp/rule2sor-wheel/rule2sor-0.1.0-py3-none-any.whl | cut -d' ' -f1)" = "8893b4cd5d9f2008cc6a8eb484ff241d84631f5e224ab1b861fc104f6e3631d7"
/tmp/rule2sor-venv/bin/python -m pip install rule2sor==0.1.0
RULE2SOR=/tmp/rule2sor-venv/bin/rule2sor python3 tools/generate_demo_fixtures.py
RULE2SOR=/tmp/rule2sor-venv/bin/rule2sor python3 tools/generate_demo_fixtures.py --check
```

The checker runs `rule2sor <rules.json> -s <sid-file> -o <temporary.sor> -q` twice per source.
It compares both outputs byte-for-byte with the checked-in SoR.
It fails clearly when the executable is unavailable or output is nondeterministic.
