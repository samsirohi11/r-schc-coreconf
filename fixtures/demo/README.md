# Deterministic demonstration context

The two OpenSCHC JSON documents are the user-facing rule sources for the final demonstration.
They are not YANG datastore JSON.

`initial-rules.json` contains these exact rules:

- `16/8`: protected management request using a zero-entry compression rule.
- `17/8`: protected management response using a compression rule whose response code is carried in the residue.
- `20/8`: ordinary application FETCH request for the resource path `c/demo-data:config/count`, with an intentionally nonmatching application IID of `::5`.
- `21/8`: ordinary application response on UDP port 5683 with CBOR Content-Format option value 140.
- `25/8`: generic ordinary no-compression fallback.

`updated-rules.json` is identical except that rule `20/8` changes the `IPV6.APP_IID` target from `::5` to `::2`.
The fixed data-client request uses `2001:db8::2` as its application/core source address and `2001:db8::1` as its device destination.
It is handled by rule `25/8` before the update and rule `20/8` after it.
The optimized rule carries only the request residue, so the demonstration can prove fewer SCHC bits without changing the logical request.

Rule `16/8` is represented as a zero-entry compression rule because the pinned `rule2sor` JSON grammar has no management nature.
The r-schc integration treats this exact protected RuleID as a complete-packet passthrough whose packet bytes are carried as residue.
This keeps standard CoAP management options such as If-Match available while preserving exact RuleID authorization.
The integration policy protects exact rule identities `16/8` and `17/8`.

The fixed logical addresses are `2001:db8::1` for the device and `2001:db8::2` for the application/core.
Application traffic uses UDP port 5683.
Protected management requests use core/application-side UDP port 5683 and device-side UDP port 5684.
Protected management responses reverse those endpoints.
The data client uses resource path `c` and fetches `/demo-data:config/count`.
The resulting CoAP FETCH request has code 5 and URI-Path options `c`, `demo-data:config`, and `count`.
Management requests use path `schc`.
The management request code and response code are carried so inspection and iPATCH share the protected rules.
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
