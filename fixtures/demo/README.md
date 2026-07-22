# Deterministic demonstration context

The two OpenSCHC JSON documents are the user-facing rule sources for the final demonstration.
They are not YANG datastore JSON.

`initial-rules.json` contains these exact rules:

- `16/8`: protected management request, compression nature, downlink IPv6/UDP/CoAP traffic to URI path `schc` on UDP port 5684, with the request code carried in the residue.
- `17/8`: protected management response, compression nature, uplink traffic on UDP port 5684, with the response code carried in the residue.
- `20/8`: ordinary application GET request on UDP port 5683 and URI path `demo`, with an intentionally nonmatching application IID of `::5`.
- `21/8`: ordinary application response on UDP port 5683.
- `25/8`: generic ordinary no-compression fallback.

`updated-rules.json` is identical except that rule `20/8` changes the `IPV6.APP_IID` target from `::5` to `::2`.
The fixed application request therefore uses `2001:db8::2` as its destination and is handled by rule `25/8` before the update and rule `20/8` after it.
The optimized rule carries only the request residue, so later work can prove fewer SCHC bits without changing the logical request.

The fixed logical addresses are `2001:db8::1` for the device and `2001:db8::2` for the application/core.
Application traffic uses UDP port 5683.
Protected management requests use core/application-side UDP port 5683 and device-side UDP port 5684; responses reverse those endpoints.
Application requests use CoAP GET code 1 and path `demo`.
Management requests use path `schc`; their CoAP method code is carried so inspection and iPATCH share one protected request rule.
Management response codes are also carried so content, changed, and error responses share one protected response rule.
The fixture entries use `BI` direction indicators so each rule is a complete bidirectional field path; exact request/response and management/application separation comes from the fixed field values and matched RuleID.
Dispatch in later work must use the exact matched RuleID and must not authorize management by URI or port alone.

`rule2sor` 0.1.0 from <https://github.com/ltn22/rule2sor> emits `nature-compression` for OpenSCHC `Compression` entries and does not expose management nature in its JSON grammar.
The integration policy therefore protects exact rule identities `16/8` and `17/8`.
This preserves the required protected management semantics without inventing a rule2sor input key.

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

The checker runs `rule2sor <rules.json> -s <sid-file> -o <temporary.sor> -q` twice per source and compares both outputs byte-for-byte with the checked-in SoR.
It fails clearly when the executable is unavailable or output is nondeterministic.
