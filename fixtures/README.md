# Fixture index

The demo and tests load the checked-in SoRs directly. Build, test, demo, and
fixture validation do not require `rule2sor`; use it only when regenerating a
SoR from its JSON source.

## Retained fixture sets

| Set | Source inputs | Generated artifact | Used for |
| --- | --- | --- | --- |
| [`demo/`](demo/README.md) | `initial-rules.json`, `ietf-schc@2026-09-22.sid`, `demo-data.sid`, `app-data.json` | `initial.sor` | Four-process demo and root integration tests. |
| [`generic-ipv6-udp/`](generic-ipv6-udp/README.md) | `rules.json`, `ietf-schc@2026-09-22.sid`, `context.json`, `profile.json`, `rule-tree.json` | `initial.sor` | Generic IPv6/UDP SCHC link tests and allocation checks. |

The JSON files and SID files are checked-in source or metadata. The `.sor`
files are generated, checked-in context data. The demo's `demo-data.sid` and
`app-data.json` are application model and datastore inputs, not outputs of
`rule2sor`.

## Validate and regenerate

From the repository root, validate fixture consistency:

```sh
python3 tools/check_generic_fixture.py
```

To regenerate and byte-check either checked-in SoR, provide a compatible
`rule2sor` executable or source/package directory:

```sh
python3 tools/generate_demo_fixtures.py --check --rule2sor /path/to/rule2sor
python3 tools/check_generic_fixture.py --rule2sor /path/to/rule2sor
```

To update the demo SoR from `initial-rules.json`, omit `--check`:

```sh
python3 tools/generate_demo_fixtures.py --rule2sor /path/to/rule2sor
```

The generic checker validates the checked-in metadata and SoR. With
`--rule2sor`, it also runs the generator twice and byte-compares both results
with `generic-ipv6-udp/initial.sor`. To regenerate that file intentionally,
run the compatible generator from the repository root:

```sh
/path/to/rule2sor fixtures/generic-ipv6-udp/rules.json \
  -s fixtures/generic-ipv6-udp/ietf-schc@2026-09-22.sid \
  -o fixtures/generic-ipv6-udp/initial.sor -q
```

Review the result with:

```sh
python3 tools/check_generic_fixture.py --rule2sor /path/to/rule2sor
```

The demo-specific rule details remain in
[`demo/README.md`](demo/README.md); generic allocation metadata is described in
[`generic-ipv6-udp/README.md`](generic-ipv6-udp/README.md).
