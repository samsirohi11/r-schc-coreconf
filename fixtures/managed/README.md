# Managed-context foundation fixture

`ietf-schc@2026-05-07.sid` and `core.sor` are generated from the `deps/r-schc`
submodule at commit `cf0b9bc` by `tools/generate_fixture.py`.
The generator reads immutable blobs with `git show` and verifies these SHA-256 values.
Run `python3 tools/generate_fixture.py --check` to verify without modifying files.

- `ietf-schc@2026-05-07.sid`: `9053856d017170092aa066f47d559169df87b71c0b32e7b702542c2b37eb78ff`
- `core.sor`: `1896b1d1fb5bda7be889ea10523560fe1c2cbe89595510fd453eeeeffd88c4a6`

`policy.json` marks RuleIDs 16/8 and 17/8 as protected slots for policy tests.
This deterministic fixture exercises atomic context construction and immutable
protected-rule enforcement.
It is intentionally not the final four-M-Rule Work Order 1 SoR.
