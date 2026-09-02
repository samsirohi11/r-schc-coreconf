# Generic IPv6/UDP SCHC+CORECONF fixtures

`context.json` is the context manifest for the generic IPv6/UDP compression
fixture set. The adjacent SID, initial SoR, `profile.json`, and
`rule-tree.json` are the frozen
mechanism-neutral context inputs. Rule 2/2 is the seven-field variable-payload
base template; Rule 6/3 is the non-concrete IPv6/UDP fallback with variable
header residue and payload. The dynamic-rule set is empty. Flow-specific rules
are created only through the library management planner and are never part of
this checked-in context.

The profile reserves the `0/1` branch for dynamic application leaves at `/4`:
`0/4` through `7/4`. Pre-provisioned rules retain their configured identities;
the allocator chooses the shortest valid free leaf, then the lowest bit
pattern. A derived rule need not be a child of its source rule.

`rule-tree.json` is the checked-in, human-readable source for the configured
RuleID tree. The report test checks the generated vectors against the real
library and the profile binds the tree policy at context construction.
Run `python3 tools/check_generic_fixture.py` to verify the source metadata
against the checked-in SoR.

`vectors.json` contains the measured real-library duplicate-rule and
steady-data vectors. The `report` integration test regenerates these values
through `InspectionService`, `SchcLink`, and this context and compares the
resulting JSON with the file. The vectors cover deterministic lowest-free
flow-change allocation and actual encoded wire frames.

The files under `fixtures/demo` remain historical demonstration fixtures and
are not modified by the generic IPv6/UDP vector check.
