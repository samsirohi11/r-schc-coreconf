# Generic IPv6/UDP SCHC+CORECONF fixtures

`context.json` is the context manifest for the generic IPv6/UDP compression
fixture set. `rules.json` is the OpenSCHC source used with the adjacent SID to
generate `initial.sor`; the six protected rules are marked with
`RuleNature: Management`. The SID, initial SoR, `profile.json`, and
`rule-tree.json` are the frozen mechanism-neutral context inputs. Rule 2/2 is the seven-field variable-payload
base template; Rule 6/3 is the non-concrete IPv6/UDP fallback with variable
header residue and payload. The dynamic-rule set is empty. Flow-specific rules
are created only through the library management planner and are never part of
this checked-in context.

The profile reserves the `0/1` branch for dynamic application leaves at `/4`:
`0/4` through `7/4`. Pre-provisioned rules retain their configured identities;
the allocator chooses the shortest valid free leaf, then the lowest bit
pattern. A derived rule need not be a child of its source rule.

`rule-tree.json` is the checked-in, human-readable source for the configured
RuleID tree. Its role labels describe allocation reservations only; runtime
Rule nature comes from the decoded SoR. The profile binds the tree policy at
context construction, while focused link and report tests exercise the
deterministic allocation and wire behavior directly.
The checked-in SoR is loaded directly by tests. See the [fixture index](../README.md)
for the artifact inventory and validation or regeneration commands. The demo
suite also uses `fixtures/demo/initial.sor` as its checked-in context.
