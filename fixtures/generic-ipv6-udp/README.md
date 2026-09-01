# Generic IPv6/UDP SCHC+CORECONF fixtures

`context.json` is the context manifest for the generic IPv6/UDP compression
fixture set. The adjacent SID and initial SoR are the frozen mechanism-neutral
context. Rule 20/8 is the seven-field variable-payload base template; Rule
21/8 is the non-concrete IPv6/UDP fallback with variable header residue and
payload. The dynamic-rule set is empty. Flow-specific rules are created only
through the library management planner and are never part of this checked-in
context.

The default allocator starts at RuleID value 0 and preserves the parent rule
width. This is a policy, not a caller-selected RuleID.

`vectors.json` contains the measured real-library duplicate-rule and
steady-data vectors. The `report` integration test regenerates these values
through `InspectionService`, `SchcLink`, and this context and compares the
resulting JSON with the file. The vectors cover deterministic lowest-free
flow-change allocation and actual encoded wire frames.

The files under `fixtures/demo` remain historical demonstration fixtures and
are not modified by the generic IPv6/UDP vector check.
