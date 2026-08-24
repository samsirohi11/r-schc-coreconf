//! Deterministic management-console coverage.

use std::sync::Arc;

use schc_coreconf::{
    format_rule_detail, parse_rule_selector, protected_management_rule_ids, ActiveContext,
    InspectionService, PreparedContext, ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn active(id: &str) -> Arc<ActiveContext> {
    Arc::new(ActiveContext::new(
        PreparedContext::from_sor_with_policy(
            SID,
            SOR,
            DeviceId::new(id).expect("device ID"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .expect("context"),
    ))
}

#[test]
fn rule_detail_is_stable_and_contexts_can_be_inspected_independently() {
    let core = active("console-core");
    let device = active("console-device");
    let selector = parse_rule_selector("20/8").expect("selector");
    let core_service = InspectionService::new(Arc::clone(&core)).expect("core service");
    let device_service = InspectionService::new(Arc::clone(&device)).expect("device service");
    let core_lines = format_rule_detail(&core_service.detail(selector).expect("core detail"));
    let device_lines = format_rule_detail(&device_service.detail(selector).expect("device detail"));
    assert_eq!(core_lines, device_lines);
    assert!(core_lines.iter().any(|line| line.contains("RULE 20/8")));
}

#[test]
fn duplicate_management_is_atomic_and_idempotent_without_a_response() {
    let core = active("console-core");
    let mut service = InspectionService::new(Arc::clone(&core)).expect("service");
    let request = service
        .duplicate_rule_datagram(
            &schc_coreconf::RuleDuplicateRequest {
                source: schc_coreconf::RuleSelector { value: 20, bits: 8 },
                destination: schc_coreconf::RuleSelector { value: 22, bits: 8 },
                overrides: vec![],
            },
            1,
        )
        .expect("duplicate request");
    assert!(service
        .handle_datagram_no_response(&request)
        .expect("duplicate")
        .is_none());
    let generation = core.generation();
    assert!(service
        .handle_datagram_no_response(&request)
        .expect("replay")
        .is_none());
    assert_eq!(core.generation(), generation);
}
