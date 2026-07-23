//! Focused protected inspection and compact-context tests.

use std::sync::Arc;

use coap_lite::{MessageClass, MessageType, Packet, RequestType, ResponseType};
use coreconf_model::instance_id::decode_instances_with_model;
use schc_core::{RuleId, SidRegistry};
use schc_coreconf::{
    context_check_request, context_check_response, decode_rule_detail_payload,
    decode_rule_list_payload, format_rule_detail, format_rule_list, parse_rule_selector,
    rule_get_request, rule_list_request, ActiveContext, ContextTag, InspectionService,
    PreparedContext, ProtectionPolicy, CONTEXT_TAG_LEN,
};
use schc_runtime::{DeviceId, DeviceProfile};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn active() -> Arc<ActiveContext> {
    let prepared = PreparedContext::from_sor_with_policy(
        SID,
        SOR,
        DeviceId::new("management-test-device").expect("device"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
    )
    .expect("prepared");
    Arc::new(ActiveContext::new(prepared))
}

#[test]
fn tags_are_stable_and_have_lowercase_wire_format() {
    let a = active();
    let b = active();
    assert_eq!(a.tag(), b.tag());
    let mut tree = a.tree();
    tree["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"] =
        serde_json::json!("0000000000000006");
    let changed = PreparedContext::from_tree(
        SID,
        tree,
        DeviceId::new("management-test-device").expect("device"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
    )
    .expect("changed context");
    assert_ne!(a.tag(), changed.tag());
    assert_eq!(a.tag().to_string().len(), CONTEXT_TAG_LEN * 2);
    assert_eq!(a.tag().to_string(), a.tag().to_string().to_lowercase());
    assert_eq!(ContextTag::new(a.tag().bytes()), a.tag());
}

#[test]
fn compact_context_check_has_only_marker_and_tag_on_mismatch() {
    let tag = ContextTag::new([1; CONTEXT_TAG_LEN]);
    let request = context_check_request(tag, 9, &[0x44]);
    let request_packet = Packet::from_bytes(&request).expect("request");
    assert_eq!(request_packet.payload.len(), CONTEXT_TAG_LEN + 1);
    let mut response = Packet::new();
    response.header.code = MessageClass::Response(ResponseType::Content);
    response.header.message_id = request_packet.header.message_id;
    response.header.set_type(MessageType::Acknowledgement);
    response.set_token(request_packet.get_token().to_vec());
    response.payload = vec![0xC6, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let result =
        context_check_response(&response.to_bytes().expect("response"), tag).expect("check");
    assert!(!result.equal);
    assert_eq!(result.device_tag.bytes(), [2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn device_context_check_reports_updated_tag_without_context_payload() {
    let core = active();
    let device = active();
    let mut tree = device.tree();
    tree["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"] =
        serde_json::json!("0000000000000006");
    let changed = PreparedContext::from_tree(
        SID,
        tree,
        DeviceId::new("management-test-device").expect("device"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
    )
    .expect("changed context");
    let device = Arc::new(ActiveContext::new(changed));
    let mut service = InspectionService::new(device.clone()).expect("service");
    let request = context_check_request(core.tag(), 10, &[0x44]);
    let response = service.handle_datagram(&request).expect("response");
    let result = context_check_response(&response, core.tag()).expect("check");
    assert!(!result.equal);
    assert_eq!(result.device_tag, device.tag());
    assert_eq!(response.len(), 4 + 1 + 1 + 1 + CONTEXT_TAG_LEN + 1);
}

#[test]
fn inspection_projects_summaries_and_rejects_mutations() {
    let active = active();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let before = active.snapshot();
    let before_runtime = before.runtime_arc();
    let request = rule_list_request(11, &[0xC1]);
    let response = Packet::from_bytes(&service.handle_datagram(&request).expect("list response"))
        .expect("response");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::Content)
    );
    let instances =
        decode_instances_with_model(service.model().composite_model(), &response.payload)
            .expect("instances");
    assert_eq!(instances.len(), 15);
    assert!(instances.iter().all(|instance| !instance
        .value
        .as_ref()
        .is_some_and(serde_json::Value::is_object)));
    assert!(instances
        .iter()
        .all(|instance| matches!(instance.path.absolute_sid(), Some(2598..=2600))));
    for (message_id, method) in [
        (12, RequestType::IPatch),
        (13, RequestType::Patch),
        (14, RequestType::Post),
        (15, RequestType::Delete),
    ] {
        let mut mutation = Packet::new();
        mutation.header.message_id = message_id;
        mutation.header.code = MessageClass::Request(method);
        mutation.header.set_type(MessageType::Confirmable);
        mutation.set_token(vec![0xC2]);
        mutation.add_option(coap_lite::CoapOption::UriPath, b"schc".to_vec());
        let mutation_response = Packet::from_bytes(
            &service
                .handle_datagram(&mutation.to_bytes().expect("mutation"))
                .expect("mutation response"),
        )
        .expect("mutation packet");
        assert_eq!(
            mutation_response.header.code,
            MessageClass::Response(ResponseType::MethodNotAllowed)
        );
        let after = active.snapshot();
        assert_eq!(before.tree(), after.tree());
        assert_eq!(before.digest(), after.digest());
        assert_eq!(before.generation(), after.generation());
        assert_eq!(before.tag(), after.tag());
        assert!(Arc::ptr_eq(&before_runtime, &after.runtime_arc()));
    }
}

#[test]
fn details_and_formatting_are_readable_and_ordered() {
    let service = InspectionService::new(active()).expect("service");
    let detail = service
        .detail(parse_rule_selector("20/8").expect("selector"))
        .expect("detail");
    let lines = format_rule_detail(&detail);
    assert!(lines[0].contains("RULE 20/8 nature=compression"));
    assert!(lines[1].contains("fid=ipv6-version") || lines[1].contains("fid-ipv6"));
    assert!(lines.iter().all(|line| !line.contains("FieldRule")));
    let list = format_rule_list(&service.summaries());
    assert!(list
        .iter()
        .any(|line| line == "RULE 20/8 nature=compression"));
    assert!(list
        .iter()
        .all(|line| !line.contains("target") && !line.contains("ENTRY")));
    assert!(parse_rule_selector("20/8").is_ok());
    assert!(service
        .detail(parse_rule_selector("20/7").expect("selector"))
        .is_err());
    let _ = SidRegistry::from_json_str(SID).expect("SID registry");
}

#[test]
fn rule_get_fetch_contains_only_selected_instance() {
    let mut service = InspectionService::new(active()).expect("service");
    let response = Packet::from_bytes(
        &service
            .handle_datagram(&rule_get_request(
                parse_rule_selector("20/8").expect("selector"),
                22,
                &[0xC2],
            ))
            .expect("response"),
    )
    .expect("packet");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::Content)
    );
    let instances =
        decode_instances_with_model(service.model().composite_model(), &response.payload)
            .expect("instances");
    assert_eq!(instances.len(), 1);
}

#[test]
fn remote_decoders_display_updated_device_rule_values() {
    let core = active();
    let mut tree = core.tree();
    tree["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        serde_json::json!("00000006");
    let prepared = PreparedContext::from_tree(
        SID,
        tree,
        DeviceId::new("management-device-updated").expect("device"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
    )
    .expect("updated context");
    let device = Arc::new(ActiveContext::new(prepared));
    let mut service = InspectionService::new(device.clone()).expect("service");
    let selector = parse_rule_selector("20/8").expect("selector");

    let list_packet = Packet::from_bytes(
        &service
            .handle_datagram(&rule_list_request(23, &[0xC1]))
            .expect("list response"),
    )
    .expect("list packet");
    let summaries = decode_rule_list_payload(&list_packet.payload, service.model()).expect("list");
    assert!(summaries.iter().any(|summary| summary.id == selector));

    let detail_packet = Packet::from_bytes(
        &service
            .handle_datagram(&rule_get_request(selector, 24, &[0xC2]))
            .expect("detail response"),
    )
    .expect("detail packet");
    let remote = decode_rule_detail_payload(
        &detail_packet.payload,
        service.model(),
        service.sid_registry(),
        service.sid_json(),
        selector,
    )
    .expect("remote detail");
    let local = InspectionService::new(core)
        .expect("core service")
        .detail(selector)
        .expect("core detail");
    assert_ne!(remote, local);
    assert_ne!(format_rule_detail(&remote), format_rule_detail(&local));
}
