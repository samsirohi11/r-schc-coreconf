//! Focused protected inspection and compact-context tests.

use std::io::Cursor;
use std::sync::Arc;

use ciborium::value::Value as CborValue;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType, ResponseType};
use coreconf_model::instance_id::{decode_instances_with_model, PathComponent};
use coreconf_runtime::coap_types::{ContentFormat, Interface, Method};
use coreconf_runtime::Datastore;
use schc_core::{RuleId, SidRegistry};
use schc_coreconf::{
    context_check_request, context_check_response, decode_rule_detail_payload,
    decode_rule_list_payload, format_rule_detail, format_rule_list, parse_rule_selector,
    parse_rule_update_command, rule_get_request, rule_list_request, ActiveContext, ContextTag,
    InspectionError, InspectionService, PreparedContext, ProtectionPolicy, RuleDetail, RuleEntry,
    CONTEXT_TAG_LEN,
};
use schc_runtime::{DeviceId, DeviceProfile};
use serde_json::Value;

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

fn target_ipatch_datagram(payload: Vec<u8>, message_id: u16) -> Vec<u8> {
    target_ipatch_datagram_with_format(payload, message_id, 142)
}

fn target_ipatch_datagram_with_format(
    payload: Vec<u8>,
    message_id: u16,
    content_format: u8,
) -> Vec<u8> {
    let mut packet = Packet::new();
    packet.header.message_id = message_id;
    packet.header.code = MessageClass::Request(RequestType::IPatch);
    packet.header.set_type(MessageType::Confirmable);
    packet.set_token(vec![0xD1]);
    packet.add_option(CoapOption::UriPath, b"schc".to_vec());
    packet.add_option(CoapOption::ContentFormat, vec![content_format]);
    packet.payload = payload;
    packet.to_bytes().expect("iPATCH datagram")
}

fn update_for(active: &Arc<ActiveContext>, command: &str) -> schc_coreconf::ResolvedRuleUpdate {
    let service = InspectionService::new(Arc::clone(active)).expect("service");
    let request = parse_rule_update_command(command).expect("request");
    let detail = service.detail(request.rule).expect("detail");
    request
        .resolve_target_value(&detail, &active.tree(), service.model())
        .expect("resolved update")
}

fn repeated_fid_detail() -> RuleDetail {
    let entry = |entry_index: usize, field_position: usize, direction: &str| RuleEntry {
        entry_index,
        fid: "fid-ipv6-appiid".into(),
        field_position,
        direction: direction.into(),
        length: "64".into(),
        target: "0x00".into(),
        matching: "equal".into(),
        cda: "not-sent".into(),
    };
    RuleDetail {
        id: parse_rule_selector("20/8").expect("selector"),
        nature: "compression".into(),
        entries: vec![entry(4, 1, "bi"), entry(9, 2, "up")],
    }
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
    let response_packet = Packet::from_bytes(&response).expect("response packet");
    assert!(response_packet
        .get_option(CoapOption::ContentFormat)
        .is_none());
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
    let request = rule_list_request(11, &[0xC1]).expect("rule-list request");
    let response = Packet::from_bytes(&service.handle_datagram(&request).expect("list response"))
        .expect("response");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::Content)
    );
    let instances =
        decode_instances_with_model(service.model().composite_model(), &response.payload)
            .expect("instances");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].path.absolute_sid(), Some(2574));
    assert!(instances[0].path.components.len() == 1);
    assert!(instances[0].value.as_ref().is_some_and(Value::is_object));
    let summaries =
        decode_rule_list_payload(&response.payload, service.model()).expect("root rule summaries");
    assert_eq!(summaries, service.summaries());
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
fn rule_list_fetch_requests_one_root_identifier_with_format_141() {
    let packet = Packet::from_bytes(&rule_list_request(21, &[0xC1]).expect("rule-list request"))
        .expect("request packet");
    assert_eq!(
        packet
            .get_option(CoapOption::ContentFormat)
            .and_then(|options| options.front()),
        Some(&vec![141])
    );
    let path = coreconf_model::instance_id::InstancePath::decode_cbor(&packet.payload)
        .expect("root identifier");
    assert_eq!(path.components, vec![PathComponent::SidDelta(2574)]);
}

#[test]
fn bare_rule_list_fetch_is_rejected_without_mutation() {
    let active = active();
    let before = active.snapshot();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let mut packet = Packet::new();
    packet.header.message_id = 22;
    packet.header.code = MessageClass::Request(RequestType::Fetch);
    packet.header.set_type(MessageType::Confirmable);
    packet.set_token(vec![0xC3]);
    packet.add_option(CoapOption::UriPath, b"schc".to_vec());
    packet.add_option(CoapOption::ContentFormat, vec![141]);
    let mut path = coreconf_model::instance_id::InstancePath::new();
    path.push_delta(2574).expect("root SID");
    path.push_delta(23).expect("rule SID delta");
    packet.payload = path.encode_cbor().expect("bare list identifier");
    let response = Packet::from_bytes(
        &service
            .handle_datagram(&packet.to_bytes().expect("request bytes"))
            .expect("response bytes"),
    )
    .expect("response packet");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::BadRequest)
    );
    let after = active.snapshot();
    assert_eq!(after.tree(), before.tree());
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.tag(), before.tag());
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
fn exact_entry_update_selects_canonical_zero_based_index() {
    let request = parse_rule_update_command("rule update 20/8 entry=9 tv=5 --if-match")
        .expect("update request");
    let service = InspectionService::new(active()).expect("service");
    assert_eq!(request.rule, parse_rule_selector("20/8").expect("selector"));
    assert_eq!(request.target_value, "5");
    assert!(request.if_match);
    assert_eq!(service.resolve_update_entry(&request).expect("entry"), 9);
}

#[test]
fn unique_human_fid_update_selects_one_entry() {
    let request = parse_rule_update_command("rule update 20/8 fid=ipv6.app-iid tv=5")
        .expect("update request");
    let service = InspectionService::new(active()).expect("service");
    assert_eq!(service.resolve_update_entry(&request).expect("entry"), 9);
}

#[test]
fn repeated_fid_uses_position_and_direction_to_disambiguate() {
    let detail = repeated_fid_detail();
    let request = parse_rule_update_command("rule update 20/8 fid=ipv6.app-iid fp=2 di=up tv=5")
        .expect("update request");
    assert_eq!(request.resolve_entry_index(&detail).expect("entry"), 9);
}

#[test]
fn resolved_update_has_exact_sid_path_and_fixed_width_wire_value() {
    let active = active();
    let service = InspectionService::new(active.clone()).expect("service");
    let request = parse_rule_update_command("rule update 20/8 fid=ipv6.app-iid tv=5")
        .expect("update request");
    let detail = service.detail(request.rule).expect("detail");
    let update = request
        .resolve_target_value(&detail, &active.tree(), service.model())
        .expect("resolved update");

    assert_eq!(update.entry_index, 9);
    assert_eq!(update.target_value_index, 0);
    assert_eq!(update.path.absolute_sid(), Some(2631));
    assert_eq!(
        update.path.components,
        vec![
            PathComponent::SidDelta(2574),
            PathComponent::SidDelta(23),
            PathComponent::KeyValue(serde_json::json!(20)),
            PathComponent::KeyValue(serde_json::json!(8)),
            PathComponent::SidDelta(23),
            PathComponent::KeyValue(serde_json::json!(9)),
            PathComponent::SidDelta(9),
            PathComponent::KeyValue(serde_json::json!(0)),
            PathComponent::SidDelta(2),
        ]
    );
    assert_eq!(update.value, serde_json::json!([0, 0, 0, 0, 0, 0, 0, 5]));

    let ipatch = update.ipatch_request().expect("iPATCH request");
    assert_eq!(ipatch.method, Method::IPatch);
    assert_eq!(ipatch.path, "");
    assert_eq!(
        ipatch.content_format,
        Some(ContentFormat::YangInstancesCborSeq)
    );
    assert_eq!(ipatch.interface, Some(Interface::Management));
    let raw: CborValue =
        ciborium::de::from_reader(Cursor::new(&ipatch.payload)).expect("raw iPATCH map");
    let CborValue::Map(raw_entries) = raw else {
        panic!("iPATCH payload is not one CBOR map");
    };
    assert_eq!(raw_entries.len(), 1);
    assert!(matches!(raw_entries[0].0, CborValue::Array(_)));
    assert_eq!(
        raw_entries[0].1,
        CborValue::Bytes(vec![0, 0, 0, 0, 0, 0, 0, 5])
    );
    let instances = decode_instances_with_model(service.model().composite_model(), &ipatch.payload)
        .expect("iPATCH instances");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].path, update.path);
    assert_eq!(instances[0].value, Some(update.value.clone()));
}

#[test]
fn ipatch_datagram_builder_emits_exact_optional_if_match_option() {
    let active = active();
    let default_update = update_for(&active, "rule update 20/8 entry=9 tv=6");
    let default_packet = Packet::from_bytes(
        &default_update
            .ipatch_datagram(50, &[0xD0], None)
            .expect("default datagram"),
    )
    .expect("default packet");
    assert_eq!(
        default_packet.header.code,
        MessageClass::Request(RequestType::IPatch)
    );
    assert_eq!(
        default_packet
            .get_option(CoapOption::UriPath)
            .expect("URI path")
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        vec![b"schc".as_slice()]
    );
    assert!(default_packet.get_option(CoapOption::IfMatch).is_none());
    assert_eq!(
        default_packet.payload,
        default_update.ipatch_payload().expect("payload")
    );

    let tagged_update = update_for(&active, "rule update 20/8 entry=9 tv=6 --if-match");
    let tag = active.tag();
    let tagged_packet = Packet::from_bytes(
        &tagged_update
            .ipatch_datagram(51, &[0xD1], Some(tag))
            .expect("tagged datagram"),
    )
    .expect("tagged packet");
    let if_match = tagged_packet
        .get_option(CoapOption::IfMatch)
        .expect("If-Match")
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(if_match, vec![&tag.bytes().to_vec()]);
    assert_eq!(
        tagged_packet.payload,
        tagged_update.ipatch_payload().expect("payload")
    );
    assert!(tagged_update.ipatch_request().is_err());
    assert!(tagged_update.ipatch_datagram(52, &[0xD2], None).is_err());
    assert!(default_update
        .ipatch_datagram(53, &[0xD3], Some(tag))
        .is_err());
}

#[test]
fn detached_update_changes_only_requested_target_value() {
    let active = active();
    assert_eq!(
        active.tree()["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
        "AAAAAAAAAAU="
    );
    let service = InspectionService::new(active.clone()).expect("service");
    let request =
        parse_rule_update_command("rule update 20/8 entry=9 tv=6").expect("update request");
    let detail = service.detail(request.rule).expect("detail");
    let update = request
        .resolve_target_value(&detail, &active.tree(), service.model())
        .expect("resolved update");
    let instances = decode_instances_with_model(
        service.model().composite_model(),
        &update.ipatch_payload().expect("iPATCH payload"),
    )
    .expect("iPATCH instances");
    let identifier_value = service
        .model()
        .composite_model()
        .sid_value_to_identifier_value_at_path(
            instances[0].value.clone().expect("replacement value"),
            "/ietf-schc:schc/rule/entry/target-value/value",
        )
        .expect("identifier value");

    let before = active.tree();
    assert_eq!(
        before["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
        "AAAAAAAAAAU="
    );
    let mut expected = before.clone();
    expected["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"] =
        identifier_value;
    assert_ne!(before, expected);
    assert_eq!(
        expected["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
        "AAAAAAAAAAY="
    );

    let mut candidate =
        Datastore::with_data(service.model().clone(), before).expect("candidate datastore");
    let instance = &instances[0];
    let sid = instance.path.absolute_sid().expect("target SID");
    let keys = instance
        .path
        .components
        .iter()
        .filter_map(|component| match component {
            PathComponent::KeyValue(value) => Some(value.clone()),
            PathComponent::SidDelta(_) => None,
        })
        .collect::<Vec<_>>();
    let xpath = candidate.create_xpath(sid, &keys).expect("target xpath");
    let value = service
        .model()
        .composite_model()
        .sid_value_to_identifier_value_at_path(
            instance.value.clone().expect("replacement value"),
            "/ietf-schc:schc/rule/entry/target-value/value",
        )
        .expect("candidate identifier value");
    candidate
        .set_path(&xpath, value)
        .expect("set candidate value");
    assert_eq!(candidate.get_all(), expected);
}

#[test]
fn device_ipatch_requires_instance_sequence_content_format_without_publication() {
    let active = active();
    let before = active.snapshot();
    let before_runtime = before.runtime_arc();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6");
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");

    let rejected = Packet::from_bytes(
        &service
            .handle_datagram(&target_ipatch_datagram_with_format(
                update.ipatch_payload().expect("payload"),
                59,
                140,
            ))
            .expect("response"),
    )
    .expect("response packet");
    assert_eq!(
        rejected.header.code,
        MessageClass::Response(ResponseType::BadRequest)
    );
    let unchanged = active.snapshot();
    assert_eq!(unchanged.tree(), before.tree());
    assert_eq!(unchanged.sor(), before.sor());
    assert_eq!(unchanged.generation(), before.generation());
    assert_eq!(unchanged.digest(), before.digest());
    assert_eq!(unchanged.tag(), before.tag());
    assert!(Arc::ptr_eq(&unchanged.runtime_arc(), &before_runtime));

    let accepted = Packet::from_bytes(
        &service
            .handle_datagram(&target_ipatch_datagram_with_format(
                update.ipatch_payload().expect("payload"),
                60,
                142,
            ))
            .expect("response"),
    )
    .expect("response packet");
    assert_eq!(
        accepted.header.code,
        MessageClass::Response(ResponseType::Changed)
    );
    assert_eq!(active.generation(), before.generation() + 1);
    assert_ne!(active.tag(), before.tag());
}

#[test]
fn device_ipatch_publishes_one_valid_target_update_and_keeps_inspection_live() {
    let active = active();
    let before = active.snapshot();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6");
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");
    let response = Packet::from_bytes(
        &service
            .handle_datagram(
                &update
                    .ipatch_datagram(60, &[0xD1], None)
                    .expect("default datagram"),
            )
            .expect("response"),
    )
    .expect("response packet");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::Changed)
    );
    let after = active.snapshot();
    assert_eq!(after.generation(), before.generation() + 1);
    assert_ne!(after.digest(), before.digest());
    assert_ne!(after.tag(), before.tag());
    assert_ne!(after.sor(), before.sor());
    assert_eq!(
        after.tree()["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
        "AAAAAAAAAAY="
    );
    assert_eq!(
        service
            .detail(parse_rule_selector("20/8").expect("selector"))
            .expect("updated detail")
            .id,
        parse_rule_selector("20/8").expect("selector")
    );
    let inspect = service
        .handle_datagram(
            &rule_get_request(parse_rule_selector("20/8").expect("selector"), 61, &[0xD2])
                .expect("rule-get request"),
        )
        .expect("inspection response");
    assert_eq!(
        Packet::from_bytes(&inspect)
            .expect("inspection packet")
            .header
            .code,
        MessageClass::Response(ResponseType::Content)
    );
}

#[test]
fn device_ipatch_accepts_current_if_match_tag_and_publishes_once() {
    let active = active();
    let before = active.snapshot();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6 --if-match");
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");
    let response = Packet::from_bytes(
        &service
            .handle_datagram(
                &update
                    .ipatch_datagram(65, &[0xD4], Some(before.tag()))
                    .expect("tagged datagram"),
            )
            .expect("response"),
    )
    .expect("response packet");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::Changed)
    );
    let after = active.snapshot();
    assert_eq!(after.generation(), before.generation() + 1);
    assert_ne!(after.tag(), before.tag());
    assert_eq!(
        after.tree()["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
        "AAAAAAAAAAY="
    );
}

#[test]
fn device_ipatch_rejects_stale_if_match_without_publication() {
    let active = active();
    let before = active.snapshot();
    let before_runtime = before.runtime_arc();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6 --if-match");
    let mut stale_bytes = before.tag().bytes();
    stale_bytes[0] ^= 0xff;
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");
    let response = Packet::from_bytes(
        &service
            .handle_datagram(
                &update
                    .ipatch_datagram(66, &[0xD5], Some(ContextTag::new(stale_bytes)))
                    .expect("stale datagram"),
            )
            .expect("response"),
    )
    .expect("response packet");
    assert_eq!(
        response.header.code,
        MessageClass::Response(ResponseType::PreconditionFailed)
    );
    let after = active.snapshot();
    assert_eq!(after.tree(), before.tree());
    assert_eq!(after.sor(), before.sor());
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.digest(), before.digest());
    assert_eq!(after.tag(), before.tag());
    assert!(Arc::ptr_eq(&after.runtime_arc(), &before_runtime));
}

#[test]
fn device_ipatch_rejects_malformed_and_duplicate_if_match_atomically() {
    let active = active();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6 --if-match");
    let valid_datagram = update
        .ipatch_datagram(67, &[0xD6], Some(active.tag()))
        .expect("tagged datagram");
    let mut malformed = Packet::from_bytes(&valid_datagram).expect("packet");
    malformed.clear_option(CoapOption::IfMatch);
    malformed.add_option(CoapOption::IfMatch, vec![0; CONTEXT_TAG_LEN - 1]);
    let malformed_datagram = malformed.to_bytes().expect("malformed datagram");

    let mut duplicate = Packet::from_bytes(&valid_datagram).expect("packet");
    duplicate.add_option(CoapOption::IfMatch, active.tag().bytes().to_vec());
    let duplicate_datagram = duplicate.to_bytes().expect("duplicate datagram");

    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");
    for datagram in [malformed_datagram, duplicate_datagram] {
        let before = active.snapshot();
        let before_runtime = before.runtime_arc();
        let response = Packet::from_bytes(&service.handle_datagram(&datagram).expect("response"))
            .expect("response packet");
        assert_eq!(
            response.header.code,
            MessageClass::Response(ResponseType::BadRequest)
        );
        let after = active.snapshot();
        assert_eq!(after.tree(), before.tree());
        assert_eq!(after.sor(), before.sor());
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.digest(), before.digest());
        assert_eq!(after.tag(), before.tag());
        assert!(Arc::ptr_eq(&after.runtime_arc(), &before_runtime));
    }
}

#[test]
fn device_ipatch_rejects_invalid_values_paths_and_multiple_operations_atomically() {
    let active = active();
    let update = update_for(&active, "rule update 20/8 entry=9 tv=6");
    let baseline = active.snapshot();
    let baseline_tree = baseline.tree().clone();
    let baseline_sor = baseline.sor().to_vec();
    let baseline_runtime = baseline.runtime_arc();
    let baseline_generation = baseline.generation();
    let baseline_digest = baseline.digest();
    let baseline_tag = baseline.tag();
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");

    let mut invalid_value: CborValue =
        ciborium::de::from_reader(Cursor::new(update.ipatch_payload().expect("payload")))
            .expect("raw payload");
    let CborValue::Map(entries) = &mut invalid_value else {
        panic!("expected map");
    };
    entries[0].1 = CborValue::Bytes(vec![6]);
    let mut invalid_value_payload = Vec::new();
    ciborium::ser::into_writer(&invalid_value, &mut invalid_value_payload).expect("encode");

    let mut malformed_path: CborValue =
        ciborium::de::from_reader(Cursor::new(update.ipatch_payload().expect("payload")))
            .expect("raw payload");
    let CborValue::Map(entries) = &mut malformed_path else {
        panic!("expected map");
    };
    let CborValue::Array(path) = &mut entries[0].0 else {
        panic!("expected path");
    };
    *path.last_mut().expect("leaf delta") = CborValue::Integer(3_i64.into());
    let mut malformed_path_payload = Vec::new();
    ciborium::ser::into_writer(&malformed_path, &mut malformed_path_payload).expect("encode");

    let mut delete_payload: CborValue =
        ciborium::de::from_reader(Cursor::new(update.ipatch_payload().expect("payload")))
            .expect("raw payload");
    let CborValue::Map(entries) = &mut delete_payload else {
        panic!("expected map");
    };
    entries[0].1 = CborValue::Null;
    let mut delete_payload_bytes = Vec::new();
    ciborium::ser::into_writer(&delete_payload, &mut delete_payload_bytes).expect("encode");

    for payload in [
        invalid_value_payload,
        malformed_path_payload,
        delete_payload_bytes,
        {
            let mut multiple = update.ipatch_payload().expect("payload");
            multiple.extend(update.ipatch_payload().expect("payload"));
            multiple
        },
    ] {
        let response = Packet::from_bytes(
            &service
                .handle_datagram(&target_ipatch_datagram(payload, 62))
                .expect("response"),
        )
        .expect("response packet");
        assert!(matches!(
            response.header.code,
            MessageClass::Response(ResponseType::BadRequest | ResponseType::Conflict)
        ));
        let current = active.snapshot();
        assert_eq!(current.tree(), &baseline_tree);
        assert_eq!(current.sor(), baseline_sor.as_slice());
        assert_eq!(current.generation(), baseline_generation);
        assert_eq!(current.digest(), baseline_digest);
        assert_eq!(current.tag(), baseline_tag);
        assert!(Arc::ptr_eq(&current.runtime_arc(), &baseline_runtime));
    }
}

#[test]
fn device_ipatch_rejects_both_configured_protected_rule_ids_without_publication() {
    let active = active();
    let mut service = InspectionService::new(Arc::clone(&active)).expect("service");
    for (message_id, command) in [
        (63, "rule update 16/8 entry=0 tv=6"),
        (64, "rule update 17/8 entry=0 tv=6"),
    ] {
        let before = active.snapshot();
        let before_runtime = before.runtime_arc();
        let update = if command.starts_with("rule update 16/8") {
            let mut update = update_for(&active, "rule update 20/8 entry=9 tv=6");
            update.path.components[2] = PathComponent::KeyValue(serde_json::json!(16));
            update.path.components[3] = PathComponent::KeyValue(serde_json::json!(8));
            update
        } else {
            let mut update = update_for(&active, "rule update 20/8 entry=9 tv=6");
            update.path.components[2] = PathComponent::KeyValue(serde_json::json!(17));
            update.path.components[3] = PathComponent::KeyValue(serde_json::json!(8));
            update
        };
        let response = Packet::from_bytes(
            &service
                .handle_datagram(&target_ipatch_datagram(
                    update.ipatch_payload().expect("payload"),
                    message_id,
                ))
                .expect("response"),
        )
        .expect("response packet");
        assert_eq!(
            response.header.code,
            MessageClass::Response(ResponseType::Conflict)
        );
        let after = active.snapshot();
        assert_eq!(after.tree(), before.tree());
        assert_eq!(after.sor(), before.sor());
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.digest(), before.digest());
        assert_eq!(after.tag(), before.tag());
        assert!(Arc::ptr_eq(&after.runtime_arc(), &before_runtime));
    }
}

#[test]
fn target_value_conversion_rejects_invalid_or_out_of_range_values() {
    let active = active();
    let service = InspectionService::new(active.clone()).expect("service");
    let detail = service
        .detail(parse_rule_selector("20/8").expect("selector"))
        .expect("detail");
    for command in [
        "rule update 20/8 entry=9 tv=not-a-number",
        "rule update 20/8 entry=9 tv=18446744073709551616",
        "rule update 20/8 entry=0 tv=16",
    ] {
        let request = parse_rule_update_command(command).expect("request");
        let error = request
            .resolve_target_value(&detail, &active.tree(), service.model())
            .expect_err("invalid target value");
        assert!(
            matches!(error, InspectionError::InvalidTarget(_)),
            "{command} produced {error:?}"
        );
    }
}

#[test]
fn no_match_reports_rule_identity_and_selector() {
    let detail = repeated_fid_detail();
    let request =
        parse_rule_update_command("rule update 20/8 fid=ipv6.tclass tv=5").expect("request");
    let error = request
        .resolve_entry_index(&detail)
        .expect_err("missing entry");
    assert!(matches!(error, InspectionError::MissingEntry { .. }));
    assert_eq!(
        error.to_string(),
        "RuleID 20/8 has no entry matching fid=ipv6.tclass"
    );
}

#[test]
fn ambiguous_human_fid_reports_readable_matching_entries() {
    let detail = repeated_fid_detail();
    let request =
        parse_rule_update_command("rule update 20/8 fid=ipv6.app-iid tv=5").expect("request");
    let error = request.resolve_entry_index(&detail).expect_err("ambiguous");
    let InspectionError::AmbiguousEntry {
        matches,
        readable_matches,
        ..
    } = &error
    else {
        panic!("expected ambiguous entry, got {error:?}");
    };
    assert_eq!(
        matches
            .iter()
            .map(|entry| entry.entry_index)
            .collect::<Vec<_>>(),
        [4, 9]
    );
    assert!(readable_matches.contains("ENTRY 4 fid=fid-ipv6-appiid"));
    assert!(readable_matches.contains("ENTRY 9 fid=fid-ipv6-appiid"));
    assert!(error.to_string().contains("RuleID 20/8"));
}

#[test]
fn malformed_update_commands_fail_clearly() {
    for (command, expected) in [
        ("rule update 20/8 entry=4", "exactly one 'tv' is required"),
        ("rule update 20/8 entry=4 tv=5 tv=6", "duplicate 'tv'"),
        (
            "rule update 20/8 entry=4 fid=ipv6.app-iid tv=5",
            "cannot be combined",
        ),
        ("rule update 20/8 fp=1 tv=5", "require a fid"),
        (
            "rule update 20/8 fid=ipv6.app-iid di=sideways tv=5",
            "di must be",
        ),
        ("rule update 20/8 entry=-1 tv=5", "entry must be"),
        (
            "rule update 20/8 entry=4 tv=5 unknown=1",
            "unknown update argument",
        ),
        (
            "rule update 20/8 entry=4 tv=5 --if-match --if-match",
            "duplicate",
        ),
    ] {
        let error = parse_rule_update_command(command).expect_err("malformed command");
        assert!(
            error.to_string().contains(expected),
            "{command:?} produced {error}, expected {expected:?}"
        );
    }
}

#[test]
fn rule_get_fetch_contains_only_selected_instance() {
    let mut service = InspectionService::new(active()).expect("service");
    let request = rule_get_request(parse_rule_selector("20/8").expect("selector"), 22, &[0xC2])
        .expect("rule-get request");
    let request_packet = Packet::from_bytes(&request).expect("request packet");
    assert_eq!(
        request_packet
            .get_option(CoapOption::ContentFormat)
            .and_then(|options| options.front()),
        Some(&vec![141])
    );
    let request_value: Value = ciborium::de::from_reader(Cursor::new(&request_packet.payload))
        .expect("request identifier");
    let request_path = coreconf_model::instance_id::InstancePath::from_cbor_value_with_model(
        &request_value,
        service.model().composite_model(),
    )
    .expect("request path");
    assert_eq!(
        request_path.components,
        vec![
            PathComponent::SidDelta(2574),
            PathComponent::SidDelta(23),
            PathComponent::KeyValue(serde_json::json!(20)),
            PathComponent::KeyValue(serde_json::json!(8)),
        ]
    );
    let response =
        Packet::from_bytes(&service.handle_datagram(&request).expect("response")).expect("packet");
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
            .handle_datagram(&rule_list_request(23, &[0xC1]).expect("rule-list request"))
            .expect("list response"),
    )
    .expect("list packet");
    let summaries = decode_rule_list_payload(&list_packet.payload, service.model()).expect("list");
    assert!(summaries.iter().any(|summary| summary.id == selector));

    let detail_packet = Packet::from_bytes(
        &service
            .handle_datagram(&rule_get_request(selector, 24, &[0xC2]).expect("rule-get request"))
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
