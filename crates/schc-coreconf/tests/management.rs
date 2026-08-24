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
    decode_rule_list_payload, format_rule_detail, format_rule_list, is_duplicate_rule_request,
    parse_rule_duplicate_command, parse_rule_selector, parse_rule_update_command,
    prepare_management_request, protected_management_rule_ids, rule_get_request, rule_list_request,
    temporary_ordinary_response, validate_management_response, ActiveContext, ContextTag,
    InspectionError, InspectionService, Ipv6UdpCoapPacket, LinkDecoded, LinkRole, PreparedContext,
    PreparedManagementRequest, ProtectionPolicy, RuleDetail, RuleEntry, SchcLink, TrafficOrigin,
    APPLICATION_PORT, CONTEXT_TAG_LEN, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
    MANAGEMENT_PORT,
};
use schc_runtime::{DeviceId, DeviceProfile};
use serde_json::Value;

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

fn active() -> Arc<ActiveContext> {
    let prepared = PreparedContext::from_sor_with_policy(
        SID,
        SOR,
        DeviceId::new("management-test-device").expect("device"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
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

fn prepared_response_fixture() -> (
    PreparedManagementRequest,
    LinkDecoded,
    SchcLink,
    SchcLink,
    Vec<u8>,
) {
    let core = active();
    let device = active();
    let core_link = SchcLink::new(Arc::clone(&core), LinkRole::Core);
    let device_link = SchcLink::new(Arc::clone(&device), LinkRole::Device);
    let mut service = InspectionService::new(device).expect("service");
    let request_datagram = rule_list_request(21, &[]).expect("request");
    let prepared = prepare_management_request(&core_link, &request_datagram).expect("prepare");
    let decoded_request = device_link
        .decode(prepared.frame().bytes())
        .expect("decode request");
    let response_datagram = service
        .handle_datagram(decoded_request.packet().coap_datagram())
        .expect("management response");
    let response_packet = Ipv6UdpCoapPacket::new(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &response_datagram,
    )
    .expect("response packet");
    let encoded_response = device_link
        .encode(TrafficOrigin::Management, &response_packet)
        .expect("encode response");
    let decoded_response = core_link
        .decode(encoded_response.frame().bytes())
        .expect("decode response");
    (
        prepared,
        decoded_response,
        core_link,
        device_link,
        response_datagram,
    )
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
fn prepared_management_request_validates_a_transport_neutral_exchange() {
    let core = active();
    let device = active();
    let core_link = SchcLink::new(Arc::clone(&core), LinkRole::Core);
    let device_link = SchcLink::new(Arc::clone(&device), LinkRole::Device);
    let mut service = InspectionService::new(Arc::clone(&device)).expect("service");
    let request_datagram = rule_list_request(21, &[]).expect("request");

    let prepared = prepare_management_request(&core_link, &request_datagram).expect("prepare");
    assert!(matches!(
        prepared.report().rule_id.value(),
        16 | 26 | 27 | 28
    ));
    assert_eq!(prepared.report().frame_bytes, prepared.frame().bytes());
    let decoded_request = device_link
        .decode(prepared.frame().bytes())
        .expect("decode request");
    let response_datagram = service
        .handle_datagram(decoded_request.packet().coap_datagram())
        .expect("management response");
    let response_packet = Ipv6UdpCoapPacket::new(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &response_datagram,
    )
    .expect("response packet");
    let encoded_response = device_link
        .encode(TrafficOrigin::Management, &response_packet)
        .expect("encode response");
    assert_eq!(encoded_response.report().rule_id.value(), 17);
    assert_eq!(encoded_response.report().rule_id.bit_len(), 8);
    let decoded_response = core_link
        .decode(encoded_response.frame().bytes())
        .expect("decode response");
    let (response_code, exchange) =
        validate_management_response(&prepared, &decoded_response).expect("validate response");

    assert_eq!(response_code, 69);
    assert_eq!(
        exchange.payload,
        Packet::from_bytes(&response_datagram)
            .expect("CoAP")
            .payload
    );
    assert_eq!(exchange.request_report, *prepared.report());
    assert_eq!(exchange.response_report, *decoded_response.report());
    assert_eq!(exchange.request_report.rule_id, prepared.report().rule_id);
    assert_eq!(
        exchange.response_report.rule_id,
        schc_core::RuleId::new(17, 8)
    );
    assert_eq!(
        exchange.request_report.packet_bytes,
        decoded_request.report().packet_bytes
    );
    assert_eq!(
        exchange.response_report.frame_bytes,
        encoded_response.frame().bytes()
    );
}

#[test]
fn validator_rejects_a_decoded_ordinary_application_response() {
    let (prepared, _, core, device, _) = prepared_response_fixture();
    let mut request = Packet::new();
    request.header.message_id = 0x1001;
    request.header.code = MessageClass::Request(RequestType::Get);
    request.header.set_type(MessageType::Confirmable);
    request.set_token(vec![0xaa]);
    request.add_option(CoapOption::UriPath, b"demo".to_vec());
    request.payload = b"demo".to_vec();
    let request = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &request.to_bytes().expect("application request"),
    )
    .expect("application packet");
    let request_frame = core
        .encode(TrafficOrigin::Application, &request)
        .expect("encode application request");
    let decoded_request = device
        .decode(request_frame.frame().bytes())
        .expect("decode application request");
    let response =
        temporary_ordinary_response(decoded_request.packet()).expect("application response");
    let response_frame = device
        .encode(TrafficOrigin::Application, &response)
        .expect("encode application response");
    let decoded_response = core
        .decode(response_frame.frame().bytes())
        .expect("decode application response");
    assert_eq!(
        decoded_response.route(),
        schc_coreconf::TrafficRoute::Application
    );
    assert_eq!(decoded_response.rule_id(), RuleId::new(21, 8));

    let error = validate_management_response(&prepared, &decoded_response)
        .expect_err("ordinary response must be rejected");
    let expected = format!(
        "management response selected {:?} instead of protected 17/8",
        RuleId::new(21, 8)
    );
    assert!(matches!(error, InspectionError::UnexpectedResponse(message) if message == expected));
}

#[test]
fn validator_rejects_a_decoded_protected_request_rule() {
    let (prepared, _, core, device, _) = prepared_response_fixture();
    let request_datagram = context_check_request(active().tag(), 22, &[]);
    let request = prepare_management_request(&core, &request_datagram).expect("prepare request");
    assert_eq!(request.report().rule_id, RuleId::new(16, 8));
    let decoded_request = device
        .decode(request.frame().bytes())
        .expect("decode protected request");
    assert_eq!(decoded_request.rule_id(), RuleId::new(16, 8));

    let error = validate_management_response(&prepared, &decoded_request)
        .expect_err("request rule must be rejected");
    let expected = format!(
        "management response selected {:?} instead of protected 17/8",
        RuleId::new(16, 8)
    );
    assert!(matches!(error, InspectionError::UnexpectedResponse(message) if message == expected));
}

#[test]
fn validator_rejects_a_production_decoded_response_with_wrong_mid() {
    let (prepared, _, core, device, mut response_datagram) = prepared_response_fixture();
    response_datagram[2..4].copy_from_slice(&22_u16.to_be_bytes());
    let response = Ipv6UdpCoapPacket::new(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &response_datagram,
    )
    .expect("wrong MID packet");
    let encoded = device
        .encode(TrafficOrigin::Management, &response)
        .expect("encode wrong MID response");
    assert_eq!(encoded.report().rule_id, RuleId::new(17, 8));
    let decoded = core
        .decode(encoded.frame().bytes())
        .expect("decode wrong MID response");
    let error =
        validate_management_response(&prepared, &decoded).expect_err("wrong MID must be rejected");
    assert!(matches!(
        error,
        InspectionError::Correlation(message) if message == "CoAP message ID or token mismatch"
    ));
}

#[test]
fn validator_rejects_a_production_decoded_response_with_wrong_token() {
    let (prepared, _, core, device, mut response_datagram) = prepared_response_fixture();
    // The production response has a zero-length token. Add one directly to
    // the serialized CoAP header so this test does not rely on reserializing
    // the large modeled response through coap_lite.
    response_datagram[0] = (response_datagram[0] & 0xf0) | 1;
    response_datagram.insert(4, 0x7f);
    let response = Ipv6UdpCoapPacket::new(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &response_datagram,
    )
    .expect("wrong token packet");
    let encoded = device.encode(TrafficOrigin::Management, &response);
    match encoded {
        Ok(encoded) => {
            // The fixture permits this token as residue; validate the real
            // RuleID 17/8 decode rather than fabricating LinkDecoded internals.
            assert_eq!(encoded.report().rule_id, RuleId::new(17, 8));
            let decoded = core
                .decode(encoded.frame().bytes())
                .expect("decode wrong token response");
            let error = validate_management_response(&prepared, &decoded)
                .expect_err("wrong token must be rejected");
            assert!(matches!(
                error,
                InspectionError::Correlation(message) if message == "CoAP message ID or token mismatch"
            ));
        }
        Err(error) => {
            // Rule 17/8 fixes the token to zero length, so production codec
            // rejection is the strongest evidence this token cannot pass.
            assert!(matches!(error, schc_coreconf::LinkError::Runtime(_)));
        }
    }
}

#[test]
fn protected_response_rule_cannot_encode_wrong_orientation_or_management_ports() {
    // Rule 17/8 fixes these fields, so production decoding cannot yield a
    // malformed 17/8 packet; validator checks remain defense in depth.
    let (_, _, _, device, datagram) = prepared_response_fixture();
    for (source, destination, source_port, destination_port, description) in [
        (
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            MANAGEMENT_PORT,
            "orientation",
        ),
        (
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            APPLICATION_PORT,
            MANAGEMENT_PORT,
            "source port",
        ),
        (
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            APPLICATION_PORT,
            "destination port",
        ),
    ] {
        let response = Ipv6UdpCoapPacket::new(
            source,
            destination,
            source_port,
            destination_port,
            &datagram,
        )
        .expect("invalid protected response packet");
        let encoded = device.encode(TrafficOrigin::Management, &response);
        assert!(
            encoded.is_err(),
            "wrong {description} must not produce an accepted protected response"
        );
    }
}

#[test]
fn prepared_management_request_excludes_compact_duplicate_rule() {
    let active = active();
    let service = InspectionService::new(Arc::clone(&active)).expect("service");
    let default_update = update_for(&active, "rule update 20/8 entry=9 tv=2");
    let conditional_update = update_for(&active, "rule update 20/8 entry=9 tv=2 --if-match");
    let requests = [
        (context_check_request(active.tag(), 1, &[]), 16),
        (rule_list_request(2, &[]).expect("inspection request"), 26),
        (
            default_update
                .ipatch_datagram(3, &[], None)
                .expect("default update"),
            27,
        ),
        (
            conditional_update
                .ipatch_datagram(4, &[], Some(active.tag()))
                .expect("conditional update"),
            28,
        ),
    ];
    let link = SchcLink::new(Arc::clone(&active), LinkRole::Core);
    for (datagram, expected_rule) in requests {
        let prepared = prepare_management_request(&link, &datagram).expect("prepare request");
        assert_eq!(
            prepared.report().rule_id,
            schc_core::RuleId::new(expected_rule, 8)
        );
    }

    let request = parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
        .expect("duplicate request");
    let datagram = service
        .duplicate_rule_datagram(&request, 37)
        .expect("duplicate datagram");
    let link = SchcLink::new(active, LinkRole::Core);
    let error = prepare_management_request(&link, &datagram).expect_err("duplicate rejected");
    assert!(matches!(
        error,
        InspectionError::UnexpectedResponse(message)
            if message == "management request selected unsupported protected RuleID 29/8"
    ));
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
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
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
    assert!(request_packet.get_token().is_empty());
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
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
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
    assert_eq!(response.len(), 4 + 1 + 1 + CONTEXT_TAG_LEN + 1);
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
    assert!(packet.get_token().is_empty());
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
    assert!(default_packet.get_token().is_empty());
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
    assert!(tagged_packet.get_token().is_empty());
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
#[allow(clippy::too_many_lines)]
fn duplicate_rule_is_modeled_atomic_and_idempotent_without_response() {
    let active = active();
    let before = active.snapshot();
    let source_before = before.tree()["ietf-schc:schc"]["rule"][2].clone();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
            .expect("duplicate request");
    let mut base_request = request.clone();
    base_request.overrides.clear();
    let base_payload = service
        .duplicate_rule_payload(&base_request)
        .expect("base duplicate payload");
    assert_eq!(base_payload.len(), 19);
    println!(
        "DUPLICATE_FIXED_RPC_PAYLOAD_BYTES={} HEX={}",
        base_payload.len(),
        hex(&base_payload)
    );
    let datagram = service
        .duplicate_rule_datagram(&request, 37)
        .expect("duplicate datagram");
    let packet = Packet::from_bytes(&datagram).expect("duplicate packet");
    assert_eq!(packet.payload.len(), 43);
    println!("DUPLICATE_RPC_PAYLOAD_HEX={}", hex(&packet.payload));
    println!("DUPLICATE_COAP_HEX={}", hex(&datagram));
    let logical = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &datagram,
    )
    .expect("logical duplicate packet");
    println!(
        "DUPLICATE_LOGICAL_IPV6_UDP_COAP_HEX={}",
        hex(logical.as_bytes())
    );
    let encoded = SchcLink::new(active.clone(), LinkRole::Core)
        .encode(TrafficOrigin::Management, &logical)
        .expect("duplicate SCHC frame");
    let breakdown = schc_coreconf::management_bit_breakdown(encoded.report()).expect("breakdown");
    println!("DUPLICATE_FRAME_HEX={}", hex(encoded.frame().bytes()));
    println!(
        "DUPLICATE_FRAME_BITS={} DUPLICATE_FRAME_BYTES={} DUPLICATE_PACKET_BYTES={}",
        encoded.frame().bit_len(),
        encoded.frame().bytes().len(),
        logical.as_bytes().len()
    );
    assert_eq!(logical.as_bytes().len(), 103);
    assert_eq!(encoded.frame().bit_len(), 371);
    assert_eq!(encoded.frame().bytes().len(), 47);
    assert_eq!(breakdown.rule_id_bits, 8);
    assert_eq!(breakdown.mid_residue_bits, 7);
    assert_eq!(breakdown.method_or_response_mapping_bits, 0);
    assert_eq!(breakdown.payload_length_bits, 12);
    assert_eq!(breakdown.payload_bits, 344);
    assert_eq!(breakdown.byte_padding_bits, 5);
    assert_eq!(breakdown.unaccounted_residue_bits, 0);
    let mut residue_report = encoded.report().clone();
    residue_report.schc_bit_len = Some(372);
    assert!(schc_coreconf::management_bit_breakdown(&residue_report).is_err());
    assert_eq!(breakdown.transport_residue_bits(), 15);
    println!("DUPLICATE_BREAKDOWN rule_id_bits={} mid_residue_bits={} method_bits={} payload_length_bits={} payload_bits={} padding_bits={}", breakdown.rule_id_bits, breakdown.mid_residue_bits, breakdown.method_or_response_mapping_bits, breakdown.payload_length_bits, breakdown.payload_bits, breakdown.byte_padding_bits);
    assert_eq!(packet.header.code, MessageClass::Request(RequestType::Post));
    assert_eq!(packet.header.get_type(), MessageType::NonConfirmable);
    assert!(packet.get_token().is_empty());
    assert_eq!(
        packet
            .get_option(CoapOption::ContentFormat)
            .unwrap()
            .front(),
        Some(&vec![142])
    );
    assert!(service
        .handle_datagram_no_response(&datagram)
        .expect("duplicate processing")
        .is_none());
    let after = active.snapshot();
    assert_eq!(after.generation(), before.generation() + 1);
    assert_eq!(after.tree()["ietf-schc:schc"]["rule"][2], source_before);
    assert_eq!(
        service
            .detail(parse_rule_selector("22/8").expect("destination"))
            .expect("destination detail")
            .entries
            .iter()
            .find(|entry| entry.entry_index == 9)
            .unwrap()
            .target,
        "0x0000000000000002"
    );
    let generation = active.generation();
    assert!(service
        .handle_datagram_no_response(&datagram)
        .expect("replay processing")
        .is_none());
    assert_eq!(active.generation(), generation);
    let multiple = schc_coreconf::parse_rule_duplicate_command(
        "rule duplicate 20/8 23/8 entry=9 tv=2 mo=equal cda=not-sent",
    )
    .unwrap();
    let multiple_datagram = service.duplicate_rule_datagram(&multiple, 38).unwrap();
    assert!(service
        .handle_datagram_no_response(&multiple_datagram)
        .unwrap()
        .is_none());
    assert_eq!(active.generation(), generation + 1);
}

#[test]
fn duplicate_rule_rejects_modeled_output_before_publication() {
    let active = active();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
            .expect("duplicate request");
    let datagram = service.duplicate_rule_datagram(&request, 44).unwrap();
    let mut packet = Packet::from_bytes(&datagram).expect("duplicate packet");
    let mut payload: CborValue =
        ciborium::de::from_reader(Cursor::new(&packet.payload)).expect("RPC payload");
    let CborValue::Map(root) = &mut payload else {
        panic!("RPC root is not a map");
    };
    let (_, operation) = root
        .iter_mut()
        .find(|(key, _)| *key == CborValue::Integer(2680.into()))
        .expect("duplicate-rule root");
    let CborValue::Map(operation) = operation else {
        panic!("duplicate-rule operation is not a map");
    };
    operation.push((
        CborValue::Integer(2.into()),
        CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer(0.into()),
        )]),
    ));
    packet.payload.clear();
    ciborium::ser::into_writer(&payload, &mut packet.payload).expect("malformed RPC payload");
    let malformed = packet.to_bytes().expect("malformed duplicate datagram");
    let before = active.snapshot();
    let source_before = before.tree()["ietf-schc:schc"]["rule"][2].clone();
    assert!(service.handle_datagram_no_response(&malformed).is_err());
    let after = active.snapshot();
    assert_eq!(after.tree(), before.tree());
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.tag(), before.tag());
    assert_eq!(after.tree()["ietf-schc:schc"]["rule"][2], source_before);
    assert!(service
        .detail(parse_rule_selector("22/8").expect("destination"))
        .is_err());
}

#[test]
fn duplicate_rule_dispatch_requires_exact_rule_29() {
    let active = active();
    let service = InspectionService::new(active).expect("service");
    let request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
            .expect("duplicate request");
    let datagram = service.duplicate_rule_datagram(&request, 45).unwrap();
    let packet = Packet::from_bytes(&datagram).expect("duplicate packet");
    assert!(is_duplicate_rule_request(RuleId::new(29, 8), &packet));
    assert!(!is_duplicate_rule_request(RuleId::new(28, 8), &packet));
}

#[test]
fn duplicate_rule_udp_port_override_preserves_binary_width_and_replays_idempotently() {
    let active = active();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let source = parse_rule_selector("20/8").expect("source");
    let request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 23/8 entry=10 tv=5683")
            .expect("duplicate request");
    let source_before = service.detail(source).expect("source detail");
    let datagram = service.duplicate_rule_datagram(&request, 46).unwrap();
    let packet = Packet::from_bytes(&datagram).expect("duplicate packet");
    assert!(hex(&packet.payload).contains("421633"));
    assert!(service
        .handle_datagram_no_response(&datagram)
        .expect("install")
        .is_none());
    let generation = active.generation();
    assert_eq!(service.detail(source).expect("source after"), source_before);
    let destination = service
        .detail(parse_rule_selector("23/8").expect("destination"))
        .expect("destination detail");
    assert_eq!(
        destination
            .entries
            .iter()
            .find(|entry| entry.entry_index == 10)
            .expect("UDP device-port entry")
            .target,
        "0x1633"
    );
    assert!(service
        .handle_datagram_no_response(&datagram)
        .expect("idempotent replay")
        .is_none());
    assert_eq!(active.generation(), generation);
}

#[test]
fn duplicate_rule_parser_supports_multiple_groups_and_rejects_incomplete_forms() {
    let request = schc_coreconf::parse_rule_duplicate_command(
        "rule duplicate 20/8 22/8 entry=9 tv=2 mo=equal cda=not-sent entry=10 cda=value-sent",
    )
    .expect("duplicate parser");
    assert_eq!(request.source, parse_rule_selector("20/8").unwrap());
    assert_eq!(request.destination, parse_rule_selector("22/8").unwrap());
    assert_eq!(request.overrides.len(), 2);
    assert_eq!(request.overrides[0].entry_index, 9);
    assert_eq!(request.overrides[0].target_value.as_deref(), Some("2"));
    assert_eq!(request.overrides[1].cda.as_deref(), Some("value-sent"));
    for command in [
        "rule duplicate 20/8",
        "rule duplicate 20/8 22/8 tv=2",
        "rule duplicate 20/8 22/8 entry=9",
        "rule duplicate 20/8 22/8 entry=9 tv=2 tv=3",
        "rule duplicate 20/8 22/8 entry=9 unknown=x",
        "rule duplicate 20/8 22/8 entry=9 tv=2 entry=9 cda=not-sent",
    ] {
        assert!(
            schc_coreconf::parse_rule_duplicate_command(command).is_err(),
            "{command}"
        );
    }
}

#[test]
fn duplicate_rule_rejects_conflicts_and_invalid_operations_without_publication() {
    let active = active();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let before = active.snapshot();
    for command in [
        "rule duplicate 16/8 22/8 entry=0 tv=2",
        "rule duplicate 20/8 22/8 entry=999 tv=2",
        "rule duplicate 20/8 22/8 entry=9 tv=not-a-number",
        "rule duplicate 20/8 22/8 entry=9 mo=not-an-operator",
        "rule duplicate 20/8 22/8 entry=9 cda=not-an-action",
    ] {
        let request = schc_coreconf::parse_rule_duplicate_command(command).expect("syntax");
        assert!(
            service.duplicate_rule_datagram(&request, 40).is_err(),
            "{command}"
        );
        let after = active.snapshot();
        assert_eq!(after.tree(), before.tree(), "{command}");
        assert_eq!(after.generation(), before.generation(), "{command}");
    }
    let conflict_request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 21/8 entry=9 tv=2")
            .unwrap();
    let conflict_datagram = service
        .duplicate_rule_datagram(&conflict_request, 40)
        .unwrap();
    assert!(service
        .handle_datagram_no_response(&conflict_datagram)
        .is_err());
    assert_eq!(active.generation(), before.generation());

    let valid =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
            .unwrap();
    let datagram = service.duplicate_rule_datagram(&valid, 41).unwrap();
    service.handle_datagram_no_response(&datagram).unwrap();
    let installed = active.snapshot();
    let generation = installed.generation();
    let mut conflict =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=3")
            .unwrap();
    conflict.overrides[0].target_value = Some("3".into());
    let conflict_datagram = service.duplicate_rule_datagram(&conflict, 42).unwrap();
    assert!(service
        .handle_datagram_no_response(&conflict_datagram)
        .is_err());
    assert_eq!(active.generation(), generation);
    assert_eq!(active.snapshot().tree(), installed.tree());
}

#[test]
fn duplicate_rule_rejects_trailing_inner_value_without_mutation() {
    let active = active();
    let mut service = InspectionService::new(active.clone()).expect("service");
    let request =
        schc_coreconf::parse_rule_duplicate_command("rule duplicate 20/8 22/8 entry=9 tv=2")
            .unwrap();
    let datagram = service.duplicate_rule_datagram(&request, 43).unwrap();
    let mut packet = Packet::from_bytes(&datagram).unwrap();
    packet.payload.push(0);
    let malformed = packet.to_bytes().unwrap();
    let before = active.snapshot();
    assert!(service.handle_datagram_no_response(&malformed).is_err());
    let after = active.snapshot();
    assert_eq!(after.tree(), before.tree());
    assert_eq!(after.generation(), before.generation());
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
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
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
