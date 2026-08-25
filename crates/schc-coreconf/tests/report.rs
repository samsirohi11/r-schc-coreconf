//! Focused packet-report and modeled RPC accounting coverage.

use std::sync::Arc;

use schc_coreconf::{
    context_check_request, format_report, inspect_report, parse_rule_duplicate_command,
    protected_management_rule_ids, ActiveContext, CoapMessage, CoapOption, Ipv6UdpCoapPacket,
    LinkRole, PacketReport, PreparedContext, ProtectionPolicy, ReportDirection, SchcLink,
    TrafficOrigin, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};
use schc_runtime::{DeviceId, DeviceProfile};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn active() -> Arc<ActiveContext> {
    Arc::new(ActiveContext::new(
        PreparedContext::from_sor_with_policy(
            SID,
            SOR,
            DeviceId::new("report-test").expect("device ID"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .expect("context"),
    ))
}

fn duplicate_packet(command: &str, message_id: u16) -> (SchcLink, Ipv6UdpCoapPacket) {
    let active = active();
    let service = schc_coreconf::InspectionService::new(active.clone()).expect("service");
    let request = parse_rule_duplicate_command(command).expect("duplicate command");
    let datagram = service
        .duplicate_rule_datagram(&request, message_id)
        .expect("duplicate datagram");
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &datagram,
    )
    .expect("logical packet");
    (SchcLink::new(active, LinkRole::Core), packet)
}

fn report_for(command: &str, message_id: u16) -> PacketReport {
    let (link, packet) = duplicate_packet(command, message_id);
    let encoded = link
        .encode(TrafficOrigin::Management, &packet)
        .expect("management packet encodes");
    inspect_report(encoded.report()).expect("report accounting")
}

#[test]
fn duplicate_report_has_exact_three_part_rpc_cost() {
    let report = report_for("rule duplicate 20/8 22/8 entry=9 tv=2", 37);
    assert_eq!(
        report.layers.packet_bytes,
        report.layers.ipv6_header_bytes
            + report.layers.udp_header_bytes
            + report.layers.coap.total_bytes
    );
    let rpc = report.rpc.expect("duplicate RPC details");
    assert_eq!(rpc.payload_bytes, 43);
    assert_eq!(rpc.fixed_bytes, 19);
    assert_eq!(rpc.variable_framing_bytes, 16);
    assert_eq!(rpc.target_value_bytes, 8);
    assert_eq!(
        rpc.fixed_bytes + rpc.variable_framing_bytes + rpc.target_value_bytes,
        rpc.payload_bytes
    );
    assert_eq!(rpc.overrides[0].target_value.as_deref(), Some("2"));
}

#[test]
fn rpc_costs_cover_empty_multiple_and_identity_only_overrides() {
    for (message_id, command) in [
        (1, "rule duplicate 20/8 22/8"),
        (
            2,
            "rule duplicate 20/8 23/8 entry=9 tv=2 mo=equal cda=not-sent entry=10 cda=value-sent",
        ),
        (3, "rule duplicate 20/8 23/8 entry=9 mo=equal cda=not-sent"),
        (4, "rule duplicate 20/8 23/8 entry=10 tv=5683"),
    ] {
        let report = report_for(command, message_id);
        let rpc = report.rpc.expect("duplicate RPC details");
        assert_eq!(
            rpc.fixed_bytes + rpc.variable_framing_bytes + rpc.target_value_bytes,
            rpc.payload_bytes,
            "cost sum for {command}"
        );
        assert_eq!(
            report.layers.coap.payload_bytes, rpc.payload_bytes,
            "RPC remains inside CoAP payload for {command}"
        );
    }
}

fn option_cost(number: u32, value_len: usize) -> schc_coreconf::CoapOptionCost {
    let link = SchcLink::new(active(), LinkRole::Core);
    let message = CoapMessage::from_parts(
        1,
        0,
        1,
        9,
        Vec::new(),
        vec![CoapOption::new(number, vec![7; value_len]).expect("option")],
        Vec::new(),
    )
    .expect("message")
    .to_vec();
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        5683,
        5683,
        &message,
    )
    .expect("packet");
    let encoded = link
        .encode(TrafficOrigin::Application, &packet)
        .expect("application packet encodes");
    inspect_report(encoded.report())
        .expect("report")
        .layers
        .coap
        .options
        .into_iter()
        .next()
        .expect("one option")
}

#[test]
fn coap_option_cost_fields_are_additive_for_all_extension_shapes() {
    for (number, value_len, expected_delta, expected_length) in [
        (11, 4, 0, 0),
        (13, 0, 1, 0),
        (269, 0, 2, 0),
        (11, 13, 0, 1),
        (11, 269, 0, 2),
        (300, 270, 2, 2),
    ] {
        let option = option_cost(number, value_len);
        assert_eq!(option.header_bytes, 1);
        assert_eq!(option.delta_extension_bytes, expected_delta);
        assert_eq!(option.length_extension_bytes, expected_length);
        assert_eq!(
            option.header_bytes
                + option.delta_extension_bytes
                + option.length_extension_bytes
                + option.value_bytes,
            option.encoded_bytes,
            "option {number}/{value_len}"
        );
    }
    let both_extended = option_cost(300, 270);
    assert_eq!(both_extended.encoded_bytes, 275);
}

#[test]
fn regular_formatting_skips_protocol_and_rpc_inspection() {
    let active = active();
    let link = SchcLink::new(active, LinkRole::Core);
    let message = CoapMessage::from_parts(1, 0, 1, 7, Vec::new(), Vec::new(), Vec::new())
        .expect("message")
        .to_vec();
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        5683,
        5683,
        &message,
    )
    .expect("packet");
    let encoded = link
        .encode(TrafficOrigin::Application, &packet)
        .expect("application packet encodes");
    let mut invalid = encoded.report().clone();
    invalid.packet_bytes.fill(0);
    let regular = format_report(ReportDirection::Tx, &invalid, false).expect("regular");
    assert!(regular.starts_with("TX APP"));
    assert!(format_report(ReportDirection::Tx, &invalid, true).is_err());
}

#[test]
fn non_duplicate_management_debug_has_generic_payload_only() {
    let active = active();
    let link = SchcLink::new(active.clone(), LinkRole::Core);
    let coap = context_check_request(active.snapshot().tag(), 7, &[]);
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap,
    )
    .expect("packet");
    let encoded = link
        .encode(TrafficOrigin::Management, &packet)
        .expect("management packet encodes");
    let debug = format_report(ReportDirection::Tx, encoded.report(), true).expect("debug");
    assert!(debug.contains("payload"));
    assert!(!debug.contains("duplicate-rule"));
    assert!(!debug.contains("fixed"));
}

#[test]
fn malformed_duplicate_debug_fails_instead_of_claiming_a_split() {
    let active = active();
    let link = SchcLink::new(active, LinkRole::Core);
    let options = vec![
        CoapOption::new(11, b"schc".to_vec()).expect("path"),
        CoapOption::new(12, vec![142]).expect("format"),
    ];
    let message = CoapMessage::from_parts(1, 1, 2, 7, Vec::new(), options, vec![0xa0])
        .expect("message")
        .to_vec();
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &message,
    )
    .expect("packet");
    let encoded = link
        .encode(TrafficOrigin::Management, &packet)
        .expect("management packet encodes");
    let regular = format_report(ReportDirection::Tx, encoded.report(), false).expect("regular");
    assert!(regular.starts_with("TX MGMT  29/8  "));
    let error = format_report(ReportDirection::Tx, encoded.report(), true)
        .expect_err("malformed duplicate must fail debug reporting");
    assert!(error.to_string().contains("duplicate-rule"));
}

#[test]
fn formatter_is_concise_and_debug_has_no_wire_hex() {
    let (link, packet) = duplicate_packet("rule duplicate 20/8 22/8 entry=9 tv=2", 37);
    let encoded = link
        .encode(TrafficOrigin::Management, &packet)
        .expect("management packet encodes");
    let regular = format_report(ReportDirection::Tx, encoded.report(), false).expect("regular");
    let report = inspect_report(encoded.report()).expect("report accounting");
    assert_eq!(
        regular,
        format!(
            "TX MGMT  29/8  {} B -> {} B\n",
            report.layers.packet_bytes, report.schc.padded_bytes
        )
    );
    assert!(!regular.contains("packet_bytes"));
    let debug = format_report(ReportDirection::Tx, encoded.report(), true).expect("debug");
    assert!(debug.starts_with(&regular));
    assert!(!debug.contains("packet_hex"));
    assert!(!debug.contains("frame_hex"));
    assert!(!debug.contains("600000"));
    assert!(debug.contains("IPv6"));
    assert!(debug.contains("RPC"));
    assert!(debug.contains("fixed                        19 B"));
}
