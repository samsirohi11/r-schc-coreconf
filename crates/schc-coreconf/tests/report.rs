//! Focused packet-report and modeled RPC accounting coverage.

use std::net::Ipv6Addr;
use std::sync::Arc;

use schc_coreconf::{
    context_check_request, format_report, inspect_report, parse_rule_duplicate_command,
    protected_management_rule_ids, ActiveContext, CoapMessage, CoapOption, FlowChange,
    FlowDirection, Ipv6UdpCoapPacket, Ipv6UdpPacket, LinkRole, PacketMetadata, PacketReport,
    PreparedContext, ProtectionPolicy, ReportDirection, RuleAllocationPolicy, SchcLink,
    TrafficOrigin, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};
use schc_runtime::{DeviceId, DeviceProfile};
use serde_json::{json, Value};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");
const GENERIC_SID: &str =
    include_str!("../../../fixtures/generic-ipv6-udp/ietf-schc@2026-05-07.sid");
const GENERIC_SOR: &[u8] = include_bytes!("../../../fixtures/generic-ipv6-udp/initial.sor");

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

fn generic_context_active() -> Arc<ActiveContext> {
    Arc::new(ActiveContext::new(
        PreparedContext::from_sor_with_policy(
            GENERIC_SID,
            GENERIC_SOR,
            DeviceId::new("generic-report-test").expect("device ID"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .expect("generic IPv6/UDP context"),
    ))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
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

const FIRST_FLOW_TARGETS: [(usize, &str); 7] = [
    (2, "0"),
    (6, "2306139568115548160"),
    (7, "1"),
    (8, "2306139568115548160"),
    (9, "2"),
    (10, "5683"),
    (11, "5683"),
];

fn first_flow_command(destination: usize, count: usize) -> String {
    use std::fmt::Write as _;

    let mut command = format!("rule duplicate 20/8 {destination}/8");
    for &(entry_index, target_value) in FIRST_FLOW_TARGETS.iter().take(count) {
        write!(command, " entry={entry_index} tv={target_value}")
            .expect("String writes cannot fail");
    }
    command
}

fn generic_flow_packet(count: usize, payload: &[u8]) -> Ipv6UdpPacket {
    let base = Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 9);
    let destination = match count {
        0 | 1 => base,
        2 => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9),
        _ => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    };
    let source = if count <= 3 {
        base
    } else {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
    };
    let (source_port, destination_port) = if count >= 7 {
        (5683, 5683)
    } else {
        (5684, 5684)
    };
    let flow_label = u32::from(count == 0);
    Ipv6UdpPacket::new(
        PacketMetadata::new(
            source,
            destination,
            source_port,
            destination_port,
            0,
            flow_label,
            64,
        ),
        payload,
    )
    .expect("generic logical packet")
}

fn transition_packet(count: usize, payload: &[u8]) -> Ipv6UdpPacket {
    let source = if count >= 5 {
        Ipv6Addr::new(0x2001, 0xdb7, 0, 0, 0, 0, 0, 7)
    } else {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
    };
    let destination = if count >= 3 {
        Ipv6Addr::new(0x2001, 0xdb7, 0, 0, 0, 0, 0, 7)
    } else if count >= 2 {
        Ipv6Addr::new(0x2001, 0xdb7, 0, 0, 0, 0, 0, 1)
    } else {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    };
    let source_port = 5683;
    let destination_port = 5683;
    let flow_label = 2;
    let traffic_class = 0;
    let hop_limit = 64;
    Ipv6UdpPacket::new(
        PacketMetadata::new(
            source,
            destination,
            source_port,
            destination_port,
            traffic_class,
            flow_label,
            hop_limit,
        ),
        payload,
    )
    .expect("transition logical packet")
}

fn logical_header(packet: &Ipv6UdpPacket) -> Value {
    json!({
        "source": packet.source().to_string(),
        "destination": packet.destination().to_string(),
        "traffic_class": packet.traffic_class(),
        "flow_label": packet.flow_label(),
        "hop_limit": packet.hop_limit(),
        "source_port": packet.source_port(),
        "destination_port": packet.destination_port(),
    })
}

fn install_first_flow(service: &mut schc_coreconf::InspectionService) {
    let packet = generic_flow_packet(7, b"payload");
    let FlowChange::Duplicate { request, .. } = service
        .flow_change(
            &packet,
            FlowDirection::Downlink,
            RuleAllocationPolicy::default(),
        )
        .expect("first flow change")
    else {
        panic!("first flow must create a concrete rule");
    };
    let datagram = service
        .duplicate_rule_datagram(&request, 200)
        .expect("first duplicate datagram");
    assert!(service
        .handle_datagram_no_response(&datagram)
        .expect("first local management apply")
        .is_none());
}

fn duplicate_vector(count: usize, expected_indices: &[usize]) -> Value {
    let active = generic_context_active();
    let mut service =
        schc_coreconf::InspectionService::new(Arc::clone(&active)).expect("inspection service");
    let packet = if count == 7 {
        generic_flow_packet(7, b"payload")
    } else {
        install_first_flow(&mut service);
        transition_packet(count, b"payload")
    };
    let change = service
        .flow_change(
            &packet,
            FlowDirection::Downlink,
            RuleAllocationPolicy::default(),
        )
        .unwrap_or_else(|error| panic!("flow change for {count}: {error}"));
    let FlowChange::Duplicate { request, .. } = change else {
        panic!("flow with {count} changes must create a concrete rule: {change:?}");
    };
    assert_eq!(
        request
            .overrides
            .iter()
            .map(|item| item.entry_index)
            .collect::<Vec<_>>(),
        expected_indices,
        "selected parent {}",
        request.source
    );
    let message_id = 100_u16 + u16::try_from(count).expect("test count fits u16");
    let datagram = service
        .duplicate_rule_datagram(&request, message_id)
        .expect("duplicate datagram");
    let management_packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &datagram,
    )
    .expect("management logical packet");
    let logical_packet =
        Ipv6UdpPacket::parse(management_packet.as_bytes()).expect("management IPv6/UDP packet");
    let encoded = SchcLink::new(active, LinkRole::Core)
        .encode(TrafficOrigin::Management, &management_packet)
        .expect("management frame");
    let report = inspect_report(encoded.report()).expect("report accounting");
    let rpc = report.rpc.expect("duplicate RPC details");
    json!({
        "case": format!("{count}_changed_entries"),
        "changed_entries": count,
        "parent_rule_id": request.source.to_string(),
        "destination_rule_id": request.destination.to_string(),
        "changed_entry_indices": request.overrides.iter().map(|item| item.entry_index).collect::<Vec<_>>(),
        "overrides": request.overrides.iter().map(|item| json!({
            "entry_index": item.entry_index,
            "target_value": item.target_value,
        })).collect::<Vec<_>>(),
        "coreconf_datagram_bytes": datagram.len(),
        "coreconf_datagram_hex": hex(&datagram),
        "logical_ipv6_udp": logical_header(&logical_packet),
        "logical_ipv6_udp_hex": hex(management_packet.as_bytes()),
        "schc_frame_hex": hex(encoded.frame().bytes()),
        "payload_bytes": rpc.payload_bytes,
        "meaningful_bits": encoded.frame().bit_len(),
        "transmitted_bytes": encoded.frame().bytes().len(),
    })
}

fn steady_vectors() -> Vec<Value> {
    let core_active = generic_context_active();
    let device_active = generic_context_active();
    let mut core_service = schc_coreconf::InspectionService::new(Arc::clone(&core_active))
        .expect("core inspection service");
    let mut device_service = schc_coreconf::InspectionService::new(Arc::clone(&device_active))
        .expect("device inspection service");
    install_first_flow(&mut core_service);
    install_first_flow(&mut device_service);
    let first_packet = generic_flow_packet(7, b"payload");
    let first_request = core_service
        .flow_change(
            &first_packet,
            FlowDirection::Downlink,
            RuleAllocationPolicy::default(),
        )
        .expect("first installed flow remains stable");
    assert!(matches!(first_request, FlowChange::AlreadyMatches { .. }));
    let first_packet = generic_flow_packet(7, b"payload");
    let core_before_second = SchcLink::new(Arc::clone(&core_active), LinkRole::Core);
    let device_before_second = SchcLink::new(Arc::clone(&device_active), LinkRole::Device);
    let first_flow = core_before_second
        .encode_bytes(TrafficOrigin::Application, first_packet.as_bytes())
        .expect("first application frame");
    let first_result = device_before_second
        .decode_bytes(first_flow.frame().bytes())
        .expect("first application decode");
    assert_eq!(first_result.packet(), first_packet.as_bytes());

    let changed_packet = transition_packet(1, b"payload");
    let FlowChange::Duplicate { request, .. } = core_service
        .flow_change(
            &changed_packet,
            FlowDirection::Downlink,
            RuleAllocationPolicy::default(),
        )
        .expect("field-change flow")
    else {
        panic!("field change must create a second concrete rule");
    };
    let datagram = core_service
        .duplicate_rule_datagram(&request, 1)
        .expect("field-change datagram");
    let packet = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &datagram,
    )
    .expect("field-change management packet");
    let management_frame = core_before_second
        .encode(TrafficOrigin::Management, &packet)
        .expect("field-change management frame");
    let arrival = device_before_second
        .decode(management_frame.frame().bytes())
        .expect("field-change management decode");
    assert!(core_service
        .handle_datagram_no_response(&datagram)
        .expect("field-change local apply")
        .is_none());
    assert!(device_service
        .handle_datagram_no_response(arrival.packet().coap_datagram())
        .expect("field-change remote apply")
        .is_none());

    let core = SchcLink::new(core_active, LinkRole::Core);
    let device = SchcLink::new(device_active, LinkRole::Device);
    [
        ("first_after_install", first_packet),
        ("repeated", generic_flow_packet(7, b"payload")),
        ("field_change", changed_packet),
    ]
    .into_iter()
    .map(|(case, packet)| {
        let encoded = core
            .encode_bytes(TrafficOrigin::Application, packet.as_bytes())
            .expect("steady application encode");
        let decoded = device
            .decode_bytes(encoded.frame().bytes())
            .expect("steady application decode");
        assert_eq!(decoded.packet(), packet.as_bytes());
        json!({
            "case": case,
            "logical_ipv6_udp": logical_header(&packet),
            "payload_length": packet.udp_payload().len(),
            "payload_hex": hex(packet.udp_payload()),
            "logical_ipv6_udp_hex": hex(packet.as_bytes()),
            "matched_rule_id": format!("{}/{}", encoded.report().rule_id.value(), encoded.report().rule_id.bit_len()),
            "schc_frame_hex": hex(encoded.frame().bytes()),
            "meaningful_bits": encoded.frame().bit_len(),
            "transmitted_bytes": encoded.frame().bytes().len(),
        })
    })
    .collect()
}

fn generated_vectors() -> Value {
    let duplicate_rule = [
        (1, vec![2]),
        (2, vec![2, 6]),
        (3, vec![2, 6, 7]),
        (5, vec![2, 6, 7, 8, 9]),
        (7, vec![2, 6, 7, 8, 9, 10, 11]),
    ]
    .into_iter()
    .map(|(count, indices)| duplicate_vector(count, &indices))
    .collect::<Vec<_>>();
    json!({
        "schema_version": 1,
        "context": "context.json",
        "duplicate_rule": duplicate_rule,
        "steady_data": steady_vectors(),
    })
}

#[test]
fn generic_vectors_match_real_library_generation() {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/generic-ipv6-udp/vectors.json"
    ))
    .expect("generic vector fixture");
    assert_eq!(generated_vectors(), expected);
}

#[test]
fn duplicate_report_measurements_cover_1_2_3_5_7_overrides() {
    let cases = [
        (1, &[2][..], 38, 331, 42),
        (2, &[2, 6][..], 62, 523, 66),
        (3, &[2, 6, 7][..], 85, 707, 89),
        (5, &[2, 6, 7, 8, 9][..], 131, 1075, 135),
        (7, &[2, 6, 7, 8, 9, 10, 11][..], 165, 1347, 169),
    ];
    let mut mismatches = Vec::new();
    for (count, expected_indices, expected_payload, expected_bits, expected_transmitted) in cases {
        let message_id = 100_u16 + u16::try_from(count).expect("test count fits u16");
        let report = report_for(&first_flow_command(40 + count, count), message_id);
        let rpc = report.rpc.expect("duplicate RPC details");
        let indices = rpc
            .overrides
            .iter()
            .map(|override_| override_.entry_index)
            .collect::<Vec<_>>();
        assert_eq!(rpc.overrides.len(), count);
        assert_eq!(indices, expected_indices);
        let actual = (
            rpc.payload_bytes,
            report.schc.meaningful_bits,
            report.schc.padded_bytes,
        );
        if actual != (expected_payload, expected_bits, expected_transmitted) {
            mismatches.push(format!(
                "{count} overrides: expected ({expected_payload}, {expected_bits}, {expected_transmitted}), actual {actual:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "measurement mismatches:\n{}",
        mismatches.join("\n")
    );
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
