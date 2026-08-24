//! Coverage for the real raw UDP SCHC link and rule-derived routing.

use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use coreconf_model::instance_id::{encode_identifiers, InstancePath};
use schc_core::{RuleId, SidRegistry};
use schc_coreconf::{
    context_check_request, management_bit_breakdown, protected_management_rule_ids,
    rule_get_request, rule_list_request, temporary_ordinary_response, ActiveContext,
    GenericDataService, Ipv6UdpCoapPacket, LinkRole, PreparedContext, ProtectionPolicy, RawUdpLink,
    SchcLink, TrafficClass, TrafficOrigin, TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS,
    DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};
use schc_runtime::{DeviceId, DeviceProfile};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn active(name: &str) -> Arc<ActiveContext> {
    Arc::new(ActiveContext::new(
        PreparedContext::from_sor_with_policy(
            SID,
            SOR,
            DeviceId::new(name).expect("device ID"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .expect("initial context"),
    ))
}

fn coap(
    message_type: u8,
    code: u8,
    message_id: u16,
    token: &[u8],
    option: Option<&[u8]>,
) -> Vec<u8> {
    let options = option.map_or_else(Vec::new, |value| {
        vec![schc_coreconf::CoapOption::new(11, value.to_vec()).expect("CoAP option")]
    });
    schc_coreconf::CoapMessage::from_parts(
        1,
        message_type,
        code,
        message_id,
        token.to_vec(),
        options,
        Vec::new(),
    )
    .expect("CoAP")
    .to_vec()
}

fn packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    message: &[u8],
) -> Ipv6UdpCoapPacket {
    Ipv6UdpCoapPacket::new(source, destination, source_port, destination_port, message)
        .expect("logical packet")
}

#[test]
fn ordinary_request_and_response_reconstruct_exactly_with_reports() {
    let core = SchcLink::new(active("core-ordinary"), LinkRole::Core);
    let device = SchcLink::new(active("device-ordinary"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 0x1001, &[0xaa], Some(b"demo")),
    );
    let encoded = core
        .encode(TrafficOrigin::Application, &request)
        .expect("ordinary request encodes");
    assert_eq!(encoded.report().rule_id, RuleId::new(25, 8));
    assert_eq!(encoded.report().traffic_class, TrafficClass::Ordinary);
    assert_eq!(encoded.report().packet_bytes, request.as_bytes());
    assert_eq!(encoded.report().frame_bytes, encoded.frame().bytes());
    assert_eq!(encoded.report().packet_size, request.as_bytes().len());
    assert_eq!(
        encoded.report().padded_byte_len,
        encoded.frame().bytes().len()
    );
    assert_eq!(
        encoded.report().schc_bit_len,
        Some(encoded.frame().bit_len())
    );
    assert!(
        encoded.report().compression_ratio().expect("request ratio") < 1.0,
        "the initial request uses the ordinary fallback RuleID"
    );

    let decoded = device
        .decode(encoded.frame().bytes())
        .expect("ordinary request decodes");
    assert_eq!(decoded.rule_id(), RuleId::new(25, 8));
    assert_eq!(decoded.route(), TrafficRoute::Application);
    assert_eq!(decoded.packet().as_bytes(), request.as_bytes());
    assert_eq!(decoded.report().packet_bytes, request.as_bytes());
    assert_eq!(decoded.report().frame_bytes, encoded.frame().bytes());
    assert_eq!(decoded.report().traffic_class, TrafficClass::Ordinary);
    assert_eq!(decoded.report().schc_bit_len, encoded.report().schc_bit_len);

    let response = temporary_ordinary_response(decoded.packet()).expect("response");
    assert_eq!(response.source(), request.destination());
    assert_eq!(response.destination(), request.source());
    assert_eq!(response.source_port(), request.destination_port());
    assert_eq!(response.destination_port(), request.source_port());
    assert_eq!(
        response.coap_message().message_id(),
        request.coap_message().message_id()
    );
    assert_eq!(
        response.coap_message().token(),
        request.coap_message().token()
    );
    assert!(response.coap_message().payload().is_empty());
    let content_formats = response
        .coap_message()
        .options()
        .iter()
        .filter(|option| option.number() == 12)
        .map(|option| option.value().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(content_formats, vec![vec![142]]);
    let response_frame = device
        .encode(TrafficOrigin::Application, &response)
        .expect("ordinary response encodes");
    assert_eq!(response_frame.report().rule_id, RuleId::new(21, 8));
    assert!(
        response_frame
            .report()
            .compression_ratio()
            .expect("response ratio")
            < 1.0
    );
    let reconstructed = core
        .decode(response_frame.frame().bytes())
        .expect("ordinary response decodes");
    assert_eq!(reconstructed.rule_id(), RuleId::new(21, 8));
    assert_eq!(reconstructed.route(), TrafficRoute::Application);
    assert_eq!(reconstructed.packet().as_bytes(), response.as_bytes());
    assert_eq!(
        reconstructed.report().schc_bit_len,
        response_frame.report().schc_bit_len
    );
    assert_eq!(reconstructed.packet().coap_message().message_id(), 0x1001);
    assert_eq!(reconstructed.packet().coap_message().token(), &[0xaa]);
}

#[test]
fn protected_rules_authorize_management_and_application_origin_cannot_impersonate_it() {
    let core = SchcLink::new(active("core-management"), LinkRole::Core);
    let device = SchcLink::new(active("device-management"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(0, 5, 1, &[], Some(b"schc")),
    );
    let encoded = core
        .encode(TrafficOrigin::Management, &request)
        .expect("management request encodes");
    assert_eq!(encoded.report().rule_id, RuleId::new(16, 8));
    let decoded = device
        .decode(encoded.frame().bytes())
        .expect("management request decodes");
    assert_eq!(decoded.route(), TrafficRoute::ProtectedManagement);
    assert_eq!(decoded.traffic_class(), TrafficClass::ProtectedManagement);
    assert_eq!(decoded.packet().as_bytes(), request.as_bytes());

    let response = packet(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(2, 69, 1, &[], None),
    );
    let response_frame = device
        .encode(TrafficOrigin::Management, &response)
        .expect("management response encodes");
    assert_eq!(response_frame.report().rule_id, RuleId::new(17, 8));
    let core_response = core
        .decode(response_frame.frame().bytes())
        .expect("management response decodes");
    assert_eq!(core_response.route(), TrafficRoute::ProtectedManagement);

    let application = core.encode(TrafficOrigin::Application, &request);
    assert!(
        application.is_err(),
        "application origin must not select a protected management RuleID"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn current_management_shapes_round_trip_with_complete_bit_accounting() {
    let core = SchcLink::new(active("core-management-measurement"), LinkRole::Core);
    let device = SchcLink::new(active("device-management-measurement"), LinkRole::Device);

    let request_packet = |datagram: Vec<u8>| {
        packet(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            MANAGEMENT_PORT,
            &datagram,
        )
    };
    let response_packet = |code: u8, message_id: u16, payload: &[u8]| {
        packet(
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            MANAGEMENT_PORT,
            &schc_coreconf::CoapMessage::from_parts(
                1,
                2,
                code,
                message_id,
                Vec::new(),
                Vec::new(),
                payload.to_vec(),
            )
            .expect("management response CoAP")
            .to_vec(),
        )
    };
    let assert_report = |report: &schc_coreconf::LinkReport,
                         expected_rule: RuleId,
                         expected_packet: usize,
                         expected_bits: usize,
                         expected_padded: usize| {
        assert_eq!(report.rule_id, expected_rule);
        assert_eq!(report.packet_bytes.len(), report.packet_size);
        assert_eq!(report.packet_size, expected_packet);
        assert_eq!(report.frame_bytes.len(), report.padded_byte_len);
        assert_eq!(report.padded_byte_len, expected_padded);
        assert_eq!(report.schc_bit_len, Some(expected_bits));
        assert!(report.schc_bit_len.expect("meaningful bits") <= report.padded_byte_len * 8);
        let breakdown = management_bit_breakdown(report).expect("management bit breakdown");
        assert_eq!(breakdown.rule_id_bits, 8);
        assert_eq!(breakdown.mid_residue_bits, 7);
        assert_eq!(
            breakdown.transport_residue_bits(),
            15 + breakdown.method_or_response_mapping_bits
        );
        assert_eq!(breakdown.unaccounted_residue_bits, 0);
        assert_eq!(
            report.schc_bit_len.expect("meaningful bits"),
            breakdown.rule_id_bits
                + breakdown.method_or_response_mapping_bits
                + breakdown.mid_residue_bits
                + breakdown.payload_bits
                + breakdown.payload_length_bits
                + breakdown.option_residue_bits
        );
    };

    let requests = [
        (
            "context check",
            context_check_request(core.active_context().tag(), 1, &[0xaa]),
            RuleId::new(16, 8),
            67,
            91,
            12,
        ),
        (
            "rule list",
            rule_list_request(2, &[0xaa]).expect("rule list request"),
            RuleId::new(26, 8),
            63,
            43,
            6,
        ),
        (
            "rule detail",
            rule_get_request(
                schc_coreconf::parse_rule_selector("20/8").expect("selector"),
                3,
                &[0xaa],
            )
            .expect("rule detail request"),
            RuleId::new(26, 8),
            67,
            75,
            10,
        ),
        (
            "rule update",
            schc_coreconf::CoapMessage::from_parts(
                1,
                0,
                7,
                4,
                Vec::new(),
                vec![
                    schc_coreconf::CoapOption::new(11, b"schc".to_vec()).expect("URI"),
                    schc_coreconf::CoapOption::new(12, vec![142]).expect("format"),
                ],
                vec![0; 22],
            )
            .expect("update request CoAP")
            .to_vec(),
            RuleId::new(27, 8),
            82,
            203,
            26,
        ),
        (
            "rule update with If-Match",
            schc_coreconf::CoapMessage::from_parts(
                1,
                0,
                7,
                5,
                Vec::new(),
                vec![
                    schc_coreconf::CoapOption::new(1, vec![0; 8]).expect("If-Match"),
                    schc_coreconf::CoapOption::new(11, b"schc".to_vec()).expect("URI"),
                    schc_coreconf::CoapOption::new(12, vec![142]).expect("format"),
                ],
                vec![0; 22],
            )
            .expect("tagged update request CoAP")
            .to_vec(),
            RuleId::new(28, 8),
            91,
            267,
            34,
        ),
    ];
    for (label, datagram, expected_rule, expected_packet, expected_bits, expected_padded) in
        requests
    {
        let request = request_packet(datagram);
        assert!(request.coap_message().token().is_empty(), "{label} token");
        let encoded = core
            .encode(TrafficOrigin::Management, &request)
            .unwrap_or_else(|error| panic!("{label} encode failed: {error}"));
        assert_report(
            encoded.report(),
            expected_rule,
            expected_packet,
            expected_bits,
            expected_padded,
        );
        let decoded = device
            .decode(encoded.frame().bytes())
            .unwrap_or_else(|error| panic!("{label} decode failed: {error}"));
        assert_eq!(
            decoded.packet().as_bytes(),
            request.as_bytes(),
            "{label} packet"
        );
        assert_eq!(
            decoded.report().frame_bytes,
            encoded.report().frame_bytes,
            "{label} frame"
        );
        assert_report(
            decoded.report(),
            expected_rule,
            expected_packet,
            expected_bits,
            expected_padded,
        );
    }

    for (label, response, expected_payload, expected_mapping_bits) in [
        (
            "content",
            response_packet(69, 6, b"content"),
            7_usize,
            4_usize,
        ),
        ("changed", response_packet(68, 7, b""), 0, 4),
        ("error", response_packet(128, 8, b"error"), 5, 4),
    ] {
        let encoded = device
            .encode(TrafficOrigin::Management, &response)
            .unwrap_or_else(|error| panic!("{label} response encode failed: {error}"));
        let (expected_packet, expected_bits, expected_padded) = match label {
            "content" => (60, 79, 10),
            "changed" => (52, 23, 3),
            "error" => (58, 63, 8),
            _ => unreachable!("known response shape"),
        };
        assert_report(
            encoded.report(),
            RuleId::new(17, 8),
            expected_packet,
            expected_bits,
            expected_padded,
        );
        let breakdown = management_bit_breakdown(encoded.report()).expect("response breakdown");
        assert_eq!(
            breakdown.payload_bits,
            expected_payload * 8,
            "{label} payload"
        );
        assert_eq!(
            breakdown.method_or_response_mapping_bits, expected_mapping_bits,
            "{label} code mapping"
        );
        let decoded = core
            .decode(encoded.frame().bytes())
            .unwrap_or_else(|error| panic!("{label} response decode failed: {error}"));
        assert_eq!(
            decoded.packet().as_bytes(),
            response.as_bytes(),
            "{label} packet"
        );
        assert_eq!(
            decoded.report().frame_bytes,
            encoded.report().frame_bytes,
            "{label} frame"
        );
        assert_report(
            decoded.report(),
            RuleId::new(17, 8),
            expected_packet,
            expected_bits,
            expected_padded,
        );
    }

    // The response mapping covers every response code currently exposed by
    // rustconf, including the error codes reachable from the management
    // service and the precondition failure used by If-Match.
    for code in [
        65_u8, 66, 68, 69, 128, 129, 130, 132, 133, 136, 137, 140, 141, 143, 160,
    ] {
        let response = response_packet(code, 9, &[]);
        let encoded = device
            .encode(TrafficOrigin::Management, &response)
            .unwrap_or_else(|error| panic!("response code {code} encode failed: {error}"));
        assert_report(encoded.report(), RuleId::new(17, 8), 52, 23, 3);
        let decoded = core
            .decode(encoded.frame().bytes())
            .unwrap_or_else(|error| panic!("response code {code} decode failed: {error}"));
        assert_eq!(decoded.packet().as_bytes(), response.as_bytes());
        assert_eq!(decoded.report().frame_bytes, encoded.report().frame_bytes);
    }
}

#[test]
fn protected_response_identity_rejects_wrong_endpoint_mid_type_and_token() {
    let device = SchcLink::new(active("device-management-identity"), LinkRole::Device);

    let wrong_endpoint = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(2, 68, 1, &[], None),
    );
    assert!(device
        .encode(TrafficOrigin::Management, &wrong_endpoint)
        .is_err());

    let wrong_mid = packet(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(2, 68, 128, &[], None),
    );
    assert!(device
        .encode(TrafficOrigin::Management, &wrong_mid)
        .is_err());

    let wrong_type = packet(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(0, 68, 1, &[], None),
    );
    assert!(device
        .encode(TrafficOrigin::Management, &wrong_type)
        .is_err());

    let wrong_token = packet(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(2, 68, 1, &[1], None),
    );
    assert!(device
        .encode(TrafficOrigin::Management, &wrong_token)
        .is_err());
}

#[test]
fn management_mid_msb_lsb_round_trips_bounded_out_of_order_and_rejects_128() {
    let core = SchcLink::new(active("core-management-mid"), LinkRole::Core);
    let device = SchcLink::new(active("device-management-mid"), LinkRole::Device);
    let mut frames = Vec::new();
    for message_id in [127_u16, 1] {
        let datagram = context_check_request(core.active_context().tag(), message_id, &[0xff]);
        let request = packet(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            MANAGEMENT_PORT,
            &datagram,
        );
        let encoded = core
            .encode(TrafficOrigin::Management, &request)
            .expect("bounded MID encodes");
        let decoded = device
            .decode(encoded.frame().bytes())
            .expect("bounded MID decodes");
        assert_eq!(decoded.packet().as_bytes(), request.as_bytes());
        assert_eq!(decoded.packet().coap_message().message_id(), message_id);
        frames.push(encoded);
    }
    assert_ne!(frames[0].frame().bytes(), frames[1].frame().bytes());

    let datagram = context_check_request(core.active_context().tag(), 128, &[]);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &datagram,
    );
    assert!(core.encode(TrafficOrigin::Management, &request).is_err());
}

#[test]
fn dispatch_seam_uses_rule_route_not_management_looking_coap_details() {
    let core = SchcLink::new(active("core-dispatch"), LinkRole::Core);
    let device = SchcLink::new(active("device-dispatch"), LinkRole::Device);
    let mut service = GenericDataService::from_files(
        &[std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/demo/demo-data.sid")],
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/demo/app-data.json"),
        "c",
    )
    .expect("application service");

    // A root FETCH with an identifier payload resembles management traffic at
    // the CoAP layer, but ordinary logical ports select the ordinary RuleID
    // and application route.
    let mut fetch_identifier = InstancePath::new();
    fetch_identifier
        .push_delta(60002)
        .expect("application identifier SID");
    let fetch_payload = encode_identifiers(&[fetch_identifier]).expect("FETCH identifiers");
    let fetch_options = vec![
        schc_coreconf::CoapOption::new(11, b"c".to_vec()).expect("URI path option"),
        schc_coreconf::CoapOption::new(12, vec![141]).expect("content format option"),
    ];
    let ordinary_request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &schc_coreconf::CoapMessage::from_parts(
            1,
            0,
            5,
            0x2401,
            Vec::new(),
            fetch_options,
            fetch_payload,
        )
        .expect("FETCH CoAP")
        .to_vec(),
    );
    let ordinary_frame = core
        .encode(TrafficOrigin::Application, &ordinary_request)
        .expect("ordinary management-looking request");
    assert_eq!(ordinary_frame.report().rule_id, RuleId::new(25, 8));
    let ordinary_decoded = device
        .decode(ordinary_frame.frame().bytes())
        .expect("ordinary request decodes");
    assert_eq!(ordinary_decoded.route(), TrafficRoute::Application);
    let ordinary_response = match ordinary_decoded.route() {
        TrafficRoute::Application => service
            .handle_datagram(ordinary_decoded.packet().coap_datagram())
            .expect("application service response"),
        TrafficRoute::ProtectedManagement => panic!("ordinary request reached management route"),
    };
    let ordinary_response =
        schc_coreconf::CoapMessage::parse(&ordinary_response).expect("ordinary service response");
    assert_eq!(ordinary_response.code(), 69);

    // The exact protected RuleID takes the protected route and therefore has
    // no call site into GenericDataService.
    let protected_request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(0, 5, 2, &[], Some(b"schc")),
    );
    let protected_frame = core
        .encode(TrafficOrigin::Management, &protected_request)
        .expect("protected request");
    assert_eq!(protected_frame.report().rule_id, RuleId::new(16, 8));
    let protected_decoded = device
        .decode(protected_frame.frame().bytes())
        .expect("protected request decodes");
    assert_eq!(protected_decoded.rule_id(), RuleId::new(16, 8));
    assert_eq!(protected_decoded.route(), TrafficRoute::ProtectedManagement);
    let reached_application = match protected_decoded.route() {
        TrafficRoute::Application => {
            let _ = service.handle_datagram(protected_decoded.packet().coap_datagram());
            true
        }
        TrafficRoute::ProtectedManagement => false,
    };
    assert!(!reached_application);
}

#[test]
fn malformed_frames_are_rejected_and_rule_identity_includes_bit_length() {
    let core = SchcLink::new(active("core-invalid"), LinkRole::Core);
    let device = SchcLink::new(active("device-invalid"), LinkRole::Device);
    assert!(device.decode(&[0xff]).is_err());
    assert!(device.decode(&[]).is_err());

    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 3, &[], Some(b"demo")),
    );
    let frame = core
        .encode(TrafficOrigin::Application, &request)
        .expect("request");
    assert_eq!(frame.frame().bit_len() % 8, 0);
    let management_request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &coap(0, 5, 3, &[], Some(b"schc")),
    );
    let management_frame = core
        .encode(TrafficOrigin::Management, &management_request)
        .expect("management request");
    let mut extra_padding = management_frame.frame().bytes().to_vec();
    extra_padding.push(0);
    assert!(device.decode(&extra_padding).is_err());
    let response = temporary_ordinary_response(&request).expect("response");
    let non_aligned = device
        .encode(TrafficOrigin::Application, &response)
        .expect("response");
    assert_ne!(non_aligned.frame().bit_len() % 8, 0);
    let mut malformed = non_aligned.frame().bytes().to_vec();
    *malformed.last_mut().expect("frame byte") |= 1;
    assert!(device.decode(&malformed).is_err());

    let policy = ProtectionPolicy::from_rule_ids([RuleId::new(16, 8)]);
    let context =
        schc_core::RuleContext::from_cbor_slice(SOR, SidRegistry::from_json_str(SID).expect("SID"))
            .expect("context");
    let protected = schc_coreconf::ProtectedRules::derive(&context, &policy).expect("policy");
    assert!(protected.contains(RuleId::new(16, 8)));
    assert!(!protected.contains(RuleId::new(16, 7)));
}

#[test]
fn raw_udp_link_delivers_only_frame_bytes_in_both_directions() {
    let core = SchcLink::new(active("core-wire"), LinkRole::Core);
    let device = SchcLink::new(active("device-wire"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 0x4001, &[0x44], Some(b"demo")),
    );
    let forward = core
        .encode(TrafficOrigin::Application, &request)
        .expect("forward frame");

    let first_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("first");
    let second_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("second");
    let first_address = first_socket.local_addr().expect("first address");
    let second_address = second_socket.local_addr().expect("second address");
    let first = RawUdpLink::from_socket(first_socket, second_address).expect("first link");
    let second = RawUdpLink::from_socket(second_socket, first_address).expect("second link");
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("first timeout");
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("second timeout");

    first.send_frame(forward.frame()).expect("forward send");
    let received = second.recv().expect("forward receive");
    assert_eq!(received.bytes(), forward.frame().bytes());
    assert_eq!(received.bytes().len(), forward.frame().bytes().len());
    let reconstructed = device.decode(received.bytes()).expect("forward decode");
    assert_eq!(reconstructed.packet().as_bytes(), request.as_bytes());

    let response = temporary_ordinary_response(reconstructed.packet()).expect("response");
    let reverse = device
        .encode(TrafficOrigin::Application, &response)
        .expect("reverse frame");
    second.send_frame(reverse.frame()).expect("reverse send");
    let received = first.recv().expect("reverse receive");
    assert_eq!(received.bytes(), reverse.frame().bytes());
    assert_eq!(received.bytes().len(), reverse.frame().bytes().len());
    let reconstructed = core.decode(received.bytes()).expect("reverse decode");
    assert_eq!(reconstructed.packet().as_bytes(), response.as_bytes());
}

#[test]
fn process_help_explains_interactive_commands_and_debug_reports() {
    for (program, expected) in [
        (
            env!("CARGO_BIN_EXE_schc-coreconf-core"),
            ["--tun-name", "--tun-mtu", "Core commands:", "context check"].as_slice(),
        ),
        (
            env!("CARGO_BIN_EXE_schc-coreconf-device"),
            [
                "--tun-name",
                "--tun-mtu",
                "Device mode:",
                "waits for SCHC frames",
            ]
            .as_slice(),
        ),
        (
            env!("CARGO_BIN_EXE_schc-data-client"),
            ["Data client commands:", "fetch <path>", "quit"].as_slice(),
        ),
    ] {
        let output = Command::new(program)
            .arg("--help")
            .output()
            .expect("run help");
        assert!(output.status.success(), "help status: {}", output.status);
        assert!(output.stderr.is_empty(), "help stderr: {:?}", output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in expected {
            assert!(stdout.contains(line), "missing {line:?} in {stdout}");
        }
    }
}
