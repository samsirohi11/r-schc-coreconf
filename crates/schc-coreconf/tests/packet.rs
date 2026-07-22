//! Regression coverage for complete logical IPv6/UDP/CoAP packets.

use std::net::Ipv6Addr;

use schc_core::packet::{CoapMessage, CoapOption, Ipv6Packet, UdpDatagram};
use schc_coreconf::{
    Ipv6UdpCoapPacket, PacketError, DEFAULT_FLOW_LABEL, DEFAULT_HOP_LIMIT, DEFAULT_TRAFFIC_CLASS,
    IPV6_VERSION, MAX_COAP_DATAGRAM_LEN, UDP_NEXT_HEADER,
};

const DEVICE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const CORE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const APPLICATION_PORT: u16 = 5683;
const MANAGEMENT_PORT: u16 = 5684;

fn message(
    message_type: u8,
    code: u8,
    message_id: u16,
    token: &[u8],
    options: Vec<CoapOption>,
    payload: &[u8],
) -> Vec<u8> {
    CoapMessage::from_parts(
        1,
        message_type,
        code,
        message_id,
        token.to_vec(),
        options,
        payload.to_vec(),
    )
    .expect("valid CoAP message")
    .to_vec()
}

fn option(number: u32, value: &[u8]) -> CoapOption {
    CoapOption::new(number, value.to_vec()).expect("valid CoAP option")
}

fn packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    coap: &[u8],
) -> Ipv6UdpCoapPacket {
    Ipv6UdpCoapPacket::from_coap_datagram(
        source,
        destination,
        source_port,
        destination_port,
        37,
        coap,
    )
    .expect("valid complete packet")
}

#[test]
fn fixed_ordinary_packets_have_expected_orientation_and_coap_fields() {
    let ordinary_request = packet(
        CORE,
        DEVICE,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &message(0, 1, 0x1001, &[0xaa], vec![option(11, b"demo")], b"odd"),
    );
    assert_packet_fields(
        &ordinary_request,
        PacketExpectation {
            source: CORE,
            destination: DEVICE,
            source_port: APPLICATION_PORT,
            destination_port: APPLICATION_PORT,
            message_type: 0,
            code: 1,
            message_id: 0x1001,
            token: &[0xaa],
            options: &[(11, b"demo".as_slice())],
            payload: b"odd",
        },
    );

    let ordinary_response = packet(
        DEVICE,
        CORE,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &message(2, 69, 0x1001, &[0xaa], vec![option(12, &[0x28])], b"even!"),
    );
    assert_packet_fields(
        &ordinary_response,
        PacketExpectation {
            source: DEVICE,
            destination: CORE,
            source_port: APPLICATION_PORT,
            destination_port: APPLICATION_PORT,
            message_type: 2,
            code: 69,
            message_id: 0x1001,
            token: &[0xaa],
            options: &[(12, &[0x28])],
            payload: b"even!",
        },
    );
}

#[test]
fn fixed_protected_packets_demonstrate_inspection_and_ipatch_traffic() {
    let management_inspection_request = packet(
        CORE,
        DEVICE,
        APPLICATION_PORT,
        MANAGEMENT_PORT,
        &message(0, 1, 0x2001, &[], vec![option(11, b"schc")], &[]),
    );
    assert_packet_fields(
        &management_inspection_request,
        PacketExpectation {
            source: CORE,
            destination: DEVICE,
            source_port: APPLICATION_PORT,
            destination_port: MANAGEMENT_PORT,
            message_type: 0,
            code: 1,
            message_id: 0x2001,
            token: &[],
            options: &[(11, b"schc")],
            payload: &[],
        },
    );

    let management_inspection_response = packet(
        DEVICE,
        CORE,
        MANAGEMENT_PORT,
        APPLICATION_PORT,
        &message(2, 69, 0x2001, &[], vec![], b"inspection"),
    );
    assert_eq!(
        management_inspection_response.source_port(),
        MANAGEMENT_PORT
    );
    assert_eq!(
        management_inspection_response.destination_port(),
        APPLICATION_PORT
    );
    assert_eq!(management_inspection_response.coap_message().code(), 69);
    assert_eq!(management_inspection_response.coap_payload(), b"inspection");

    let management_update_request = packet(
        CORE,
        DEVICE,
        APPLICATION_PORT,
        MANAGEMENT_PORT,
        &message(
            0,
            7,
            0x2002,
            &[1, 2],
            vec![option(11, b"schc"), option(12, &[42])],
            b"iPATCH",
        ),
    );
    assert_packet_fields(
        &management_update_request,
        PacketExpectation {
            source: CORE,
            destination: DEVICE,
            source_port: APPLICATION_PORT,
            destination_port: MANAGEMENT_PORT,
            message_type: 0,
            code: 7,
            message_id: 0x2002,
            token: &[1, 2],
            options: &[(11, b"schc"), (12, &[42])],
            payload: b"iPATCH",
        },
    );

    let management_update_response = packet(
        DEVICE,
        CORE,
        MANAGEMENT_PORT,
        APPLICATION_PORT,
        &message(2, 68, 0x2002, &[1, 2], vec![], &[]),
    );
    assert_eq!(management_update_response.source_port(), MANAGEMENT_PORT);
    assert_eq!(
        management_update_response.destination_port(),
        APPLICATION_PORT
    );
    assert_eq!(management_update_response.coap_message().code(), 68);
    assert!(management_update_response.coap_payload().is_empty());
}

#[derive(Clone, Copy)]
struct PacketExpectation<'a> {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    message_type: u8,
    code: u8,
    message_id: u16,
    token: &'a [u8],
    options: &'a [(u32, &'a [u8])],
    payload: &'a [u8],
}

fn assert_packet_fields(packet: &Ipv6UdpCoapPacket, expected: PacketExpectation<'_>) {
    assert_eq!(packet.source(), expected.source);
    assert_eq!(packet.destination(), expected.destination);
    assert_eq!(packet.source_port(), expected.source_port);
    assert_eq!(packet.destination_port(), expected.destination_port);
    assert_eq!(packet.hop_limit(), 37);
    assert_eq!(packet.traffic_class(), DEFAULT_TRAFFIC_CLASS);
    assert_eq!(packet.flow_label(), DEFAULT_FLOW_LABEL);
    assert_eq!(packet.coap_message().version(), 1);
    assert_eq!(packet.coap_message_type(), expected.message_type);
    assert_eq!(packet.coap_message().code(), expected.code);
    assert_eq!(packet.coap_message().message_id(), expected.message_id);
    assert_eq!(packet.coap_message().token(), expected.token);
    assert_eq!(
        packet
            .coap_options()
            .iter()
            .map(|option| (option.number(), option.value()))
            .collect::<Vec<_>>(),
        expected.options.to_vec()
    );
    assert_eq!(packet.coap_payload(), expected.payload);
    assert_eq!(packet.next_header(), UDP_NEXT_HEADER);
    assert_eq!(
        packet.as_bytes().len(),
        usize::from(packet.ipv6_payload_length()) + 40
    );
    assert_eq!(
        usize::from(packet.udp_length()),
        packet.coap_datagram().len() + 8
    );
    assert_eq!(
        packet.ipv6_payload_length(),
        packet.udp_length(),
        "IPv6 payload is exactly the UDP datagram"
    );
    assert_ne!(packet.udp_checksum(), 0);

    let reparsed = Ipv6UdpCoapPacket::parse(packet.as_bytes()).expect("packet parses");
    assert_eq!(reparsed.as_bytes(), packet.as_bytes());
    assert_eq!(reparsed.coap_datagram(), packet.coap_datagram());
}

#[test]
fn construction_defaults_and_known_checksum_vector_are_exact() {
    let coap = [0x40, 0x01, 0x00, 0x2a];
    let packet = Ipv6UdpCoapPacket::new(CORE, DEVICE, APPLICATION_PORT, APPLICATION_PORT, &coap)
        .expect("known vector packet");

    assert_eq!(packet.as_bytes()[0] >> 4, IPV6_VERSION);
    assert_eq!(packet.traffic_class(), DEFAULT_TRAFFIC_CLASS);
    assert_eq!(packet.flow_label(), DEFAULT_FLOW_LABEL);
    assert_eq!(packet.hop_limit(), DEFAULT_HOP_LIMIT);
    assert_eq!(packet.ipv6_payload_length(), 12);
    assert_eq!(packet.udp_length(), 12);
    assert_eq!(packet.udp_checksum(), 0x37d0);
    assert_eq!(
        packet.as_bytes(),
        &hex_bytes(
            "60000000000c114020010db8000000000000000000000002\
         20010db800000000000000000000000116331633000c37d0\
         4001002a",
        )
    );

    let ipv6 = Ipv6Packet::parse(packet.as_bytes()).expect("r-schc accepts IPv6");
    assert_eq!(ipv6.next_header(), UDP_NEXT_HEADER);
    assert_eq!(ipv6.payload().len(), 12);
    let udp = UdpDatagram::parse(ipv6.payload()).expect("r-schc accepts UDP");
    assert_eq!(udp.source_port(), APPLICATION_PORT);
    assert_eq!(udp.destination_port(), APPLICATION_PORT);
    assert_eq!(udp.payload(), &coap);
    let coap_message = CoapMessage::parse(udp.payload()).expect("r-schc accepts CoAP");
    assert_eq!(coap_message.to_vec(), coap);

    let udp_segment = packet.as_bytes()[40..].to_vec();
    let independent_checksum = udp_checksum_with_zero_field(CORE, DEVICE, &udp_segment);
    assert_eq!(independent_checksum, 0x37d0);
    assert_eq!(independent_checksum, packet.udp_checksum());
    let segment_with_checksum = udp_segment;
    assert_eq!(
        ones_complement_sum(&pseudo_header(CORE, DEVICE, 17, 12), &segment_with_checksum,),
        0xffff
    );

    // For this independently found message ID the mathematical checksum is
    // zero, so IPv6 UDP encodes it as all ones rather than all zeroes.
    let zero_result = Ipv6UdpCoapPacket::new(
        CORE,
        DEVICE,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &[0x40, 0x01, 0x37, 0xfa],
    )
    .expect("zero-result checksum vector");
    assert_eq!(zero_result.udp_checksum(), 0xffff);
    assert!(Ipv6UdpCoapPacket::parse(zero_result.as_bytes()).is_ok());
}

#[test]
fn odd_even_and_empty_payloads_round_trip_with_options() {
    for payload in [
        b"".as_slice(),
        b"x".as_slice(),
        b"xy".as_slice(),
        b"xyz".as_slice(),
    ] {
        let coap = message(
            0,
            1,
            u16::try_from(payload.len()).expect("test payload length"),
            &[],
            vec![option(11, b"demo")],
            payload,
        );
        let packet =
            Ipv6UdpCoapPacket::new(CORE, DEVICE, APPLICATION_PORT, APPLICATION_PORT, &coap)
                .expect("payload size is legal");
        assert_eq!(packet.coap_datagram(), coap);
        assert_eq!(packet.coap_payload(), payload);
        assert_eq!(
            Ipv6UdpCoapPacket::parse(packet.as_bytes())
                .unwrap()
                .to_vec(),
            packet.to_vec()
        );
    }
}

#[test]
fn parser_rejects_header_length_next_header_udp_and_coap_errors() {
    let coap = message(0, 1, 1, &[], vec![], b"payload");
    let valid = packet(CORE, DEVICE, APPLICATION_PORT, APPLICATION_PORT, &coap);

    let mut wrong_version = valid.to_vec();
    wrong_version[0] = 0x40;
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&wrong_version),
        Err(PacketError::Ipv6(_))
    ));

    let mut unsupported_next_header = valid.to_vec();
    unsupported_next_header[6] = 58;
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&unsupported_next_header),
        Err(PacketError::UnsupportedNextHeader(58))
    ));

    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&valid.as_bytes()[..39]),
        Err(PacketError::Ipv6(_))
    ));
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&trailing),
        Err(PacketError::Ipv6(_))
    ));

    let mut ipv6_short = valid.to_vec();
    ipv6_short[4..6].copy_from_slice(&11_u16.to_be_bytes());
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&ipv6_short),
        Err(PacketError::Ipv6(_))
    ));
    let mut ipv6_long = valid.to_vec();
    ipv6_long[4..6].copy_from_slice(&13_u16.to_be_bytes());
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&ipv6_long),
        Err(PacketError::Ipv6(_))
    ));

    let mut udp_short = valid.to_vec();
    udp_short[44..46].copy_from_slice(&7_u16.to_be_bytes());
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&udp_short),
        Err(PacketError::Udp(_))
    ));
    let mut udp_long = valid.to_vec();
    let extended_ipv6_length = u16::try_from(udp_long.len() - 40 + 1).unwrap();
    udp_long[4..6].copy_from_slice(&extended_ipv6_length.to_be_bytes());
    udp_long.push(0);
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&udp_long),
        Err(PacketError::Udp(_))
    ));

    let mut bad_checksum = valid.to_vec();
    bad_checksum[47] ^= 0x01;
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&bad_checksum),
        Err(PacketError::InvalidUdpChecksum { .. })
    ));
    let mut zero_checksum = valid.to_vec();
    zero_checksum[46..48].copy_from_slice(&[0, 0]);
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&zero_checksum),
        Err(PacketError::ZeroUdpChecksum)
    ));

    let mut malformed_coap = valid.to_vec();
    malformed_coap[48] = 0x4f;
    refresh_checksum(&mut malformed_coap);
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&malformed_coap),
        Err(PacketError::Coap(_))
    ));

    let mut unsupported_coap_version = valid.to_vec();
    unsupported_coap_version[48] = 0x00;
    refresh_checksum(&mut unsupported_coap_version);
    assert!(matches!(
        Ipv6UdpCoapPacket::parse(&unsupported_coap_version),
        Err(PacketError::UnsupportedCoapVersion(0))
    ));
}

#[test]
fn maximum_legal_udp_and_ipv6_lengths_are_supported_without_truncation() {
    let mut coap = vec![0x40, 0x01, 0x00, 0x01, 0xff];
    coap.extend(std::iter::repeat(0xa5).take(MAX_COAP_DATAGRAM_LEN - 5));
    let packet = Ipv6UdpCoapPacket::new(CORE, DEVICE, 1, 2, &coap).expect("maximum packet");
    assert_eq!(coap.len(), MAX_COAP_DATAGRAM_LEN);
    assert_eq!(packet.udp_length(), u16::MAX);
    assert_eq!(packet.ipv6_payload_length(), u16::MAX);
    assert_eq!(packet.as_bytes().len(), 40 + usize::from(u16::MAX));
    assert_eq!(
        Ipv6UdpCoapPacket::parse(packet.as_bytes())
            .unwrap()
            .coap_datagram(),
        coap
    );

    coap.push(0xa5);
    assert!(matches!(
        Ipv6UdpCoapPacket::new(CORE, DEVICE, 1, 2, &coap),
        Err(PacketError::CoapDatagramTooLong { .. })
    ));
}

fn hex_bytes(input: &str) -> Vec<u8> {
    input
        .split_whitespace()
        .flat_map(|line| line.as_bytes().chunks(2))
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex ASCII");
            u8::from_str_radix(text, 16).expect("hex byte")
        })
        .collect()
}

fn pseudo_header(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    udp_length: u16,
) -> Vec<u8> {
    let mut pseudo = Vec::with_capacity(40);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&u32::from(udp_length).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo
}

fn ones_complement_sum(first: &[u8], second: &[u8]) -> u32 {
    let mut sum = 0_u32;
    for bytes in [first, second] {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(u16::from_be_bytes([*byte, 0]));
        }
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    sum
}

fn udp_checksum_with_zero_field(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    segment_with_checksum: &[u8],
) -> u16 {
    let mut segment = segment_with_checksum.to_vec();
    segment[6..8].copy_from_slice(&[0, 0]);
    let sum = ones_complement_sum(
        &pseudo_header(
            source,
            destination,
            17,
            u16::try_from(segment.len()).expect("test UDP length"),
        ),
        &segment,
    );
    let checksum = !u16::try_from(sum).expect("folded checksum");
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn refresh_checksum(packet: &mut [u8]) {
    let checksum = udp_checksum_with_zero_field(
        Ipv6Addr::from([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13], packet[14],
            packet[15], packet[16], packet[17], packet[18], packet[19], packet[20], packet[21],
            packet[22], packet[23],
        ]),
        Ipv6Addr::from([
            packet[24], packet[25], packet[26], packet[27], packet[28], packet[29], packet[30],
            packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37],
            packet[38], packet[39],
        ]),
        &packet[40..],
    );
    packet[46..48].copy_from_slice(&checksum.to_be_bytes());
}
