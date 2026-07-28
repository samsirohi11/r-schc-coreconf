//! Complete logical IPv6, UDP, and CoAP packet construction and parsing.
//!
//! The layer operates only on byte slices and standard-library addresses.
//! It does not open sockets or add transport framing.

use std::net::Ipv6Addr;

use schc_core::{
    packet::{Ipv6Packet, UdpDatagram},
    SchcError,
};
use thiserror::Error;

pub use schc_core::packet::{CoapMessage, CoapOption};

/// The fixed size of an IPv6 header without extension headers.
pub const IPV6_HEADER_LEN: usize = 40;
/// The fixed size of a UDP header.
pub const UDP_HEADER_LEN: usize = 8;
/// The IPv6 next-header value for UDP.
pub const UDP_NEXT_HEADER: u8 = 17;
/// The IPv6 version emitted by this packet layer.
pub const IPV6_VERSION: u8 = 6;
/// The default IPv6 traffic class used by [`Ipv6UdpCoapPacket::new`].
pub const DEFAULT_TRAFFIC_CLASS: u8 = 0;
/// The default IPv6 flow label used by [`Ipv6UdpCoapPacket::new`].
pub const DEFAULT_FLOW_LABEL: u32 = 0;
/// The default IPv6 hop limit used by [`Ipv6UdpCoapPacket::new`].
pub const DEFAULT_HOP_LIMIT: u8 = 64;
/// The largest CoAP datagram that fits in a legal UDP datagram.
pub const MAX_COAP_DATAGRAM_LEN: usize = u16::MAX as usize - UDP_HEADER_LEN;

/// Errors returned by complete IPv6, UDP, and CoAP packet operations.
#[derive(Debug, Error)]
pub enum PacketError {
    /// The pinned r-schc IPv6 parser rejected the packet.
    #[error("IPv6 packet rejected: {0}")]
    Ipv6(#[source] SchcError),
    /// The pinned r-schc UDP parser rejected the datagram.
    #[error("UDP datagram rejected: {0}")]
    Udp(#[source] SchcError),
    /// The pinned r-schc CoAP parser rejected the datagram.
    #[error("CoAP datagram rejected: {0}")]
    Coap(#[source] SchcError),
    /// The packet used a next-header value other than UDP.
    #[error("unsupported IPv6 next header {0}; expected UDP ({UDP_NEXT_HEADER})")]
    UnsupportedNextHeader(u8),
    /// The UDP checksum field was zero even though IPv6 UDP requires a checksum.
    #[error("IPv6 UDP checksum is zero")]
    ZeroUdpChecksum,
    /// The UDP checksum did not match the IPv6 pseudo-header and datagram.
    #[error("invalid IPv6 UDP checksum: expected {expected:#06x}, found {actual:#06x}")]
    InvalidUdpChecksum {
        /// Checksum calculated from the packet with a zero checksum field.
        expected: u16,
        /// Checksum present in the packet.
        actual: u16,
    },
    /// The CoAP version was not the version defined for CoAP over UDP.
    #[error("unsupported CoAP version {0}; expected version 1")]
    UnsupportedCoapVersion(u8),
    /// The serialized CoAP datagram cannot fit in the UDP length field.
    #[error("CoAP datagram is too long: {length} bytes; maximum is {MAX_COAP_DATAGRAM_LEN} bytes")]
    CoapDatagramTooLong {
        /// Length of the supplied CoAP datagram.
        length: usize,
    },
}

/// Result type for complete IPv6, UDP, and CoAP packet operations.
pub type PacketResult<T> = std::result::Result<T, PacketError>;

/// The IPv6 and UDP metadata carried by one logical packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMetadata {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    traffic_class: u8,
    flow_label: u32,
    hop_limit: u8,
}

impl PacketMetadata {
    /// Returns the IPv6 source address.
    #[must_use]
    pub const fn source(&self) -> Ipv6Addr {
        self.source
    }

    /// Returns the IPv6 destination address.
    #[must_use]
    pub const fn destination(&self) -> Ipv6Addr {
        self.destination
    }

    /// Returns the UDP source port.
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }

    /// Returns the UDP destination port.
    #[must_use]
    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }

    /// Returns the IPv6 traffic class.
    #[must_use]
    pub const fn traffic_class(&self) -> u8 {
        self.traffic_class
    }

    /// Returns the 20-bit IPv6 flow label.
    #[must_use]
    pub const fn flow_label(&self) -> u32 {
        self.flow_label
    }

    /// Returns the IPv6 hop limit.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }
}

/// A complete logical IPv6 packet containing a UDP datagram and CoAP message.
///
/// Construction emits an IPv6 header with version 6, traffic class 0, flow
/// label 0, next header UDP, and a default hop limit of 64.
/// The supplied CoAP datagram is parsed for validity and retained byte for
/// byte, including any valid non-canonical option encoding accepted by r-schc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6UdpCoapPacket {
    bytes: Vec<u8>,
    metadata: PacketMetadata,
    coap_datagram: Vec<u8>,
    coap_message: CoapMessage,
}

impl Ipv6UdpCoapPacket {
    /// Builds a complete packet using [`DEFAULT_HOP_LIMIT`].
    ///
    /// The CoAP input must already be serialized. It is parsed with the pinned
    /// r-schc [`CoapMessage`] parser, and only CoAP version 1 is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::Coap`] for malformed CoAP, or
    /// [`PacketError::CoapDatagramTooLong`] when the CoAP datagram cannot fit
    /// in the UDP length field.
    pub fn new(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        coap_datagram: &[u8],
    ) -> PacketResult<Self> {
        Self::from_coap_datagram(
            source,
            destination,
            source_port,
            destination_port,
            DEFAULT_HOP_LIMIT,
            coap_datagram,
        )
    }

    /// Builds a complete packet with an explicitly selected IPv6 hop limit.
    ///
    /// Traffic class and flow label remain [`DEFAULT_TRAFFIC_CLASS`] and
    /// [`DEFAULT_FLOW_LABEL`]. The UDP checksum is calculated over the IPv6
    /// pseudo-header and encoded as `0xffff` if the mathematical result is
    /// zero, as required for IPv6 UDP.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::Coap`] for malformed CoAP, or
    /// [`PacketError::CoapDatagramTooLong`] when the CoAP datagram cannot fit
    /// in the UDP length field.
    pub fn from_coap_datagram(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        hop_limit: u8,
        coap_datagram: &[u8],
    ) -> PacketResult<Self> {
        let coap_message = parse_coap(coap_datagram)?;
        let udp_length = coap_datagram.len().checked_add(UDP_HEADER_LEN).ok_or(
            PacketError::CoapDatagramTooLong {
                length: coap_datagram.len(),
            },
        )?;
        if udp_length > usize::from(u16::MAX) {
            return Err(PacketError::CoapDatagramTooLong {
                length: coap_datagram.len(),
            });
        }

        let Ok(udp_length_u16) = u16::try_from(udp_length) else {
            return Err(PacketError::CoapDatagramTooLong {
                length: coap_datagram.len(),
            });
        };
        let mut udp = Vec::with_capacity(udp_length);
        udp.extend_from_slice(&source_port.to_be_bytes());
        udp.extend_from_slice(&destination_port.to_be_bytes());
        udp.extend_from_slice(&udp_length_u16.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(coap_datagram);

        let checksum = compute_udp_checksum(source, destination, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        let mut bytes = Vec::with_capacity(IPV6_HEADER_LEN + udp_length);
        let flow_label_bytes = DEFAULT_FLOW_LABEL.to_be_bytes();
        bytes.push((IPV6_VERSION << 4) | (DEFAULT_TRAFFIC_CLASS >> 4));
        bytes.push((DEFAULT_TRAFFIC_CLASS << 4) | (flow_label_bytes[1] & 0x0f));
        bytes.push(flow_label_bytes[2]);
        bytes.push(flow_label_bytes[3]);
        bytes.extend_from_slice(&udp_length_u16.to_be_bytes());
        bytes.push(UDP_NEXT_HEADER);
        bytes.push(hop_limit);
        bytes.extend_from_slice(&source.octets());
        bytes.extend_from_slice(&destination.octets());
        bytes.extend_from_slice(&udp);

        let metadata = PacketMetadata {
            source,
            destination,
            source_port,
            destination_port,
            traffic_class: DEFAULT_TRAFFIC_CLASS,
            flow_label: DEFAULT_FLOW_LABEL,
            hop_limit,
        };
        Ok(Self {
            bytes,
            metadata,
            coap_datagram: coap_datagram.to_vec(),
            coap_message,
        })
    }

    /// Parses and validates a complete IPv6/UDP/CoAP packet.
    ///
    /// IPv6 and UDP declared lengths must consume the complete input. The
    /// next header must be UDP, the checksum must be nonzero and correct, and
    /// the UDP payload must be a CoAP version 1 message.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed packet, unsupported next header, zero
    /// or incorrect UDP checksum, or malformed CoAP datagram.
    pub fn parse(input: &[u8]) -> PacketResult<Self> {
        let ipv6 = Ipv6Packet::parse(input).map_err(PacketError::Ipv6)?;
        if ipv6.next_header() != UDP_NEXT_HEADER {
            return Err(PacketError::UnsupportedNextHeader(ipv6.next_header()));
        }

        let udp = UdpDatagram::parse(ipv6.payload()).map_err(PacketError::Udp)?;
        let udp_bytes = udp.to_vec();
        let actual_checksum = u16::from_be_bytes([udp_bytes[6], udp_bytes[7]]);
        if actual_checksum == 0 {
            return Err(PacketError::ZeroUdpChecksum);
        }
        let mut checksum_input = udp_bytes.clone();
        checksum_input[6..8].copy_from_slice(&[0, 0]);
        let source = ipv6_addr(&input[8..24]);
        let destination = ipv6_addr(&input[24..40]);
        let expected_checksum = compute_udp_checksum(source, destination, &checksum_input);
        if actual_checksum != expected_checksum {
            return Err(PacketError::InvalidUdpChecksum {
                expected: expected_checksum,
                actual: actual_checksum,
            });
        }

        let coap_datagram = udp.payload().to_vec();
        let coap_message = parse_coap(&coap_datagram)?;
        let metadata = PacketMetadata {
            source,
            destination,
            source_port: udp.source_port(),
            destination_port: udp.destination_port(),
            traffic_class: ((input[0] & 0x0f) << 4) | (input[1] >> 4),
            flow_label: (u32::from(input[1] & 0x0f) << 16)
                | (u32::from(input[2]) << 8)
                | u32::from(input[3]),
            hop_limit: input[7],
        };
        Ok(Self {
            bytes: input.to_vec(),
            metadata,
            coap_datagram,
            coap_message,
        })
    }

    /// Returns the immutable IPv6 and UDP metadata.
    #[must_use]
    pub const fn metadata(&self) -> &PacketMetadata {
        &self.metadata
    }

    /// Returns the IPv6 source address.
    #[must_use]
    pub const fn source(&self) -> Ipv6Addr {
        self.metadata.source()
    }

    /// Returns the IPv6 destination address.
    #[must_use]
    pub const fn destination(&self) -> Ipv6Addr {
        self.metadata.destination()
    }

    /// Returns the UDP source port.
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.metadata.source_port()
    }

    /// Returns the UDP destination port.
    #[must_use]
    pub const fn destination_port(&self) -> u16 {
        self.metadata.destination_port()
    }

    /// Returns the IPv6 traffic class.
    #[must_use]
    pub const fn traffic_class(&self) -> u8 {
        self.metadata.traffic_class()
    }

    /// Returns the 20-bit IPv6 flow label.
    #[must_use]
    pub const fn flow_label(&self) -> u32 {
        self.metadata.flow_label()
    }

    /// Returns the IPv6 hop limit.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.metadata.hop_limit()
    }

    /// Returns the IPv6 payload length declared in the packet.
    #[must_use]
    pub fn ipv6_payload_length(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }

    /// Returns the IPv6 next-header value.
    #[must_use]
    pub const fn next_header(&self) -> u8 {
        UDP_NEXT_HEADER
    }

    /// Returns the UDP length declared in the packet.
    #[must_use]
    pub fn udp_length(&self) -> u16 {
        u16::from_be_bytes([self.bytes[44], self.bytes[45]])
    }

    /// Returns the validated UDP checksum.
    #[must_use]
    pub fn udp_checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[46], self.bytes[47]])
    }

    /// Returns the CoAP message type from the serialized CoAP header.
    #[must_use]
    pub fn coap_message_type(&self) -> u8 {
        (self.coap_datagram[0] >> 4) & 0x03
    }

    /// Returns the parsed CoAP message.
    #[must_use]
    pub const fn coap_message(&self) -> &CoapMessage {
        &self.coap_message
    }

    /// Returns the exact serialized CoAP datagram supplied to or parsed from
    /// the packet.
    #[must_use]
    pub fn coap_datagram(&self) -> &[u8] {
        &self.coap_datagram
    }

    /// Returns the parsed CoAP options.
    #[must_use]
    pub fn coap_options(&self) -> &[CoapOption] {
        self.coap_message.options()
    }

    /// Returns the parsed CoAP payload.
    #[must_use]
    pub fn coap_payload(&self) -> &[u8] {
        self.coap_message.payload()
    }

    /// Returns the exact complete IPv6/UDP/CoAP packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies the exact complete IPv6/UDP/CoAP packet bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

fn ipv6_addr(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}

fn parse_coap(input: &[u8]) -> PacketResult<CoapMessage> {
    let message = CoapMessage::parse(input).map_err(PacketError::Coap)?;
    if message.version() != 1 {
        return Err(PacketError::UnsupportedCoapVersion(message.version()));
    }
    Ok(message)
}

fn compute_udp_checksum(source: Ipv6Addr, destination: Ipv6Addr, segment: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = add_words(sum, &source.octets());
    sum = add_words(sum, &destination.octets());
    sum = add_words(
        sum,
        &u32::try_from(segment.len())
            .expect("UDP segment fits u32")
            .to_be_bytes(),
    );
    sum = add_words(sum, &[0, 0, 0, UDP_NEXT_HEADER]);
    sum = add_words(sum, segment);
    let folded = fold_checksum(sum);
    let checksum = !u16::try_from(folded).expect("folded checksum fits u16");
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([*byte, 0]));
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u32 {
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    sum
}
