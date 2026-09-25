//! Root integration adapter for the r-schc packet codecs.
//!
//! The complete IPv6/UDP/CoAP construction, parsing, and checksum logic lives
//! in `schc-core`; the root crate keeps these names for its link and application
//! APIs.

pub use schc_core::packet::{
    CoapMessage, CoapOption, Ipv6UdpCoapPacket, Ipv6UdpPacket, PacketError, PacketMetadata,
    PacketResult, DEFAULT_FLOW_LABEL, DEFAULT_HOP_LIMIT, DEFAULT_TRAFFIC_CLASS, IPV6_HEADER_LEN,
    IPV6_VERSION, MAX_COAP_DATAGRAM_LEN, MAX_UDP_PAYLOAD_LEN, UDP_HEADER_LEN, UDP_NEXT_HEADER,
};
