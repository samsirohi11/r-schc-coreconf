//! UDP SCHC link operations.
//!
//! The link deliberately keeps the logical packet and the SCHC frame as two
//! different values.  A UDP link datagram is exactly the padded bytes returned
//! by r-schc; no rule, route, bit length, or packet metadata is serialized.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use schc_core::{Rule, RuleId};
use schc_runtime::{DeviceId, NodeRole, RuntimeError, SchcFrame};

pub use schc_runtime::NodeRole as LinkRole;
use thiserror::Error;

use crate::{ActiveContext, Ipv6UdpCoapPacket, PacketError, PacketResult};

/// The fixed logical address used by the demonstration core.
pub const CORE_LOGICAL_ADDRESS: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
/// The fixed logical address used by the demonstration device.
pub const DEVICE_LOGICAL_ADDRESS: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// The ordinary application UDP port in the logical packet.
pub const APPLICATION_PORT: u16 = 5683;
/// The protected context-management UDP port used by both logical endpoints.
pub const MANAGEMENT_PORT: u16 = 8724;

/// The origin declared by the producer of a logical packet.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrafficOrigin {
    /// Ordinary application traffic.
    Application,
    /// Protected SCHC context-management traffic.
    Management,
}

/// The traffic class derived from the exact selected or matched `RuleID`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrafficClass {
    /// Traffic using an unprotected ordinary rule.
    Ordinary,
    /// Traffic using a protected management rule.
    ProtectedManagement,
}

/// The route available after successful device-side validation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrafficRoute {
    /// Deliver to the temporary ordinary application handler.
    Application,
    /// Deliver to the protected context-management handler.
    ProtectedManagement,
}

impl TrafficClass {
    fn route(self) -> TrafficRoute {
        match self {
            Self::Ordinary => TrafficRoute::Application,
            Self::ProtectedManagement => TrafficRoute::ProtectedManagement,
        }
    }
}

/// Whether a report describes compression or decompression.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LinkOperation {
    /// A logical packet was compressed.
    Encode,
    /// A raw SCHC datagram was decompressed.
    Decode,
}

/// Complete observability for one SCHC operation.
///
/// `packet_bytes` always contains a complete IPv6/UDP/CoAP packet and
/// `frame_bytes` always contains only the padded SCHC frame.  They are kept
/// separate so callers cannot accidentally treat a link frame as an IP packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkReport {
    /// Operation represented by this report.
    pub operation: LinkOperation,
    /// Exact selected or matched rule identity.
    pub rule_id: RuleId,
    /// Active-context publication generation used by this operation.
    pub generation: u64,
    /// Traffic class derived from the rule identity.
    pub traffic_class: TrafficClass,
    /// Complete logical packet bytes.
    pub packet_bytes: Vec<u8>,
    /// Raw padded SCHC frame bytes.
    pub frame_bytes: Vec<u8>,
    /// Number of complete logical packet bytes.
    pub packet_size: usize,
    /// Number of meaningful SCHC bits, when compression supplied it.
    pub schc_bit_len: Option<usize>,
    /// Number of bytes sent or received on the SCHC link.
    pub padded_byte_len: usize,
    /// The selected rule structure used for protected-management accounting.
    ///
    /// This is retained in reports rather than inferred from a `RuleID` so the
    /// diagnostic breakdown cannot silently become stale when a rule changes.
    pub(crate) management_rule: Option<Rule>,
    /// SID model source used lazily for debug-only duplicate-RPC reporting.
    pub(crate) management_rpc_sid: Option<Arc<str>>,
}

impl LinkReport {
    /// Returns meaningful SCHC bits divided by complete logical packet bits.
    ///
    /// Values below one indicate compression. A no-compression frame can be
    /// slightly above one because it also carries its `RuleID`.
    #[must_use]
    pub fn compression_ratio(&self) -> Option<f64> {
        let packet_bits = u32::try_from(self.packet_size.checked_mul(8)?).ok()?;
        let schc_bits = u32::try_from(self.schc_bit_len?).ok()?;
        (packet_bits != 0).then(|| f64::from(schc_bits) / f64::from(packet_bits))
    }

    fn encoded(
        generation: u64,
        rule_id: RuleId,
        traffic_class: TrafficClass,
        packet: &[u8],
        frame: &SchcFrame,
        management_rule: Option<Rule>,
        management_rpc_sid: Option<Arc<str>>,
    ) -> Self {
        Self {
            operation: LinkOperation::Encode,
            rule_id,
            generation,
            traffic_class,
            packet_bytes: packet.to_vec(),
            frame_bytes: frame.bytes().to_vec(),
            packet_size: packet.len(),
            schc_bit_len: Some(frame.bit_len()),
            padded_byte_len: frame.bytes().len(),
            management_rule,
            management_rpc_sid,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decoded(
        generation: u64,
        rule_id: RuleId,
        traffic_class: TrafficClass,
        packet: &[u8],
        frame: &[u8],
        bit_len: usize,
        management_rule: Option<Rule>,
        management_rpc_sid: Option<Arc<str>>,
    ) -> Self {
        Self {
            operation: LinkOperation::Decode,
            rule_id,
            generation,
            traffic_class,
            packet_bytes: packet.to_vec(),
            frame_bytes: frame.to_vec(),
            packet_size: packet.len(),
            // The wire carries only padded bytes. The decoder's selected rule
            // and the verified canonical re-encoding recover the unique
            // meaningful bit length without adding metadata to the datagram.
            schc_bit_len: Some(bit_len),
            padded_byte_len: frame.len(),
            management_rule,
            management_rpc_sid,
        }
    }
}

/// A successful outbound compression result with its report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkEncoding {
    frame: SchcFrame,
    report: LinkReport,
}

impl LinkEncoding {
    /// Returns the raw padded SCHC frame.
    #[must_use]
    pub const fn frame(&self) -> &SchcFrame {
        &self.frame
    }

    /// Returns the operation report.
    #[must_use]
    pub const fn report(&self) -> &LinkReport {
        &self.report
    }

    /// Consumes the result and returns its frame.
    #[must_use]
    pub fn into_frame(self) -> SchcFrame {
        self.frame
    }
}

/// A successful inbound decode and rule-derived route.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LinkDecoded {
    packet: Ipv6UdpCoapPacket,
    rule_id: RuleId,
    traffic_class: TrafficClass,
    route: TrafficRoute,
    report: LinkReport,
}

impl LinkDecoded {
    /// Returns the fully validated logical packet.
    #[must_use]
    pub const fn packet(&self) -> &Ipv6UdpCoapPacket {
        &self.packet
    }

    /// Returns the exact matched rule identity.
    #[must_use]
    pub const fn rule_id(&self) -> RuleId {
        self.rule_id
    }

    /// Returns the rule-derived traffic class.
    #[must_use]
    pub const fn traffic_class(&self) -> TrafficClass {
        self.traffic_class
    }

    /// Returns the route authorized by the matched rule.
    #[must_use]
    pub const fn route(&self) -> TrafficRoute {
        self.route
    }

    /// Returns the operation report.
    #[must_use]
    pub const fn report(&self) -> &LinkReport {
        &self.report
    }
}

/// Errors from SCHC encoding, decoding, policy classification, and packet
/// validation.
#[derive(Debug, Error)]
pub enum LinkError {
    /// The pinned runtime rejected the operation.
    #[error("SCHC runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
    /// The reconstructed logical packet was not a complete valid packet.
    #[error("logical packet validation failed: {0}")]
    Packet(#[from] PacketError),
    /// A decoder reported a rule that is not in this context snapshot.
    #[error("matched unknown RuleID {value}/{bit_len}")]
    UnknownRuleId {
        /// Numeric `RuleID` value.
        value: u64,
        /// `RuleID` encoded bit length.
        bit_len: usize,
    },
    /// A producer declaration disagreed with the exact selected rule.
    #[error("{origin:?} origin selected {value}/{bit_len}, classified as {selected:?}")]
    OriginRuleMismatch {
        /// Declared producer origin.
        origin: TrafficOrigin,
        /// Numeric selected `RuleID` value.
        value: u64,
        /// Selected `RuleID` encoded bit length.
        bit_len: usize,
        /// Class derived from the selected identity.
        selected: TrafficClass,
    },
    /// A raw link send accepted fewer bytes than the complete datagram.
    #[error("short raw SCHC datagram send: expected {expected} bytes, sent {actual}")]
    ShortSend {
        /// Number of bytes supplied to the socket.
        expected: usize,
        /// Number of bytes accepted by the socket.
        actual: usize,
    },
    /// A raw link datagram was empty.
    #[error("empty SCHC link datagram")]
    EmptyFrame,
    /// A decoded frame was not the canonical encoding of its reconstruction.
    #[error("decoded frame is not canonical for its reconstructed packet")]
    FrameMismatch {
        /// Canonical frame bytes produced from the reconstructed packet.
        expected: Vec<u8>,
        /// Bytes received from the link.
        actual: Vec<u8>,
    },
    /// A connected link received a datagram from an unexpected peer.
    #[error("unexpected SCHC peer: expected {expected}, received {actual}")]
    UnexpectedPeer {
        /// Configured peer address.
        expected: SocketAddr,
        /// Received source address.
        actual: SocketAddr,
    },
    /// A socket operation failed.
    #[error("raw SCHC UDP socket operation failed: {0}")]
    Io(#[source] io::Error),
}

/// A reusable SCHC encoder/decoder that reads one context snapshot per call.
#[derive(Debug, Clone)]
pub struct SchcLink {
    active: Arc<ActiveContext>,
    device: DeviceId,
    role: LinkRole,
}

impl SchcLink {
    /// Builds a link around an active context and one endpoint role.
    #[must_use]
    pub fn new(active: Arc<ActiveContext>, role: LinkRole) -> Self {
        let device = active.snapshot().runtime().device_id().clone();
        Self {
            active,
            device,
            role,
        }
    }

    /// Returns the configured endpoint role.
    #[must_use]
    pub const fn role(&self) -> LinkRole {
        self.role
    }

    /// Returns the active context source used by this link.
    #[must_use]
    pub fn active_context(&self) -> &Arc<ActiveContext> {
        &self.active
    }

    /// Compresses a complete logical packet and enforces its declared origin.
    ///
    /// The runtime, protected-rule set, generation, and packet operation all
    /// come from one immutable [`crate::ContextSnapshot`].
    ///
    /// # Errors
    ///
    /// Returns [`LinkError`] when SCHC compression fails or the selected rule
    /// does not match the declared origin.
    pub fn encode(
        &self,
        origin: TrafficOrigin,
        packet: &Ipv6UdpCoapPacket,
    ) -> Result<LinkEncoding, LinkError> {
        let snapshot = self.active.snapshot();
        let (endpoint, flow) = self.role.outbound();
        let runtime = match origin {
            TrafficOrigin::Application => snapshot.application_runtime(),
            TrafficOrigin::Management => snapshot.runtime(),
        };
        let encoded = runtime.encode_detailed(&self.device, endpoint, flow, packet.as_bytes())?;
        let class = classify(&snapshot, encoded.rule_id())?;
        enforce_origin(origin, encoded.rule_id(), class)?;
        let management_rule = (class == TrafficClass::ProtectedManagement)
            .then(|| {
                snapshot
                    .rules()
                    .iter()
                    .find(|rule| rule.id() == encoded.rule_id())
                    .cloned()
            })
            .flatten();
        let management_rpc_sid = (encoded.rule_id() == RuleId::new(29, 8))
            .then(|| Arc::clone(&self.active.recipe().sid_json));
        let report = LinkReport::encoded(
            snapshot.generation(),
            encoded.rule_id(),
            class,
            packet.as_bytes(),
            encoded.frame(),
            management_rule,
            management_rpc_sid,
        );
        Ok(LinkEncoding {
            frame: encoded.into_frame(),
            report,
        })
    }

    /// Decompresses one raw padded frame, validates the complete packet, and
    /// derives its route only from the exact matched `RuleID`.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError`] when decompression fails, the frame is empty, or
    /// the reconstructed logical packet is malformed.
    pub fn decode(&self, frame: &[u8]) -> Result<LinkDecoded, LinkError> {
        if frame.is_empty() {
            return Err(LinkError::EmptyFrame);
        }
        let snapshot = self.active.snapshot();
        let (endpoint, flow) = self.role.inbound();
        let decoded =
            match snapshot
                .runtime()
                .decode_padded_detailed(&self.device, endpoint, flow, frame)
            {
                Ok(decoded) => decoded,
                Err(full_error) => match snapshot.application_runtime().decode_padded_detailed(
                    &self.device,
                    endpoint,
                    flow,
                    frame,
                ) {
                    Ok(decoded) => decoded,
                    Err(_) => return Err(full_error.into()),
                },
            };
        let class = classify(&snapshot, decoded.rule_id())?;
        let packet = Ipv6UdpCoapPacket::parse(decoded.packet())?;
        let peer_role = match self.role {
            LinkRole::Core => NodeRole::Device,
            LinkRole::Device => NodeRole::Core,
        };
        let (canonical_endpoint, canonical_flow) = peer_role.outbound();
        let canonical_runtime = if snapshot.protected_rules().contains(decoded.rule_id()) {
            snapshot.runtime()
        } else {
            snapshot.application_runtime()
        };
        let canonical = canonical_runtime.encode_detailed(
            &self.device,
            canonical_endpoint,
            canonical_flow,
            packet.as_bytes(),
        )?;
        if canonical.rule_id() != decoded.rule_id() || canonical.frame().bytes() != frame {
            return Err(LinkError::FrameMismatch {
                expected: canonical.frame().bytes().to_vec(),
                actual: frame.to_vec(),
            });
        }
        let management_rule = (class == TrafficClass::ProtectedManagement)
            .then(|| {
                snapshot
                    .rules()
                    .iter()
                    .find(|rule| rule.id() == decoded.rule_id())
                    .cloned()
            })
            .flatten();
        let management_rpc_sid = (decoded.rule_id() == RuleId::new(29, 8))
            .then(|| Arc::clone(&self.active.recipe().sid_json));
        let report = LinkReport::decoded(
            snapshot.generation(),
            decoded.rule_id(),
            class,
            packet.as_bytes(),
            frame,
            canonical.frame().bit_len(),
            management_rule,
            management_rpc_sid,
        );
        Ok(LinkDecoded {
            packet,
            rule_id: decoded.rule_id(),
            traffic_class: class,
            route: class.route(),
            report,
        })
    }

    /// Returns the current snapshot generation for diagnostics.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.active.snapshot().generation()
    }
}

fn classify(snapshot: &crate::ContextSnapshot, rule_id: RuleId) -> Result<TrafficClass, LinkError> {
    if !snapshot.contains_rule_id(rule_id) && !snapshot.contains_application_rule_id(rule_id) {
        return Err(LinkError::UnknownRuleId {
            value: rule_id.value(),
            bit_len: rule_id.bit_len(),
        });
    }
    if snapshot.protected_rules().contains(rule_id) {
        Ok(TrafficClass::ProtectedManagement)
    } else {
        Ok(TrafficClass::Ordinary)
    }
}

fn enforce_origin(
    origin: TrafficOrigin,
    rule_id: RuleId,
    class: TrafficClass,
) -> Result<(), LinkError> {
    let accepted = matches!(
        (origin, class),
        (TrafficOrigin::Application, TrafficClass::Ordinary)
            | (TrafficOrigin::Management, TrafficClass::ProtectedManagement)
    );
    if accepted {
        Ok(())
    } else {
        Err(LinkError::OriginRuleMismatch {
            origin,
            value: rule_id.value(),
            bit_len: rule_id.bit_len(),
            selected: class,
        })
    }
}

/// A single raw UDP link datagram and its socket-level source address.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RawDatagram {
    bytes: Vec<u8>,
    source: SocketAddr,
}

impl RawDatagram {
    /// Returns the datagram bytes exactly as received.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the source address reported by the UDP socket.
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }
}

/// A connected UDP socket carrying one raw SCHC frame per datagram.
#[derive(Debug)]
pub struct RawUdpLink {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl RawUdpLink {
    /// Binds and connects a UDP socket to explicit local and peer addresses.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Io`] when binding or connecting the socket fails.
    pub fn bind(local: SocketAddr, peer: SocketAddr) -> Result<Self, LinkError> {
        let socket = UdpSocket::bind(local).map_err(LinkError::Io)?;
        Self::from_socket(socket, peer)
    }

    /// Connects an already-bound socket to an explicit peer.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Io`] when connecting the socket fails.
    pub fn from_socket(socket: UdpSocket, peer: SocketAddr) -> Result<Self, LinkError> {
        socket.connect(peer).map_err(LinkError::Io)?;
        Ok(Self { socket, peer })
    }

    /// Returns the actual local address, including an OS-selected port.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Io`] when querying the socket fails.
    pub fn local_addr(&self) -> Result<SocketAddr, LinkError> {
        self.socket.local_addr().map_err(LinkError::Io)
    }

    /// Returns the configured peer address.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Sets the receive timeout used by one-datagram operations.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Io`] when the operating system rejects the timeout.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), LinkError> {
        self.socket.set_read_timeout(timeout).map_err(LinkError::Io)
    }

    /// Sets the send timeout used by datagram operations.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::Io`] when the operating system rejects the timeout.
    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), LinkError> {
        self.socket
            .set_write_timeout(timeout)
            .map_err(LinkError::Io)
    }

    /// Sends exactly one raw padded frame datagram.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError`] when the frame is empty, the socket fails, or a
    /// short datagram send is reported.
    pub fn send_frame(&self, frame: &SchcFrame) -> Result<(), LinkError> {
        self.send_bytes(frame.bytes())
    }

    /// Sends exactly one raw datagram without adding a framing prefix.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError`] when the datagram is empty, the socket fails, or
    /// a short datagram send is reported.
    pub fn send_bytes(&self, bytes: &[u8]) -> Result<(), LinkError> {
        if bytes.is_empty() {
            return Err(LinkError::EmptyFrame);
        }
        let sent = self.socket.send(bytes).map_err(LinkError::Io)?;
        if sent != bytes.len() {
            return Err(LinkError::ShortSend {
                expected: bytes.len(),
                actual: sent,
            });
        }
        Ok(())
    }

    /// Receives exactly one datagram without synthesizing payload metadata.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError`] when receiving fails, the peer is unexpected, or
    /// an empty datagram is received.
    pub fn recv(&self) -> Result<RawDatagram, LinkError> {
        let mut bytes = vec![0_u8; 65_535];
        let (length, source) = self.socket.recv_from(&mut bytes).map_err(LinkError::Io)?;
        if source != self.peer {
            return Err(LinkError::UnexpectedPeer {
                expected: self.peer,
                actual: source,
            });
        }
        bytes.truncate(length);
        if bytes.is_empty() {
            return Err(LinkError::EmptyFrame);
        }
        Ok(RawDatagram { bytes, source })
    }

    /// Receives one datagram and returns only its exact bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors described by [`Self::recv`].
    pub fn recv_bytes(&self) -> Result<Vec<u8>, LinkError> {
        Ok(self.recv()?.bytes)
    }
}

/// Builds a synthetic format-142 `yang-instances+cbor-seq` FETCH response.
///
/// The response carries the format-142 Content-Format option used by the
/// sample application.
/// The CoAP message ID and token are retained, and both logical IPv6 and UDP
/// endpoints are swapped.  This helper is intentionally independent of any
/// datastore or URI semantics.
///
/// # Errors
///
/// Returns a packet error if the response cannot be serialized or validated.
pub fn temporary_ordinary_response(request: &Ipv6UdpCoapPacket) -> PacketResult<Ipv6UdpCoapPacket> {
    let request_message = request.coap_message();
    let content_format = crate::CoapOption::new(12, vec![142]).map_err(PacketError::Coap)?;
    let response = crate::CoapMessage::from_parts(
        1,
        2,
        69,
        request_message.message_id(),
        request_message.token().to_vec(),
        vec![content_format],
        Vec::new(),
    )
    .map_err(PacketError::Coap)?
    .to_vec();
    Ipv6UdpCoapPacket::new(
        request.destination(),
        request.source(),
        request.destination_port(),
        request.source_port(),
        &response,
    )
}
