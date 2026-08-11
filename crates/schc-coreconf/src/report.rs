//! Deterministic human-readable packet reports and byte accounting.

use std::fmt::{self, Write as _};
use std::net::Ipv6Addr;

use thiserror::Error;

use crate::DuplicateRpcCost;
use crate::{CoapMessage, CoapOption, Ipv6UdpCoapPacket, LinkReport, TrafficClass};

/// Direction shown by a packet report.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReportDirection {
    /// Packet is being transmitted.
    Tx,
    /// Packet is being received.
    Rx,
}

impl ReportDirection {
    fn label(self) -> &'static str {
        match self {
            Self::Tx => "TX",
            Self::Rx => "RX",
        }
    }
}

/// Errors returned when a packet report cannot be safely generated.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ReportError {
    /// The report packet is malformed or internally inconsistent.
    #[error("packet report rejected: {0}")]
    InvalidPacket(String),
    /// The SCHC bit accounting is inconsistent with the padded frame.
    #[error("packet report SCHC accounting failed: {0}")]
    InvalidSchc(String),
}

/// Exact encoded cost of one CoAP option.
///
/// The additive invariant is `header_bytes + delta_extension_bytes +
/// length_extension_bytes + value_bytes == encoded_bytes`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapOptionCost {
    /// Absolute option number.
    pub number: u32,
    /// Encoded option value length.
    pub value_bytes: usize,
    /// Shared one-byte option header.
    pub header_bytes: usize,
    /// Extended delta bytes, excluding the shared header.
    pub delta_extension_bytes: usize,
    /// Extended length bytes, excluding the shared header.
    pub length_extension_bytes: usize,
    /// Total encoded option cost.
    pub encoded_bytes: usize,
}

/// Exact byte cost of a CoAP datagram.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapCost {
    /// Fixed four-byte CoAP base header.
    pub base_header_bytes: usize,
    /// Token bytes.
    pub token_bytes: usize,
    /// Options in encoded order.
    pub options: Vec<CoapOptionCost>,
    /// Payload marker bytes, either zero or one.
    pub payload_marker_bytes: usize,
    /// CoAP payload bytes.
    pub payload_bytes: usize,
    /// Complete CoAP datagram size.
    pub total_bytes: usize,
}

/// Exact byte cost of the IPv6 and UDP layers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PacketLayerCost {
    /// IPv6 base-header bytes.
    pub ipv6_header_bytes: usize,
    /// UDP header bytes.
    pub udp_header_bytes: usize,
    /// CoAP datagram cost.
    pub coap: CoapCost,
    /// Complete packet size.
    pub packet_bytes: usize,
}

/// Exact SCHC meaningful-bit and padding cost.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchcCost {
    /// Meaningful encoded SCHC bits.
    pub meaningful_bits: usize,
    /// Padded transmitted frame bytes.
    pub padded_bytes: usize,
    /// Byte padding bits.
    pub padding_bits: usize,
}

/// All independently testable costs used by one rendered report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PacketReport {
    /// Parsed IPv6 metadata.
    pub ipv6: Ipv6Report,
    /// Parsed UDP metadata.
    pub udp: UdpReport,
    /// Parsed CoAP metadata and costs.
    pub coap: CoapReport,
    /// Layer byte-cost proof.
    pub layers: PacketLayerCost,
    /// SCHC bit-cost proof.
    pub schc: SchcCost,
    /// Specialized duplicate-rule RPC description, when applicable.
    pub rpc: Option<DuplicateRpcCost>,
}

/// IPv6 fields shown in debug reports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv6Report {
    /// IPv6 version.
    pub version: u8,
    /// Traffic class.
    pub traffic_class: u8,
    /// Flow label.
    pub flow_label: u32,
    /// Declared payload length.
    pub payload_length: u16,
    /// Next-header value.
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address.
    pub source: Ipv6Addr,
    /// Destination address.
    pub destination: Ipv6Addr,
}

/// UDP fields shown in debug reports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpReport {
    /// Source port.
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// Declared UDP length.
    pub length: u16,
    /// UDP checksum.
    pub checksum: u16,
}

/// CoAP fields shown in debug reports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapReport {
    /// CoAP version.
    pub version: u8,
    /// Message type.
    pub message_type: u8,
    /// Request or response code.
    pub code: u8,
    /// Message ID.
    pub message_id: u16,
    /// Token length.
    pub token_bytes: usize,
    /// Safe human-readable token value.
    pub token: String,
    /// Option values in encoded order.
    pub options: Vec<CoapOptionDescription>,
    /// Payload length.
    pub payload_bytes: usize,
}

/// One decoded CoAP option description.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapOptionDescription {
    /// Option number.
    pub number: u32,
    /// Stable human-readable option name.
    pub name: &'static str,
    /// Decoded value suitable for plain-text display.
    pub value: String,
}

/// Builds the parsed report data without rendering strings.
///
/// # Errors
///
/// Returns an error for malformed packet layers, invalid declared lengths, or
/// inconsistent SCHC padding.
#[allow(clippy::too_many_lines)]
pub fn inspect_report(report: &LinkReport) -> Result<PacketReport, ReportError> {
    validate_line_report(report)?;
    let bytes = &report.packet_bytes;
    if bytes.len() < crate::IPV6_HEADER_LEN {
        return Err(ReportError::InvalidPacket(format!(
            "IPv6 packet is shorter than {} bytes",
            crate::IPV6_HEADER_LEN
        )));
    }
    let version = bytes[0] >> 4;
    if version != crate::IPV6_VERSION {
        return Err(ReportError::InvalidPacket(format!(
            "IPv6 version is {version}, expected {}",
            crate::IPV6_VERSION
        )));
    }
    let packet = Ipv6UdpCoapPacket::parse(bytes)
        .map_err(|error| ReportError::InvalidPacket(error.to_string()))?;
    let ipv6_payload_length = usize::from(packet.ipv6_payload_length());
    let expected_payload_length = bytes
        .len()
        .checked_sub(crate::IPV6_HEADER_LEN)
        .ok_or_else(|| ReportError::InvalidPacket("IPv6 packet length underflow".to_owned()))?;
    if ipv6_payload_length != expected_payload_length {
        return Err(ReportError::InvalidPacket(format!(
            "IPv6 payload length is {ipv6_payload_length}, packet contains {expected_payload_length}"
        )));
    }
    let udp_length = usize::from(packet.udp_length());
    let expected_udp_length = bytes
        .len()
        .checked_sub(crate::IPV6_HEADER_LEN)
        .ok_or_else(|| ReportError::InvalidPacket("UDP length underflow".to_owned()))?;
    if udp_length != expected_udp_length || udp_length < crate::UDP_HEADER_LEN {
        return Err(ReportError::InvalidPacket(format!(
            "UDP length is {udp_length}, expected {expected_udp_length} and at least {}",
            crate::UDP_HEADER_LEN
        )));
    }
    let coap = packet.coap_message();
    let coap_cost = inspect_coap(packet.coap_datagram(), coap)?;
    let coap_total = coap_cost
        .base_header_bytes
        .checked_add(coap_cost.token_bytes)
        .and_then(|total| {
            coap_cost.options.iter().try_fold(total, |total, option| {
                total.checked_add(option.encoded_bytes)
            })
        })
        .and_then(|total| total.checked_add(coap_cost.payload_marker_bytes))
        .and_then(|total| total.checked_add(coap_cost.payload_bytes))
        .ok_or_else(|| ReportError::InvalidPacket("CoAP byte cost overflow".to_owned()))?;
    if coap_total != packet.coap_datagram().len() {
        return Err(ReportError::InvalidPacket(format!(
            "CoAP cost is {coap_total}, datagram has {} bytes",
            packet.coap_datagram().len()
        )));
    }
    let layers = PacketLayerCost {
        ipv6_header_bytes: crate::IPV6_HEADER_LEN,
        udp_header_bytes: crate::UDP_HEADER_LEN,
        coap: CoapCost {
            total_bytes: coap_total,
            ..coap_cost
        },
        packet_bytes: bytes.len(),
    };
    let layer_sum = layers
        .ipv6_header_bytes
        .checked_add(layers.udp_header_bytes)
        .and_then(|total| total.checked_add(layers.coap.total_bytes))
        .ok_or_else(|| ReportError::InvalidPacket("packet byte cost overflow".to_owned()))?;
    if layer_sum != bytes.len() {
        return Err(ReportError::InvalidPacket(format!(
            "packet cost is {layer_sum}, packet has {} bytes",
            bytes.len()
        )));
    }
    let meaningful_bits = report.schc_bit_len.ok_or_else(|| {
        ReportError::InvalidSchc("meaningful SCHC bit length is unavailable".to_owned())
    })?;
    let padded_bits = report
        .padded_byte_len
        .checked_mul(8)
        .ok_or_else(|| ReportError::InvalidSchc("padded byte count overflows bits".to_owned()))?;
    let padding_bits = padded_bits.checked_sub(meaningful_bits).ok_or_else(|| {
        ReportError::InvalidSchc(format!(
            "meaningful bits {meaningful_bits} exceed padded bits {padded_bits}"
        ))
    })?;
    let rpc = if report.rule_id == schc_core::RuleId::new(29, 8) {
        let sid_json = report.management_rpc_sid.as_deref().ok_or_else(|| {
            ReportError::InvalidPacket("duplicate-rule report has no SID model source".to_owned())
        })?;
        Some(
            crate::management::duplicate_rpc_cost(sid_json, coap.payload())
                .map_err(|error| ReportError::InvalidPacket(error.to_string()))?,
        )
    } else {
        None
    };
    Ok(PacketReport {
        ipv6: Ipv6Report {
            version,
            traffic_class: packet.traffic_class(),
            flow_label: packet.flow_label(),
            payload_length: packet.ipv6_payload_length(),
            next_header: packet.next_header(),
            hop_limit: packet.hop_limit(),
            source: packet.source(),
            destination: packet.destination(),
        },
        udp: UdpReport {
            source_port: packet.source_port(),
            destination_port: packet.destination_port(),
            length: packet.udp_length(),
            checksum: packet.udp_checksum(),
        },
        coap: CoapReport {
            version: coap.version(),
            message_type: packet.coap_message_type(),
            code: coap.code(),
            message_id: coap.message_id(),
            token_bytes: coap.token().len(),
            token: describe_token(coap.token()),
            options: coap.options().iter().map(describe_option).collect(),
            payload_bytes: coap.payload().len(),
        },
        layers,
        schc: SchcCost {
            meaningful_bits,
            padded_bytes: report.padded_byte_len,
            padding_bits,
        },
        rpc,
    })
}

fn validate_line_report(report: &LinkReport) -> Result<(), ReportError> {
    if report.packet_size != report.packet_bytes.len() {
        return Err(ReportError::InvalidPacket(format!(
            "packet_size={} but packet_bytes has {} bytes",
            report.packet_size,
            report.packet_bytes.len()
        )));
    }
    if report.padded_byte_len != report.frame_bytes.len() {
        return Err(ReportError::InvalidSchc(format!(
            "padded_byte_len={} but frame_bytes has {} bytes",
            report.padded_byte_len,
            report.frame_bytes.len()
        )));
    }
    Ok(())
}

/// Formats one report, with the concise line first in both modes.
///
/// # Errors
///
/// Returns an error when the report metadata is inconsistent or debug
/// inspection rejects the packet or accounting.
pub fn format_report(
    direction: ReportDirection,
    report: &LinkReport,
    debug: bool,
) -> Result<String, ReportError> {
    validate_line_report(report)?;
    let class = match report.traffic_class {
        TrafficClass::Ordinary => "APP",
        TrafficClass::ProtectedManagement => "MGMT",
    };
    let mut output = format!(
        "{} {class:<4}  {}/{}  {} B -> {} B\n",
        direction.label(),
        report.rule_id.value(),
        report.rule_id.bit_len(),
        report.packet_size,
        report.padded_byte_len
    );
    if debug {
        let inspected = inspect_report(report)?;
        render_debug(&mut output, &inspected)?;
    }
    Ok(output)
}

#[allow(clippy::too_many_lines)]
fn render_debug(output: &mut String, report: &PacketReport) -> Result<(), ReportError> {
    let has_coreconf_content_format = report
        .coap
        .options
        .iter()
        .any(|option| option.number == 12 && matches!(option.value.as_str(), "141" | "142"));
    let coap_payload_description = if has_coreconf_content_format {
        "binary CORECONF payload"
    } else {
        "payload"
    };
    writeln!(
        output,
        "  Packet                           {} B",
        report.layers.packet_bytes
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    IPv6                            {} B",
        report.layers.ipv6_header_bytes
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    UDP                              {} B",
        report.layers.udp_header_bytes
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    CoAP                            {} B",
        report.layers.coap.total_bytes
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    let semantic_overhead = report.layers.coap.base_header_bytes
        + report.layers.coap.token_bytes
        + report
            .layers
            .coap
            .options
            .iter()
            .map(|option| option.encoded_bytes)
            .sum::<usize>()
        + report.layers.coap.payload_marker_bytes;
    writeln!(
        output,
        "      header/token/options/marker {semantic_overhead:>3} B"
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    if let Some(rpc) = &report.rpc {
        writeln!(
            output,
            "      RPC                           {:>3} B",
            rpc.payload_bytes
        )
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
        writeln!(
            output,
            "        fixed                       {:>3} B",
            rpc.fixed_bytes
        )
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
        writeln!(
            output,
            "        variable framing           {:>3} B",
            rpc.variable_framing_bytes
        )
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
        writeln!(
            output,
            "        target values              {:>3} B",
            rpc.target_value_bytes
        )
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    } else {
        writeln!(
            output,
            "      payload          {} B ({coap_payload_description})",
            report.layers.coap.payload_bytes
        )
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    }
    render_ipv6(output, &report.ipv6)?;
    render_udp(output, &report.udp)?;
    render_coap(output, &report.coap)?;
    if let Some(rpc) = &report.rpc {
        render_rpc(output, rpc)?;
    }
    writeln!(output, "  SCHC")
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    meaningful      {} bits",
        report.schc.meaningful_bits
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    padded           {} B",
        report.schc.padded_bytes
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    writeln!(
        output,
        "    padding          {} bits",
        report.schc.padding_bits
    )
    .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    Ok(())
}

fn write_line(output: &mut String, args: fmt::Arguments<'_>) -> Result<(), ReportError> {
    output
        .write_fmt(args)
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))?;
    output
        .write_char('\n')
        .map_err(|_| ReportError::InvalidPacket("render failed".to_owned()))
}

fn render_ipv6(output: &mut String, ipv6: &Ipv6Report) -> Result<(), ReportError> {
    write_line(output, format_args!("  IPv6"))?;
    write_line(
        output,
        format_args!("    version          {}", ipv6.version),
    )?;
    write_line(output, format_args!("    source           {}", ipv6.source))?;
    write_line(
        output,
        format_args!("    destination      {}", ipv6.destination),
    )?;
    write_line(
        output,
        format_args!("    traffic class    {}", ipv6.traffic_class),
    )?;
    write_line(
        output,
        format_args!("    flow label       {}", ipv6.flow_label),
    )?;
    write_line(
        output,
        format_args!("    payload length   {} B", ipv6.payload_length),
    )?;
    write_line(
        output,
        format_args!(
            "    next header      {} ({})",
            next_header_name(ipv6.next_header),
            ipv6.next_header
        ),
    )?;
    write_line(
        output,
        format_args!("    hop limit        {}", ipv6.hop_limit),
    )
}

fn render_udp(output: &mut String, udp: &UdpReport) -> Result<(), ReportError> {
    write_line(output, format_args!("  UDP"))?;
    write_line(
        output,
        format_args!("    source port       {}", udp.source_port),
    )?;
    write_line(
        output,
        format_args!("    destination port  {}", udp.destination_port),
    )?;
    write_line(
        output,
        format_args!("    length            {} B", udp.length),
    )?;
    write_line(
        output,
        format_args!("    checksum          {}", udp.checksum),
    )
}

fn render_coap(output: &mut String, coap: &CoapReport) -> Result<(), ReportError> {
    write_line(output, format_args!("  CoAP"))?;
    write_line(
        output,
        format_args!("    version           {}", coap.version),
    )?;
    write_line(
        output,
        format_args!(
            "    type              {}",
            message_type_name(coap.message_type)
        ),
    )?;
    write_line(
        output,
        format_args!(
            "    code              0x{:02x} {}",
            coap.code,
            code_name(coap.code)
        ),
    )?;
    write_line(
        output,
        format_args!("    message ID        {}", coap.message_id),
    )?;
    if coap.token_bytes == 0 {
        write_line(output, format_args!("    token             empty"))?;
    } else {
        write_line(
            output,
            format_args!(
                "    token             {} B {}",
                coap.token_bytes, coap.token
            ),
        )?;
    }
    write_line(output, format_args!("    options"))?;
    for option in &coap.options {
        write_line(
            output,
            format_args!(
                "      {} ({})  {}",
                option.name, option.number, option.value
            ),
        )?;
    }
    write_line(
        output,
        format_args!("    payload           {} B", coap.payload_bytes),
    )
}

fn render_rpc(output: &mut String, rpc: &DuplicateRpcCost) -> Result<(), ReportError> {
    write_line(output, format_args!("  RPC"))?;
    write_line(output, format_args!("    operation         duplicate-rule"))?;
    write_line(output, format_args!("    source            {}", rpc.source))?;
    write_line(
        output,
        format_args!("    destination       {}", rpc.destination),
    )?;
    write_line(output, format_args!("    overrides"))?;
    for override_ in &rpc.overrides {
        let mut fields = Vec::new();
        if let Some(value) = &override_.target_value {
            fields.push(format!("target={value}"));
        }
        if let Some(value) = &override_.matching_operator {
            fields.push(format!("mo={value}"));
        }
        if let Some(value) = &override_.cda {
            fields.push(format!("cda={value}"));
        }
        write_line(
            output,
            format_args!(
                "      entry {}       {}",
                override_.entry_index,
                fields.join(" ")
            ),
        )?;
    }
    Ok(())
}

fn inspect_coap(bytes: &[u8], message: &CoapMessage) -> Result<CoapCost, ReportError> {
    if bytes.len() < 4 {
        return Err(ReportError::InvalidPacket(
            "CoAP datagram is shorter than four bytes".to_owned(),
        ));
    }
    let token_len = usize::from(bytes[0] & 0x0f);
    let token_end = 4usize
        .checked_add(token_len)
        .ok_or_else(|| ReportError::InvalidPacket("CoAP token length overflow".to_owned()))?;
    if token_end > bytes.len() || token_len != message.token().len() {
        return Err(ReportError::InvalidPacket(
            "CoAP token length is inconsistent".to_owned(),
        ));
    }
    let mut offset = token_end;
    let mut previous_number = 0_u32;
    let mut options = Vec::new();
    while offset < bytes.len() {
        if bytes[offset] == 0xff {
            if offset + 1 >= bytes.len() {
                return Err(ReportError::InvalidPacket(
                    "CoAP payload marker has no payload".to_owned(),
                ));
            }
            offset += 1;
            break;
        }
        let start = offset;
        let header = bytes[offset];
        offset += 1;
        let delta = read_coap_extended(header >> 4, bytes, &mut offset, "delta")?;
        let length = read_coap_extended(header & 0x0f, bytes, &mut offset, "length")?;
        let number = previous_number
            .checked_add(delta)
            .ok_or_else(|| ReportError::InvalidPacket("CoAP option number overflow".to_owned()))?;
        let length = usize::try_from(length).map_err(|_| {
            ReportError::InvalidPacket("CoAP option length does not fit usize".to_owned())
        })?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| ReportError::InvalidPacket("CoAP option length overflow".to_owned()))?;
        if end > bytes.len() {
            return Err(ReportError::InvalidPacket(
                "CoAP option exceeds datagram".to_owned(),
            ));
        }
        let encoded_bytes = end - start;
        let delta_extension_bytes = extended_bytes(header >> 4);
        let length_extension_bytes = extended_bytes(header & 0x0f);
        options.push(CoapOptionCost {
            number,
            value_bytes: length,
            header_bytes: 1,
            delta_extension_bytes,
            length_extension_bytes,
            encoded_bytes,
        });
        previous_number = number;
        offset = end;
    }
    let payload_bytes = bytes
        .len()
        .checked_sub(offset)
        .ok_or_else(|| ReportError::InvalidPacket("CoAP payload length underflow".to_owned()))?;
    if options.len() != message.options().len() || payload_bytes != message.payload().len() {
        return Err(ReportError::InvalidPacket(
            "CoAP parsed fields do not match encoded datagram".to_owned(),
        ));
    }
    for (cost, option) in options.iter().zip(message.options()) {
        if cost.number != option.number() || cost.value_bytes != option.value().len() {
            return Err(ReportError::InvalidPacket(
                "CoAP option cost does not match parsed option".to_owned(),
            ));
        }
    }
    Ok(CoapCost {
        base_header_bytes: 4,
        token_bytes: token_len,
        options,
        payload_marker_bytes: usize::from(payload_bytes != 0),
        payload_bytes,
        total_bytes: bytes.len(),
    })
}

fn read_coap_extended(
    nibble: u8,
    bytes: &[u8],
    offset: &mut usize,
    label: &str,
) -> Result<u32, ReportError> {
    match nibble {
        0..=12 => Ok(u32::from(nibble)),
        13 => {
            let byte = *bytes.get(*offset).ok_or_else(|| {
                ReportError::InvalidPacket(format!("CoAP {label} extension is truncated"))
            })?;
            *offset += 1;
            Ok(u32::from(byte) + 13)
        }
        14 => {
            let end = offset.checked_add(2).ok_or_else(|| {
                ReportError::InvalidPacket(format!("CoAP {label} extension overflows"))
            })?;
            if end > bytes.len() {
                return Err(ReportError::InvalidPacket(format!(
                    "CoAP {label} extension is truncated"
                )));
            }
            let value = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
            *offset = end;
            Ok(u32::from(value) + 269)
        }
        _ => Err(ReportError::InvalidPacket(format!(
            "CoAP {label} uses reserved nibble"
        ))),
    }
}

fn extended_bytes(nibble: u8) -> usize {
    match nibble {
        13 => 1,
        14 => 2,
        _ => 0,
    }
}

fn describe_option(option: &CoapOption) -> CoapOptionDescription {
    let name = option_name(option.number());
    let value = match option.number() {
        1 => format!("{} B If-Match", option.value().len()),
        11 => String::from_utf8_lossy(option.value()).into_owned(),
        12 | 17 | 23 | 35 | 60 => decode_unsigned(option.value()),
        _ => format!("{} B", option.value().len()),
    };
    CoapOptionDescription {
        number: option.number(),
        name,
        value,
    }
}

fn option_name(number: u32) -> &'static str {
    match number {
        1 => "If-Match",
        3 => "Uri-Host",
        4 => "ETag",
        5 => "If-None-Match",
        6 => "Observe",
        7 => "Uri-Port",
        8 => "Location-Path",
        11 => "Uri-Path",
        12 => "Content-Format",
        14 => "Max-Age",
        15 => "Uri-Query",
        17 => "Accept",
        20 => "Location-Query",
        23 => "Block2",
        27 => "Block1",
        35 => "Proxy-Uri",
        39 => "Proxy-Scheme",
        60 => "Size1",
        _ => "Option",
    }
}

fn decode_unsigned(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_owned();
    }
    if bytes.len() > 8 {
        return format!("binary {} B", bytes.len());
    }
    let Some(value) = bytes.iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(256)?.checked_add(u64::from(*byte))
    }) else {
        return format!("binary {} B", bytes.len());
    };
    value.to_string()
}

fn describe_token(token: &[u8]) -> String {
    if token.is_empty() {
        return "empty".to_owned();
    }
    if token.iter().all(u8::is_ascii_graphic) {
        return format!("{}", String::from_utf8_lossy(token));
    }
    format!("binary {} B", token.len())
}

fn message_type_name(value: u8) -> &'static str {
    match value {
        0 => "CON",
        1 => "NON",
        2 => "ACK",
        3 => "RST",
        _ => "unknown",
    }
}

fn code_name(code: u8) -> &'static str {
    match code {
        1 => "0.01 GET",
        2 => "0.02 POST",
        3 => "0.03 PUT",
        4 => "0.04 DELETE",
        5 => "0.05 FETCH",
        65 => "2.01 Created",
        66 => "2.02 Deleted",
        67 => "2.03 Valid",
        68 => "2.04 Changed",
        69 => "2.05 Content",
        128 => "4.00 Bad Request",
        129 => "4.01 Unauthorized",
        132 => "4.04 Not Found",
        160 => "5.00 Internal Server Error",
        _ => "unknown code",
    }
}

fn next_header_name(value: u8) -> &'static str {
    match value {
        crate::UDP_NEXT_HEADER => "UDP",
        _ => "unknown",
    }
}
