use schc_coreconf::Ipv6UdpCoapPacket;

pub(crate) fn ordinary_response(
    request: &Ipv6UdpCoapPacket,
) -> Result<Ipv6UdpCoapPacket, schc_coreconf::PacketError> {
    let content_format =
        schc_coreconf::CoapOption::new(12, vec![142]).map_err(schc_coreconf::PacketError::Coap)?;
    let response = schc_coreconf::CoapMessage::from_parts(
        1,
        2,
        69,
        request.coap_message().message_id(),
        request.coap_message().token().to_vec(),
        vec![content_format],
        Vec::new(),
    )
    .map_err(schc_coreconf::PacketError::Coap)?
    .to_vec();
    Ipv6UdpCoapPacket::new(
        request.destination(),
        request.source(),
        request.destination_port(),
        request.source_port(),
        &response,
    )
}
