//! Core process for the localhost SCHC demonstration.

mod common;

use std::io::{self, Write};
use std::net::UdpSocket;

use common::{bind_raw_link, print_report, Args, OPERATION_TIMEOUT};
use schc_coreconf::{
    Ipv6UdpCoapPacket, LinkRole, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT,
    CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-core: error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let Some((args, app_bind)) = Args::parse("schc-coreconf-core", true)? else {
        return Ok(());
    };
    let link = SchcLink::new(args.active_context()?, LinkRole::Core);
    let (app_sid, app_data) = args.application_inputs();
    if !app_sid.is_empty() || app_data.is_some() {
        return Err("--app-sid and --app-data are valid only for the device process".to_owned());
    }
    let app_bind = app_bind.ok_or("core arguments require --app-bind")?;
    let app_socket = UdpSocket::bind(app_bind)
        .map_err(|error| format!("bind application socket {app_bind}: {error}"))?;
    app_socket
        .set_read_timeout(Some(OPERATION_TIMEOUT))
        .map_err(|error| format!("set application timeout: {error}"))?;
    let (raw_link, link_local) = bind_raw_link(&args)?;
    let app_local = app_socket
        .local_addr()
        .map_err(|error| format!("query application socket: {error}"))?;
    println!("READY role=core app={app_local} link={link_local}");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;

    let mut request_bytes = vec![0_u8; 65_535];
    loop {
        let (length, application_peer) = app_socket
            .recv_from(&mut request_bytes)
            .map_err(|error| format!("receive application CoAP datagram: {error}"))?;
        let coap = &request_bytes[..length];
        let request = Ipv6UdpCoapPacket::new(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            APPLICATION_PORT,
            APPLICATION_PORT,
            coap,
        )
        .map_err(|error| format!("construct logical request: {error}"))?;
        let encoded = link
            .encode(TrafficOrigin::Application, &request)
            .map_err(|error| format!("encode ordinary request: {error}"))?;
        print_report("CORE TX", encoded.report());
        raw_link
            .send_frame(encoded.frame())
            .map_err(|error| format!("send request SCHC frame: {error}"))?;

        let received = raw_link
            .recv()
            .map_err(|error| format!("receive response SCHC frame: {error}"))?;
        let decoded = link
            .decode(received.bytes())
            .map_err(|error| format!("decode response SCHC frame: {error}"))?;
        print_report("CORE RX", decoded.report());
        if decoded.route() != TrafficRoute::Application {
            return Err("protected response reached the ordinary core path".to_owned());
        }
        let response = decoded.packet();
        if response.source() != DEVICE_LOGICAL_ADDRESS
            || response.destination() != CORE_LOGICAL_ADDRESS
            || response.source_port() != APPLICATION_PORT
            || response.destination_port() != APPLICATION_PORT
        {
            return Err(
                "uplink response had unexpected logical address or port orientation".to_owned(),
            );
        }
        let response_datagram = response.coap_datagram();
        let sent = app_socket
            .send_to(response_datagram, application_peer)
            .map_err(|error| format!("send application CoAP response: {error}"))?;
        if sent != response_datagram.len() {
            return Err(format!(
                "short application response send: expected {}, sent {sent}",
                response_datagram.len()
            ));
        }
        println!("CORE DONE response_bytes={sent} peer={application_peer}");
        io::stdout()
            .flush()
            .map_err(|error| format!("flush operation output: {error}"))?;
        if args.once {
            return Ok(());
        }
    }
}
