//! Device process for the localhost SCHC demonstration.

mod common;

use std::io::{self, Write};

use common::{bind_raw_link, print_report, Args};
use schc_coreconf::{
    GenericDataService, Ipv6UdpCoapPacket, LinkRole, SchcLink, TrafficOrigin, TrafficRoute,
    APPLICATION_PORT, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-device: error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let Some((args, app_bind)) = Args::parse("schc-coreconf-device", false)? else {
        return Ok(());
    };
    if app_bind.is_some() {
        return Err("device process unexpectedly received --app-bind".to_owned());
    }
    let link = SchcLink::new(args.active_context()?, LinkRole::Device);
    let (app_sid, app_data) = args.application_inputs();
    if app_sid.is_empty() {
        return Err("missing required --app-sid".to_owned());
    }
    let app_data = app_data.ok_or("missing required --app-data")?;
    let mut application = GenericDataService::from_files(app_sid, app_data, "c")
        .map_err(|error| format!("load application datastore: {error}"))?;
    let (raw_link, link_local) = bind_raw_link(&args)?;
    println!("READY role=device link={link_local}");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;

    loop {
        let received = raw_link
            .recv()
            .map_err(|error| format!("receive request SCHC frame: {error}"))?;
        let decoded = link
            .decode(received.bytes())
            .map_err(|error| format!("decode request SCHC frame: {error}"))?;
        print_report("DEVICE RX", decoded.report());
        match decoded.route() {
            TrafficRoute::ProtectedManagement => {
                println!(
                    "DEVICE PROTECTED rule={}/{} action=deferred",
                    decoded.rule_id().value(),
                    decoded.rule_id().bit_len()
                );
                io::stdout()
                    .flush()
                    .map_err(|error| format!("flush protected report: {error}"))?;
                if args.once {
                    return Ok(());
                }
            }
            TrafficRoute::Application => {
                let request = decoded.packet();
                if request.source() != CORE_LOGICAL_ADDRESS
                    || request.destination() != DEVICE_LOGICAL_ADDRESS
                    || request.source_port() != APPLICATION_PORT
                    || request.destination_port() != APPLICATION_PORT
                {
                    return Err(
                        "application request had unexpected logical address or port orientation"
                            .to_owned(),
                    );
                }
                let response_datagram = application
                    .handle_datagram(decoded.packet().coap_datagram())
                    .map_err(|error| format!("handle application CoAP request: {error}"))?;
                let response = Ipv6UdpCoapPacket::new(
                    DEVICE_LOGICAL_ADDRESS,
                    CORE_LOGICAL_ADDRESS,
                    APPLICATION_PORT,
                    APPLICATION_PORT,
                    &response_datagram,
                )
                .map_err(|error| format!("construct application response: {error}"))?;
                let encoded = link
                    .encode(TrafficOrigin::Application, &response)
                    .map_err(|error| format!("encode ordinary response: {error}"))?;
                print_report("DEVICE TX", encoded.report());
                raw_link
                    .send_frame(encoded.frame())
                    .map_err(|error| format!("send response SCHC frame: {error}"))?;
                println!("DEVICE DONE logical_device={DEVICE_LOGICAL_ADDRESS}");
                io::stdout()
                    .flush()
                    .map_err(|error| format!("flush operation output: {error}"))?;
                if args.once {
                    return Ok(());
                }
            }
        }
    }
}
