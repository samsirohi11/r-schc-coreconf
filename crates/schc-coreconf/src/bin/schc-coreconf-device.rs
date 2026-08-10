//! Device process for the localhost SCHC demonstration.

mod common;

use std::io::{self, Write};

use coap_lite::Packet;
use common::{bind_raw_link, print_report, Args, DEVICE_POLL};
use schc_coreconf::{
    is_duplicate_rule_request, GenericDataService, InspectionService, Ipv6UdpCoapPacket, LinkError,
    LinkRole, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS,
    DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-device: error: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let Some((args, app_bind)) = Args::parse("schc-coreconf-device", false)? else {
        return Ok(());
    };
    if app_bind.is_some() {
        return Err("device process unexpectedly received --app-bind".to_owned());
    }
    let active = args.active_context()?;
    let link = SchcLink::new(active.clone(), LinkRole::Device);
    let mut inspection = InspectionService::new(active)
        .map_err(|error| format!("load management inspection service: {error}"))?;
    let (app_sid, app_data) = args.application_inputs();
    if app_sid.is_empty() {
        return Err("missing required --app-sid".to_owned());
    }
    let app_data = app_data.ok_or("missing required --app-data")?;
    let mut application = GenericDataService::from_files(app_sid, app_data, "c")
        .map_err(|error| format!("load application datastore: {error}"))?;
    let (raw_link, link_local) = bind_raw_link(&args, Some(DEVICE_POLL))?;
    println!("READY role=device link={link_local}");
    println!("WAITING role=device peer={}", args.link_peer);
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;

    loop {
        let received = match raw_link.recv() {
            Ok(received) => received,
            Err(LinkError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(format!("receive request SCHC frame: {error}")),
        };
        let decoded = link
            .decode(received.bytes())
            .map_err(|error| format!("decode request SCHC frame: {error}"))?;
        print_report("DEVICE RX", decoded.report(), args.debug);
        match decoded.route() {
            TrafficRoute::ProtectedManagement => {
                let request = decoded.packet();
                if request.source() != CORE_LOGICAL_ADDRESS
                    || request.destination() != DEVICE_LOGICAL_ADDRESS
                    || request.source_port() != MANAGEMENT_PORT
                    || request.destination_port() != MANAGEMENT_PORT
                {
                    return Err(
                        "management request had unexpected logical address or port orientation"
                            .to_owned(),
                    );
                }
                let duplicate = Packet::from_bytes(request.coap_datagram())
                    .map_err(|error| format!("parse management request: {error}"))?;
                let is_duplicate = is_duplicate_rule_request(decoded.rule_id(), &duplicate);
                if is_duplicate {
                    let before_generation = inspection.status().generation;
                    match inspection.handle_datagram_no_response(request.coap_datagram()) {
                        Ok(None) => {
                            let after_generation = inspection.status().generation;
                            let result = if after_generation == before_generation + 1 {
                                "installed"
                            } else {
                                "idempotent"
                            };
                            println!(
                                "DEVICE PROTECTED rule={}/{} action=duplicate result={} no_response=yes generation={}",
                                decoded.rule_id().value(),
                                decoded.rule_id().bit_len(),
                                result,
                                after_generation
                            );
                        }
                        Ok(Some(_)) => {
                            println!(
                                "DEVICE PROTECTED rule={}/{} action=duplicate result=error error=unexpected-response no_response=yes",
                                decoded.rule_id().value(),
                                decoded.rule_id().bit_len()
                            );
                        }
                        Err(error) => {
                            println!(
                                "DEVICE PROTECTED rule={}/{} action=duplicate result=error error={} no_response=yes generation={}",
                                decoded.rule_id().value(),
                                decoded.rule_id().bit_len(),
                                error,
                                before_generation
                            );
                        }
                    }
                    io::stdout()
                        .flush()
                        .map_err(|error| format!("flush protected report: {error}"))?;
                    if args.once {
                        return Ok(());
                    }
                    continue;
                }
                let response_datagram = inspection
                    .handle_datagram(request.coap_datagram())
                    .map_err(|error| format!("handle management inspection request: {error}"))?;
                let response = Ipv6UdpCoapPacket::new(
                    DEVICE_LOGICAL_ADDRESS,
                    CORE_LOGICAL_ADDRESS,
                    MANAGEMENT_PORT,
                    MANAGEMENT_PORT,
                    &response_datagram,
                )
                .map_err(|error| format!("construct management response: {error}"))?;
                let encoded = link
                    .encode(TrafficOrigin::Management, &response)
                    .map_err(|error| format!("encode management response: {error}"))?;
                if encoded.report().rule_id != schc_core::RuleId::new(17, 8) {
                    return Err("management response did not select RuleID 17/8".to_owned());
                }
                print_report("DEVICE MGMT TX", encoded.report(), args.debug);
                raw_link
                    .send_frame(encoded.frame())
                    .map_err(|error| format!("send management response SCHC frame: {error}"))?;
                println!(
                    "DEVICE PROTECTED rule={}/{} action=inspect",
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
                print_report("DEVICE TX", encoded.report(), args.debug);
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
