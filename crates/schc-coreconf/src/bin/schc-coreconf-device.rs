//! Device process for the localhost SCHC demonstration.

mod common;

use std::io::{self, Write};

use common::{bind_raw_link, print_report, Args};
use schc_coreconf::{
    temporary_ordinary_response, LinkRole, SchcLink, TrafficRoute, DEVICE_LOGICAL_ADDRESS,
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
                let response = temporary_ordinary_response(decoded.packet())
                    .map_err(|error| format!("construct ordinary response: {error}"))?;
                let encoded = link
                    .encode(schc_coreconf::TrafficOrigin::Application, &response)
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
