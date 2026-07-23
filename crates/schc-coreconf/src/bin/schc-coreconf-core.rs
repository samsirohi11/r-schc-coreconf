//! Core process for the localhost SCHC demonstration.

mod common;

use std::io::{self, BufRead, Write};
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use common::{bind_raw_link, print_report, Args};
use schc_coreconf::{
    context_check_request, decode_context_check_payload, decode_rule_detail_payload,
    decode_rule_list_payload, exchange_management, format_rule_detail, format_rule_list,
    parse_rule_selector, rule_get_request, rule_list_request, ContextStatus, InspectionService,
    Ipv6UdpCoapPacket, LinkRole, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT,
    CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
};

const CONSOLE_POLL: Duration = Duration::from_millis(50);

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-core: error: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let Some((args, app_bind)) = Args::parse("schc-coreconf-core", true)? else {
        return Ok(());
    };
    let active = args.active_context()?;
    let link = SchcLink::new(active.clone(), LinkRole::Core);
    let inspection = InspectionService::new(active.clone())
        .map_err(|error| format!("load management inspection service: {error}"))?;
    let (app_sid, app_data) = args.application_inputs();
    if !app_sid.is_empty() || app_data.is_some() {
        return Err("--app-sid and --app-data are valid only for the device process".to_owned());
    }
    let app_bind = app_bind.ok_or("core arguments require --app-bind")?;
    let app_socket = UdpSocket::bind(app_bind)
        .map_err(|error| format!("bind application socket {app_bind}: {error}"))?;
    app_socket
        .set_read_timeout(Some(CONSOLE_POLL))
        .map_err(|error| format!("set application timeout: {error}"))?;
    let (raw_link, link_local) = bind_raw_link(&args)?;
    let app_local = app_socket
        .local_addr()
        .map_err(|error| format!("query application socket: {error}"))?;
    println!("READY role=core app={app_local} link={link_local}");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;

    let commands = stdin_commands();
    let mut request_bytes = vec![0_u8; 65_535];
    let mut next_message_id = 1_u16;
    loop {
        while let Ok(command) = commands.try_recv() {
            match handle_command(
                command.trim(),
                &inspection,
                &active,
                &link,
                &raw_link,
                &mut next_message_id,
            ) {
                Ok(CommandResult::Quit) => return Ok(()),
                Ok(CommandResult::Successful) if args.once => return Ok(()),
                Ok(
                    CommandResult::Continue
                    | CommandResult::Successful
                    | CommandResult::Unavailable,
                ) => {}
                Err(error) => {
                    println!("ERROR {error}");
                    io::stdout()
                        .flush()
                        .map_err(|flush_error| format!("flush command error: {flush_error}"))?;
                }
            }
        }

        let (length, application_peer) = match app_socket.recv_from(&mut request_bytes) {
            Ok(result) => result,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(format!("receive application CoAP datagram: {error}")),
        };
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
        let response_message = response.coap_message();
        let request_message = request.coap_message();
        if response_message.message_id() != request_message.message_id()
            || response_message.token() != request_message.token()
        {
            return Err("application CoAP response did not correlate".to_owned());
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CommandResult {
    Continue,
    Successful,
    Unavailable,
    Quit,
}

fn stdin_commands() -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
        // EOF is intentionally ignored.  Existing process tests often inherit
        // a closed stdin while application traffic remains valid.
    });
    receiver
}

#[allow(clippy::too_many_lines)]
fn handle_command(
    command: &str,
    inspection: &InspectionService,
    active: &std::sync::Arc<schc_coreconf::ActiveContext>,
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    next_message_id: &mut u16,
) -> Result<CommandResult, String> {
    if command.is_empty() {
        return Ok(CommandResult::Continue);
    }
    if command == "quit" {
        return Ok(CommandResult::Quit);
    }
    if command == "help" {
        println!(
            "commands: context status | context check | rule list core|device | rule get core|device <value>/<bits> | help | quit"
        );
        io::stdout().flush().map_err(|error| error.to_string())?;
        return Ok(CommandResult::Continue);
    }
    if command.starts_with("rule update") || command.starts_with("context set") {
        println!("ERROR management mutation unavailable until Task 7");
        return Ok(CommandResult::Unavailable);
    }
    if command == "context status" {
        let snapshot = active.snapshot();
        let status = ContextStatus::from_snapshot(&snapshot);
        println!(
            "CONTEXT generation={} tag={} digest={} rules={}",
            status.generation,
            status.tag,
            hex_digest(status.digest),
            status.rule_count
        );
        return Ok(CommandResult::Successful);
    }
    if command == "context check" {
        let tag = active.snapshot().tag();
        let token = vec![0xC0];
        let coap = context_check_request(tag, *next_message_id, &token);
        *next_message_id = next_message_id.wrapping_add(1);
        let exchange = exchange_management(link, raw_link, &coap)
            .map_err(|error| format!("context check failed: {error}"))?;
        print_report("CORE MGMT TX", &exchange.request_report);
        print_report("CORE MGMT RX", &exchange.response_report);
        let result = decode_context_check_payload(&exchange.payload, tag)
            .map_err(|error| format!("context check response failed: {error}"))?;
        println!(
            "CONTEXT CHECK {} core_tag={} device_tag={}",
            if result.equal { "equal" } else { "mismatch" },
            result.core_tag,
            result.device_tag
        );
        return Ok(CommandResult::Successful);
    }
    if command == "rule list core" {
        for line in format_rule_list(&inspection.summaries()) {
            println!("{line}");
        }
        return Ok(CommandResult::Successful);
    }
    if let Some(target) = command.strip_prefix("rule list ") {
        if target != "device" && target != "core" {
            return Err("rule list target must be core or device".to_owned());
        }
        if target == "core" {
            for line in format_rule_list(&inspection.summaries()) {
                println!("{line}");
            }
            return Ok(CommandResult::Successful);
        }
        let coap = rule_list_request(*next_message_id, &[0xC1]);
        *next_message_id = next_message_id.wrapping_add(1);
        let exchange = exchange_management(link, raw_link, &coap)
            .map_err(|error| format!("device rule list failed: {error}"))?;
        let summaries = decode_rule_list_payload(&exchange.payload, inspection.model())
            .map_err(|error| format!("device rule list response failed: {error}"))?;
        print_report("CORE MGMT TX", &exchange.request_report);
        print_report("CORE MGMT RX", &exchange.response_report);
        for line in format_rule_list(&summaries) {
            println!("{line}");
        }
        return Ok(CommandResult::Successful);
    }
    if let Some(rest) = command.strip_prefix("rule get ") {
        let mut words = rest.split_whitespace();
        let side = words.next().ok_or("rule get requires core or device")?;
        let selector = parse_rule_selector(words.next().ok_or("rule get requires selector")?)
            .map_err(|error| error.to_string())?;
        if words.next().is_some() {
            return Err("rule get accepts exactly one selector".to_owned());
        }
        if side == "device" {
            let coap = rule_get_request(selector, *next_message_id, &[0xC2]);
            *next_message_id = next_message_id.wrapping_add(1);
            let exchange = exchange_management(link, raw_link, &coap)
                .map_err(|error| format!("device rule get failed: {error}"))?;
            let detail = decode_rule_detail_payload(
                &exchange.payload,
                inspection.model(),
                inspection.sid_registry(),
                inspection.sid_json(),
                selector,
            )
            .map_err(|error| format!("device rule get response failed: {error}"))?;
            print_report("CORE MGMT TX", &exchange.request_report);
            print_report("CORE MGMT RX", &exchange.response_report);
            for line in format_rule_detail(&detail) {
                println!("{line}");
            }
            return Ok(CommandResult::Successful);
        } else if side != "core" {
            return Err("rule get target must be core or device".to_owned());
        }
        let detail = inspection
            .detail(selector)
            .map_err(|error| error.to_string())?;
        for line in format_rule_detail(&detail) {
            println!("{line}");
        }
        return Ok(CommandResult::Successful);
    }
    println!("ERROR unknown command; use help");
    Ok(CommandResult::Continue)
}

fn hex_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
