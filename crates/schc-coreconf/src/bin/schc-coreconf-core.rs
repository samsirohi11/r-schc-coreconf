//! Core process for the localhost SCHC demonstration.

mod common;

use std::io::{self, BufRead, IsTerminal, Write};
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use coap_lite::{MessageClass, Packet, ResponseType};
use common::{bind_raw_link, print_report, Args, OPERATION_TIMEOUT};
use schc_coreconf::{
    context_check_request, decode_context_check_payload, decode_rule_detail_payload,
    decode_rule_list_payload, exchange_management, exchange_management_update, format_rule_detail,
    format_rule_list, parse_rule_duplicate_command, parse_rule_selector, parse_rule_update_command,
    rule_get_request, rule_list_request, ActiveContext, ContextStatus, DuplicateRuleResult,
    InspectionService, Ipv6UdpCoapPacket, LinkRole, SchcLink, TrafficOrigin, TrafficRoute,
    APPLICATION_PORT, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
};

const CONSOLE_POLL: Duration = Duration::from_millis(50);
const MANAGEMENT_MID_MODULUS: u16 = 128;

/// Allocates one MID from the stateless seven-bit reconstruction window.
///
/// Management exchanges are synchronous and have at most one outstanding
/// request, so a completed exchange releases its MID for reuse after the
/// bounded 0..=127 cycle. No value outside that reconstruction window is
/// emitted on the protected link.
fn next_management_message_id(next: &mut u16) -> u16 {
    if *next >= MANAGEMENT_MID_MODULUS {
        *next = 0;
    }
    let message_id = *next;
    *next = (*next + 1) % MANAGEMENT_MID_MODULUS;
    message_id
}

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-core: ERROR {error}");
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
    let mut inspection = InspectionService::new(active.clone())
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
    let (raw_link, link_local) = bind_raw_link(&args, Some(OPERATION_TIMEOUT))?;
    let app_local = app_socket
        .local_addr()
        .map_err(|error| format!("query application socket: {error}"))?;
    println!("READY core  app={app_local}  link={link_local}");
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if interactive {
        println!("Type 'help' for commands");
        print_prompt()?;
    } else {
        io::stdout()
            .flush()
            .map_err(|error| format!("flush readiness: {error}"))?;
    }

    let commands = stdin_commands();
    let mut request_bytes = vec![0_u8; 65_535];
    let mut next_message_id = 1_u16;
    loop {
        while let Ok(command) = commands.try_recv() {
            match handle_command(
                command.trim(),
                &mut inspection,
                &active,
                &link,
                &raw_link,
                &mut next_message_id,
                args.debug,
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
            if interactive {
                print_prompt()?;
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
        if interactive {
            println!();
        }
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
        print_report(
            schc_coreconf::ReportDirection::Tx,
            encoded.report(),
            args.debug,
        )?;
        raw_link
            .send_frame(encoded.frame())
            .map_err(|error| format!("send request SCHC frame: {error}"))?;

        let received = raw_link
            .recv()
            .map_err(|error| format!("receive response SCHC frame: {error}"))?;
        let decoded = link
            .decode(received.bytes())
            .map_err(|error| format!("decode response SCHC frame: {error}"))?;
        print_report(
            schc_coreconf::ReportDirection::Rx,
            decoded.report(),
            args.debug,
        )?;
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
        io::stdout()
            .flush()
            .map_err(|error| format!("flush operation output: {error}"))?;
        if interactive {
            print_prompt()?;
        }
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

fn print_console_help() {
    println!("Core commands:");
    println!("  context status");
    println!("  context check");
    println!("  rule list <core|device>");
    println!("  rule get <core|device> <value>/<bits>");
    println!("  rule duplicate <source>/<bits> <destination>/<bits> [entry=<index> tv=<value> mo=<identity> cda=<identity> ...]");
    println!("  rule update <value>/<bits> entry=<index> tv=<value> [--if-match]");
    println!("  rule update <value>/<bits> fid=<field> [fp=<position>] [di=<direction>] tv=<value> [--if-match]");
    println!("  help");
    println!("  quit");
}

fn print_prompt() -> Result<(), String> {
    print!("core> ");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush core prompt: {error}"))
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
    inspection: &mut InspectionService,
    active: &std::sync::Arc<schc_coreconf::ActiveContext>,
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    next_message_id: &mut u16,
    debug: bool,
) -> Result<CommandResult, String> {
    if command.is_empty() {
        return Ok(CommandResult::Continue);
    }
    if command == "quit" {
        return Ok(CommandResult::Quit);
    }
    if command == "help" {
        print_console_help();
        io::stdout().flush().map_err(|error| error.to_string())?;
        return Ok(CommandResult::Continue);
    }
    if command.starts_with("rule duplicate") {
        return execute_rule_duplicate(
            command,
            inspection,
            active,
            next_message_id,
            debug,
            |datagram| {
                let request = Ipv6UdpCoapPacket::new(
                    CORE_LOGICAL_ADDRESS,
                    DEVICE_LOGICAL_ADDRESS,
                    schc_coreconf::MANAGEMENT_PORT,
                    schc_coreconf::MANAGEMENT_PORT,
                    datagram,
                )
                .map_err(|error| error.to_string())?;
                let encoded = link
                    .encode(TrafficOrigin::Management, &request)
                    .map_err(|error| error.to_string())?;
                if encoded.report().rule_id != schc_core::RuleId::new(29, 8) {
                    return Err(format!(
                        "duplicate-rule selected {}/{} instead of 29/8",
                        encoded.report().rule_id.value(),
                        encoded.report().rule_id.bit_len()
                    ));
                }
                print_report(schc_coreconf::ReportDirection::Tx, encoded.report(), debug)?;
                raw_link
                    .send_frame(encoded.frame())
                    .map_err(|error| error.to_string())
            },
            |service, datagram| {
                service
                    .handle_datagram_no_response(datagram)
                    .map_err(|error| error.to_string())
            },
        );
    }
    if command.starts_with("rule update") {
        return execute_rule_update(
            command,
            inspection,
            active,
            next_message_id,
            debug,
            |datagram| {
                let (code, exchange) = exchange_management_update(link, raw_link, datagram)
                    .map_err(|error| error.to_string())?;
                print_report(
                    schc_coreconf::ReportDirection::Tx,
                    &exchange.request_report,
                    debug,
                )?;
                print_report(
                    schc_coreconf::ReportDirection::Rx,
                    &exchange.response_report,
                    debug,
                )?;
                Ok(code)
            },
            |service, datagram| {
                service
                    .handle_datagram(datagram)
                    .map_err(|error| error.to_string())
            },
        );
    }
    if command.starts_with("context set") {
        println!(
            "ERROR context-wide mutation is unsupported; use rule update for targeted changes"
        );
        return Ok(CommandResult::Unavailable);
    }
    if command == "context status" {
        let snapshot = active.snapshot();
        let status = ContextStatus::from_snapshot(&snapshot);
        println!(
            "CONTEXT generation={}  rules={}",
            status.generation, status.rule_count
        );
        if debug {
            println!("  tag={}  digest={}", status.tag, hex_digest(status.digest));
        }
        return Ok(CommandResult::Successful);
    }
    if command == "context check" {
        let tag = active.snapshot().tag();
        let message_id = next_management_message_id(next_message_id);
        let coap = context_check_request(tag, message_id, &[]);
        let exchange = exchange_management(link, raw_link, &coap)
            .map_err(|error| format!("context check failed: {error}"))?;
        print_report(
            schc_coreconf::ReportDirection::Tx,
            &exchange.request_report,
            debug,
        )?;
        print_report(
            schc_coreconf::ReportDirection::Rx,
            &exchange.response_report,
            debug,
        )?;
        let result = decode_context_check_payload(&exchange.payload, tag)
            .map_err(|error| format!("context check response failed: {error}"))?;
        if result.equal {
            println!("OK context check  equal");
        } else {
            println!("ERROR context check  mismatch");
        }
        if debug {
            println!(
                "  core tag={}  device tag={}",
                result.core_tag, result.device_tag
            );
        }
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
        let message_id = next_management_message_id(next_message_id);
        let coap = rule_list_request(message_id, &[])
            .map_err(|error| format!("device rule list request failed: {error}"))?;
        let exchange = exchange_management(link, raw_link, &coap)
            .map_err(|error| format!("device rule list failed: {error}"))?;
        let summaries = decode_rule_list_payload(&exchange.payload, inspection.model())
            .map_err(|error| format!("device rule list response failed: {error}"))?;
        print_report(
            schc_coreconf::ReportDirection::Tx,
            &exchange.request_report,
            debug,
        )?;
        print_report(
            schc_coreconf::ReportDirection::Rx,
            &exchange.response_report,
            debug,
        )?;
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
            let message_id = next_management_message_id(next_message_id);
            let coap = rule_get_request(selector, message_id, &[])
                .map_err(|error| format!("device rule get request failed: {error}"))?;
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
            print_report(
                schc_coreconf::ReportDirection::Tx,
                &exchange.request_report,
                debug,
            )?;
            print_report(
                schc_coreconf::ReportDirection::Rx,
                &exchange.response_report,
                debug,
            )?;
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

#[allow(clippy::too_many_lines)]
fn execute_rule_duplicate<SendDevice, ApplyLocal>(
    command: &str,
    inspection: &mut InspectionService,
    active: &std::sync::Arc<schc_coreconf::ActiveContext>,
    next_message_id: &mut u16,
    debug: bool,
    send_device: SendDevice,
    apply_local: ApplyLocal,
) -> Result<CommandResult, String>
where
    SendDevice: FnOnce(&[u8]) -> Result<(), String>,
    ApplyLocal: FnOnce(&mut InspectionService, &[u8]) -> Result<Option<Vec<u8>>, String>,
{
    let request = parse_rule_duplicate_command(command).map_err(|error| {
        format!("duplicate rejected: {error}; device=not-sent; local=unchanged")
    })?;
    let selector = format!(
        "{}/{} -> {}/{}",
        request.source.value,
        request.source.bits,
        request.destination.value,
        request.destination.bits
    );
    let datagram = inspection
        .duplicate_rule_datagram(&request, next_management_message_id(next_message_id))
        .map_err(|error| {
            format!("duplicate {selector} rejected: {error}; device=not-sent; local=unchanged")
        })?;
    send_device(&datagram).map_err(|error| {
        format!("duplicate {selector}  remote=not-sent  local=unchanged: {error}")
    })?;
    let before_generation = active.generation();
    let response = apply_local(inspection, &datagram).map_err(|error| {
        format!("duplicate {selector}  remote=unacknowledged  local=failed: {error}; possible divergence - run context check")
    })?;
    if response.is_some() {
        return Err(format!(
            "duplicate {selector}  remote=unacknowledged  local=failed: local handler unexpectedly produced a response; possible divergence - run context check"
        ));
    }
    let after_generation = active.generation();
    let tag = inspection.status().tag;
    let result = if after_generation == before_generation + 1 {
        DuplicateRuleResult::Applied {
            generation: after_generation,
            tag,
        }
    } else {
        DuplicateRuleResult::Idempotent {
            generation: after_generation,
            tag,
        }
    };
    match result {
        DuplicateRuleResult::Applied { generation, tag } => {
            println!("OK duplicate {selector}  local=installed  remote=unacknowledged");
            if debug {
                println!("  generation={generation}  tag={tag}");
            }
        }
        DuplicateRuleResult::Idempotent { generation, tag } => {
            println!("OK duplicate {selector}  local=idempotent  remote=unacknowledged");
            if debug {
                println!("  generation={generation}  tag={tag}");
            }
        }
    }
    Ok(CommandResult::Successful)
}

fn execute_rule_update<SendDevice, ApplyLocal>(
    command: &str,
    inspection: &mut InspectionService,
    active: &std::sync::Arc<ActiveContext>,
    next_message_id: &mut u16,
    debug: bool,
    send_device: SendDevice,
    apply_local: ApplyLocal,
) -> Result<CommandResult, String>
where
    SendDevice: FnOnce(&[u8]) -> Result<u8, String>,
    ApplyLocal: FnOnce(&mut InspectionService, &[u8]) -> Result<Vec<u8>, String>,
{
    let request = parse_rule_update_command(command).map_err(|error| {
        format!("rule update rejected: {error}; device=not-sent; local=unchanged")
    })?;
    let snapshot = active.snapshot();
    if snapshot.protected_rules().contains(request.rule.rule_id()) {
        return Err(format!(
            "rule update {}/{} rejected: protected RuleID; device=not-sent; local=unchanged",
            request.rule.value, request.rule.bits
        ));
    }
    let detail = inspection
        .detail_from_snapshot(&snapshot, request.rule)
        .map_err(|error| {
            format!(
                "rule update {}/{} rejected: {error}; device=not-sent; local=unchanged",
                request.rule.value, request.rule.bits
            )
        })?;
    let update = request
        .resolve_target_value(&detail, snapshot.tree(), inspection.model())
        .map_err(|error| {
            format!(
                "rule update {}/{} rejected: {error}; device=not-sent; local=unchanged",
                request.rule.value, request.rule.bits
            )
        })?;
    let base_tag = request.if_match.then_some(snapshot.tag());
    let message_id = next_management_message_id(next_message_id);
    let datagram = update
        .ipatch_datagram(message_id, &[], base_tag)
        .map_err(|error| {
            format!(
                "rule update {}/{} entry={} rejected: {error}; device=not-sent; local=unchanged",
                request.rule.value, request.rule.bits, update.entry_index
            )
        })?;

    let device_code = send_device(&datagram).map_err(|error| {
        format!(
            "rule update {}/{} entry={} device exchange failed: {error}; local=unchanged",
            request.rule.value, request.rule.bits, update.entry_index
        )
    })?;
    if device_code != 68 {
        return Err(format!(
            "rule update {}/{} entry={} device={} rejected; local=not-attempted; local=unchanged",
            request.rule.value,
            request.rule.bits,
            update.entry_index,
            format_coap_code(device_code)
        ));
    }

    let local_datagram = apply_local(inspection, &datagram).map_err(|error| {
        format!(
            "rule update {}/{} entry={} device=2.04; local application failed: {error}; possible divergence - run context check",
            request.rule.value, request.rule.bits, update.entry_index
        )
    })?;
    validate_changed_response(&datagram, &local_datagram).map_err(|error| {
        format!(
            "rule update {}/{} entry={} device=2.04; local response failed: {error}; possible divergence - run context check",
            request.rule.value, request.rule.bits, update.entry_index
        )
    })?;
    let after = active.snapshot();
    let expected_generation = snapshot.generation().checked_add(1).ok_or_else(|| {
        format!(
            "rule update {}/{} entry={} device=2.04; local generation overflow; possible divergence - run context check",
            request.rule.value, request.rule.bits, update.entry_index
        )
    })?;
    if after.generation() != expected_generation {
        return Err(format!(
            "rule update {}/{} entry={} device=2.04; local acknowledgement did not publish exactly once (generation={}); possible divergence - run context check",
            request.rule.value,
            request.rule.bits,
            update.entry_index,
            after.generation()
        ));
    }
    println!(
        "OK update {}/{} entry={}  device=changed  local=changed",
        request.rule.value, request.rule.bits, update.entry_index
    );
    if debug {
        println!(
            "  response=2.04  generation={}  tag={}",
            after.generation(),
            after.tag()
        );
    }
    Ok(CommandResult::Successful)
}

fn validate_changed_response(
    request_datagram: &[u8],
    response_datagram: &[u8],
) -> Result<(), String> {
    let request = Packet::from_bytes(request_datagram)
        .map_err(|error| format!("malformed local request correlation: {error}"))?;
    let response = Packet::from_bytes(response_datagram)
        .map_err(|error| format!("malformed local CoAP response: {error}"))?;
    if response.header.code != MessageClass::Response(ResponseType::Changed) {
        return Err(format!(
            "expected local CoAP 2.04 Changed, got {:?}",
            response.header.code
        ));
    }
    if response.header.message_id != request.header.message_id
        || response.get_token() != request.get_token()
    {
        return Err("local CoAP response did not correlate".to_owned());
    }
    Ok(())
}

fn format_coap_code(code: u8) -> String {
    format!("{}.{:02}", code >> 5, code & 0x1f)
}

fn hex_digest(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::Arc;

    use coap_lite::{MessageClass, MessageType, Packet, RequestType, ResponseType};
    use schc_coreconf::{
        protected_management_rule_ids, ActiveContext, InspectionService, PreparedContext,
        ProtectionPolicy,
    };
    use schc_runtime::{DeviceId, DeviceProfile};

    use super::{execute_rule_update, validate_changed_response, CommandResult};

    const SID: &str = include_str!("../../../../fixtures/demo/ietf-schc@2026-05-07.sid");
    const SOR: &[u8] = include_bytes!("../../../../fixtures/demo/initial.sor");

    fn active(device: &str) -> Arc<ActiveContext> {
        let prepared = PreparedContext::from_sor_with_policy(
            SID,
            SOR,
            DeviceId::new(device).expect("device"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .expect("prepared");
        Arc::new(ActiveContext::new(prepared))
    }

    #[test]
    fn management_mid_allocator_reuses_the_bounded_reconstruction_window() {
        let mut next = 127;
        assert_eq!(super::next_management_message_id(&mut next), 127);
        assert_eq!(next, 0);
        assert_eq!(super::next_management_message_id(&mut next), 0);
        assert_eq!(next, 1);
    }

    #[test]
    fn device_rejection_does_not_attempt_local_application() {
        let core = active("core-rejection");
        let mut inspection = InspectionService::new(Arc::clone(&core)).expect("inspection");
        let before = core.snapshot();
        let mut device_sent = false;
        let mut local_called = false;
        let result = execute_rule_update(
            "rule update 20/8 entry=9 tv=6",
            &mut inspection,
            &core,
            &mut 1,
            false,
            |_datagram| {
                device_sent = true;
                Ok(128)
            },
            |_service, _datagram| {
                local_called = true;
                Err("local must not run".to_owned())
            },
        );
        let error = result.expect_err("device rejection");
        assert!(error.contains("device=4.00"));
        assert!(error.contains("local=not-attempted"));
        assert!(device_sent);
        assert!(!local_called);
        let after = core.snapshot();
        assert_eq!(after.tree(), before.tree());
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.tag(), before.tag());
    }

    #[test]
    fn device_success_precedes_local_publication_and_contexts_match() {
        let core = active("core-success");
        let device = active("device-success");
        let mut core_inspection =
            InspectionService::new(Arc::clone(&core)).expect("core inspection");
        let mut device_inspection =
            InspectionService::new(Arc::clone(&device)).expect("device inspection");
        let sequence = RefCell::new(Vec::new());
        let mut next_message_id = 10;
        let result = execute_rule_update(
            "rule update 20/8 entry=9 tv=6 --if-match",
            &mut core_inspection,
            &core,
            &mut next_message_id,
            false,
            |datagram| {
                sequence.borrow_mut().push("device".to_owned());
                let response = device_inspection
                    .handle_datagram(datagram)
                    .expect("device response");
                let packet = Packet::from_bytes(&response).expect("device packet");
                assert_eq!(
                    packet.header.code,
                    MessageClass::Response(ResponseType::Changed)
                );
                Ok(68)
            },
            |service, datagram| {
                sequence.borrow_mut().push("local".to_owned());
                service
                    .handle_datagram(datagram)
                    .map_err(|error| error.to_string())
            },
        );
        assert_eq!(result.expect("update success"), CommandResult::Successful);
        assert_eq!(sequence.into_inner(), ["device", "local"]);
        let core_after = core.snapshot();
        let device_after = device.snapshot();
        assert_eq!(core_after.tree(), device_after.tree());
        assert_eq!(core_after.tag(), device_after.tag());
        assert_eq!(core_after.generation(), 2);
        assert_eq!(device_after.generation(), 2);
        assert_eq!(
            core_after.tree()["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"],
            "AAAAAAAAAAY="
        );
    }

    #[test]
    fn protected_update_is_rejected_before_device_send() {
        let core = active("core-protected");
        let mut inspection = InspectionService::new(Arc::clone(&core)).expect("inspection");
        let before = core.snapshot();
        let mut device_sent = false;
        let result = execute_rule_update(
            "rule update 16/8 entry=0 tv=6",
            &mut inspection,
            &core,
            &mut 1,
            false,
            |_datagram| {
                device_sent = true;
                Ok(68)
            },
            |_service, _datagram| panic!("local must not run"),
        );
        let error = result.expect_err("protected update");
        assert!(error.contains("protected RuleID"));
        assert!(!device_sent);
        let after = core.snapshot();
        assert_eq!(after.tree(), before.tree());
        assert_eq!(after.generation(), before.generation());
    }

    #[test]
    fn local_changed_response_rejects_wrong_mid_or_token() {
        let mut request = Packet::new();
        request.header.message_id = 41;
        request.header.code = MessageClass::Request(RequestType::IPatch);
        request.header.set_type(MessageType::Confirmable);
        request.set_token(Vec::new());
        let request_bytes = request.to_bytes().expect("request");

        let mut wrong_mid = Packet::new();
        wrong_mid.header.message_id = 42;
        wrong_mid.header.code = MessageClass::Response(ResponseType::Changed);
        wrong_mid.header.set_type(MessageType::Acknowledgement);
        wrong_mid.set_token(Vec::new());
        assert!(validate_changed_response(
            &request_bytes,
            &wrong_mid.to_bytes().expect("wrong MID response")
        )
        .is_err());

        let mut wrong_token = Packet::new();
        wrong_token.header.message_id = 41;
        wrong_token.header.code = MessageClass::Response(ResponseType::Changed);
        wrong_token.header.set_type(MessageType::Acknowledgement);
        wrong_token.set_token(vec![1]);
        assert!(validate_changed_response(
            &request_bytes,
            &wrong_token.to_bytes().expect("wrong token response")
        )
        .is_err());
    }

    #[test]
    fn local_failure_after_device_success_reports_possible_divergence() {
        let core = active("core-divergence");
        let mut inspection = InspectionService::new(Arc::clone(&core)).expect("inspection");
        let before = core.snapshot();
        let mut device_sent = false;
        let result = execute_rule_update(
            "rule update 20/8 entry=9 tv=6",
            &mut inspection,
            &core,
            &mut 1,
            false,
            |_datagram| {
                device_sent = true;
                Ok(68)
            },
            |_service, _datagram| Err("forced local failure".to_owned()),
        );
        let error = result.expect_err("local failure");
        assert!(device_sent);
        assert!(error.contains("possible divergence"));
        assert!(error.contains("run context check"));
        let after = core.snapshot();
        assert_eq!(after.tree(), before.tree());
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.tag(), before.tag());
    }
}
