//! Core process for the localhost SCHC demonstration.

mod common;

use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use coap_lite::{MessageClass, Packet, ResponseType};
use common::{bind_raw_link, print_report, Args};
use schc_coreconf::{
    context_check_request, decode_context_check_payload, decode_rule_detail_payload,
    decode_rule_list_payload, format_rule_detail, format_rule_list, parse_rule_duplicate_command,
    parse_rule_selector, parse_rule_update_command, rule_get_request, rule_list_request,
    ActiveContext, ContextStatus, DuplicateRuleResult, InspectionService, Ipv6UdpCoapPacket,
    LinkRole, PacketEventLoop, PacketPoll, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT,
    CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
};
#[cfg(target_os = "linux")]
use schc_runtime::linux_tun::{LinuxTunConfig, LinuxTunDevice};
use schc_runtime::packet::PacketDevice;
use thiserror::Error;

const RAW_POLL: Duration = Duration::from_millis(50);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
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

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), String> {
    Err("schc-coreconf-core requires Linux TUN support".to_owned())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn run() -> Result<(), String> {
    let Some(args) = Args::parse("schc-coreconf-core", true)? else {
        return Ok(());
    };
    let active = args.active_context()?;
    let link = SchcLink::new(active.clone(), LinkRole::Core);
    let mut inspection = InspectionService::new(active.clone())
        .map_err(|error| format!("load management inspection service: {error}"))?;
    let tun = LinuxTunDevice::create(LinuxTunConfig::new(&args.tun_name, args.tun_mtu))
        .map_err(|error| format!("create TUN: {error}"))?;
    let actual_tun_name = tun.interface_name().to_owned();
    let actual_tun_mtu = tun.mtu();
    let mut packet_loop = PacketEventLoop::new(tun);
    let (raw_link, link_local) = bind_raw_link(&args, Some(RAW_POLL))?;
    println!(
        "READY core  tun_name={actual_tun_name}  mtu={actual_tun_mtu}  link={link_local}  peer={}",
        args.link_peer
    );
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
    let mut next_message_id = 1_u16;
    loop {
        if let Ok(command) = commands.try_recv() {
            match handle_command(
                command.trim(),
                &mut inspection,
                &active,
                &link,
                &raw_link,
                &mut packet_loop,
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

        if let PacketPoll::Packet(packet) = packet_loop.poll().map_err(|error| error.to_string())? {
            let completed = match process_core_tun_packet(&link, &raw_link, &packet, args.debug) {
                Ok(()) => true,
                Err(CorePacketError::Drop(error)) => {
                    println!("ERROR {error}");
                    false
                }
                Err(CorePacketError::Fatal(error)) => return Err(error),
            };
            if args.once && completed {
                return Ok(());
            }
        }
        match raw_link.recv() {
            Ok(received) => {
                match process_core_raw_frame(
                    &link,
                    &mut packet_loop,
                    received.bytes(),
                    args.debug,
                    None,
                ) {
                    Ok(CoreFrameResult::Application) if args.once => return Ok(()),
                    Ok(CoreFrameResult::Application | CoreFrameResult::Management(_)) => {}
                    Err(CorePacketError::Drop(error)) => println!("ERROR {error}"),
                    Err(CorePacketError::Fatal(error)) => return Err(error),
                }
            }
            Err(schc_coreconf::LinkError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => println!("ERROR receive SCHC frame: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
enum CorePacketError {
    #[error("{0}")]
    Drop(String),
    #[error("{0}")]
    Fatal(String),
}

#[cfg(target_os = "linux")]
fn process_core_tun_packet(
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    bytes: &[u8],
    debug: bool,
) -> Result<(), CorePacketError> {
    let packet = Ipv6UdpCoapPacket::parse(bytes)
        .map_err(|error| CorePacketError::Drop(format!("drop malformed TUN packet: {error}")))?;
    if packet.source() != CORE_LOGICAL_ADDRESS
        || packet.destination() != DEVICE_LOGICAL_ADDRESS
        || packet.source_port() != APPLICATION_PORT
        || packet.destination_port() != APPLICATION_PORT
    {
        return Err(CorePacketError::Drop(
            "drop unsupported TUN application orientation".to_owned(),
        ));
    }
    let encoded = link
        .encode(TrafficOrigin::Application, &packet)
        .map_err(|error| {
            CorePacketError::Drop(format!("encode TUN application packet: {error}"))
        })?;
    print_report(schc_coreconf::ReportDirection::Tx, encoded.report(), debug)
        .map_err(CorePacketError::Fatal)?;
    raw_link
        .send_frame(encoded.frame())
        .map_err(|error| CorePacketError::Fatal(format!("send application SCHC frame: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum CoreFrameResult {
    Application,
    Management(Box<(u8, schc_coreconf::ManagementExchange)>),
}

#[cfg(target_os = "linux")]
fn process_core_raw_frame<D: PacketDevice>(
    link: &SchcLink,
    packet_loop: &mut PacketEventLoop<D>,
    frame: &[u8],
    debug: bool,
    prepared: Option<&schc_coreconf::PreparedManagementRequest>,
) -> Result<CoreFrameResult, CorePacketError> {
    let decoded = link
        .decode(frame)
        .map_err(|error| CorePacketError::Drop(format!("drop malformed SCHC frame: {error}")))?;
    print_report(schc_coreconf::ReportDirection::Rx, decoded.report(), debug)
        .map_err(CorePacketError::Fatal)?;
    if let Some(prepared) = prepared {
        if decoded.route() == TrafficRoute::ProtectedManagement {
            return schc_coreconf::validate_management_response(prepared, &decoded)
                .map(|exchange| CoreFrameResult::Management(Box::new(exchange)))
                .map_err(|error| {
                    CorePacketError::Drop(format!("ignore unrelated management response: {error}"))
                });
        }
    }
    if decoded.route() != TrafficRoute::Application {
        return Err(CorePacketError::Drop(
            "drop unrelated protected SCHC frame".to_owned(),
        ));
    }
    let response = decoded.packet();
    if response.source() != DEVICE_LOGICAL_ADDRESS
        || response.destination() != CORE_LOGICAL_ADDRESS
        || response.source_port() != APPLICATION_PORT
        || response.destination_port() != APPLICATION_PORT
    {
        return Err(CorePacketError::Drop(
            "drop unsupported SCHC application orientation".to_owned(),
        ));
    }
    packet_loop.write(response.as_bytes()).map_err(|error| {
        CorePacketError::Fatal(format!("write application packet to TUN: {error}"))
    })?;
    Ok(CoreFrameResult::Application)
}

#[cfg(target_os = "linux")]
fn wait_management_response<D: PacketDevice>(
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    packet_loop: &mut PacketEventLoop<D>,
    prepared: &schc_coreconf::PreparedManagementRequest,
    debug: bool,
    timeout: Duration,
) -> Result<(u8, schc_coreconf::ManagementExchange), String> {
    raw_link
        .send_frame(prepared.frame())
        .map_err(|error| format!("send management SCHC frame: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "management response timeout after {} ms",
                timeout.as_millis()
            ));
        }
        if let PacketPoll::Packet(packet) = packet_loop.poll().map_err(|error| error.to_string())? {
            match process_core_tun_packet(link, raw_link, &packet, debug) {
                Ok(()) => {}
                Err(CorePacketError::Drop(error)) => println!("ERROR {error}"),
                Err(CorePacketError::Fatal(error)) => return Err(error),
            }
        }
        match raw_link.recv() {
            Ok(received) => {
                match process_core_raw_frame(
                    link,
                    packet_loop,
                    received.bytes(),
                    debug,
                    Some(prepared),
                ) {
                    Ok(CoreFrameResult::Management(exchange)) => return Ok(*exchange),
                    Ok(CoreFrameResult::Application) => {}
                    Err(CorePacketError::Drop(error)) => println!("ERROR {error}"),
                    Err(CorePacketError::Fatal(error)) => return Err(error),
                }
            }
            Err(schc_coreconf::LinkError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("receive management SCHC frame: {error}")),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "management response timeout after {} ms",
                timeout.as_millis()
            ));
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

#[cfg(target_os = "linux")]
fn exchange_management_routed<D: PacketDevice>(
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    packet_loop: &mut PacketEventLoop<D>,
    datagram: &[u8],
    debug: bool,
) -> Result<(u8, schc_coreconf::ManagementExchange), String> {
    let prepared = schc_coreconf::prepare_management_request(link, datagram)
        .map_err(|error| error.to_string())?;
    print_report(schc_coreconf::ReportDirection::Tx, prepared.report(), debug)?;
    wait_management_response(
        link,
        raw_link,
        packet_loop,
        &prepared,
        debug,
        OPERATION_TIMEOUT,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle_command<D: PacketDevice>(
    command: &str,
    inspection: &mut InspectionService,
    active: &std::sync::Arc<schc_coreconf::ActiveContext>,
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    packet_loop: &mut PacketEventLoop<D>,
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
                let (code, _exchange) =
                    exchange_management_routed(link, raw_link, packet_loop, datagram, debug)?;
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
        let (_, exchange) = exchange_management_routed(link, raw_link, packet_loop, &coap, debug)
            .map_err(|error| format!("context check failed: {error}"))?;
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
        let (_, exchange) = exchange_management_routed(link, raw_link, packet_loop, &coap, debug)
            .map_err(|error| format!("device rule list failed: {error}"))?;
        let summaries = decode_rule_list_payload(&exchange.payload, inspection.model())
            .map_err(|error| format!("device rule list response failed: {error}"))?;
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
            let (_, exchange) =
                exchange_management_routed(link, raw_link, packet_loop, &coap, debug)
                    .map_err(|error| format!("device rule get failed: {error}"))?;
            let detail = decode_rule_detail_payload(
                &exchange.payload,
                inspection.model(),
                inspection.sid_registry(),
                inspection.sid_json(),
                selector,
            )
            .map_err(|error| format!("device rule get response failed: {error}"))?;
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
    use std::collections::VecDeque;
    use std::io;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use coap_lite::{MessageClass, MessageType, Packet, RequestType, ResponseType};
    use schc_core::RuleId;
    use schc_coreconf::{
        context_check_request, protected_management_rule_ids, temporary_ordinary_response,
        ActiveContext, InspectionService, Ipv6UdpCoapPacket, LinkOperation, LinkRole,
        PacketEventLoop, PreparedContext, ProtectionPolicy, RawUdpLink, SchcLink, TrafficOrigin,
        TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS,
    };
    use schc_runtime::packet::{PacketDevice, PacketDeviceError};
    use schc_runtime::{DeviceId, DeviceProfile};

    use super::{
        execute_rule_update, process_core_raw_frame, process_core_tun_packet,
        validate_changed_response, wait_management_response, CommandResult, CoreFrameResult,
        CorePacketError,
    };

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

    #[cfg(target_os = "linux")]
    struct FakePacketDevice {
        reads: VecDeque<Result<Vec<u8>, PacketDeviceError>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        write_limit: Option<usize>,
    }

    #[cfg(target_os = "linux")]
    impl PacketDevice for FakePacketDevice {
        fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError> {
            self.reads
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::WouldBlock).into()))
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PacketDeviceError> {
            self.writes
                .lock()
                .expect("writes lock")
                .push(packet.to_vec());
            Ok(self.write_limit.unwrap_or(packet.len()))
        }
    }

    #[cfg(target_os = "linux")]
    fn fake_device(
        reads: Vec<Result<Vec<u8>, PacketDeviceError>>,
    ) -> (FakePacketDevice, Arc<Mutex<Vec<Vec<u8>>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            FakePacketDevice {
                reads: reads.into_iter().collect(),
                writes: Arc::clone(&writes),
                write_limit: None,
            },
            writes,
        )
    }

    #[cfg(target_os = "linux")]
    fn loopback_pair() -> (RawUdpLink, RawUdpLink) {
        let first_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("first");
        let second_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("second");
        let first_address = first_socket.local_addr().expect("first address");
        let second_address = second_socket.local_addr().expect("second address");
        let first = RawUdpLink::from_socket(first_socket, second_address).expect("first link");
        let second = RawUdpLink::from_socket(second_socket, first_address).expect("second link");
        first
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("first timeout");
        second
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("second timeout");
        (first, second)
    }

    #[cfg(target_os = "linux")]
    fn coap_request(message_id: u16) -> Vec<u8> {
        schc_coreconf::CoapMessage::from_parts(
            1,
            0,
            1,
            message_id,
            vec![0xaa],
            vec![schc_coreconf::CoapOption::new(11, b"demo".to_vec()).expect("option")],
            Vec::new(),
        )
        .expect("CoAP request")
        .to_vec()
    }

    #[cfg(target_os = "linux")]
    fn application_request(message_id: u16) -> Ipv6UdpCoapPacket {
        Ipv6UdpCoapPacket::new(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            APPLICATION_PORT,
            APPLICATION_PORT,
            &coap_request(message_id),
        )
        .expect("application request")
    }

    #[cfg(target_os = "linux")]
    fn management_response(
        request: &Ipv6UdpCoapPacket,
        service: &mut InspectionService,
    ) -> Ipv6UdpCoapPacket {
        let response_datagram = service
            .handle_datagram(request.coap_datagram())
            .expect("management response");
        Ipv6UdpCoapPacket::new(
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            schc_coreconf::MANAGEMENT_PORT,
            schc_coreconf::MANAGEMENT_PORT,
            &response_datagram,
        )
        .expect("management response packet")
    }

    #[test]
    fn management_mid_allocator_reuses_the_bounded_reconstruction_window() {
        let mut next = 127;
        assert_eq!(super::next_management_message_id(&mut next), 127);
        assert_eq!(next, 0);
        assert_eq!(super::next_management_message_id(&mut next), 0);
        assert_eq!(next, 1);
    }

    #[cfg(target_os = "linux")]
    struct IdlePacketDevice;

    #[cfg(target_os = "linux")]
    impl PacketDevice for IdlePacketDevice {
        fn read_packet(&mut self) -> Result<Vec<u8>, PacketDeviceError> {
            Err(io::Error::from(io::ErrorKind::WouldBlock).into())
        }

        fn write_packet(&mut self, packet: &[u8]) -> Result<usize, PacketDeviceError> {
            Ok(packet.len())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn management_wait_has_a_testable_bounded_deadline_and_sends_once() {
        let active = active("core-timeout");
        let link = SchcLink::new(Arc::clone(&active), LinkRole::Core);
        let request = context_check_request(active.snapshot().tag(), 1, &[]);
        let prepared = schc_coreconf::prepare_management_request(&link, &request)
            .expect("prepare management request");
        let receiver = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("receiver");
        let receiver_address = receiver.local_addr().expect("receiver address");
        let sender = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("sender");
        let raw =
            schc_coreconf::RawUdpLink::from_socket(sender, receiver_address).expect("raw link");
        raw.set_read_timeout(Some(Duration::from_millis(1)))
            .expect("short timeout");
        let mut packets = PacketEventLoop::new(IdlePacketDevice);
        let error = super::wait_management_response(
            &link,
            &raw,
            &mut packets,
            &prepared,
            false,
            Duration::from_millis(5),
        )
        .expect_err("missing response must time out");
        assert!(error.contains("management response timeout"));
        let mut frame = [0_u8; 2048];
        receiver
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("receiver timeout");
        let (length, _) = receiver.recv_from(&mut frame).expect("one request");
        assert_eq!(&frame[..length], prepared.frame().bytes());
        assert!(
            receiver.recv_from(&mut frame).is_err(),
            "request was resent"
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn core_tun_application_request_reaches_peer_as_raw_schc_frame() {
        let core = SchcLink::new(active("core-tun-request"), LinkRole::Core);
        let device = SchcLink::new(active("device-tun-request"), LinkRole::Device);
        let request = application_request(0x1201);
        let (raw, peer) = loopback_pair();

        process_core_tun_packet(&core, &raw, request.as_bytes(), false).expect("forward request");
        let received = peer.recv().expect("raw request");
        let decoded = device.decode(received.bytes()).expect("decode request");
        assert_eq!(decoded.route(), TrafficRoute::Application);
        assert_eq!(decoded.rule_id(), RuleId::new(25, 8));
        assert_eq!(
            decoded.report().operation,
            schc_coreconf::LinkOperation::Decode
        );
        assert_eq!(decoded.packet().as_bytes(), request.as_bytes());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_raw_application_response_reaches_tun_byte_for_byte() {
        let core = SchcLink::new(active("core-raw-response"), LinkRole::Core);
        let device = SchcLink::new(active("device-raw-response"), LinkRole::Device);
        let request = application_request(0x1202);
        let response = temporary_ordinary_response(&request).expect("response");
        let frame = device
            .encode(TrafficOrigin::Application, &response)
            .expect("encode response");
        let (fake, writes) = fake_device(Vec::new());
        let mut packet_loop = PacketEventLoop::new(fake);

        let result =
            process_core_raw_frame(&core, &mut packet_loop, frame.frame().bytes(), false, None)
                .expect("process response");
        assert!(matches!(result, CoreFrameResult::Application));
        assert_eq!(
            writes.lock().expect("writes lock").as_slice(),
            &[response.to_vec()]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_management_response_isolated_from_tun_and_owns_one_rx_report() {
        let core_context = active("core-management-isolation");
        let device_context = active("device-management-isolation");
        let core = SchcLink::new(Arc::clone(&core_context), LinkRole::Core);
        let device = SchcLink::new(Arc::clone(&device_context), LinkRole::Device);
        let request_datagram = context_check_request(core_context.snapshot().tag(), 7, &[]);
        let prepared = schc_coreconf::prepare_management_request(&core, &request_datagram)
            .expect("prepare request");
        let mut service = InspectionService::new(Arc::clone(&device_context)).expect("service");
        let response = management_response(
            &Ipv6UdpCoapPacket::parse(&prepared.report().packet_bytes).expect("request packet"),
            &mut service,
        );
        let frame = device
            .encode(TrafficOrigin::Management, &response)
            .expect("encode response");
        let (fake, writes) = fake_device(Vec::new());
        let mut packet_loop = PacketEventLoop::new(fake);

        let result = process_core_raw_frame(
            &core,
            &mut packet_loop,
            frame.frame().bytes(),
            false,
            Some(&prepared),
        )
        .expect("management response");
        let CoreFrameResult::Management(exchange) = result else {
            panic!("expected management result");
        };
        assert_eq!(exchange.0, 69);
        assert_eq!(exchange.1.request_report.operation, LinkOperation::Encode);
        assert_eq!(exchange.1.response_report.operation, LinkOperation::Decode);
        assert_eq!(exchange.1.response_report.rule_id, RuleId::new(17, 8));
        assert!(writes.lock().expect("writes lock").is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_management_wait_interleaves_tun_request_and_application_response() {
        let core_context = active("core-interleave");
        let device_context = active("device-interleave");
        let core = SchcLink::new(Arc::clone(&core_context), LinkRole::Core);
        let device = SchcLink::new(Arc::clone(&device_context), LinkRole::Device);
        let request_datagram = context_check_request(core_context.snapshot().tag(), 8, &[]);
        let prepared = schc_coreconf::prepare_management_request(&core, &request_datagram)
            .expect("prepare request");
        let request_packet = application_request(0x1203);
        let (raw, peer) = loopback_pair();
        let (fake, writes) = fake_device(vec![Ok(request_packet.to_vec())]);
        let mut packet_loop = PacketEventLoop::new(fake);
        let expected_request = request_packet.clone();
        let peer_thread = std::thread::spawn(move || {
            let management_frame = peer.recv().expect("one management request");
            let management_request = device
                .decode(management_frame.bytes())
                .expect("decode management request");
            assert_eq!(
                management_request.route(),
                TrafficRoute::ProtectedManagement
            );
            let application_frame = peer.recv().expect("one application request");
            let decoded_request = device
                .decode(application_frame.bytes())
                .expect("decode application request");
            assert_eq!(
                decoded_request.packet().as_bytes(),
                expected_request.as_bytes()
            );
            let response = temporary_ordinary_response(decoded_request.packet())
                .expect("application response");
            let response_frame = device
                .encode(TrafficOrigin::Application, &response)
                .expect("encode application response");
            peer.send_frame(response_frame.frame())
                .expect("send application response");
            let mut service =
                InspectionService::new(device.active_context().clone()).expect("service");
            let response_packet = management_response(management_request.packet(), &mut service);
            let management_response_frame = device
                .encode(TrafficOrigin::Management, &response_packet)
                .expect("encode management response");
            peer.send_frame(management_response_frame.frame())
                .expect("send management response");
            assert!(peer.recv().is_err(), "management request was resent");
        });
        let exchange = wait_management_response(
            &core,
            &raw,
            &mut packet_loop,
            &prepared,
            false,
            Duration::from_secs(1),
        )
        .expect("interleaved management response");
        peer_thread.join().expect("peer thread");
        assert_eq!(exchange.0, 69);
        assert_eq!(
            writes.lock().expect("writes lock").as_slice(),
            &[temporary_ordinary_response(&request_packet)
                .expect("response")
                .to_vec()]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_management_wait_ignores_wrong_protected_response_before_correct_one() {
        let core_context = active("core-wrong-management-response");
        let device_context = active("device-wrong-management-response");
        let core = SchcLink::new(Arc::clone(&core_context), LinkRole::Core);
        let device = SchcLink::new(Arc::clone(&device_context), LinkRole::Device);
        let request_datagram = context_check_request(core_context.snapshot().tag(), 9, &[]);
        let prepared = schc_coreconf::prepare_management_request(&core, &request_datagram)
            .expect("prepare request");
        let request_packet =
            Ipv6UdpCoapPacket::parse(&prepared.report().packet_bytes).expect("request packet");
        let mut service = InspectionService::new(Arc::clone(&device_context)).expect("service");
        let valid_response = management_response(&request_packet, &mut service);
        let wrong_response = Ipv6UdpCoapPacket::new(
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            schc_coreconf::MANAGEMENT_PORT,
            schc_coreconf::MANAGEMENT_PORT,
            &schc_coreconf::CoapMessage::from_parts(
                1,
                2,
                valid_response.coap_message().code(),
                10,
                Vec::new(),
                Vec::new(),
                valid_response.coap_payload().to_vec(),
            )
            .expect("wrong response")
            .to_vec(),
        )
        .expect("wrong response packet");
        let wrong_frame = device
            .encode(TrafficOrigin::Management, &wrong_response)
            .expect("wrong frame");
        let valid_frame = device
            .encode(TrafficOrigin::Management, &valid_response)
            .expect("valid frame");
        let (raw, peer) = loopback_pair();
        let (fake, _writes) = fake_device(Vec::new());
        let mut packet_loop = PacketEventLoop::new(fake);
        let peer_thread = std::thread::spawn(move || {
            peer.recv().expect("management request");
            peer.send_frame(wrong_frame.frame())
                .expect("wrong response");
            peer.send_frame(valid_frame.frame())
                .expect("valid response");
        });
        let result = wait_management_response(
            &core,
            &raw,
            &mut packet_loop,
            &prepared,
            false,
            Duration::from_secs(1),
        )
        .expect("correct response after wrong response");
        peer_thread.join().expect("peer thread");
        assert_eq!(result.0, 69);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_tun_wrong_orientation_drops_then_valid_packet_recovers() {
        let core = SchcLink::new(active("core-recovery"), LinkRole::Core);
        let request = application_request(0x1204);
        let reverse = Ipv6UdpCoapPacket::new(
            DEVICE_LOGICAL_ADDRESS,
            CORE_LOGICAL_ADDRESS,
            APPLICATION_PORT,
            APPLICATION_PORT,
            request.coap_datagram(),
        )
        .expect("wrong orientation packet");
        let (raw, peer) = loopback_pair();
        let drop = process_core_tun_packet(&core, &raw, reverse.as_bytes(), false)
            .expect_err("wrong orientation drop");
        assert!(matches!(drop, CorePacketError::Drop(message) if message.contains("orientation")));
        process_core_tun_packet(&core, &raw, request.as_bytes(), false).expect("valid request");
        let received = peer.recv().expect("recovered request");
        assert_eq!(
            SchcLink::new(active("device-recovery"), LinkRole::Device)
                .decode(received.bytes())
                .expect("decode recovered")
                .packet()
                .as_bytes(),
            request.as_bytes()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn core_raw_frame_short_tun_write_is_a_contextual_fatal_error() {
        let core = SchcLink::new(active("core-short-write"), LinkRole::Core);
        let device = SchcLink::new(active("device-short-write"), LinkRole::Device);
        let response = temporary_ordinary_response(&application_request(0x1205)).expect("response");
        let frame = device
            .encode(TrafficOrigin::Application, &response)
            .expect("frame");
        let writes = Arc::new(Mutex::new(Vec::new()));
        let fake = FakePacketDevice {
            reads: VecDeque::new(),
            writes,
            write_limit: Some(response.as_bytes().len() - 1),
        };
        let mut packet_loop = PacketEventLoop::new(fake);
        let error =
            process_core_raw_frame(&core, &mut packet_loop, frame.frame().bytes(), false, None)
                .expect_err("short write");
        let CorePacketError::Fatal(message) = error else {
            panic!("expected fatal error");
        };
        assert!(message.contains("write application packet to TUN"));
        assert!(message.contains(&format!("expected {}", response.as_bytes().len())));
        assert!(message.contains(&format!("wrote {}", response.as_bytes().len() - 1)));
    }
}
