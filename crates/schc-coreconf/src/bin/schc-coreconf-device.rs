//! Device endpoint for the direct-TUN SCHC demonstration.

mod common;

use std::io::{self, Write};

use thiserror::Error;

use coap_lite::Packet;
use common::{bind_raw_link, print_report, Args};
use schc_coreconf::{
    is_duplicate_rule_request, InspectionService, Ipv6UdpCoapPacket, LinkError, LinkRole,
    PacketEventLoop, PacketPoll, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT,
    CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

#[cfg(target_os = "linux")]
use schc_runtime::linux_tun::{LinuxTunConfig, LinuxTunDevice};
#[cfg(target_os = "linux")]
use schc_runtime::packet::PacketDevice;

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-coreconf-device: ERROR {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), String> {
    Err("schc-coreconf-device requires Linux TUN support".to_owned())
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    let Some(args) = Args::parse("schc-coreconf-device", false)? else {
        return Ok(());
    };
    let active = args.active_context()?;
    let link = SchcLink::new(active.clone(), LinkRole::Device);
    let mut inspection = InspectionService::new(active)
        .map_err(|error| format!("load management inspection service: {error}"))?;
    let tun = LinuxTunDevice::create(LinuxTunConfig::new(&args.tun_name, args.tun_mtu))
        .map_err(|error| format!("create TUN: {error}"))?;
    let tun_name = tun.interface_name().to_owned();
    let tun_mtu = tun.mtu();
    let mut packet_loop = PacketEventLoop::new(tun);
    let (raw_link, link_local) = bind_raw_link(&args, Some(std::time::Duration::from_millis(50)))?;
    println!(
        "READY device  tun_name={tun_name}  mtu={tun_mtu}  link={link_local}  peer={}",
        args.link_peer
    );
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;

    loop {
        if let PacketPoll::Packet(packet) = packet_loop.poll().map_err(|error| error.to_string())? {
            match send_device_tun_response(&link, &raw_link, &packet, args.debug) {
                Ok(()) if args.once => return Ok(()),
                Ok(()) => {}
                Err(DevicePacketError::Drop(error)) => println!("ERROR {error}"),
                Err(DevicePacketError::Fatal(error)) => return Err(error),
            }
        }
        match raw_link.recv() {
            Ok(received) => {
                match receive_device_frame(
                    &link,
                    &raw_link,
                    &mut packet_loop,
                    &mut inspection,
                    received.bytes(),
                    args.debug,
                ) {
                    Ok(()) if args.once => return Ok(()),
                    Ok(()) => {}
                    Err(DevicePacketError::Drop(error)) => println!("ERROR {error}"),
                    Err(DevicePacketError::Fatal(error)) => return Err(error),
                }
                io::stdout()
                    .flush()
                    .map_err(|error| format!("flush operation output: {error}"))?;
            }
            Err(LinkError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => println!("ERROR receive request SCHC frame: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Error)]
enum DevicePacketError {
    #[error("{0}")]
    Drop(String),
    #[error("{0}")]
    Fatal(String),
}

#[cfg(target_os = "linux")]
fn send_device_tun_response(
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    bytes: &[u8],
    debug: bool,
) -> Result<(), DevicePacketError> {
    let packet = Ipv6UdpCoapPacket::parse(bytes)
        .map_err(|error| DevicePacketError::Drop(format!("drop malformed TUN packet: {error}")))?;
    if packet.source() != DEVICE_LOGICAL_ADDRESS
        || packet.destination() != CORE_LOGICAL_ADDRESS
        || packet.source_port() != APPLICATION_PORT
        || packet.destination_port() != APPLICATION_PORT
    {
        return Err(DevicePacketError::Drop(
            "drop unsupported TUN response orientation".to_owned(),
        ));
    }
    let encoded = link
        .encode(TrafficOrigin::Application, &packet)
        .map_err(|error| {
            DevicePacketError::Drop(format!("encode TUN application response: {error}"))
        })?;
    print_report(schc_coreconf::ReportDirection::Tx, encoded.report(), debug)
        .map_err(DevicePacketError::Fatal)?;
    raw_link
        .send_frame(encoded.frame())
        .map_err(|error| DevicePacketError::Fatal(format!("send application SCHC frame: {error}")))
}

#[cfg(target_os = "linux")]
fn receive_device_frame<D: PacketDevice>(
    link: &SchcLink,
    raw_link: &schc_coreconf::RawUdpLink,
    packet_loop: &mut PacketEventLoop<D>,
    inspection: &mut InspectionService,
    frame: &[u8],
    debug: bool,
) -> Result<(), DevicePacketError> {
    let decoded = link
        .decode(frame)
        .map_err(|error| DevicePacketError::Drop(format!("drop malformed SCHC frame: {error}")))?;
    print_report(schc_coreconf::ReportDirection::Rx, decoded.report(), debug)
        .map_err(DevicePacketError::Fatal)?;
    match decoded.route() {
        TrafficRoute::ProtectedManagement => {
            let request = decoded.packet();
            if request.source() != CORE_LOGICAL_ADDRESS
                || request.destination() != DEVICE_LOGICAL_ADDRESS
                || request.source_port() != MANAGEMENT_PORT
                || request.destination_port() != MANAGEMENT_PORT
            {
                return Err(DevicePacketError::Drop(
                    "drop unsupported management orientation".to_owned(),
                ));
            }
            let management = Packet::from_bytes(request.coap_datagram()).map_err(|error| {
                DevicePacketError::Drop(format!("drop malformed management request: {error}"))
            })?;
            if is_duplicate_rule_request(decoded.rule_id(), &management) {
                let before = inspection.status().generation;
                match inspection.handle_datagram_no_response(request.coap_datagram()) {
                    Ok(None) => {
                        let after = inspection.status().generation;
                        println!(
                            "OK duplicate  local={}  response=none",
                            if after == before + 1 {
                                "installed"
                            } else {
                                "idempotent"
                            }
                        );
                    }
                    Ok(Some(_)) => println!("ERROR duplicate  local=failed  response=unexpected"),
                    Err(error) => {
                        println!("ERROR duplicate  local=failed  response=none  cause={error}");
                    }
                }
                return Ok(());
            }
            let response_datagram = inspection
                .handle_datagram(request.coap_datagram())
                .map_err(|error| {
                    DevicePacketError::Drop(format!("handle management request: {error}"))
                })?;
            let response = Ipv6UdpCoapPacket::new(
                DEVICE_LOGICAL_ADDRESS,
                CORE_LOGICAL_ADDRESS,
                MANAGEMENT_PORT,
                MANAGEMENT_PORT,
                &response_datagram,
            )
            .map_err(|error| {
                DevicePacketError::Drop(format!("construct management response: {error}"))
            })?;
            let encoded = link
                .encode(TrafficOrigin::Management, &response)
                .map_err(|error| {
                    DevicePacketError::Drop(format!("encode management response: {error}"))
                })?;
            if encoded.report().rule_id != schc_core::RuleId::new(17, 8) {
                return Err(DevicePacketError::Drop(
                    "management response did not select RuleID 17/8".to_owned(),
                ));
            }
            print_report(schc_coreconf::ReportDirection::Tx, encoded.report(), debug)
                .map_err(DevicePacketError::Fatal)?;
            raw_link.send_frame(encoded.frame()).map_err(|error| {
                DevicePacketError::Fatal(format!("send management response: {error}"))
            })
        }
        TrafficRoute::Application => {
            let request = decoded.packet();
            if request.source() != CORE_LOGICAL_ADDRESS
                || request.destination() != DEVICE_LOGICAL_ADDRESS
                || request.source_port() != APPLICATION_PORT
                || request.destination_port() != APPLICATION_PORT
            {
                return Err(DevicePacketError::Drop(
                    "drop unsupported application orientation".to_owned(),
                ));
            }
            packet_loop.write(request.as_bytes()).map_err(|error| {
                DevicePacketError::Fatal(format!("write application packet to TUN: {error}"))
            })
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use schc_core::RuleId;
    use schc_coreconf::{
        context_check_request, protected_management_rule_ids, temporary_ordinary_response,
        validate_management_response, ActiveContext, InspectionService, Ipv6UdpCoapPacket,
        LinkOperation, LinkRole, PacketEventLoop, PreparedContext, ProtectionPolicy, RawUdpLink,
        SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
    };
    use schc_runtime::packet::{PacketDevice, PacketDeviceError};
    use schc_runtime::{DeviceId, DeviceProfile};

    use super::{receive_device_frame, send_device_tun_response, DevicePacketError};

    const SID: &str = include_str!("../../../../fixtures/demo/ietf-schc@2026-05-07.sid");
    const SOR: &[u8] = include_bytes!("../../../../fixtures/demo/initial.sor");

    fn active(device: &str) -> Arc<ActiveContext> {
        Arc::new(ActiveContext::new(
            PreparedContext::from_sor_with_policy(
                SID,
                SOR,
                DeviceId::new(device).expect("device"),
                DeviceProfile::default(),
                ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
            )
            .expect("prepared context"),
        ))
    }

    struct FakePacketDevice {
        reads: VecDeque<Result<Vec<u8>, PacketDeviceError>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        write_limit: Option<usize>,
    }

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

    fn fake_device() -> (FakePacketDevice, Arc<Mutex<Vec<Vec<u8>>>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        (
            FakePacketDevice {
                reads: VecDeque::new(),
                writes: Arc::clone(&writes),
                write_limit: None,
            },
            writes,
        )
    }

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

    fn application_request(message_id: u16) -> Ipv6UdpCoapPacket {
        let datagram = schc_coreconf::CoapMessage::from_parts(
            1,
            0,
            1,
            message_id,
            vec![0xaa],
            vec![schc_coreconf::CoapOption::new(11, b"demo".to_vec()).expect("option")],
            Vec::new(),
        )
        .expect("request CoAP")
        .to_vec();
        Ipv6UdpCoapPacket::new(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            APPLICATION_PORT,
            APPLICATION_PORT,
            &datagram,
        )
        .expect("request packet")
    }

    fn response_for(request: &Ipv6UdpCoapPacket) -> Ipv6UdpCoapPacket {
        temporary_ordinary_response(request).expect("ordinary response")
    }

    #[test]
    fn device_raw_schc_request_reaches_tun_byte_for_byte() {
        let core = SchcLink::new(active("core-device-raw-request"), LinkRole::Core);
        let device = SchcLink::new(active("device-raw-request"), LinkRole::Device);
        let request = application_request(0x2201);
        let frame = core
            .encode(TrafficOrigin::Application, &request)
            .expect("encode request");
        let (raw, _peer) = loopback_pair();
        let (fake, writes) = fake_device();
        let mut packet_loop = PacketEventLoop::new(fake);
        let mut service = InspectionService::new(device.active_context().clone()).expect("service");

        receive_device_frame(
            &device,
            &raw,
            &mut packet_loop,
            &mut service,
            frame.frame().bytes(),
            false,
        )
        .expect("receive request");
        assert_eq!(
            writes.lock().expect("writes lock").as_slice(),
            &[request.to_vec()]
        );
    }

    #[test]
    fn device_tun_application_response_reaches_peer_as_raw_schc_frame() {
        let core = SchcLink::new(active("core-device-tun-response"), LinkRole::Core);
        let device = SchcLink::new(active("device-tun-response"), LinkRole::Device);
        let request = application_request(0x2202);
        let response = response_for(&request);
        let (raw, peer) = loopback_pair();

        send_device_tun_response(&device, &raw, response.as_bytes(), false).expect("send response");
        let received = peer.recv().expect("raw response");
        let decoded = core.decode(received.bytes()).expect("decode response");
        assert_eq!(decoded.route(), TrafficRoute::Application);
        assert_eq!(decoded.rule_id(), RuleId::new(21, 8));
        assert_eq!(decoded.packet().as_bytes(), response.as_bytes());
    }

    #[test]
    fn device_management_isolated_from_tun_and_response_correlates() {
        let core_context = active("core-device-management");
        let device_context = active("device-management");
        let core_link = SchcLink::new(Arc::clone(&core_context), LinkRole::Core);
        let device = SchcLink::new(Arc::clone(&device_context), LinkRole::Device);
        let request_datagram = context_check_request(core_context.snapshot().tag(), 3, &[]);
        let prepared = schc_coreconf::prepare_management_request(&core_link, &request_datagram)
            .expect("prepare management request");
        let (raw, peer) = loopback_pair();
        let (fake, writes) = fake_device();
        let mut packet_loop = PacketEventLoop::new(fake);
        let mut service = InspectionService::new(Arc::clone(&device_context)).expect("service");

        receive_device_frame(
            &device,
            &raw,
            &mut packet_loop,
            &mut service,
            prepared.frame().bytes(),
            false,
        )
        .expect("handle management request");
        assert!(writes.lock().expect("writes lock").is_empty());
        let response_frame = peer.recv().expect("management response");
        let decoded = core_link
            .decode(response_frame.bytes())
            .expect("decode response");
        assert_eq!(decoded.route(), TrafficRoute::ProtectedManagement);
        let (response_code, exchange) = validate_management_response(&prepared, &decoded)
            .expect("correlated management response");
        assert_eq!(response_code, 69);
        assert_eq!(exchange.request_report.operation, LinkOperation::Encode);
        assert_eq!(exchange.response_report.operation, LinkOperation::Decode);
        assert_eq!(exchange.response_report.rule_id, RuleId::new(17, 8));
    }

    #[test]
    fn device_raw_drop_then_valid_request_recovers() {
        let core = SchcLink::new(active("core-device-recovery"), LinkRole::Core);
        let device = SchcLink::new(active("device-recovery"), LinkRole::Device);
        let request = application_request(0x2203);
        let frame = core
            .encode(TrafficOrigin::Application, &request)
            .expect("encode request");
        let (raw, _peer) = loopback_pair();
        let (fake, writes) = fake_device();
        let mut packet_loop = PacketEventLoop::new(fake);
        let mut service = InspectionService::new(device.active_context().clone()).expect("service");
        let error = receive_device_frame(
            &device,
            &raw,
            &mut packet_loop,
            &mut service,
            &[0xff],
            false,
        )
        .expect_err("malformed frame must drop");
        assert!(matches!(error, DevicePacketError::Drop(message) if message.contains("malformed")));
        receive_device_frame(
            &device,
            &raw,
            &mut packet_loop,
            &mut service,
            frame.frame().bytes(),
            false,
        )
        .expect("valid request after drop");
        assert_eq!(
            writes.lock().expect("writes lock").as_slice(),
            &[request.to_vec()]
        );
    }

    #[test]
    fn device_raw_frame_short_tun_write_is_a_contextual_fatal_error() {
        let core = SchcLink::new(active("core-device-short-write"), LinkRole::Core);
        let device = SchcLink::new(active("device-short-write"), LinkRole::Device);
        let request = application_request(0x2204);
        let frame = core
            .encode(TrafficOrigin::Application, &request)
            .expect("encode request");
        let writes = Arc::new(Mutex::new(Vec::new()));
        let fake = FakePacketDevice {
            reads: VecDeque::new(),
            writes,
            write_limit: Some(request.as_bytes().len() - 1),
        };
        let mut packet_loop = PacketEventLoop::new(fake);
        let mut service = InspectionService::new(device.active_context().clone()).expect("service");
        let (raw, _peer) = loopback_pair();
        let error = receive_device_frame(
            &device,
            &raw,
            &mut packet_loop,
            &mut service,
            frame.frame().bytes(),
            false,
        )
        .expect_err("short write must be fatal");
        let DevicePacketError::Fatal(message) = error else {
            panic!("expected fatal error");
        };
        assert!(message.contains("write application packet to TUN"));
        assert!(message.contains(&format!("expected {}", request.as_bytes().len())));
        assert!(message.contains(&format!("wrote {}", request.as_bytes().len() - 1)));
    }
}
