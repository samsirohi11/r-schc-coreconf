//! Coverage for the real raw UDP SCHC link and rule-derived routing.

use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use schc_core::{RuleId, SidRegistry};
use schc_coreconf::{
    temporary_ordinary_response, ActiveContext, Ipv6UdpCoapPacket, LinkError, LinkRole,
    PreparedContext, ProtectionPolicy, RawUdpLink, SchcLink, TrafficClass, TrafficOrigin,
    TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};
use schc_runtime::{DeviceId, DeviceProfile};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn active(name: &str) -> Arc<ActiveContext> {
    Arc::new(ActiveContext::new(
        PreparedContext::from_sor_with_policy(
            SID,
            SOR,
            DeviceId::new(name).expect("device ID"),
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
        )
        .expect("initial context"),
    ))
}

fn coap(
    message_type: u8,
    code: u8,
    message_id: u16,
    token: &[u8],
    option: Option<&[u8]>,
) -> Vec<u8> {
    let options = option.map_or_else(Vec::new, |value| {
        vec![schc_coreconf::CoapOption::new(11, value.to_vec()).expect("CoAP option")]
    });
    schc_coreconf::CoapMessage::from_parts(
        1,
        message_type,
        code,
        message_id,
        token.to_vec(),
        options,
        Vec::new(),
    )
    .expect("CoAP")
    .to_vec()
}

fn packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    message: &[u8],
) -> Ipv6UdpCoapPacket {
    Ipv6UdpCoapPacket::new(source, destination, source_port, destination_port, message)
        .expect("logical packet")
}

#[test]
fn ordinary_request_and_response_reconstruct_exactly_with_reports() {
    let core = SchcLink::new(active("core-ordinary"), LinkRole::Core);
    let device = SchcLink::new(active("device-ordinary"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 0x1001, &[0xaa], Some(b"demo")),
    );
    let encoded = core
        .encode(TrafficOrigin::Application, &request)
        .expect("ordinary request encodes");
    assert_eq!(encoded.report().rule_id, RuleId::new(25, 8));
    assert_eq!(encoded.report().traffic_class, TrafficClass::Ordinary);
    assert_eq!(encoded.report().packet_bytes, request.as_bytes());
    assert_eq!(encoded.report().frame_bytes, encoded.frame().bytes());
    assert_eq!(encoded.report().packet_size, request.as_bytes().len());
    assert_eq!(
        encoded.report().padded_byte_len,
        encoded.frame().bytes().len()
    );
    assert_eq!(
        encoded.report().schc_bit_len,
        Some(encoded.frame().bit_len())
    );
    assert!(
        encoded.report().compression_ratio().expect("request ratio") > 1.0,
        "the initial request uses no-compression fallback including its RuleID"
    );

    let decoded = device
        .decode(encoded.frame().bytes())
        .expect("ordinary request decodes");
    assert_eq!(decoded.rule_id(), RuleId::new(25, 8));
    assert_eq!(decoded.route(), TrafficRoute::Application);
    assert_eq!(decoded.packet().as_bytes(), request.as_bytes());
    assert_eq!(decoded.report().packet_bytes, request.as_bytes());
    assert_eq!(decoded.report().frame_bytes, encoded.frame().bytes());
    assert_eq!(decoded.report().traffic_class, TrafficClass::Ordinary);
    assert_eq!(decoded.report().schc_bit_len, encoded.report().schc_bit_len);

    let response = temporary_ordinary_response(decoded.packet()).expect("response");
    let response_frame = device
        .encode(TrafficOrigin::Application, &response)
        .expect("ordinary response encodes");
    assert_eq!(response_frame.report().rule_id, RuleId::new(21, 8));
    assert!(
        response_frame
            .report()
            .compression_ratio()
            .expect("response ratio")
            < 1.0
    );
    let reconstructed = core
        .decode(response_frame.frame().bytes())
        .expect("ordinary response decodes");
    assert_eq!(reconstructed.rule_id(), RuleId::new(21, 8));
    assert_eq!(reconstructed.route(), TrafficRoute::Application);
    assert_eq!(reconstructed.packet().as_bytes(), response.as_bytes());
    assert_eq!(
        reconstructed.report().schc_bit_len,
        response_frame.report().schc_bit_len
    );
    assert_eq!(reconstructed.packet().coap_message().message_id(), 0x1001);
    assert_eq!(reconstructed.packet().coap_message().token(), &[0xaa]);
}

#[test]
fn protected_rules_authorize_management_and_application_origin_cannot_impersonate_it() {
    let core = SchcLink::new(active("core-management"), LinkRole::Core);
    let device = SchcLink::new(active("device-management"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        MANAGEMENT_PORT,
        &coap(0, 1, 0x2001, &[], Some(b"schc")),
    );
    let encoded = core
        .encode(TrafficOrigin::Management, &request)
        .expect("management request encodes");
    assert_eq!(encoded.report().rule_id, RuleId::new(16, 8));
    let decoded = device
        .decode(encoded.frame().bytes())
        .expect("management request decodes");
    assert_eq!(decoded.route(), TrafficRoute::ProtectedManagement);
    assert_eq!(decoded.traffic_class(), TrafficClass::ProtectedManagement);
    assert_eq!(decoded.packet().as_bytes(), request.as_bytes());

    let response = packet(
        DEVICE_LOGICAL_ADDRESS,
        CORE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        APPLICATION_PORT,
        &coap(2, 69, 0x2001, &[], None),
    );
    let response_frame = device
        .encode(TrafficOrigin::Management, &response)
        .expect("management response encodes");
    assert_eq!(response_frame.report().rule_id, RuleId::new(17, 8));
    let core_response = core
        .decode(response_frame.frame().bytes())
        .expect("management response decodes");
    assert_eq!(core_response.route(), TrafficRoute::ProtectedManagement);

    let error = core
        .encode(TrafficOrigin::Application, &request)
        .expect_err("application origin must not select protected rule");
    assert!(matches!(
        error,
        LinkError::OriginRuleMismatch {
            origin: TrafficOrigin::Application,
            value: 16,
            bit_len: 8,
            selected: TrafficClass::ProtectedManagement,
        }
    ));
}

#[test]
fn malformed_frames_are_rejected_and_rule_identity_includes_bit_length() {
    let core = SchcLink::new(active("core-invalid"), LinkRole::Core);
    let device = SchcLink::new(active("device-invalid"), LinkRole::Device);
    assert!(device.decode(&[0xff]).is_err());
    assert!(device.decode(&[]).is_err());

    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 3, &[], Some(b"demo")),
    );
    let frame = core
        .encode(TrafficOrigin::Application, &request)
        .expect("request");
    assert_eq!(frame.frame().bit_len() % 8, 0);
    let mut extra_padding = frame.frame().bytes().to_vec();
    extra_padding.push(0);
    assert!(device.decode(&extra_padding).is_err());
    let response = temporary_ordinary_response(&request).expect("response");
    let non_aligned = device
        .encode(TrafficOrigin::Application, &response)
        .expect("response");
    assert_ne!(non_aligned.frame().bit_len() % 8, 0);
    let mut malformed = non_aligned.frame().bytes().to_vec();
    *malformed.last_mut().expect("frame byte") |= 1;
    assert!(device.decode(&malformed).is_err());

    let policy = ProtectionPolicy::from_rule_ids([RuleId::new(16, 8)]);
    let context =
        schc_core::RuleContext::from_cbor_slice(SOR, SidRegistry::from_json_str(SID).expect("SID"))
            .expect("context");
    let protected = schc_coreconf::ProtectedRules::derive(&context, &policy).expect("policy");
    assert!(protected.contains(RuleId::new(16, 8)));
    assert!(!protected.contains(RuleId::new(16, 7)));
}

#[test]
fn raw_udp_link_delivers_only_frame_bytes_in_both_directions() {
    let core = SchcLink::new(active("core-wire"), LinkRole::Core);
    let device = SchcLink::new(active("device-wire"), LinkRole::Device);
    let request = packet(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        APPLICATION_PORT,
        &coap(0, 1, 0x4001, &[0x44], Some(b"demo")),
    );
    let forward = core
        .encode(TrafficOrigin::Application, &request)
        .expect("forward frame");

    let first_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("first");
    let second_socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("second");
    let first_address = first_socket.local_addr().expect("first address");
    let second_address = second_socket.local_addr().expect("second address");
    let first = RawUdpLink::from_socket(first_socket, second_address).expect("first link");
    let second = RawUdpLink::from_socket(second_socket, first_address).expect("second link");
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("first timeout");
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("second timeout");

    first.send_frame(forward.frame()).expect("forward send");
    let received = second.recv().expect("forward receive");
    assert_eq!(received.bytes(), forward.frame().bytes());
    assert_eq!(received.bytes().len(), forward.frame().bytes().len());
    let reconstructed = device.decode(received.bytes()).expect("forward decode");
    assert_eq!(reconstructed.packet().as_bytes(), request.as_bytes());

    let response = temporary_ordinary_response(reconstructed.packet()).expect("response");
    let reverse = device
        .encode(TrafficOrigin::Application, &response)
        .expect("reverse frame");
    second.send_frame(reverse.frame()).expect("reverse send");
    let received = first.recv().expect("reverse receive");
    assert_eq!(received.bytes(), reverse.frame().bytes());
    assert_eq!(received.bytes().len(), reverse.frame().bytes().len());
    let reconstructed = core.decode(received.bytes()).expect("reverse decode");
    assert_eq!(reconstructed.packet().as_bytes(), response.as_bytes());
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_core_and_device_processes_complete_one_ordinary_operation() {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::Instant;

    struct Process {
        child: Child,
        ready: Receiver<String>,
        stdout: Arc<std::sync::Mutex<String>>,
        stderr: Arc<std::sync::Mutex<String>>,
        stdout_thread: Option<thread::JoinHandle<()>>,
        stderr_thread: Option<thread::JoinHandle<()>>,
    }

    impl Process {
        fn spawn(program: &str, args: &[String]) -> Self {
            let mut child = Command::new(program)
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn demonstration process");
            let stdout = Arc::new(std::sync::Mutex::new(String::new()));
            let stderr = Arc::new(std::sync::Mutex::new(String::new()));
            let (sender, ready) = mpsc::channel();
            let stdout_value = Arc::clone(&stdout);
            let stdout_pipe = child.stdout.take().expect("child stdout");
            let stdout_thread = thread::spawn(move || {
                for line in BufReader::new(stdout_pipe).lines() {
                    let Ok(line) = line else { break };
                    if line.starts_with("READY ") {
                        let _ = sender.send(line.clone());
                    }
                    if let Ok(mut output) = stdout_value.lock() {
                        output.push_str(&line);
                        output.push('\n');
                    }
                }
            });
            let stderr_value = Arc::clone(&stderr);
            let stderr_pipe = child.stderr.take().expect("child stderr");
            let stderr_thread = thread::spawn(move || {
                for line in BufReader::new(stderr_pipe).lines() {
                    let Ok(line) = line else { break };
                    if let Ok(mut output) = stderr_value.lock() {
                        output.push_str(&line);
                        output.push('\n');
                    }
                }
            });
            Self {
                child,
                ready,
                stdout,
                stderr,
                stdout_thread: Some(stdout_thread),
                stderr_thread: Some(stderr_thread),
            }
        }

        fn wait_timeout(&mut self, timeout: Duration) -> ExitStatus {
            let start = Instant::now();
            loop {
                if let Some(status) = self.child.try_wait().expect("poll child") {
                    self.join_readers();
                    return status;
                }
                assert!(
                    start.elapsed() < timeout,
                    "child did not exit before timeout"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn join_readers(&mut self) {
            if let Some(thread) = self.stdout_thread.take() {
                thread.join().expect("stdout reader");
            }
            if let Some(thread) = self.stderr_thread.take() {
                thread.join().expect("stderr reader");
            }
        }

        fn output(&self) -> (String, String) {
            (
                self.stdout.lock().expect("stdout lock").clone(),
                self.stderr.lock().expect("stderr lock").clone(),
            )
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            if self.child.try_wait().expect("poll child on drop").is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            self.join_readers();
        }
    }

    fn reserve_address() -> (UdpSocket, SocketAddr) {
        let socket =
            UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("reserve UDP port");
        let address = socket.local_addr().expect("reserved address");
        (socket, address)
    }

    let (device_reservation, device_link) = reserve_address();
    let (core_reservation, core_link) = reserve_address();
    let (app_reservation, core_app) = reserve_address();
    let device_args = vec![
        "--link-bind".to_owned(),
        device_link.to_string(),
        "--link-peer".to_owned(),
        core_link.to_string(),
        "--once".to_owned(),
    ];
    let core_args = vec![
        "--link-bind".to_owned(),
        core_link.to_string(),
        "--link-peer".to_owned(),
        device_link.to_string(),
        "--app-bind".to_owned(),
        core_app.to_string(),
        "--once".to_owned(),
    ];
    drop(device_reservation);
    let mut device = Process::spawn(env!("CARGO_BIN_EXE_schc-coreconf-device"), &device_args);
    device
        .ready
        .recv_timeout(Duration::from_secs(5))
        .expect("device readiness");
    drop(core_reservation);
    drop(app_reservation);
    let mut core = Process::spawn(env!("CARGO_BIN_EXE_schc-coreconf-core"), &core_args);
    core.ready
        .recv_timeout(Duration::from_secs(5))
        .expect("core readiness");

    let application = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("application");
    application
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("application timeout");
    let request = coap(0, 1, 0x3010, &[0x55], Some(b"demo"));
    application
        .send_to(&request, core_app)
        .expect("send application request");
    let mut response = vec![0_u8; 65_535];
    let (length, _) = application
        .recv_from(&mut response)
        .expect("receive application response");
    assert_eq!(&response[..length], &[0x61, 69, 0x30, 0x10, 0x55]);

    let core_status = core.wait_timeout(Duration::from_secs(5));
    let device_status = device.wait_timeout(Duration::from_secs(5));
    assert!(core_status.success(), "core status: {core_status}");
    assert!(device_status.success(), "device status: {device_status}");
    let (core_stdout, core_stderr) = core.output();
    let (device_stdout, device_stderr) = device.output();
    assert!(core_stderr.is_empty(), "core stderr: {core_stderr}");
    assert!(device_stderr.is_empty(), "device stderr: {device_stderr}");
    assert!(core_stdout.contains("CORE TX class=Ordinary rule=25/8 packet_bytes=58"));
    assert!(core_stdout.contains("CORE RX class=Ordinary rule=21/8 packet_bytes=53"));
    assert!(device_stdout.contains("DEVICE RX class=Ordinary rule=25/8 packet_bytes=58"));
    assert!(device_stdout.contains("DEVICE TX class=Ordinary rule=21/8 packet_bytes=53"));
}
