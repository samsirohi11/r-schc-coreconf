//! Real-process IPv6 coverage for the standalone application boundary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const SID: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/demo/demo-data.sid"
);
const DATA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/demo/app-data.json"
);

struct ProcessGuard {
    server: Option<Child>,
    client: Option<Child>,
    directory: std::path::PathBuf,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        for child in [&mut self.client, &mut self.server].into_iter().flatten() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn standalone_server_and_bound_client_exchange_ipv6_application_requests() {
    let probe = match UdpSocket::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)) {
        Ok(socket) => socket,
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => return,
        Err(error) => panic!("IPv6 loopback is unavailable: {error}"),
    };
    let server_probe_address = probe.local_addr().expect("server probe address");
    drop(probe);

    let directory = std::env::temp_dir().join(format!(
        "schc-coreconf-application-server-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("temporary directory");
    let sid_path = directory.join("application.sid");
    let data_path = directory.join("application.json");
    std::fs::copy(SID, &sid_path).expect("copy SID fixture");
    std::fs::copy(DATA, &data_path).expect("copy data fixture");

    let server = Command::new(env!("CARGO_BIN_EXE_schc-data-server"))
        .args([
            "--sid",
            sid_path.to_str().unwrap(),
            "--data",
            data_path.to_str().unwrap(),
            "--bind",
            "[::1]:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start application server");
    let mut guard = ProcessGuard {
        server: Some(server),
        client: None,
        directory,
    };

    let server_stdout = guard.server.as_mut().unwrap().stdout.take().unwrap();
    let (ready_sender, ready_receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(server_stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| (line, reader));
        let _ = ready_sender.send(result);
    });
    let (ready_line, mut server_stdout) = ready_receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("server readiness timeout")
        .expect("read server readiness");
    assert!(
        ready_line.starts_with("READY server  bind="),
        "{ready_line}"
    );
    assert!(ready_line.ends_with("  path=c\n"), "{ready_line}");
    let server_address = ready_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("bind="))
        .expect("server bind in readiness")
        .parse::<SocketAddr>()
        .expect("server readiness address");
    assert_eq!(
        server_address.ip(),
        std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
    assert_ne!(server_address.port(), 0);
    assert_eq!(
        server_probe_address.ip(),
        std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
    assert!(
        guard.server.as_mut().unwrap().try_wait().unwrap().is_none(),
        "server exited after readiness"
    );

    let source_reservation = UdpSocket::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
        .expect("reserve client source address");
    let client_address = source_reservation
        .local_addr()
        .expect("client source address");
    assert_ne!(client_address.port(), server_address.port());
    drop(source_reservation);

    let mut client = Command::new(env!("CARGO_BIN_EXE_schc-data-client"))
        .args([
            "--sid",
            sid_path.to_str().unwrap(),
            "--server",
            &server_address.to_string(),
            "--bind",
            &client_address.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start bound application client");
    let mut input = client.stdin.take().unwrap();
    input
        .write_all(
            b"fetch /demo-data:config/count\nset /demo-data:config/count 42\nfetch /demo-data:config/count\ndelete /demo-data:config/count\nfetch /demo-data:config/count\nreload\nquit\n",
        )
        .expect("write client commands");
    drop(input);
    guard.client = Some(client);

    let client_status = wait_for_exit(guard.client.as_mut().unwrap(), Duration::from_secs(10));
    assert!(client_status.success(), "client status: {client_status}");
    let mut client_stdout = String::new();
    guard
        .client
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut client_stdout)
        .expect("read client stdout");
    let mut client_stderr = String::new();
    guard
        .client
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut client_stderr)
        .expect("read client stderr");
    let expected_ready = format!("READY client  server={server_address}  bind={client_address}");
    assert!(client_stdout.contains(&expected_ready), "{client_stdout}");
    assert!(
        client_stdout.contains("\n7\n"),
        "initial fetch missing: {client_stdout}"
    );
    assert!(
        client_stdout.contains("OK set"),
        "set missing: {client_stdout}"
    );
    assert!(
        client_stdout.contains("\n42\n"),
        "updated fetch missing: {client_stdout}"
    );
    assert!(
        client_stdout.contains("\nnot found\n"),
        "deleted fetch missing: {client_stdout}"
    );
    assert!(
        client_stdout.contains("\nOK reload\n"),
        "reload result missing: {client_stdout}"
    );
    assert!(client_stderr.is_empty(), "client stderr: {client_stderr}");
    assert!(
        guard.server.as_mut().unwrap().try_wait().unwrap().is_none(),
        "server did not remain alive across requests"
    );

    let mut server = guard.server.take().unwrap();
    server.kill().expect("terminate server independently");
    let server_status = server.wait().expect("wait for server");
    assert!(
        !server_status.success(),
        "server unexpectedly exited cleanly"
    );
    let mut server_stderr = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut server_stderr)
        .expect("read server stderr");
    assert!(server_stderr.is_empty(), "server stderr: {server_stderr}");
    let mut server_output = String::new();
    server_stdout
        .read_to_string(&mut server_output)
        .expect("read server stdout");
    assert!(server_output.contains("RX APP"));
    assert!(server_output.contains("TX APP"));
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        assert!(Instant::now() < deadline, "child process timeout");
        thread::sleep(Duration::from_millis(10));
    }
}
