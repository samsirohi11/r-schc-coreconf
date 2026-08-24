//! Standalone CORECONF application data server.

use std::env;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;

use schc_coreconf::GenericDataService;

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-data-server: ERROR {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse()?;
    if options.help {
        print_usage();
        return Ok(());
    }
    let mut service = GenericDataService::from_files(
        &options.sid_paths,
        &options.data_path,
        options.resource_path.clone(),
    )
    .map_err(|error| format!("load application service: {error}"))?;
    let socket = UdpSocket::bind(options.bind)
        .map_err(|error| format!("bind application socket {}: {error}", options.bind))?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("query application socket: {error}"))?;
    println!("READY server  bind={local}  path={}", options.resource_path);
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness: {error}"))?;
    serve(&socket, &mut service)
}

fn serve(socket: &UdpSocket, service: &mut GenericDataService) -> Result<(), String> {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        serve_once(socket, service, &mut buffer)?;
    }
}

fn serve_once(
    socket: &UdpSocket,
    service: &mut GenericDataService,
    buffer: &mut [u8],
) -> Result<(), String> {
    let (length, peer) = loop {
        match socket.recv_from(buffer) {
            Ok(result) => break result,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("receive application datagram: {error}")),
        }
    };
    println!("RX APP   {length} B");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush receive report: {error}"))?;
    match service.handle_datagram(&buffer[..length]) {
        Ok(response) => match socket.send_to(&response, peer) {
            Ok(sent) if sent == response.len() => {
                println!("TX APP   {sent} B");
                io::stdout()
                    .flush()
                    .map_err(|error| format!("flush transmit report: {error}"))?;
            }
            Ok(sent) => eprintln!(
                "schc-data-server: ERROR short UDP send to {peer}: {sent}/{} bytes",
                response.len()
            ),
            Err(error) => {
                eprintln!("schc-data-server: ERROR send response to {peer}: {error}");
            }
        },
        Err(error) => eprintln!("schc-data-server: ERROR handle datagram from {peer}: {error}"),
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    sid_paths: Vec<PathBuf>,
    data_path: PathBuf,
    bind: SocketAddr,
    resource_path: String,
    help: bool,
}

impl Options {
    fn parse() -> Result<Self, String> {
        Self::parse_arguments(env::args().skip(1))
    }

    fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut sid_paths = Vec::new();
        let mut data_path = None;
        let mut bind = None;
        let mut resource_path = None;
        let mut help = false;
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--sid" => sid_paths.push(PathBuf::from(next(&mut arguments, "--sid")?)),
                "--data" => {
                    if data_path.is_some() {
                        return Err("duplicate --data option".to_owned());
                    }
                    data_path = Some(PathBuf::from(next(&mut arguments, "--data")?));
                }
                "--bind" => {
                    if bind.is_some() {
                        return Err("duplicate --bind option".to_owned());
                    }
                    let value = next(&mut arguments, "--bind")?;
                    bind = Some(
                        value
                            .parse()
                            .map_err(|error| format!("invalid --bind address {value}: {error}"))?,
                    );
                }
                "--path" => {
                    if resource_path.is_some() {
                        return Err("duplicate --path option".to_owned());
                    }
                    resource_path = Some(next(&mut arguments, "--path")?);
                }
                "-h" | "--help" => help = true,
                other => return Err(format!("unknown argument {other}; use --help")),
            }
        }
        if help {
            return Ok(Self {
                sid_paths,
                data_path: PathBuf::new(),
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                resource_path: resource_path.unwrap_or_else(|| "c".to_owned()),
                help,
            });
        }
        Ok(Self {
            sid_paths,
            data_path: data_path.ok_or("missing required --data PATH")?,
            bind: bind.ok_or("missing required --bind ADDR")?,
            resource_path: resource_path.unwrap_or_else(|| "c".to_owned()),
            help,
        })
        .and_then(|options| {
            if options.sid_paths.is_empty() {
                Err("missing required --sid PATH".to_owned())
            } else {
                Ok(options)
            }
        })
    }
}

fn next(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    match arguments.next() {
        Some(value) if !value.starts_with('-') => Ok(value),
        Some(_) | None => Err(format!("missing value for {flag}")),
    }
}

fn print_usage() {
    println!("{}", usage());
    println!("Options:");
    println!("  --sid PATH    Application SID file (repeatable)");
    println!("  --data PATH   JSON application datastore");
    println!("  --bind ADDR   UDP bind address");
    println!("  --path PATH   CORECONF resource path (default: c)");
}

fn usage() -> &'static str {
    "Usage: schc-data-server --sid PATH [--sid PATH ...] --data PATH --bind ADDR [--path PATH]"
}

#[cfg(test)]
mod tests {
    use super::{serve_once, usage, Options};
    use coap_lite::{MessageClass, MessageType, Packet, RequestType};
    use schc_coreconf::GenericDataService;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    fn parse(arguments: &[&str]) -> Result<Options, String> {
        Options::parse_arguments(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    const REQUIRED: &[&str] = &[
        "--sid",
        "model.sid",
        "--data",
        "data.json",
        "--bind",
        "[::1]:5683",
    ];

    #[test]
    fn accepts_repeated_sid_ipv6_bind_and_default_path() {
        let options = parse(&[
            "--sid",
            "one.sid",
            "--sid",
            "two.sid",
            "--data",
            "data.json",
            "--bind",
            "[::1]:5683",
        ])
        .expect("options");
        assert_eq!(options.sid_paths.len(), 2);
        assert_eq!(options.bind, "[::1]:5683".parse::<SocketAddr>().unwrap());
        assert_eq!(options.resource_path, "c");
    }

    #[test]
    fn accepts_custom_path() {
        let mut arguments = vec!["--path", "mgmt"];
        arguments.extend_from_slice(REQUIRED);
        let options = parse(&arguments).expect("options");
        assert_eq!(options.resource_path, "mgmt");
    }

    #[test]
    fn rejects_missing_required_options() {
        for (flag, arguments) in [
            ("--sid", vec!["--data", "data.json", "--bind", "[::1]:5683"]),
            ("--data", vec!["--sid", "model.sid", "--bind", "[::1]:5683"]),
            ("--bind", vec!["--sid", "model.sid", "--data", "data.json"]),
        ] {
            let error = parse(&arguments).expect_err("missing required option");
            assert!(error.contains(flag), "{flag}: {error}");
        }
    }

    #[test]
    fn rejects_missing_values_malformed_bind_duplicates_and_unknown() {
        let cases = [
            (&["--sid"][..], "missing value for --sid"),
            (&["--data"][..], "missing value for --data"),
            (&["--bind"][..], "missing value for --bind"),
            (&["--path"][..], "missing value for --path"),
            (
                &["--bind", "not-an-address"][..],
                "invalid --bind address not-an-address:",
            ),
            (
                &["--data", "a", "--data", "b"][..],
                "duplicate --data option",
            ),
            (
                &["--bind", "127.0.0.1:1", "--bind", "127.0.0.1:2"][..],
                "duplicate --bind option",
            ),
            (
                &["--path", "a", "--path", "b"][..],
                "duplicate --path option",
            ),
            (&["--unknown"][..], "unknown argument --unknown; use --help"),
        ];
        for (arguments, expected) in cases {
            let error = parse(arguments).expect_err("invalid arguments");
            assert!(error == expected || error.starts_with(expected), "{error}");
        }
    }

    #[test]
    fn help_is_concise_and_lists_required_options() {
        assert!(usage().contains("--sid PATH"));
        assert!(usage().contains("--data PATH"));
        assert!(usage().contains("--bind ADDR"));
        assert!(usage().contains("[--path PATH]"));
        assert!(usage().len() < 150);
    }

    #[test]
    fn malformed_datagram_does_not_consume_service_loop_state() {
        let sid = include_str!("../../../../fixtures/demo/demo-data.sid");
        let data = include_str!("../../../../fixtures/demo/app-data.json");
        let mut service =
            GenericDataService::from_sid_contents(&[sid], data, "c").expect("application service");
        let server_socket = UdpSocket::bind("127.0.0.1:0").expect("server socket");
        let client_socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        client_socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("client timeout");
        let server_address = server_socket.local_addr().expect("server address");
        let mut buffer = vec![0_u8; 65_535];

        client_socket
            .send_to(&[0xff], server_address)
            .expect("malformed datagram");
        serve_once(&server_socket, &mut service, &mut buffer).expect("malformed iteration");
        assert!(client_socket.recv_from(&mut buffer).is_err());

        let mut request = Packet::new();
        request.header.code = MessageClass::Request(RequestType::Get);
        request.header.set_type(MessageType::Confirmable);
        client_socket
            .send_to(&request.to_bytes().expect("request bytes"), server_address)
            .expect("valid datagram");
        serve_once(&server_socket, &mut service, &mut buffer).expect("valid iteration");
        let (length, peer) = client_socket
            .recv_from(&mut buffer)
            .expect("valid response");
        assert_eq!(peer, server_address);
        let response = Packet::from_bytes(&buffer[..length]).expect("response packet");
        assert!(matches!(response.header.code, MessageClass::Response(_)));
    }
}
