//! Scriptable CORECONF application data client.

use std::env;
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use coreconf_model::CompositeModel;
use schc_coreconf::DataClient;
use serde_json::Value;

fn main() {
    if let Err(error) = run() {
        eprintln!("schc-data-client: ERROR {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse()?;
    if options.help {
        print_usage();
        return Ok(());
    }
    let sid_contents = options
        .sid_paths
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .map_err(|error| format!("read SID {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sid_refs: Vec<&str> = sid_contents.iter().map(String::as_str).collect();
    let model = CompositeModel::from_sid_strings(&sid_refs)
        .map_err(|error| format!("load application SID model: {error}"))?;
    let mut client = DataClient::connect(model, options.server, options.resource_path)
        .map_err(|error| format!("connect application endpoint: {error}"))?;
    println!("READY client  server={}", client.endpoint());
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if interactive {
        println!("Type 'help' for commands");
        print_prompt()?;
    } else {
        io::stdout()
            .flush()
            .map_err(|error| format!("flush readiness: {error}"))?;
    }

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read command: {error}"))?;
        if line.trim().is_empty() {
            if interactive {
                print_prompt()?;
            }
            continue;
        }
        let quit = match execute_command(&mut client, &line) {
            Ok(quit) => quit,
            Err(error) => {
                println!("ERROR {error}");
                false
            }
        };
        if quit {
            break;
        }
        if interactive {
            print_prompt()?;
        } else {
            io::stdout()
                .flush()
                .map_err(|error| format!("flush command output: {error}"))?;
        }
    }
    Ok(())
}

fn execute_command(client: &mut DataClient, line: &str) -> Result<bool, String> {
    let mut words = line.splitn(2, char::is_whitespace);
    let command = words.next().unwrap_or_default();
    let rest = words.next().map(str::trim).unwrap_or_default();
    match command {
        "discover" => {
            let query = (!rest.is_empty()).then_some(rest);
            print_result(client.discover(query));
        }
        "schema" => {
            let filter = (!rest.is_empty()).then_some(rest);
            for entry in client.schema(filter) {
                println!("{entry}");
            }
        }
        "get" => {
            let path = required_argument(rest, "get <path>")?;
            print_json_result(client.get(path));
        }
        "fetch" => {
            let path = required_argument(rest, "fetch <path>")?;
            print_json_result(client.fetch(path));
        }
        "set" => {
            let mut arguments = rest.splitn(2, char::is_whitespace);
            let path = required_argument(
                arguments.next().unwrap_or_default(),
                "set <path> <json-value>",
            )?;
            let json = required_argument(
                arguments.next().unwrap_or_default().trim(),
                "set <path> <json-value>",
            )?;
            let value: Value = serde_json::from_str(json)
                .map_err(|error| format!("invalid JSON value: {error}"))?;
            print_mutation("set", client.set(path, value));
        }
        "delete" => {
            let path = required_argument(rest, "delete <path>")?;
            print_delete(client.delete(path));
        }
        "reload" => print_reload(client.reload()),
        "help" => print_command_help(),
        "quit" => return Ok(true),
        other => println!("ERROR unknown command '{other}'; use help"),
    }
    Ok(false)
}

fn print_result(result: Result<String, schc_coreconf::ApplicationError>) {
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => println!("ERROR {error}"),
    }
}

fn print_mutation(action: &str, result: Result<(), schc_coreconf::ApplicationError>) {
    match result {
        Ok(()) => println!("OK {action}"),
        Err(error) => println!("ERROR {error}"),
    }
}

fn print_delete(result: Result<(), schc_coreconf::ApplicationError>) {
    match result {
        Ok(()) => println!("OK delete"),
        Err(schc_coreconf::ApplicationError::Remote { code, .. }) if code == "4.04" => {
            println!("OK delete  not-found");
        }
        Err(error) => println!("ERROR {error}"),
    }
}

fn print_reload(result: Result<Value, schc_coreconf::ApplicationError>) {
    match result {
        Ok(_) => println!("OK reload"),
        Err(error) => println!("ERROR {error}"),
    }
}

fn print_json_result(result: Result<Option<Value>, schc_coreconf::ApplicationError>) {
    match result {
        Ok(Some(value)) => print_json(&value),
        Ok(None) => println!("not found"),
        Err(error) => println!("ERROR {error}"),
    }
}

fn print_json(value: &Value) {
    match serde_json::to_string_pretty(&value) {
        Ok(value) => println!("{value}"),
        Err(error) => println!("ERROR render JSON value: {error}"),
    }
}

fn required_argument<'a>(value: &'a str, usage: &str) -> Result<&'a str, String> {
    if value.is_empty() {
        Err(format!("usage: {usage}"))
    } else {
        Ok(value)
    }
}

struct Options {
    sid_paths: Vec<PathBuf>,
    server: SocketAddr,
    resource_path: String,
    help: bool,
}

impl Options {
    fn parse() -> Result<Self, String> {
        let mut sid_paths = Vec::new();
        let mut server = None;
        let mut resource_path = "c".to_owned();
        let mut help = false;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--sid" => sid_paths.push(PathBuf::from(next(&mut arguments, "--sid")?)),
                "--server" | "--endpoint" => {
                    let value = next(&mut arguments, argument.as_str())?;
                    server =
                        Some(value.parse().map_err(|error| {
                            format!("invalid {argument} address {value}: {error}")
                        })?);
                }
                "--path" => resource_path = next(&mut arguments, "--path")?,
                "-h" | "--help" => help = true,
                other => return Err(format!("unknown argument {other}; use --help")),
            }
        }
        if help {
            return Ok(Self {
                sid_paths,
                server: SocketAddr::from(([127, 0, 0, 1], 0)),
                resource_path,
                help,
            });
        }
        if sid_paths.is_empty() {
            return Err("missing required --sid PATH".to_owned());
        }
        Ok(Self {
            sid_paths,
            server: server.ok_or("missing required --server ADDR")?,
            resource_path,
            help,
        })
    }
}

fn next(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    println!("Usage: schc-data-client --sid PATH [--sid PATH ...] --server ADDR [--path PATH]");
    print_command_help();
}

fn print_command_help() {
    println!("Data client commands:");
    println!("  discover [query]");
    println!("  schema [filter]");
    println!("  get <path>");
    println!("  fetch <path>");
    println!("  set <path> <json-value>");
    println!("  delete <path>");
    println!("  reload");
    println!("  help");
    println!("  quit");
}

fn print_prompt() -> Result<(), String> {
    print!("data> ");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush data prompt: {error}"))
}
