//! Shared finite-process configuration and reporting.

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use schc_coreconf::{
    format_report, protected_management_rule_ids, ActiveContext, LinkReport, PreparedContext,
    ProtectionPolicy, RawUdpLink, ReportDirection,
};
use schc_runtime::{DeviceId, DeviceProfile};

const DEFAULT_SID: &str = include_str!("../../../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const DEFAULT_SOR: &[u8] = include_bytes!("../../../../../fixtures/demo/initial.sor");

#[allow(dead_code)]
pub(crate) const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(dead_code)]
pub(crate) const DEVICE_POLL: Duration = Duration::from_millis(250);

pub(crate) struct Args {
    pub(crate) link_bind: SocketAddr,
    pub(crate) link_peer: SocketAddr,
    pub(crate) debug: bool,
    pub(crate) once: bool,
    app_sid: Vec<PathBuf>,
    app_data: Option<PathBuf>,
    sid: Option<PathBuf>,
    sor: Option<PathBuf>,
    device_id: String,
}

impl Args {
    pub(crate) fn parse(
        process_name: &'static str,
        requires_app_bind: bool,
    ) -> Result<Option<(Self, Option<SocketAddr>)>, String> {
        let mut sid = None;
        let mut sor = None;
        let mut app_sid = Vec::new();
        let mut app_data = None;
        let mut device_id = "demo-device".to_owned();
        let mut link_bind = None;
        let mut link_peer = None;
        let mut app_bind = None;
        let mut debug = false;
        let mut once = false;
        let mut help = false;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--sid" => sid = Some(PathBuf::from(next(&mut arguments, "--sid")?)),
                "--sor" => sor = Some(PathBuf::from(next(&mut arguments, "--sor")?)),
                "--app-sid" => app_sid.push(PathBuf::from(next(&mut arguments, "--app-sid")?)),
                "--app-data" => app_data = Some(PathBuf::from(next(&mut arguments, "--app-data")?)),
                "--device-id" => device_id = next(&mut arguments, "--device-id")?,
                "--link-bind" => {
                    link_bind = Some(parse_addr(
                        &next(&mut arguments, "--link-bind")?,
                        "--link-bind",
                    )?);
                }
                "--link-peer" => {
                    link_peer = Some(parse_addr(
                        &next(&mut arguments, "--link-peer")?,
                        "--link-peer",
                    )?);
                }
                "--app-bind" => {
                    app_bind = Some(parse_addr(
                        &next(&mut arguments, "--app-bind")?,
                        "--app-bind",
                    )?);
                }
                "--debug" => debug = true,
                "--once" => once = true,
                "-h" | "--help" => help = true,
                other => return Err(format!("unknown argument {other}; use --help")),
            }
        }
        if help {
            print_usage(process_name, requires_app_bind);
            return Ok(None);
        }
        if requires_app_bind && app_bind.is_none() {
            return Err("missing required --app-bind".to_owned());
        }
        if !requires_app_bind && app_bind.is_some() {
            return Err("--app-bind is valid only for the core process".to_owned());
        }
        if requires_app_bind && (!app_sid.is_empty() || app_data.is_some()) {
            return Err(
                "--app-sid and --app-data are valid only for the device process".to_owned(),
            );
        }
        if !requires_app_bind && app_sid.is_empty() {
            return Err("missing required --app-sid".to_owned());
        }
        if !requires_app_bind && app_data.is_none() {
            return Err("missing required --app-data".to_owned());
        }
        Ok(Some((
            Self {
                app_sid,
                app_data,
                sid,
                sor,
                device_id,
                link_bind: link_bind.ok_or("missing required --link-bind")?,
                link_peer: link_peer.ok_or("missing required --link-peer")?,
                debug,
                once,
            },
            app_bind,
        )))
    }

    pub(crate) fn application_inputs(&self) -> (&[PathBuf], Option<&Path>) {
        (&self.app_sid, self.app_data.as_deref())
    }

    pub(crate) fn active_context(&self) -> Result<Arc<ActiveContext>, String> {
        let sid = load_text(self.sid.as_deref(), DEFAULT_SID)?;
        let sor = load_bytes(self.sor.as_deref(), DEFAULT_SOR)?;
        let device_id = DeviceId::new(self.device_id.clone()).map_err(|error| error.to_string())?;
        let prepared = PreparedContext::from_sor_with_policy(
            &sid,
            &sor,
            device_id,
            DeviceProfile::default(),
            ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
        )
        .map_err(|error| error.to_string())?;
        Ok(Arc::new(ActiveContext::new(prepared)))
    }
}

pub(crate) fn bind_raw_link(
    args: &Args,
    read_timeout: Option<Duration>,
) -> Result<(RawUdpLink, SocketAddr), String> {
    let raw_link = RawUdpLink::bind(args.link_bind, args.link_peer)
        .map_err(|error| format!("bind SCHC link: {error}"))?;
    raw_link
        .set_read_timeout(read_timeout)
        .map_err(|error| format!("set SCHC link timeout: {error}"))?;
    let local = raw_link
        .local_addr()
        .map_err(|error| format!("query SCHC link socket: {error}"))?;
    Ok((raw_link, local))
}

pub(crate) fn print_report(
    direction: ReportDirection,
    report: &LinkReport,
    debug: bool,
) -> Result<(), String> {
    print!(
        "{}",
        format_report(direction, report, debug).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn load_text(path: Option<&Path>, default: &str) -> Result<String, String> {
    path.map_or_else(
        || Ok(default.to_owned()),
        |path| {
            std::fs::read_to_string(path)
                .map_err(|error| format!("read SID {}: {error}", path.display()))
        },
    )
}

fn load_bytes(path: Option<&Path>, default: &[u8]) -> Result<Vec<u8>, String> {
    path.map_or_else(
        || Ok(default.to_vec()),
        |path| std::fs::read(path).map_err(|error| format!("read SoR {}: {error}", path.display())),
    )
}

fn print_usage(process_name: &str, requires_app_bind: bool) {
    let app = if requires_app_bind {
        " --app-bind ADDR"
    } else {
        " --app-sid PATH --app-data PATH"
    };
    println!(
        "Usage: {process_name} --link-bind ADDR --link-peer ADDR{app} [--debug] [--once] [--sid PATH] [--sor PATH] [--device-id ID]"
    );
    println!("Options:");
    println!("  --debug  Include structured packet and SCHC accounting in traffic reports");
    println!("  --once   Exit after the first completed operation");
    if requires_app_bind {
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
    } else {
        println!("Device mode: waits for SCHC frames from its configured peer");
    }
}

fn next(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_addr(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|error| format!("invalid {flag} address {value}: {error}"))
}
