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

pub(crate) struct Args {
    pub(crate) link_bind: SocketAddr,
    pub(crate) link_peer: SocketAddr,
    pub(crate) debug: bool,
    pub(crate) once: bool,
    pub(crate) tun_name: String,
    pub(crate) tun_mtu: u16,
    sid: Option<PathBuf>,
    sor: Option<PathBuf>,
    device_id: String,
}

impl Args {
    pub(crate) fn parse(process_name: &'static str, is_core: bool) -> Result<Option<Self>, String> {
        let mut sid = None;
        let mut sor = None;
        let mut device_id = "demo-device".to_owned();
        let mut link_bind = None;
        let mut link_peer = None;
        let mut tun_name = None;
        let mut tun_mtu = 1280_u16;
        let mut debug = false;
        let mut once = false;
        let mut help = false;
        let mut arguments = env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--sid" => sid = Some(PathBuf::from(next(&mut arguments, "--sid")?)),
                "--sor" => sor = Some(PathBuf::from(next(&mut arguments, "--sor")?)),
                "--tun-name" => tun_name = Some(next(&mut arguments, "--tun-name")?),
                "--tun-mtu" => {
                    tun_mtu = next(&mut arguments, "--tun-mtu")?
                        .parse()
                        .map_err(|error| format!("invalid --tun-mtu value: {error}"))?;
                }
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
                "--debug" => debug = true,
                "--once" => once = true,
                "-h" | "--help" => help = true,
                other => return Err(format!("unknown argument {other}; use --help")),
            }
        }
        if help {
            print_usage(process_name, is_core);
            return Ok(None);
        }
        let tun_name = tun_name.ok_or("missing required --tun-name")?;
        if tun_name.is_empty() {
            return Err("--tun-name must not be empty".to_owned());
        }
        if tun_mtu < 1280 {
            return Err("--tun-mtu must be at least 1280".to_owned());
        }
        let _ = is_core;
        Ok(Some(Self {
            sid,
            sor,
            device_id,
            link_bind: link_bind.ok_or("missing required --link-bind")?,
            link_peer: link_peer.ok_or("missing required --link-peer")?,
            debug,
            once,
            tun_name,
            tun_mtu,
        }))
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

fn print_usage(process_name: &str, is_core: bool) {
    println!(
        "Usage: {process_name} --link-bind ADDR --link-peer ADDR --tun-name NAME [--tun-mtu MTU] [--debug] [--once] [--sid PATH] [--sor PATH] [--device-id ID]"
    );
    println!("Options:");
    println!("  --debug  Include structured packet and SCHC accounting in traffic reports");
    println!("  --once   Exit after the first completed operation");
    if is_core {
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
