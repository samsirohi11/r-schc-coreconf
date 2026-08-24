//! Real core/device console inspection coverage.

mod support;

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use schc_coreconf::{
    format_rule_detail, protected_management_rule_ids, ActiveContext, InspectionService,
    PreparedContext, ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile};
use support::TestProcess;

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn reserve_address() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("reserve UDP port");
    let address = socket.local_addr().expect("reserved address");
    (socket, address)
}

fn prepared(sor: &[u8], device_id: &str) -> PreparedContext {
    PreparedContext::from_sor_with_policy(
        SID,
        sor,
        DeviceId::new(device_id).expect("device ID"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
    )
    .expect("prepared context")
}

fn start_processes(
    core_sor: Option<&Path>,
    device_sor: Option<&Path>,
) -> (TestProcess, TestProcess) {
    let app_sid =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo/demo-data.sid");
    let app_data =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo/app-data.json");
    let (device_reservation, device_link) = reserve_address();
    let (core_reservation, core_link) = reserve_address();
    let (app_reservation, core_app) = reserve_address();
    let mut device_args = vec![
        "--link-bind".to_owned(),
        device_link.to_string(),
        "--link-peer".to_owned(),
        core_link.to_string(),
        "--app-sid".to_owned(),
        app_sid.to_string_lossy().into_owned(),
        "--app-data".to_owned(),
        app_data.to_string_lossy().into_owned(),
    ];
    if let Some(path) = device_sor {
        device_args.extend(["--sor".to_owned(), path.to_string_lossy().into_owned()]);
    }
    drop(device_reservation);
    let device = TestProcess::spawn(env!("CARGO_BIN_EXE_schc-coreconf-device"), &device_args);
    device
        .ready
        .recv_timeout(Duration::from_secs(5))
        .expect("device readiness");

    let mut core_args = vec![
        "--link-bind".to_owned(),
        core_link.to_string(),
        "--link-peer".to_owned(),
        device_link.to_string(),
        "--app-bind".to_owned(),
        core_app.to_string(),
    ];
    if let Some(path) = core_sor {
        core_args.extend(["--sor".to_owned(), path.to_string_lossy().into_owned()]);
    }
    drop(core_reservation);
    drop(app_reservation);
    let core = TestProcess::spawn(env!("CARGO_BIN_EXE_schc-coreconf-core"), &core_args);
    core.ready
        .recv_timeout(Duration::from_secs(5))
        .expect("core readiness");
    (device, core)
}

fn assert_no_stderr(process_name: &str, stderr: &str) {
    assert!(stderr.is_empty(), "{process_name} stderr: {stderr}");
}

fn context_checks(stdout: &str, result: &str) -> Vec<String> {
    let expected = if result == "equal" {
        format!("OK context check  {result}")
    } else {
        format!("ERROR context check  {result}")
    };
    stdout
        .lines()
        .filter(|line| *line == expected)
        .map(str::to_owned)
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_console_inspection_reports_remote_mismatch_and_detail() {
    let core_active = Arc::new(ActiveContext::new(prepared(SOR, "console-core")));
    let mut updated_tree = core_active.tree();
    updated_tree["ietf-schc:schc"]["rule"][2]["entry"][9]["target-value"][0]["value"] =
        serde_json::json!("0000000000000006");
    let updated_source = PreparedContext::from_tree(
        SID,
        updated_tree,
        DeviceId::new("console-device").expect("device ID"),
        DeviceProfile::default(),
        ProtectionPolicy::from_rule_ids(protected_management_rule_ids()),
    )
    .expect("updated context");
    let updated = prepared(updated_source.sor(), "console-device");
    let updated_service = InspectionService::new(Arc::new(ActiveContext::new(updated.clone())))
        .expect("updated inspection service");
    let core_service = InspectionService::new(Arc::clone(&core_active)).expect("core service");
    let selector = schc_coreconf::parse_rule_selector("20/8").expect("selector");
    let initial_lines = format_rule_detail(&core_service.detail(selector).expect("core detail"));
    let remote_lines =
        format_rule_detail(&updated_service.detail(selector).expect("device detail"));
    assert_ne!(initial_lines, remote_lines);

    let updated_path = std::env::temp_dir().join(format!(
        "schc-coreconf-console-{}-{}.sor",
        std::process::id(),
        core_active.tag()
    ));
    std::fs::write(&updated_path, updated.sor()).expect("write updated SoR");

    let (device_reservation, device_link) = reserve_address();
    let (core_reservation, core_link) = reserve_address();
    let (app_reservation, core_app) = reserve_address();
    let app_sid =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo/demo-data.sid");
    let app_data =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo/app-data.json");
    let device_args = vec![
        "--link-bind".to_owned(),
        device_link.to_string(),
        "--link-peer".to_owned(),
        core_link.to_string(),
        "--sor".to_owned(),
        updated_path.to_string_lossy().into_owned(),
        "--app-sid".to_owned(),
        app_sid.to_string_lossy().into_owned(),
        "--app-data".to_owned(),
        app_data.to_string_lossy().into_owned(),
    ];
    drop(device_reservation);
    let mut device = TestProcess::spawn(env!("CARGO_BIN_EXE_schc-coreconf-device"), &device_args);
    device
        .ready
        .recv_timeout(Duration::from_secs(5))
        .expect("device readiness");

    let core_args = vec![
        "--link-bind".to_owned(),
        core_link.to_string(),
        "--link-peer".to_owned(),
        device_link.to_string(),
        "--app-bind".to_owned(),
        core_app.to_string(),
    ];
    drop(core_reservation);
    drop(app_reservation);
    let mut core = TestProcess::spawn(env!("CARGO_BIN_EXE_schc-coreconf-core"), &core_args);
    core.ready
        .recv_timeout(Duration::from_secs(5))
        .expect("core readiness");
    core.write_stdin(
        b"context check\nrule list device\nrule get core 20/8\nrule get device 20/8\nquit\n",
    );

    let core_status = core.wait_timeout(Duration::from_secs(15));
    assert!(core_status.success(), "core status: {core_status}");
    let (core_stdout, core_stderr) = core.output();
    assert!(core_stderr.is_empty(), "core stderr: {core_stderr}");
    assert!(core_stdout.contains("ERROR context check  mismatch"));
    assert!(
        core_stdout.contains("TX MGMT  16/8"),
        "core stdout: {core_stdout}"
    );
    assert!(core_stdout.contains("RX MGMT  17/8"));
    assert!(core_stdout.contains("RULE 16/8 nature=compression"));
    assert!(core_stdout.contains("RULE 20/8 nature=compression"));
    for line in initial_lines {
        assert!(
            core_stdout.contains(&line),
            "missing core detail line: {line}"
        );
    }
    for line in remote_lines {
        assert!(
            core_stdout.contains(&line),
            "missing remote detail line: {line}"
        );
    }
    assert!(!core_stdout.contains("core tag="));

    device.kill();
    let (_, device_stderr) = device.output();
    assert!(device_stderr.is_empty(), "device stderr: {device_stderr}");
    std::fs::remove_file(updated_path).expect("remove temporary SoR");
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_console_rule_update_synchronizes_contexts_over_protected_link() {
    let (mut device, mut core) = start_processes(None, None);
    core.write_stdin(
        b"context check\nrule update 20/8 fid=ipv6.app-iid tv=6 --if-match\ncontext check\nrule get core 20/8\nrule get device 20/8\nquit\n",
    );
    let core_status = core.wait_timeout(Duration::from_secs(20));
    assert!(core_status.success(), "core status: {core_status}");
    let (core_stdout, core_stderr) = core.output();
    assert_no_stderr("core", &core_stderr);
    let equal_checks = context_checks(&core_stdout, "equal");
    assert_eq!(equal_checks.len(), 2, "core stdout: {core_stdout}");
    assert_eq!(equal_checks[0], "OK context check  equal");
    assert_eq!(equal_checks[1], "OK context check  equal");
    assert!(
        core_stdout.contains("TX MGMT  16/8"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("RX MGMT  17/8"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("OK update 20/8 entry=9  device=changed  local=changed"),
        "core stdout: {core_stdout}"
    );
    assert!(core_stdout.contains("ENTRY 9 fid=fid-ipv6-appiid"));
    assert!(core_stdout.contains("tv=0x0000000000000006"));
    assert!(core_stdout.contains("RULE 20/8 nature=compression"));

    device.kill();
    let (device_stdout, device_stderr) = device.output();
    assert_no_stderr("device", &device_stderr);
    assert!(
        device_stdout.contains("RX MGMT  16/8"),
        "device stdout: {device_stdout}"
    );
    assert!(
        device_stdout.contains("TX MGMT  17/8"),
        "device stdout: {device_stdout}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_console_duplicate_rule_is_atomic_idempotent_and_no_response() {
    let (mut device, mut core) = start_processes(None, None);
    core.write_stdin(
        b"context status\nrule duplicate 20/8 22/8 entry=9 tv=2\nrule duplicate 20/8 22/8 entry=9 tv=2\nrule duplicate 20/8 22/8 entry=9 tv=3\nrule get core 20/8\nrule get core 22/8\ncontext status\nquit\n",
    );
    let core_status = core.wait_timeout(Duration::from_secs(20));
    assert!(core_status.success(), "core status: {core_status}");
    let (core_stdout, core_stderr) = core.output();
    assert_no_stderr("core", &core_stderr);
    assert!(core_stdout.lines().any(|line| {
        line == "OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged"
    }));
    assert!(core_stdout.lines().any(|line| {
        line == "OK duplicate 20/8 -> 22/8  local=idempotent  remote=unacknowledged"
    }));
    assert!(
        core_stdout.contains("RULE 22/8 nature=compression"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("ENTRY 9 fid=fid-ipv6-appiid"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("tv=0x0000000000000002"),
        "core stdout: {core_stdout}"
    );
    let statuses = core_stdout
        .lines()
        .filter(|line| line.starts_with("CONTEXT generation="))
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        [
            "CONTEXT generation=1  rules=9",
            "CONTEXT generation=2  rules=10"
        ]
    );

    device.wait_for_stdout("ERROR duplicate  local=failed", Duration::from_secs(5));
    device.kill();
    let (device_stdout, device_stderr) = device.output();
    assert_no_stderr("device", &device_stderr);
    assert!(
        device_stdout.contains("RX MGMT  29/8"),
        "device stdout: {device_stdout}"
    );
    assert!(
        device_stdout
            .lines()
            .any(|line| line == "OK duplicate  local=installed  response=none")
            && device_stdout
                .lines()
                .any(|line| line == "OK duplicate  local=idempotent  response=none")
            && device_stdout
                .lines()
                .any(|line| line.starts_with("ERROR duplicate  local=failed")),
        "device stdout: {device_stdout}"
    );
    assert!(
        !device_stdout.contains("TX MGMT"),
        "device unexpectedly sent a response: {device_stdout}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_console_default_rule_update_uses_dedicated_compressed_rule() {
    let (mut device, mut core) = start_processes(None, None);
    core.write_stdin(b"rule update 20/8 fid=ipv6.app-iid tv=6\nquit\n");
    let core_status = core.wait_timeout(Duration::from_secs(20));
    assert!(core_status.success(), "core status: {core_status}");
    let (core_stdout, core_stderr) = core.output();
    assert_no_stderr("core", &core_stderr);
    assert!(
        core_stdout.contains("TX MGMT  27/8"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("RX MGMT  17/8"),
        "core stdout: {core_stdout}"
    );
    assert!(core_stdout.contains("OK update 20/8 entry=9  device=changed  local=changed"));

    device.kill();
    let (device_stdout, device_stderr) = device.output();
    assert_no_stderr("device", &device_stderr);
    assert!(
        device_stdout.contains("RX MGMT  27/8"),
        "device stdout: {device_stdout}"
    );
    assert!(
        device_stdout.contains("TX MGMT  17/8"),
        "device stdout: {device_stdout}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_console_rule_update_rejects_stale_if_match_without_local_publication() {
    let updated = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo/updated.sor");
    let (mut device, mut core) = start_processes(Some(&updated), None);
    core.write_stdin(
        b"context status\ncontext check\nrule update 20/8 fid=ipv6.app-iid tv=6 --if-match\ncontext status\ncontext check\nquit\n",
    );
    let core_status = core.wait_timeout(Duration::from_secs(20));
    assert!(core_status.success(), "core status: {core_status}");
    let (core_stdout, core_stderr) = core.output();
    assert_no_stderr("core", &core_stderr);
    let mismatch_checks = context_checks(&core_stdout, "mismatch");
    assert_eq!(mismatch_checks.len(), 2, "core stdout: {core_stdout}");
    assert_eq!(mismatch_checks[0], "ERROR context check  mismatch");
    assert_eq!(mismatch_checks[1], "ERROR context check  mismatch");
    assert!(
        core_stdout.contains("TX MGMT  16/8"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("RX MGMT  17/8"),
        "core stdout: {core_stdout}"
    );
    assert!(
        core_stdout.contains("ERROR rule update 20/8 entry=9 device=4.12 rejected; local=not-attempted; local=unchanged"),
        "core stdout: {core_stdout}"
    );
    assert!(!core_stdout.contains("RULE UPDATE 20/8 entry=9 device=2.04"));
    assert!(!core_stdout.contains("tag="));
    let statuses = core_stdout
        .lines()
        .filter(|line| line.starts_with("CONTEXT generation="))
        .collect::<Vec<_>>();
    assert_eq!(statuses.len(), 2, "core stdout: {core_stdout}");
    assert!(statuses
        .iter()
        .all(|line| *line == "CONTEXT generation=1  rules=9"));
    assert!(statuses.iter().all(|line| !line.contains("tag=")));

    device.kill();
    let (device_stdout, device_stderr) = device.output();
    assert_no_stderr("device", &device_stderr);
    assert!(
        device_stdout.contains("RX MGMT  16/8"),
        "device stdout: {device_stdout}"
    );
    assert!(
        device_stdout.contains("TX MGMT  17/8"),
        "device stdout: {device_stdout}"
    );
}
