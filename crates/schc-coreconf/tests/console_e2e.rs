//! Real core/device console inspection coverage.

mod support;

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use schc_core::RuleId;
use schc_coreconf::{
    format_rule_detail, ActiveContext, InspectionService, PreparedContext, ProtectionPolicy,
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
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
    )
    .expect("prepared context")
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
        ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)]),
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
    assert!(core_stdout.contains("CONTEXT CHECK mismatch core_tag="));
    assert!(
        core_stdout.contains("CORE MGMT TX class=ProtectedManagement rule=16/8"),
        "core stdout: {core_stdout}"
    );
    assert!(core_stdout.contains("CORE MGMT RX class=ProtectedManagement rule=17/8"));
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
    let check_line = core_stdout
        .lines()
        .find(|line| line.starts_with("CONTEXT CHECK mismatch "))
        .expect("mismatch line");
    let tags = check_line.split_whitespace().collect::<Vec<_>>();
    assert_ne!(
        tags[3].strip_prefix("core_tag="),
        tags[4].strip_prefix("device_tag="),
        "context tags should differ"
    );

    device.kill();
    let (_, device_stderr) = device.output();
    assert!(device_stderr.is_empty(), "device stderr: {device_stderr}");
    std::fs::remove_file(updated_path).expect("remove temporary SoR");
}
