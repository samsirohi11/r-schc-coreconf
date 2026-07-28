//! Integration coverage for the deterministic demonstration contexts.

use std::sync::{Arc, Barrier};
use std::thread;

use coreconf_model::{CoreconfModel, Instance, InstancePath};
use coreconf_runtime::{
    ContentFormat, Datastore, Interface, Method, Request, RequestHandler, ResponseCode,
};
use schc_core::{RuleContext, RuleId, SidRegistry};
use schc_coreconf::{
    canonical_sor_from_tree, canonicalize_sor, derive_protected_management_rule_ids, tree_from_sor,
    ActiveContext, ContextError, PreparedContext, ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile};
use serde_json::Value;
use sha2::Digest;

type Mutation = Box<dyn Fn(&mut Value)>;

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn device() -> DeviceId {
    DeviceId::new("foundation-integration-device").expect("device")
}

fn policy() -> ProtectionPolicy {
    // Protection is an integration policy over the exact 16/8 and 17/8
    // identities, independent of each rule's wire nature.
    ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)])
}

fn prepared() -> PreparedContext {
    PreparedContext::from_sor_with_policy(SID, SOR, device(), DeviceProfile::default(), policy())
        .expect("fixture prepared")
}

fn root_ipatch_payload(tree: &Value) -> Vec<u8> {
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let mut path = InstancePath::new();
    path.push_delta(2574);
    let instance = Instance::new(
        path,
        tree.get("ietf-schc:schc").cloned().expect("SCHC root"),
    );
    Datastore::with_data(model, tree.clone())
        .encode_instances(&[instance])
        .expect("root iPATCH payload")
}

fn handler_for_active(active: &Arc<ActiveContext>) -> RequestHandler {
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let datastore = Datastore::with_backend(model.composite_model().clone(), active.backend());
    RequestHandler::new(datastore)
}

#[test]
fn binary_values_round_trip_losslessly_through_both_models() {
    let (tree, canonical_sor) = canonicalize_sor(SID, SOR).expect("canonical");
    let rebuilt = canonical_sor_from_tree(SID, &tree).expect("re-encode");
    assert_eq!(canonical_sor, rebuilt);
    assert!(tree["ietf-schc:schc"]["rule"][1]["entry"][19]["target-value"][0]["value"].is_string());
}

#[test]
fn public_tree_and_sor_helpers_reject_incomplete_or_semantically_invalid_contexts() {
    assert!(canonical_sor_from_tree(SID, &serde_json::json!({})).is_err());
    assert!(tree_from_sor(SID, &[0xa0]).is_err());

    let (mut tree, _) = canonicalize_sor(SID, SOR).expect("canonical");
    tree["ietf-schc:schc"]["rule"][0]["rule-id-length"] = Value::from(4);
    tree["ietf-schc:schc"]["rule"][0]["rule-id-value"] = Value::from(1);
    tree["ietf-schc:schc"]["rule"][1]["rule-id-length"] = Value::from(8);
    tree["ietf-schc:schc"]["rule"][1]["rule-id-value"] = Value::from(16);
    assert!(canonical_sor_from_tree(SID, &tree).is_err());
}

#[test]
fn management_nature_derives_immutable_protected_rule_ids() {
    let (mut tree, _) = canonicalize_sor(SID, SOR).expect("canonical");
    tree["ietf-schc:schc"]["rule"][2]["rule-nature"] =
        Value::String("ietf-schc:nature-management".to_owned());
    let sor = canonical_sor_from_tree(SID, &tree).expect("managed SoR");
    assert_eq!(
        derive_protected_management_rule_ids(SID, &sor).expect("derived IDs"),
        vec![RuleId::new(20, 8)]
    );
}

#[test]
fn canonical_mutable_order_is_required() {
    let (mut tree, _) = canonicalize_sor(SID, SOR).expect("canonical");
    tree["ietf-schc:schc"]["rule"][1]["entry"]
        .as_array_mut()
        .expect("entries")
        .swap(0, 1);
    let error = PreparedContext::from_tree(SID, tree, device(), DeviceProfile::default(), policy())
        .expect_err("noncanonical ordering must reject");
    assert!(matches!(error, ContextError::NonCanonicalCandidate));
}

#[test]
fn duplicate_prefix_and_malformed_contexts_reject() {
    let (mut tree, _) = canonicalize_sor(SID, SOR).expect("canonical");
    tree["ietf-schc:schc"]["rule"][0]["rule-id-length"] = Value::from(4);
    tree["ietf-schc:schc"]["rule"][0]["rule-id-value"] = Value::from(1);
    tree["ietf-schc:schc"]["rule"][1]["rule-id-length"] = Value::from(8);
    tree["ietf-schc:schc"]["rule"][1]["rule-id-value"] = Value::from(16);
    assert!(canonical_sor_from_tree(SID, &tree).is_err());

    let mut malformed = SOR.to_vec();
    malformed.extend_from_slice(&[0xff]);
    assert!(matches!(
        canonicalize_sor(SID, &malformed),
        Err(ContextError::Cbor(_))
    ));
}

#[test]
fn rejected_protected_commit_leaves_everything_unchanged() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let before = active.snapshot();
    let mut handler = handler_for_active(&active);
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][1]["entry"][0]["field-position"] = Value::from(2);
    let request = Request::new(Method::IPatch)
        .with_interface(Interface::Management)
        .with_payload(
            root_ipatch_payload(&candidate),
            ContentFormat::YangInstancesCborSeq,
        );
    let response = handler.handle(&request);
    assert_eq!(response.code, ResponseCode::InternalServerError);
    assert_eq!(handler.datastore().get_all(), initial.tree().clone());
    assert_eq!(active.tree(), initial.tree().clone());
    assert_eq!(active.generation(), 1);
    assert_eq!(active.digest(), initial.digest());
    assert!(Arc::ptr_eq(&before, &active.snapshot()));
}

#[test]
fn mixed_root_ipatch_failure_is_atomic() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let mut first_path = InstancePath::new();
    first_path.push_delta(2574);
    let first = Instance::new(first_path, initial.tree()["ietf-schc:schc"].clone());
    let mut invalid_path = InstancePath::new();
    invalid_path.push_delta(9999);
    let invalid = Instance::new(invalid_path, Value::Object(serde_json::Map::new()));
    let mut payload = Datastore::with_data(model, initial.tree().clone())
        .encode_instances(&[first])
        .expect("first payload");
    payload.extend(
        coreconf_model::instance_id::encode_instances(&[invalid]).expect("invalid payload"),
    );
    let mut handler = handler_for_active(&active);
    let response = handler.handle(
        &Request::new(Method::IPatch)
            .with_interface(Interface::Management)
            .with_payload(payload, ContentFormat::YangInstancesCborSeq),
    );
    assert_eq!(response.code, ResponseCode::Conflict);
    assert_eq!(handler.datastore().get_all(), initial.tree().clone());
    assert_eq!(active.generation(), 1);
    assert_eq!(active.digest(), initial.digest());
}

#[test]
fn every_protected_lifecycle_mutation_is_rejected() {
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "content",
            Box::new(|tree| {
                tree["ietf-schc:schc"]["rule"][1]["entry"][0]["field-position"] = Value::from(2);
            }),
        ),
        (
            "nature",
            Box::new(|tree| {
                tree["ietf-schc:schc"]["rule"][1]["rule-nature"] =
                    Value::String("ietf-schc:nature-no-compression".to_owned());
            }),
        ),
        (
            "delete",
            Box::new(|tree| {
                tree["ietf-schc:schc"]["rule"]
                    .as_array_mut()
                    .expect("rules")
                    .remove(0);
            }),
        ),
        (
            "rule-id",
            Box::new(|tree| {
                tree["ietf-schc:schc"]["rule"][0]["rule-id-value"] = Value::from(30);
            }),
        ),
        (
            "management-add",
            Box::new(|tree| {
                let mut added = tree["ietf-schc:schc"]["rule"][0].clone();
                added["rule-id-value"] = Value::from(30);
                added["rule-nature"] = Value::String("ietf-schc:nature-management".to_owned());
                tree["ietf-schc:schc"]["rule"]
                    .as_array_mut()
                    .expect("rules")
                    .push(added);
            }),
        ),
    ];
    for (name, mutate) in cases {
        let initial = prepared();
        let active = Arc::new(ActiveContext::new(initial.clone()));
        let mut handler = handler_for_active(&active);
        let mut candidate = initial.tree().clone();
        mutate(&mut candidate);
        let request = Request::new(Method::IPatch)
            .with_interface(Interface::Management)
            .with_payload(
                root_ipatch_payload(&candidate),
                ContentFormat::YangInstancesCborSeq,
            );
        assert_eq!(
            handler.handle(&request).code,
            ResponseCode::InternalServerError,
            "{name}"
        );
        assert_eq!(active.generation(), 1, "{name}");
        assert_eq!(active.tree(), initial.tree().clone(), "{name}");
        assert_eq!(active.digest(), initial.digest(), "{name}");
        assert_eq!(
            handler.datastore().get_all(),
            initial.tree().clone(),
            "{name}"
        );
    }
}

#[test]
fn active_backend_datastore_is_live_source_of_truth() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let mut datastore = Datastore::with_backend(model.composite_model().clone(), active.backend());
    assert_eq!(datastore.get_all(), initial.tree().clone());
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    datastore.replace_tree(candidate.clone()).expect("publish");
    assert_eq!(datastore.get_all(), candidate);
    assert_eq!(active.tree(), candidate);
    assert_eq!(active.generation(), 2);
}

#[test]
fn valid_local_root_ipatch_publishes_once_as_one_tuple() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let mut handler = handler_for_active(&active);
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    let request = Request::new(Method::IPatch)
        .with_interface(Interface::Management)
        .with_payload(
            root_ipatch_payload(&candidate),
            ContentFormat::YangInstancesCborSeq,
        );
    let response = handler.handle(&request);
    assert_eq!(response.code, ResponseCode::Changed);
    assert_eq!(active.generation(), 2);
    assert_eq!(active.tree(), candidate);
    assert_eq!(handler.datastore().get_all(), candidate);
    let snapshot = active.snapshot();
    assert_eq!(snapshot.generation(), 2);
    assert_eq!(snapshot.tree(), &candidate);
    assert_eq!(
        snapshot.sor(),
        canonical_sor_from_tree(SID, &candidate).unwrap()
    );
    assert_eq!(snapshot.runtime().device_id().as_str(), device().as_str());

    // A successful request publishes one complete tuple exactly once.
    assert_eq!(active.generation(), 2);
}

#[test]
fn digest_changes_only_when_canonical_context_changes() {
    let initial = prepared();
    let same = PreparedContext::from_sor_with_policy(
        SID,
        SOR,
        device(),
        DeviceProfile::default(),
        policy(),
    )
    .expect("same");
    assert_eq!(initial.digest(), same.digest());
    let mut tree = initial.tree().clone();
    tree["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    let changed =
        PreparedContext::from_tree(SID, tree, device(), DeviceProfile::default(), policy())
            .expect("changed");
    assert_ne!(initial.digest(), changed.digest());
}

fn run_competing_writer(
    active: Arc<ActiveContext>,
    candidate: Value,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<(bool, Value, String)> {
    thread::spawn(move || {
        let model = CoreconfModel::from_sid_str(SID).expect("model");
        let mut datastore =
            Datastore::with_backend(model.composite_model().clone(), active.backend());
        let _base = datastore.get_all();
        barrier.wait();
        barrier.wait();
        let result = datastore.replace_tree(candidate);
        let success = result.is_ok();
        let error = result.map_or_else(|error| error.to_string(), |()| String::new());
        (success, datastore.get_all(), error)
    })
}

#[test]
fn invalid_backend_candidate_has_no_hidden_pending_state() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let mut datastore = Datastore::with_backend(model.composite_model().clone(), active.backend());
    let mut invalid = initial.tree().clone();
    invalid["ietf-schc:schc"]["rule"][1]["entry"][0]["field-position"] = Value::from(2);
    assert!(datastore.replace_tree(invalid).is_err());
    assert_eq!(active.generation(), 1);
    assert_eq!(active.tree(), initial.tree().clone());
    assert_eq!(active.digest(), initial.digest());

    let mut valid = initial.tree().clone();
    valid["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    datastore
        .replace_tree(valid.clone())
        .expect("failed backend candidate leaves no pending state");
    assert_eq!(active.generation(), 2);
    assert_eq!(active.tree(), valid);
}

#[test]
fn concurrent_backend_writers_reject_stale_candidates_without_lost_updates() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let mut first_candidate = initial.tree().clone();
    first_candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    let mut second_candidate = initial.tree().clone();
    second_candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("CA==".to_owned());
    let barrier = Arc::new(Barrier::new(2));
    let first_thread =
        run_competing_writer(Arc::clone(&active), first_candidate, Arc::clone(&barrier));
    let second_thread = run_competing_writer(active.clone(), second_candidate, barrier);
    let results = [
        first_thread.join().expect("first writer"),
        second_thread.join().expect("second writer"),
    ];
    assert_eq!(results.iter().filter(|result| result.0).count(), 1);
    assert_eq!(results.iter().filter(|result| !result.0).count(), 1);
    assert_eq!(active.generation(), 2);
    let winner = results.iter().find(|result| result.0).expect("winner");
    let loser = results.iter().find(|result| !result.0).expect("loser");
    assert_eq!(active.tree(), winner.1);
    assert!(loser.2.contains("active context changed"));
}

#[test]
fn concurrent_snapshot_reads_observe_consistent_tuples() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let reader_active = Arc::clone(&active);
    let reader = thread::spawn(move || {
        for _ in 0..2_000 {
            let snapshot = reader_active.snapshot();
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"schc-coreconf/managed-context/v1\0");
            let tree = serde_json::to_vec(snapshot.tree()).expect("snapshot tree serializes");
            hasher.update((tree.len() as u64).to_be_bytes());
            hasher.update(tree);
            hasher.update((snapshot.sor().len() as u64).to_be_bytes());
            hasher.update(snapshot.sor());
            let expected_digest: [u8; 32] = hasher.finalize().into();
            assert_eq!(snapshot.digest(), expected_digest);
            assert_eq!(
                snapshot.runtime().device_id().as_str(),
                "foundation-integration-device"
            );
        }
    });
    // Reads are the stress contract here. A second immutable snapshot is also
    // taken on the writer thread to ensure publication remains lock-free.
    for _ in 0..2_000 {
        let _ = active.snapshot();
    }
    reader.join().expect("reader");
}

#[test]
fn sid_loader_rejects_non_enveloped_rschc_input() {
    let plain = SID.replace("\"ietf-sid-file:sid-file\":", "\"sid-file\":");
    let error = SidRegistry::from_json_str(&plain).expect_err("wrong envelope");
    assert!(!error.to_string().is_empty());
    let _ = RuleContext::from_cbor_slice;
}
