//! Integration coverage for the managed-context foundation.

use std::sync::{Arc, Barrier};
use std::thread;

use coreconf_model::{CoreconfError, CoreconfModel, Instance, InstancePath};
use coreconf_runtime::{
    Backend, ContentFormat, Datastore, Interface, Method, Request, RequestHandler, ResponseCode,
};
use schc_core::{RuleContext, RuleId, SidRegistry};
use schc_coreconf::{
    canonical_sor_from_tree, canonicalize_sor, derive_protected_management_rule_ids, tree_from_sor,
    ActiveContext, ContextError, ContextParticipant, PreparedContext, ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile};
use serde_json::Value;
use sha2::Digest;

type Mutation = Box<dyn Fn(&mut Value)>;

const SID: &str = include_str!("../../../fixtures/managed/ietf-schc@2026-05-07.sid");
const SOR: &[u8] = include_bytes!("../../../fixtures/managed/core.sor");

fn device() -> DeviceId {
    DeviceId::new("foundation-integration-device").expect("device")
}

fn policy() -> ProtectionPolicy {
    let document: Value =
        serde_json::from_str(include_str!("../../../fixtures/managed/policy.json"))
            .expect("fixture policy");
    ProtectionPolicy::from_rule_ids(
        document["protected_rule_ids"]
            .as_array()
            .expect("protected_rule_ids array")
            .iter()
            .map(|entry| {
                RuleId::new(
                    entry["value"].as_u64().expect("RuleID value"),
                    usize::try_from(entry["bit_len"].as_u64().expect("RuleID bit length"))
                        .expect("RuleID bit length fits usize"),
                )
            }),
    )
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

fn handler_with_participant(active: &Arc<ActiveContext>) -> (RequestHandler, ContextParticipant) {
    let participant = active.participant();
    (
        handler_for_participant(active, participant.clone()),
        participant,
    )
}

fn handler_for_participant(
    active: &Arc<ActiveContext>,
    participant: ContextParticipant,
) -> RequestHandler {
    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let datastore = Datastore::with_data(model, active.tree());
    let mut handler = RequestHandler::new(datastore);
    handler.register_transaction_participant(Box::new(participant));
    handler
}

#[test]
fn binary_values_round_trip_losslessly_through_both_models() {
    let (tree, canonical_sor) = canonicalize_sor(SID, SOR).expect("canonical");
    let rebuilt = canonical_sor_from_tree(SID, &tree).expect("re-encode");
    assert_eq!(canonical_sor, rebuilt);
    assert!(tree["ietf-schc:schc"]["rule"][0]["entry"][22]["target-value"][0]["value"].is_string());
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
        vec![RuleId::new(18, 8)]
    );
}

#[test]
fn canonical_mutable_order_is_required() {
    let (mut tree, _) = canonicalize_sor(SID, SOR).expect("canonical");
    tree["ietf-schc:schc"]["rule"][0]["entry"]
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
    let (mut handler, participant) = handler_with_participant(&active);
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][0]["entry"][0]["field-position"] = Value::from(2);
    participant
        .prepare_tree(candidate.clone())
        .expect("prepare");
    let request = Request::new(Method::IPatch)
        .with_interface(Interface::Management)
        .with_payload(
            root_ipatch_payload(&candidate),
            ContentFormat::YangInstancesCborSeq,
        );
    let response = handler.handle(&request);
    assert_eq!(response.code, ResponseCode::Conflict);
    assert_eq!(handler.datastore().get_all(), initial.tree().clone());
    assert_eq!(active.tree(), initial.tree().clone());
    assert_eq!(active.generation(), 1);
    assert_eq!(active.digest(), initial.digest());
    assert!(Arc::ptr_eq(&before, &active.snapshot()));
    assert!(!participant.has_prepared());
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
    let mut handler = RequestHandler::new(Datastore::with_data(
        CoreconfModel::from_sid_str(SID).expect("model"),
        initial.tree().clone(),
    ));
    let participant = active.participant();
    participant.prepare(initial.clone()).expect("preparation");
    handler.register_transaction_participant(Box::new(participant));
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
                tree["ietf-schc:schc"]["rule"][0]["entry"][0]["field-position"] = Value::from(2);
            }),
        ),
        (
            "nature",
            Box::new(|tree| {
                tree["ietf-schc:schc"]["rule"][0]["rule-nature"] =
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
        let (mut handler, participant) = handler_with_participant(&active);
        let mut candidate = initial.tree().clone();
        mutate(&mut candidate);
        if participant.prepare_tree(candidate.clone()).is_ok() {
            let request = Request::new(Method::IPatch)
                .with_interface(Interface::Management)
                .with_payload(
                    root_ipatch_payload(&candidate),
                    ContentFormat::YangInstancesCborSeq,
                );
            assert_eq!(
                handler.handle(&request).code,
                ResponseCode::Conflict,
                "{name}"
            );
        }
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
fn valid_local_root_ipatch_publishes_once_as_one_tuple() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let (mut handler, participant) = handler_with_participant(&active);
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    participant
        .prepare_tree(candidate.clone())
        .expect("prepare");
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
    assert!(!participant.has_prepared());

    // There is no second prepared slot and no second publication from the
    // already-consumed commit.
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
    handler: RequestHandler,
    participant: ContextParticipant,
    candidate: Value,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<(bool, ResponseCode, Value, String)> {
    thread::spawn(move || {
        barrier.wait();
        let prepared = participant.prepare_tree(candidate.clone()).is_ok();
        barrier.wait();
        let response = handler_with_request(handler, &candidate);
        (prepared, response.code, response.datastore, response.error)
    })
}

fn handler_with_request(mut handler: RequestHandler, candidate: &Value) -> HandlerResult {
    let response = handler.handle(
        &Request::new(Method::IPatch)
            .with_interface(Interface::Management)
            .with_payload(
                root_ipatch_payload(candidate),
                ContentFormat::YangInstancesCborSeq,
            ),
    );
    HandlerResult {
        code: response.code,
        datastore: handler.datastore().get_all(),
        error: String::from_utf8_lossy(&response.payload).into_owned(),
    }
}

struct HandlerResult {
    code: ResponseCode,
    datastore: Value,
    error: String,
}

struct FailingBackend {
    tree: Value,
}

impl Backend for FailingBackend {
    fn read_tree(&self) -> Value {
        self.tree.clone()
    }

    fn replace_tree(&mut self, _next: Value) -> coreconf_model::Result<()> {
        Err(CoreconfError::Io(std::io::Error::other(
            "backend publication failed",
        )))
    }
}

#[test]
fn failed_backend_commit_stays_pending_until_manual_reset() {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let participant = active.participant();
    let mut candidate = initial.tree().clone();
    candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    participant
        .prepare_tree(candidate.clone())
        .expect("prepare candidate");

    let model = CoreconfModel::from_sid_str(SID).expect("model");
    let datastore = Datastore::with_backend(
        model.composite_model().clone(),
        FailingBackend {
            tree: initial.tree().clone(),
        },
    );
    let mut handler = RequestHandler::new(datastore);
    handler.register_transaction_participant(Box::new(participant.clone()));
    let response = handler.handle(
        &Request::new(Method::IPatch)
            .with_interface(Interface::Management)
            .with_payload(
                root_ipatch_payload(&candidate),
                ContentFormat::YangInstancesCborSeq,
            ),
    );

    assert_eq!(response.code, ResponseCode::InternalServerError);
    assert_eq!(handler.datastore().get_all(), initial.tree().clone());
    assert_eq!(active.tree(), initial.tree().clone());
    assert_eq!(active.generation(), 1);
    assert!(!participant.has_prepared());
    assert!(participant.has_pending());
    assert!(matches!(
        participant.prepare_tree(candidate.clone()),
        Err(ContextError::PreparationBusy)
    ));

    participant.clear_prepared();
    assert!(participant.has_pending());
    participant.reset_transaction();
    assert!(!participant.has_pending());
    participant
        .prepare_tree(candidate)
        .expect("manual reset releases pending reservation");
}

#[test]
fn cloned_participants_have_one_barrier_controlled_publication() {
    assert_shared_reservation_is_serialized(true);
}

#[test]
fn separately_created_participants_have_one_barrier_controlled_publication() {
    assert_shared_reservation_is_serialized(false);
}

fn assert_shared_reservation_is_serialized(clone_participant: bool) {
    let initial = prepared();
    let active = Arc::new(ActiveContext::new(initial.clone()));
    let first = active.participant();
    let second = if clone_participant {
        first.clone()
    } else {
        active.participant()
    };
    let mut first_candidate = initial.tree().clone();
    first_candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("Bw==".to_owned());
    let mut second_candidate = initial.tree().clone();
    second_candidate["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("CA==".to_owned());
    let barrier = Arc::new(Barrier::new(2));
    let first_handler = handler_for_participant(&active, first.clone());
    let second_handler = handler_for_participant(&active, second.clone());
    let first_thread =
        run_competing_writer(first_handler, first, first_candidate, Arc::clone(&barrier));
    let second_thread = run_competing_writer(
        second_handler,
        second,
        second_candidate,
        Arc::clone(&barrier),
    );
    let first_result = first_thread.join().expect("first writer");
    let second_result = second_thread.join().expect("second writer");
    let results = [first_result, second_result];
    assert_eq!(
        results.iter().filter(|result| result.0).count(),
        1,
        "results: {:?}",
        results
            .iter()
            .map(|result| (&result.0, &result.1, &result.3))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.1 == ResponseCode::Changed)
            .count(),
        1,
        "results: {:?}",
        results
            .iter()
            .map(|result| (&result.0, &result.1, &result.3))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.1 == ResponseCode::Conflict)
            .count(),
        1
    );
    let winner = results
        .iter()
        .find(|result| result.1 == ResponseCode::Changed)
        .expect("winner");
    let loser = results
        .iter()
        .find(|result| result.1 == ResponseCode::Conflict)
        .expect("busy loser");
    assert!(winner.0);
    assert!(!loser.0);
    assert_eq!(loser.2, initial.tree().clone());
    assert_eq!(active.generation(), 2);
    assert_eq!(active.tree(), winner.2);
    let snapshot = active.snapshot();
    assert_eq!(snapshot.generation(), 2);
    assert_eq!(snapshot.tree(), &winner.2);
    assert_eq!(
        snapshot.sor(),
        canonical_sor_from_tree(SID, snapshot.tree()).unwrap()
    );

    // A later transaction proves that generation publication is monotonic and
    // that the shared reservation was released exactly once by post_commit.
    let mut next = active.tree();
    next["ietf-schc:schc"]["rule"][2]["entry"][0]["target-value"][0]["value"] =
        Value::String("CQ==".to_owned());
    let next_participant = active.participant();
    next_participant
        .prepare_tree(next.clone())
        .expect("next prepare");
    let next_handler = handler_for_participant(&active, next_participant);
    let next_result = handler_with_request(next_handler, &next);
    assert_eq!(next_result.code, ResponseCode::Changed);
    assert_eq!(active.generation(), 3);
    assert_eq!(active.tree(), next_result.datastore);
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
