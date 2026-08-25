//! Regression coverage for the deterministic demonstration contexts.

use coreconf_model::CoreconfModel;
use schc_core::{RuleContext, RuleId, RuleNature, SidRegistry, TargetValue};
use schc_coreconf::{
    canonical_sor_from_tree, canonicalize_sor, protected_management_rule_ids,
    validate_sid_with_both_models, PreparedContext, ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile, Runtime};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const INITIAL_RULES: &str = include_str!("../../../fixtures/demo/initial-rules.json");
const UPDATED_RULES: &str = include_str!("../../../fixtures/demo/updated-rules.json");
const INITIAL_SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");
const UPDATED_SOR: &[u8] = include_bytes!("../../../fixtures/demo/updated.sor");
const INITIAL_SOR_SHA256: &str = "142993758d6f11191f1089ea54d1f84c5884f5d8da9c3dcbbe49b2ca89c0acc3";
const UPDATED_SOR_SHA256: &str = "b0cc95cd5c84a838c84f7c9d77d62f58d453655f1792bcd237fa49089e9b1645";

fn source(document: &str) -> Value {
    serde_json::from_str(document).expect("OpenSCHC rule source")
}

fn source_rule(document: &Value, rule_id: u64) -> &Value {
    document
        .as_array()
        .expect("rule source array")
        .iter()
        .find(|rule| rule["RuleID"] == rule_id)
        .expect("expected rule")
}

fn source_field<'a>(rule: &'a Value, fid: &str) -> &'a Value {
    rule["Compression"]
        .as_array()
        .expect("compression entries")
        .iter()
        .find(|field| field["FID"] == fid)
        .expect("expected field")
}

fn rule_context(sor: &[u8]) -> RuleContext {
    RuleContext::from_cbor_slice(sor, SidRegistry::from_json_str(SID).expect("r-schc SID"))
        .expect("r-schc SoR")
}

fn source_fields<'a>(rule: &'a Value, fid: &str) -> Vec<&'a Value> {
    rule["Compression"]
        .as_array()
        .expect("compression entries")
        .iter()
        .filter(|field| field["FID"] == fid)
        .collect()
}

fn source_field_values(rule: &Value, fid: &str) -> Vec<(Value, Value)> {
    source_fields(rule, fid)
        .into_iter()
        .map(|field| (field["FP"].clone(), field["TV"].clone()))
        .collect()
}

fn protected_policy() -> ProtectionPolicy {
    ProtectionPolicy::from_rule_ids(protected_management_rule_ids())
}

fn prepared(sor: &[u8], name: &str) -> PreparedContext {
    PreparedContext::from_sor_with_policy(
        SID,
        sor,
        DeviceId::new(name).expect("device ID"),
        DeviceProfile::default(),
        protected_policy(),
    )
    .expect("prepared context")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn checked_in_sors_have_stable_bytes_and_load_through_both_models() {
    assert_eq!(sha256_hex(INITIAL_SOR), INITIAL_SOR_SHA256);
    assert_eq!(sha256_hex(UPDATED_SOR), UPDATED_SOR_SHA256);

    let (initial_tree, initial_canonical) = canonicalize_sor(SID, INITIAL_SOR).expect("initial");
    let (updated_tree, updated_canonical) = canonicalize_sor(SID, UPDATED_SOR).expect("updated");
    assert_eq!(
        canonical_sor_from_tree(SID, &initial_tree).expect("initial tree"),
        initial_canonical
    );
    assert_eq!(
        canonical_sor_from_tree(SID, &updated_tree).expect("updated tree"),
        updated_canonical
    );

    let (initial_sid, initial_registry) = validate_sid_with_both_models(SID).expect("initial SID");
    let (updated_sid, updated_registry) = validate_sid_with_both_models(SID).expect("updated SID");
    assert_eq!(initial_sid.module_name, updated_sid.module_name);
    assert_eq!(initial_sid.module_revision, updated_sid.module_revision);
    assert_eq!(initial_sid.sids, updated_sid.sids);
    assert_eq!(initial_sid.ids, updated_sid.ids);
    assert_eq!(initial_sid.key_mapping, updated_sid.key_mapping);
    assert_eq!(initial_registry, updated_registry);
    let model = CoreconfModel::from_sid_str(SID).expect("rustconf model");
    assert_eq!(model.sid_file.module_name, initial_sid.module_name);
    assert_eq!(model.sid_file.sids, initial_sid.sids);
    let initial_context = rule_context(INITIAL_SOR);
    let updated_context = rule_context(UPDATED_SOR);
    assert_eq!(initial_context.rules().rules().len(), 9);
    assert_eq!(updated_context.rules().rules().len(), 9);

    // The ignore/value-sent and ignore/compute entries have no target-value
    // list in the encoded tree, while the equal-zero target remains present.
    for tree in [&initial_tree, &updated_tree] {
        for rule_id in [20, 21] {
            let rule = tree["ietf-schc:schc"]["rule"]
                .as_array()
                .expect("rules")
                .iter()
                .find(|rule| rule["rule-id-value"] == rule_id)
                .expect("rule");
            for entry_index in [3, 12, 13, 15, 16, 18, 19] {
                let entry = rule["entry"]
                    .as_array()
                    .expect("entries")
                    .iter()
                    .find(|entry| entry["entry-index"] == entry_index)
                    .expect("entry");
                assert!(entry.get("target-value").is_none());
            }
        }
        let rule25 = tree["ietf-schc:schc"]["rule"]
            .as_array()
            .expect("rules")
            .iter()
            .find(|rule| rule["rule-id-value"] == 25)
            .expect("rule");
        let rule25_length = rule25["entry"]
            .as_array()
            .expect("entries")
            .iter()
            .find(|entry| entry["entry-index"] == 3)
            .expect("entry");
        assert!(rule25_length.get("target-value").is_none());

        let zero_entry = tree["ietf-schc:schc"]["rule"]
            .as_array()
            .expect("rules")
            .iter()
            .find(|rule| rule["rule-id-value"] == 16)
            .expect("rule")["entry"][1]
            .clone();
        assert!(zero_entry.get("target-value").is_some());
    }
    for context in [&initial_context, &updated_context] {
        for rule_id in [20, 21] {
            let rule = context.find_rule(RuleId::new(rule_id, 8)).expect("rule");
            for entry_index in [3, 12, 13, 15, 16, 18, 19] {
                assert_eq!(
                    rule.fields()
                        .iter()
                        .find(|field| field.entry_index == entry_index)
                        .expect("entry")
                        .target,
                    TargetValue::None
                );
            }
        }
        assert_eq!(
            context
                .find_rule(RuleId::new(25, 8))
                .expect("rule")
                .fields()[3]
                .target,
            TargetValue::None
        );
        assert_eq!(
            context
                .find_rule(RuleId::new(16, 8))
                .expect("rule")
                .fields()[1]
                .target,
            TargetValue::Bytes(vec![0])
        );
    }
}

#[test]
fn rule_sources_have_only_the_minimal_inventory_and_expected_natures() {
    let initial = source(INITIAL_RULES);
    let updated = source(UPDATED_RULES);
    let expected_ids = [16, 17, 26, 27, 28, 29, 20, 21, 25];
    assert_eq!(
        initial
            .as_array()
            .expect("initial rules")
            .iter()
            .map(|rule| rule["RuleID"].as_u64().expect("RuleID"))
            .collect::<Vec<_>>(),
        expected_ids
    );
    let updated_ids = updated
        .as_array()
        .expect("updated rules")
        .iter()
        .map(|rule| rule["RuleID"].as_u64().expect("RuleID"))
        .collect::<Vec<_>>();
    assert_eq!(updated_ids, expected_ids);
    for document in [&initial, &updated] {
        for rule in document.as_array().expect("rules") {
            assert_eq!(rule["RuleIDLength"], 8);
        }
        let protected = source_rule(document, 16);
        assert!(protected["Compression"].is_array());
        assert!(protected.get("NoCompression").is_none());
        let code = source_field(source_rule(document, 17), "COAP.CODE");
        assert_eq!(code["MO"], "match-mapping");
        assert_eq!(code["CDA"], "mapping-sent");
        assert_eq!(
            code["TV"],
            serde_json::json!([
                65, 66, 68, 69, 128, 129, 130, 132, 133, 136, 137, 140, 141, 143, 160
            ])
        );

        let fetch_rule = source_rule(document, 20);
        assert_eq!(source_field(fetch_rule, "COAP.CODE")["TV"], 5);
        let uri_paths = source_field_values(fetch_rule, "COAP.option(11)");
        assert_eq!(
            uri_paths,
            vec![(serde_json::json!(1), serde_json::json!("c"))]
        );
        let content_formats = source_field_values(fetch_rule, "COAP.option(12)");
        assert_eq!(
            content_formats,
            vec![(serde_json::json!(1), serde_json::json!(141))]
        );
        let response_formats = source_field_values(source_rule(document, 21), "COAP.option(12)");
        assert_eq!(
            response_formats,
            vec![(serde_json::json!(1), serde_json::json!(142))]
        );
        for rule_id in [20, 21] {
            for fid in [
                "IPV6.LEN",
                "UDP.LEN",
                "UDP.CKSUM",
                "COAP.TYPE",
                "COAP.TKL",
                "COAP.MID",
                "COAP.TOKEN",
            ] {
                assert!(source_field(source_rule(document, rule_id), fid)["TV"].is_null());
            }
        }
        assert!(source_field(source_rule(document, 25), "IPV6.LEN")["TV"].is_null());
        assert_eq!(source_field(source_rule(document, 16), "IPV6.TC")["TV"], 0);
        assert_eq!(source_field(source_rule(document, 16), "COAP.MID")["TV"], 0);
    }

    let initial_context = rule_context(INITIAL_SOR);
    let updated_context = rule_context(UPDATED_SOR);
    for context in [&initial_context, &updated_context] {
        for id in [16, 17, 20, 21, 25, 26, 27, 28, 29] {
            assert_eq!(
                context
                    .find_rule(RuleId::new(id, 8))
                    .expect("rule")
                    .nature(),
                RuleNature::Compression
            );
        }
    }
    assert!(source_rule(&initial, 25).get("Compression").is_some());
    assert!(source_rule(&initial, 25).get("NoCompression").is_none());
}

#[test]
fn only_rule_20_application_iid_changes_between_variants() {
    let initial = source(INITIAL_RULES);
    let updated = source(UPDATED_RULES);
    let initial_rule = source_rule(&initial, 20);
    let updated_rule = source_rule(&updated, 20);
    assert_eq!(source_field(initial_rule, "IPV6.APP_IID")["TV"], "::5");
    assert_eq!(source_field(updated_rule, "IPV6.APP_IID")["TV"], "::2");

    let mut normalized_initial = initial.clone();
    let mutable_initial = source_field_mut(&mut normalized_initial, 20, "IPV6.APP_IID");
    mutable_initial["TV"] = updated_field_value(&updated, 20, "IPV6.APP_IID");
    assert_eq!(normalized_initial, updated);
}

fn source_field_mut<'a>(document: &'a mut Value, rule_id: u64, fid: &str) -> &'a mut Value {
    document
        .as_array_mut()
        .expect("rule source array")
        .iter_mut()
        .find(|rule| rule["RuleID"] == rule_id)
        .expect("expected rule")["Compression"]
        .as_array_mut()
        .expect("compression entries")
        .iter_mut()
        .find(|field| field["FID"] == fid)
        .expect("expected field")
}

fn updated_field_value(document: &Value, rule_id: u64, fid: &str) -> Value {
    source_field(source_rule(document, rule_id), fid)["TV"].clone()
}

#[test]
fn protected_rules_are_identical_and_both_variants_build_runtime() {
    let initial = rule_context(INITIAL_SOR);
    let updated = rule_context(UPDATED_SOR);
    for id in protected_management_rule_ids() {
        assert_eq!(initial.find_rule(id), updated.find_rule(id));
    }

    let initial_prepared = prepared(INITIAL_SOR, "demo-initial");
    let updated_prepared = prepared(UPDATED_SOR, "demo-updated");
    assert_eq!(
        initial_prepared.protected_rule_ids(),
        protected_management_rule_ids().to_vec()
    );
    assert_eq!(
        updated_prepared.protected_rule_ids(),
        protected_management_rule_ids().to_vec()
    );
    let _: &Runtime = initial_prepared.runtime();
    let _: &Runtime = updated_prepared.runtime();
}
