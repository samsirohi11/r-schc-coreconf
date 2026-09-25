//! Regression coverage for the deterministic demonstration contexts.

use coreconf_model::CoreconfModel;
use schc_core::{RuleContext, RuleId, RuleNature, TargetValue};
use schc_coreconf::{
    canonical_sor_from_tree, canonicalize_sor, validate_sid_with_both_models, LoadedContext,
    PreparedContext,
};
use schc_runtime::{DeviceId, DeviceProfile, Runtime};
use serde_json::Value;

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-09-22.sid");
const INITIAL_RULES: &str = include_str!("../../../fixtures/demo/initial-rules.json");
const INITIAL_SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

fn source(document: &str) -> Value {
    serde_json::from_str(document).expect("OpenSCHC rule source")
}

fn source_rule(document: &Value, rule_id: u64) -> &Value {
    document["SoR"]
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
    LoadedContext::from_sor(SID, sor)
        .expect("current-model SoR")
        .rule_context()
        .clone()
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

fn source_field_index(document: &Value, rule_id: u64, fid: &str) -> usize {
    source_rule(document, rule_id)["Compression"]
        .as_array()
        .expect("compression entries")
        .iter()
        .position(|field| field["FID"] == fid)
        .expect("expected field")
}

fn tree_rule_mut(tree: &mut Value, rule_id: u64) -> &mut Value {
    tree["ietf-schc:schc"]["rule"]
        .as_array_mut()
        .expect("rules")
        .iter_mut()
        .find(|rule| rule["rule-id-value"] == rule_id)
        .expect("expected rule")
}

fn updated_demo_tree(initial_tree: &Value, source_rules: &Value) -> Value {
    let iid_entry_index = source_field_index(source_rules, 20, "IPV6.APP_IID") as u64;
    let mut updated_tree = initial_tree.clone();
    let iid_entry = tree_rule_mut(&mut updated_tree, 20)["entry-universal"]
        .as_array_mut()
        .expect("entries")
        .iter_mut()
        .find(|entry| entry["entry-index"] == iid_entry_index)
        .expect("IPV6.APP_IID entry");
    iid_entry["target-value"][0]["value"] = Value::String("AAAAAAAAAAI=".to_owned());
    updated_tree
}

fn prepared(sor: &[u8], name: &str) -> PreparedContext {
    PreparedContext::from_sor(
        SID,
        sor,
        DeviceId::new(name).expect("device ID"),
        DeviceProfile::default(),
    )
    .expect("prepared context")
}

#[test]
fn initial_sor_round_trips_canonically_through_both_models() {
    let (initial_tree, initial_canonical) = canonicalize_sor(SID, INITIAL_SOR).expect("initial");
    assert_eq!(
        canonical_sor_from_tree(SID, &initial_tree).expect("initial tree"),
        initial_canonical
    );

    let (initial_sid, _) = validate_sid_with_both_models(SID).expect("SID");
    let model = CoreconfModel::from_sid_str(SID).expect("rustconf model");
    assert_eq!(model.sid_file.module_name, initial_sid.module_name);
    assert_eq!(model.sid_file.sids, initial_sid.sids);
    let initial_context = rule_context(INITIAL_SOR);
    assert_eq!(initial_context.rules().rules().len(), 9);

    // The ignore/value-sent and ignore/compute entries have no target-value
    // list in the encoded tree, while the equal-zero target remains present.
    for rule_id in [20, 21] {
        let rule = initial_tree["ietf-schc:schc"]["rule"]
            .as_array()
            .expect("rules")
            .iter()
            .find(|rule| rule["rule-id-value"] == rule_id)
            .expect("rule");
        for entry_index in [3, 12, 13, 15, 16, 18, 19] {
            let entry = rule["entry-universal"]
                .as_array()
                .expect("entries")
                .iter()
                .find(|entry| entry["entry-index"] == entry_index)
                .expect("entry");
            assert!(entry.get("target-value").is_none());
        }
    }
    let rule25 = initial_tree["ietf-schc:schc"]["rule"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|rule| rule["rule-id-value"] == 25)
        .expect("rule");
    let rule25_length = rule25["entry-universal"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["entry-index"] == 3)
        .expect("entry");
    assert!(rule25_length.get("target-value").is_none());

    let zero_entry = initial_tree["ietf-schc:schc"]["rule"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|rule| rule["rule-id-value"] == 16)
        .expect("rule")["entry-universal"][1]
        .clone();
    assert!(zero_entry.get("target-value").is_some());
    for rule_id in [20, 21] {
        let rule = initial_context
            .find_rule(RuleId::new(rule_id, 8))
            .expect("rule");
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
        initial_context
            .find_rule(RuleId::new(25, 8))
            .expect("rule")
            .fields()[3]
            .target,
        TargetValue::None
    );
    assert_eq!(
        initial_context
            .find_rule(RuleId::new(16, 8))
            .expect("rule")
            .fields()[1]
            .target,
        TargetValue::Bytes(vec![0])
    );
}

#[test]
fn rule_sources_have_only_the_minimal_inventory_and_expected_natures() {
    let initial = source(INITIAL_RULES);
    let expected_ids = [16, 17, 26, 27, 28, 29, 20, 21, 25];
    assert_eq!(
        initial["SoR"]
            .as_array()
            .expect("initial rules")
            .iter()
            .map(|rule| rule["RuleID"].as_u64().expect("RuleID"))
            .collect::<Vec<_>>(),
        expected_ids
    );
    for rule in initial["SoR"].as_array().expect("rules") {
        assert_eq!(rule["RuleIDLength"], 8);
    }
    let protected = source_rule(&initial, 16);
    assert!(protected["Compression"].is_array());
    assert!(protected.get("NoCompression").is_none());
    let code = source_field(source_rule(&initial, 17), "COAP.CODE");
    assert_eq!(code["MO"], "match-mapping");
    assert_eq!(code["CDA"], "mapping-sent");
    assert_eq!(
        code["TV"],
        serde_json::json!([65, 66, 68, 69, 128, 129, 130, 132, 133, 136, 137, 140, 141, 143, 160])
    );

    let fetch_rule = source_rule(&initial, 20);
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
    let response_formats = source_field_values(source_rule(&initial, 21), "COAP.option(12)");
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
            assert!(source_field(source_rule(&initial, rule_id), fid)["TV"].is_null());
        }
    }
    assert!(source_field(source_rule(&initial, 25), "IPV6.LEN")["TV"].is_null());
    assert_eq!(source_field(source_rule(&initial, 16), "IPV6.TC")["TV"], 0);
    assert_eq!(source_field(source_rule(&initial, 16), "COAP.MID")["TV"], 0);

    let initial_context = rule_context(INITIAL_SOR);
    for id in [16, 17, 20, 21, 25, 26, 27, 28, 29] {
        let expected_nature = if [16, 17, 26, 27, 28, 29].contains(&id) {
            RuleNature::Management
        } else {
            RuleNature::Compression
        };
        assert_eq!(
            initial_context
                .find_rule(RuleId::new(id, 8))
                .expect("rule")
                .nature(),
            expected_nature
        );
    }
    assert!(source_rule(&initial, 25).get("Compression").is_some());
    assert!(source_rule(&initial, 25).get("NoCompression").is_none());
}

#[test]
fn derived_rule_20_variant_preserves_protection_and_loads_into_runtime() {
    let source_rules = source(INITIAL_RULES);
    assert_eq!(
        source_field(source_rule(&source_rules, 20), "IPV6.APP_IID")["TV"],
        "::5"
    );
    let initial_prepared = prepared(INITIAL_SOR, "demo-initial");
    let updated_prepared = PreparedContext::from_tree(
        SID,
        updated_demo_tree(initial_prepared.tree(), &source_rules),
        DeviceId::new("demo-updated").expect("device ID"),
        DeviceProfile::default(),
    )
    .expect("prepared derived context");
    let initial_loaded = LoadedContext::from_sor(SID, initial_prepared.sor()).expect("initial");
    let updated_loaded = LoadedContext::from_sor(SID, updated_prepared.sor()).expect("updated");
    let iid_entry_index = source_field_index(&source_rules, 20, "IPV6.APP_IID");
    for id in [16, 17, 21, 25, 26, 27, 28, 29].map(|value| RuleId::new(value, 8)) {
        assert_eq!(
            initial_loaded.rule_context().find_rule(id),
            updated_loaded.rule_context().find_rule(id)
        );
    }
    let initial_rule_20 = initial_loaded
        .rule_context()
        .find_rule(RuleId::new(20, 8))
        .expect("initial rule");
    let updated_rule_20 = updated_loaded
        .rule_context()
        .find_rule(RuleId::new(20, 8))
        .expect("updated rule");
    assert_eq!(
        initial_rule_20
            .fields()
            .iter()
            .filter(|field| field.entry_index != iid_entry_index)
            .collect::<Vec<_>>(),
        updated_rule_20
            .fields()
            .iter()
            .filter(|field| field.entry_index != iid_entry_index)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        initial_rule_20
            .fields()
            .iter()
            .find(|field| field.entry_index == iid_entry_index)
            .expect("IPV6.APP_IID")
            .target,
        TargetValue::Bytes(vec![0, 0, 0, 0, 0, 0, 0, 5])
    );
    assert_eq!(
        updated_rule_20
            .fields()
            .iter()
            .find(|field| field.entry_index == iid_entry_index)
            .expect("IPV6.APP_IID")
            .target,
        TargetValue::Bytes(vec![0, 0, 0, 0, 0, 0, 0, 2])
    );
    assert_eq!(
        canonical_sor_from_tree(SID, updated_prepared.tree()).expect("derived tree"),
        updated_prepared.sor()
    );
    assert_eq!(
        initial_prepared.protected_rule_ids(),
        vec![16, 17, 26, 27, 28, 29]
            .into_iter()
            .map(|value| RuleId::new(value, 8))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        updated_prepared.protected_rule_ids(),
        initial_prepared.protected_rule_ids()
    );
    let _: &Runtime = initial_prepared.runtime();
    let _: &Runtime = updated_prepared.runtime();
}
