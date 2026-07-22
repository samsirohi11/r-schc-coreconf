//! Regression coverage for the deterministic demonstration contexts.

use coreconf_model::CoreconfModel;
use schc_core::{RuleContext, RuleId, RuleNature, SidRegistry};
use schc_coreconf::{
    canonical_sor_from_tree, canonicalize_sor, validate_sid_with_both_models, PreparedContext,
    ProtectionPolicy,
};
use schc_runtime::{DeviceId, DeviceProfile, Runtime};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
const INITIAL_RULES: &str = include_str!("../../../fixtures/demo/initial-rules.json");
const UPDATED_RULES: &str = include_str!("../../../fixtures/demo/updated-rules.json");
const INITIAL_SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");
const UPDATED_SOR: &[u8] = include_bytes!("../../../fixtures/demo/updated.sor");
const INITIAL_SOR_SHA256: &str = "3b5cff837a09e39c9cd063b373ebda27716d00436190e755453f0b7051fb7185";
const UPDATED_SOR_SHA256: &str = "692c9956783dea29c3286df9cb646630b2a02c5ac2038d10ddbf9749efd80abd";

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

fn protected_policy() -> ProtectionPolicy {
    ProtectionPolicy::from_rule_ids([RuleId::new(16, 8), RuleId::new(17, 8)])
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
    assert_eq!(rule_context(INITIAL_SOR).rules().rules().len(), 5);
    assert_eq!(rule_context(UPDATED_SOR).rules().rules().len(), 5);
}

#[test]
fn rule_sources_have_only_the_minimal_inventory_and_expected_natures() {
    let initial = source(INITIAL_RULES);
    let updated = source(UPDATED_RULES);
    let expected_ids = [16, 17, 20, 21, 25];
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
        for rule_id in [16, 17] {
            let code = source_field(source_rule(document, rule_id), "COAP.CODE");
            assert_eq!(code["MO"], "ignore");
            assert_eq!(code["CDA"], "value-sent");
            assert!(code.get("TV").is_none());
        }
    }

    let initial_context = rule_context(INITIAL_SOR);
    let updated_context = rule_context(UPDATED_SOR);
    for (context, expected) in [
        (&initial_context, RuleNature::Compression),
        (&updated_context, RuleNature::Compression),
    ] {
        assert_eq!(
            context
                .find_rule(RuleId::new(16, 8))
                .expect("16/8")
                .nature(),
            expected
        );
        assert_eq!(
            context
                .find_rule(RuleId::new(17, 8))
                .expect("17/8")
                .nature(),
            expected
        );
        assert_eq!(
            context
                .find_rule(RuleId::new(20, 8))
                .expect("20/8")
                .nature(),
            expected
        );
        assert_eq!(
            context
                .find_rule(RuleId::new(21, 8))
                .expect("21/8")
                .nature(),
            expected
        );
        assert_eq!(
            context
                .find_rule(RuleId::new(25, 8))
                .expect("25/8")
                .nature(),
            RuleNature::NoCompression
        );
    }
    assert!(source_rule(&initial, 25).get("Compression").is_none());
    assert!(source_rule(&initial, 25).get("NoCompression").is_some());
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
    for id in [RuleId::new(16, 8), RuleId::new(17, 8)] {
        assert_eq!(initial.find_rule(id), updated.find_rule(id));
    }

    let initial_prepared = prepared(INITIAL_SOR, "demo-initial");
    let updated_prepared = prepared(UPDATED_SOR, "demo-updated");
    assert_eq!(
        initial_prepared.protected_rule_ids(),
        vec![RuleId::new(16, 8), RuleId::new(17, 8)]
    );
    assert_eq!(
        updated_prepared.protected_rule_ids(),
        vec![RuleId::new(16, 8), RuleId::new(17, 8)]
    );
    let _: &Runtime = initial_prepared.runtime();
    let _: &Runtime = updated_prepared.runtime();
}
