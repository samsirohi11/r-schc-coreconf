use std::collections::BTreeSet;
use std::io::Cursor;

use ciborium::value::Value as CborValue;
use coreconf_model::{CompositeModel, CoreconfModel, YangType};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ContextError, Result};

const DIGEST_DOMAIN: &[u8] = b"schc-coreconf/managed-context/v1\0";

pub(crate) fn strict_cbor_value(bytes: &[u8]) -> Result<CborValue> {
    let mut cursor = Cursor::new(bytes);
    let value: CborValue = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ContextError::Cbor(format!(
            "trailing bytes after root value at offset {} of {}",
            cursor.position(),
            bytes.len()
        )));
    }
    reject_duplicate_map_keys(&value)?;
    Ok(value)
}

fn reject_duplicate_map_keys(value: &CborValue) -> Result<()> {
    match value {
        CborValue::Array(values) => {
            for value in values {
                reject_duplicate_map_keys(value)?;
            }
        }
        CborValue::Map(entries) => {
            for (index, (key, value)) in entries.iter().enumerate() {
                if entries[..index].iter().any(|(previous, _)| previous == key) {
                    return Err(ContextError::Cbor("duplicate CBOR map key".to_owned()));
                }
                reject_duplicate_map_keys(key)?;
                reject_duplicate_map_keys(value)?;
            }
        }
        CborValue::Tag(_, value) => reject_duplicate_map_keys(value)?,
        _ => {}
    }
    Ok(())
}

pub(crate) fn ensure_schc_root(value: &CborValue) -> Result<()> {
    let CborValue::Map(entries) = value else {
        return Err(ContextError::Cbor("SoR root must be a CBOR map".to_owned()));
    };
    let has_root = entries
        .iter()
        .any(|(key, _)| matches!(key, CborValue::Integer(integer) if i128::from(*integer) == 2574));
    if !has_root {
        return Err(ContextError::Cbor(
            "SoR root is missing SCHC SID 2574".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_tree(mut tree: Value) -> Result<Value> {
    normalize_value(&mut tree, None)?;
    Ok(tree)
}

fn normalize_value(value: &mut Value, key: Option<&str>) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map.iter_mut() {
                normalize_value(child, Some(child_key))?;
            }
        }
        Value::Array(values) => {
            for child in values.iter_mut() {
                normalize_value(child, None)?;
            }
            match key {
                Some("rule") => values.sort_by(compare_rule_values),
                Some("entry") => {
                    values.sort_by(compare_entry_values);
                    let mut seen = BTreeSet::new();
                    for value in values.iter() {
                        let index = value
                            .get("entry-index")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| {
                                ContextError::Model(
                                    "SCHC entry is missing numeric entry-index".to_owned(),
                                )
                            })?;
                        if !seen.insert(index) {
                            return Err(ContextError::Model(format!(
                                "duplicate SCHC entry-index {index}"
                            )));
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

fn compare_rule_values(left: &Value, right: &Value) -> std::cmp::Ordering {
    let left_len = left
        .get("rule-id-length")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let right_len = right
        .get("rule-id-length")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let left_id = left
        .get("rule-id-value")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let right_id = right
        .get("rule-id-value")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    left_len
        .cmp(&right_len)
        .then_with(|| left_id.cmp(&right_id))
}

fn compare_entry_values(left: &Value, right: &Value) -> std::cmp::Ordering {
    left.get("entry-index")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .cmp(
            &right
                .get("entry-index")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        )
}

pub(crate) fn encode_tree(model: &CoreconfModel, tree: &Value) -> Result<Vec<u8>> {
    let composite: &CompositeModel = model.composite_model();
    let sid_value = composite
        .identifier_value_to_sid_value(tree.clone())
        .map_err(ContextError::Rustconf)?;
    let cbor_value = coreconf_model::codec::json_to_cbor_value(composite, &sid_value, 0);
    // rustconf models identityrefs as ordinary integers in JSON/CBOR. The
    // SCHC SoR uses the identityref tag, so restore that tag after rustconf's
    // lossless modeled conversion. This also keeps union field-length
    // identities (for example fl-variable) distinguishable from numeric
    // lengths to r-schc.
    let cbor_value = restore_identity_tags(cbor_value, 0, composite)?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut bytes)
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    let _ = strict_cbor_value(&bytes)?;
    Ok(bytes)
}

fn restore_identity_tags(
    value: CborValue,
    parent_sid: i64,
    model: &CompositeModel,
) -> Result<CborValue> {
    match value {
        CborValue::Map(entries) => {
            let mut restored = Vec::with_capacity(entries.len());
            for (key, child) in entries {
                let sid_delta = match &key {
                    CborValue::Integer(integer) => i64::try_from(i128::from(*integer)).ok(),
                    _ => None,
                };
                let absolute_sid = sid_delta.map_or(parent_sid, |delta| parent_sid + delta);
                let child = restore_identity_tags(child, absolute_sid, model)?;
                let child = if let Some(identifier) = model.get_identifier(absolute_sid) {
                    if let Some(yang_type) = model.get_type(identifier) {
                        if is_identity_like(yang_type) && is_identity_sid(&child, model) {
                            CborValue::Tag(45, Box::new(child))
                        } else {
                            child
                        }
                    } else {
                        child
                    }
                } else {
                    child
                };
                restored.push((key, child));
            }
            Ok(CborValue::Map(restored))
        }
        CborValue::Array(values) => {
            let values = values
                .into_iter()
                .map(|value| restore_identity_tags(value, parent_sid, model))
                .collect::<Result<Vec<_>>>()?;
            Ok(CborValue::Array(values))
        }
        CborValue::Tag(tag, value) => Ok(CborValue::Tag(
            tag,
            Box::new(restore_identity_tags(*value, parent_sid, model)?),
        )),
        other => Ok(other),
    }
}

fn is_identity_like(yang_type: &YangType) -> bool {
    match yang_type {
        // r-schc's SoR representation keeps ordinary identityrefs as integers.
        // Only a union needs the explicit tag to distinguish an identity SID
        // from a numeric union member such as field-length=4.
        YangType::Union(types) => types
            .iter()
            .any(|member| matches!(member, YangType::Identityref) || is_identity_like(member)),
        _ => false,
    }
}

fn is_identity_sid(value: &CborValue, model: &CompositeModel) -> bool {
    let CborValue::Integer(integer) = value else {
        return false;
    };
    let Ok(sid) = i64::try_from(i128::from(*integer)) else {
        return false;
    };
    model
        .get_identifier(sid)
        .is_some_and(|identifier| !identifier.contains('/'))
}

pub(crate) fn digest_context(tree: &Value, sor: &[u8]) -> Result<[u8; 32]> {
    let tree_bytes = serde_json::to_vec(tree)
        .map_err(|error| ContextError::Model(format!("tree serialization: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((tree_bytes.len() as u64).to_be_bytes());
    hasher.update(tree_bytes);
    hasher.update((sor.len() as u64).to_be_bytes());
    hasher.update(sor);
    Ok(hasher.finalize().into())
}
