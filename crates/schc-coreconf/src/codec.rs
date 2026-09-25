use std::collections::BTreeSet;
use std::io::Cursor;

use ciborium::value::Value as CborValue;
use coreconf_model::{CompositeModel, CoreconfModel};
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

pub(crate) fn ensure_schc_root(value: &CborValue, root_sid: i64) -> Result<()> {
    let CborValue::Map(entries) = value else {
        return Err(ContextError::Cbor("SoR root must be a CBOR map".to_owned()));
    };
    let has_root = entries
        .iter()
        .any(|(key, _)| matches!(key, CborValue::Integer(integer) if i128::from(*integer) == i128::from(root_sid)));
    if !has_root {
        return Err(ContextError::Cbor(format!(
            "SoR root is missing SCHC SID {root_sid}"
        )));
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
                Some("entry-universal") => {
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
    let cbor_value = coreconf_model::codec::identifier_json_to_cbor_value(composite, tree)
        .map_err(ContextError::Rustconf)?;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut bytes)
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    let _ = strict_cbor_value(&bytes)?;
    Ok(bytes)
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

pub(crate) fn context_tag(digest: [u8; 32]) -> crate::ContextTag {
    let mut bytes = [0_u8; crate::CONTEXT_TAG_LEN];
    bytes.copy_from_slice(&digest[..crate::CONTEXT_TAG_LEN]);
    crate::ContextTag::from_bytes(bytes)
}
