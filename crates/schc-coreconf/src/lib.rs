#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Atomic, domain-oriented managed SCHC context construction.
//!
//! This crate binds the r-schc rule context, a rustconf model/tree, and a
//! schc-runtime runtime in one immutable snapshot, then carries validated
//! logical packets over a raw UDP SCHC link. Management RPC
//! semantics are added by higher-level components.

mod application;
mod codec;
mod context;
mod link;
mod management;
mod packet;
mod packet_loop;
mod policy;
mod report;

pub use application::{schema_lines, ApplicationError, DataClient, GenericDataService};
pub use context::{
    ActiveContext, ActiveContextBackend, ContextSnapshot, ContextTag, LoadedContext,
    PreparedContext, CONTEXT_TAG_LEN,
};
pub use link::{
    temporary_ordinary_response, LinkDecoded, LinkEncoding, LinkError, LinkOperation, LinkReport,
    LinkRole, RawDatagram, RawUdpLink, SchcLink, TrafficClass, TrafficOrigin, TrafficRoute,
    APPLICATION_PORT, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};
pub use management::{
    context_check_request, context_check_response, decode_context_check_payload,
    decode_rule_detail_payload, decode_rule_list_payload, exchange_management,
    exchange_management_update, format_rule_detail, format_rule_list, is_duplicate_rule_request,
    management_bit_breakdown, parse_rule_duplicate_command, parse_rule_selector,
    parse_rule_update_command, prepare_management_request, rule_get_request, rule_list_request,
    validate_management_response, ContextCheckResult, ContextStatus, DuplicateRpcCost,
    DuplicateRpcOverride, DuplicateRuleResult, InspectionError, InspectionService,
    ManagementBitBreakdown, ManagementExchange, PreparedManagementRequest, ResolvedRuleUpdate,
    RuleDetail, RuleDuplicateOverride, RuleDuplicateRequest, RuleEntry, RuleEntrySelector,
    RuleSelector, RuleSummary, RuleUpdateRequest, CONTEXT_CHECK_MARKER,
};
pub use packet::{
    CoapMessage, CoapOption, Ipv6UdpCoapPacket, PacketError, PacketMetadata, PacketResult,
    DEFAULT_FLOW_LABEL, DEFAULT_HOP_LIMIT, DEFAULT_TRAFFIC_CLASS, IPV6_HEADER_LEN, IPV6_VERSION,
    MAX_COAP_DATAGRAM_LEN, UDP_HEADER_LEN, UDP_NEXT_HEADER,
};
pub use packet_loop::{PacketEventLoop, PacketLoopError, PacketPoll};
pub use policy::{ProtectedRule, ProtectedRules, ProtectionPolicy};
pub use report::{
    format_report, inspect_report, CoapCost, CoapOptionCost, CoapOptionDescription, CoapReport,
    Ipv6Report, PacketLayerCost, PacketReport, ReportDirection, ReportError, SchcCost, UdpReport,
};

/// Returns the immutable protected management rule identities used by the prototype.
#[must_use]
pub fn protected_management_rule_ids() -> [RuleId; 6] {
    [
        RuleId::new(16, 8),
        RuleId::new(17, 8),
        RuleId::new(26, 8),
        RuleId::new(27, 8),
        RuleId::new(28, 8),
        RuleId::new(29, 8),
    ]
}

use coreconf_model::{CoreconfError, SidFile};
use schc_core::{RuleId, SidRegistry};
use serde_json::Value;
use thiserror::Error;

/// Errors returned by managed-context loading, construction, or publication.
#[derive(Debug, Error)]
pub enum ContextError {
    /// CBOR was malformed, incomplete, non-complete, or had duplicate map keys.
    #[error("invalid complete CBOR: {0}")]
    Cbor(String),
    /// The same input could not be loaded by one of the two model libraries.
    #[error("model loading failed: {0}")]
    Model(String),
    /// The SCHC rule context could not be constructed.
    #[error("SCHC context construction failed: {0}")]
    Schc(String),
    /// The schc-runtime runtime could not be constructed.
    #[error("SCHC runtime construction failed: {0}")]
    Runtime(String),
    /// A candidate tree was not the canonical complete tree.
    #[error("candidate tree is not canonical")]
    NonCanonicalCandidate,
    /// A protected rule was added, removed, re-identified, re-natured, or changed.
    #[error("protected management rule changed: {0}")]
    ProtectedRuleChanged(String),
    /// Candidate runtime or construction parameters differ from the active
    /// context's immutable construction parameters.
    #[error("candidate construction parameters differ from the active context")]
    CandidateRecipeMismatch,
    /// A rustconf operation failed.
    #[error("rustconf error: {0}")]
    Rustconf(#[from] CoreconfError),
    /// A rule ID supplied by explicit policy was not present in the context.
    #[error("protected RuleID {value}/{bit_len} is absent from the context")]
    MissingProtectedRule {
        /// Numeric `RuleID` value.
        value: u64,
        /// `RuleID` encoded bit length.
        bit_len: usize,
    },
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, ContextError>;

/// Canonicalizes a complete `SoR` and returns its identifier-keyed tree and
/// canonical bytes.
///
/// # Errors
///
/// Returns an error when the SID/SoR pair is malformed, incomplete, or fails
/// rustconf or r-schc semantic validation.
pub fn canonicalize_sor(sid_json: &str, sor: &[u8]) -> Result<(Value, Vec<u8>)> {
    let loaded = LoadedContext::from_sor(sid_json, sor)?;
    Ok((loaded.tree().clone(), loaded.sor().to_vec()))
}

/// Loads both dependency models and returns their independently parsed SID views.
///
/// # Errors
///
/// Returns an error when either dependency model rejects the SID JSON.
pub fn validate_sid_with_both_models(sid_json: &str) -> Result<(SidFile, SidRegistry)> {
    let rustconf =
        SidFile::from_json_str(sid_json).map_err(|error| ContextError::Model(error.to_string()))?;
    let schc = SidRegistry::from_json_str(sid_json)
        .map_err(|error| ContextError::Schc(error.to_string()))?;
    Ok((rustconf, schc))
}

/// Converts a rustconf tree to strict complete canonical `SoR` bytes.
///
/// The tree is routed through [`LoadedContext`] after encoding, so root,
/// RuleID-prefix, entry, and all r-schc semantic checks are applied.
///
/// # Errors
///
/// Returns an error when the tree is not canonical, cannot be encoded, or does
/// not describe a complete semantically valid SCHC context.
pub fn canonical_sor_from_tree(sid_json: &str, tree: &Value) -> Result<Vec<u8>> {
    let model = coreconf_model::CoreconfModel::from_sid_str(sid_json)
        .map_err(|error| ContextError::Model(error.to_string()))?;
    let normalized = codec::normalize_tree(tree.clone())?;
    if normalized != *tree {
        return Err(ContextError::NonCanonicalCandidate);
    }
    let sor = codec::encode_tree(&model, tree)?;
    let loaded = LoadedContext::from_sor(sid_json, &sor)?;
    if loaded.tree() != tree {
        return Err(ContextError::NonCanonicalCandidate);
    }
    Ok(loaded.sor().to_vec())
}

/// Converts strict complete `SoR` to the canonical rustconf identifier tree.
///
/// The input is routed through [`LoadedContext`], so root, RuleID-prefix,
/// entry, and all r-schc semantic checks are applied.
///
/// # Errors
///
/// Returns an error when the bytes are malformed, incomplete, or fail model or
/// r-schc semantic validation.
pub fn tree_from_sor(sid_json: &str, sor: &[u8]) -> Result<Value> {
    Ok(LoadedContext::from_sor(sid_json, sor)?.tree().clone())
}

/// Returns the `RuleIDs` whose nature is management in a complete `SoR`.
///
/// # Errors
///
/// Returns an error when the SID/SoR pair is malformed, incomplete, or fails
/// model or r-schc semantic validation.
pub fn derive_protected_management_rule_ids(sid_json: &str, sor: &[u8]) -> Result<Vec<RuleId>> {
    let loaded = LoadedContext::from_sor(sid_json, sor)?;
    Ok(loaded.protected_rules().ids())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-05-07.sid");
    const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

    #[test]
    fn fixture_loads_through_both_models_and_is_deterministic() {
        let (tree_a, sor_a) = canonicalize_sor(SID, SOR).expect("canonical fixture");
        let (tree_b, sor_b) = canonicalize_sor(SID, SOR).expect("canonical fixture");
        assert_eq!(tree_a, tree_b);
        assert_eq!(sor_a, sor_b);
    }

    #[test]
    fn strict_loader_rejects_trailing_value() {
        let mut bytes = SOR.to_vec();
        bytes.push(0);
        assert!(matches!(
            canonicalize_sor(SID, &bytes),
            Err(ContextError::Cbor(_))
        ));

        // Two occurrences of the complete-context root are malformed even
        // though a permissive map decoder might retain only the last one.
        let duplicate_root = [0xa2, 0x19, 0x0a, 0x0e, 0xa0, 0x19, 0x0a, 0x0e, 0xa0];
        assert!(matches!(
            canonicalize_sor(SID, &duplicate_root),
            Err(ContextError::Cbor(_))
        ));
    }
}
