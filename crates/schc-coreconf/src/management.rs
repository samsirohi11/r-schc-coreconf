//! Protected, inspection-only SCHC context management.
//!
//! The wire service uses ordinary CORECONF FETCH payloads for rule inspection.
//! Context checks use a compact marker and eight-byte tag because the fixed
//! management rules do not describe an `ETag` option.

use std::fmt;
use std::sync::Arc;

use ciborium::value::Value as CborValue;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType, ResponseType};
use coreconf_model::instance_id::{decode_instances_with_model, PathComponent};
use coreconf_model::{CompositeModel, CoreconfModel};
use coreconf_runtime::request_handler::RequestHandler;
use coreconf_runtime::transport::coap_lite::{packet_to_request, response_to_packet};
use coreconf_runtime::{Datastore, ResponseCode};
use schc_core::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Rule, RuleContext, RuleId,
    RuleNature, SidRegistry, TargetValue,
};
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    ActiveContext, ContextSnapshot, ContextTag, Ipv6UdpCoapPacket, LinkError, LinkReport,
    RawUdpLink, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT, CORE_LOGICAL_ADDRESS,
    DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

/// Marker used as the first byte of the compact context-check FETCH payload.
pub const CONTEXT_CHECK_MARKER: u8 = 0xC6;
const CONTEXT_CHECK_EQUAL: u8 = 0;
const CONTEXT_CHECK_MISMATCH: u8 = 1;
const RULE_LIST_SID: i64 = 2597;
const RULE_ID_LENGTH_SID: i64 = 2598;
const RULE_ID_VALUE_SID: i64 = 2599;
const RULE_NATURE_SID: i64 = 2600;

/// Errors returned by context inspection and its protected exchange.
#[derive(Debug, Error)]
pub enum InspectionError {
    /// A `RuleID` selector was malformed or out of range.
    #[error("invalid RuleID selector: {0}")]
    InvalidSelector(String),
    /// A requested rule was not found.
    #[error("RuleID {value}/{bits} was not found")]
    MissingRule {
        /// Numeric `RuleID` value.
        value: u64,
        /// `RuleID` bit length.
        bits: usize,
    },
    /// A result contained more than one matching rule.
    #[error("RuleID {value}/{bits} was ambiguous ({matches} matches)")]
    AmbiguousRule {
        /// Numeric `RuleID` value.
        value: u64,
        /// `RuleID` bit length.
        bits: usize,
        /// Number of matching rules.
        matches: usize,
    },
    /// The local management datastore or model rejected a request.
    #[error("management datastore error: {0}")]
    Datastore(String),
    /// A CoAP request or response could not be represented.
    #[error("management CoAP error: {0}")]
    Coap(String),
    /// A protected link operation failed.
    #[error("management SCHC link error: {0}")]
    Link(#[from] LinkError),
    /// The protected response did not match its request.
    #[error("management response correlation failed: {0}")]
    Correlation(String),
    /// The remote endpoint returned unexpected content.
    #[error("unexpected management response: {0}")]
    UnexpectedResponse(String),
}

/// A strict numeric `RuleID` selector containing both value and bit length.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleSelector {
    /// Numeric `RuleID` value.
    pub value: u64,
    /// Number of bits in the encoded `RuleID`.
    pub bits: usize,
}

impl RuleSelector {
    /// Creates a selector after validating its value and length.
    ///
    /// # Errors
    ///
    /// Returns an error when the bit length is outside 1..=64 or the value
    /// does not fit in the requested number of bits.
    pub fn new(value: u64, bits: usize) -> Result<Self, InspectionError> {
        if !(1..=64).contains(&bits) {
            return Err(InspectionError::InvalidSelector(format!(
                "bit length must be between 1 and 64, got {bits}"
            )));
        }
        if bits < 64 && value >= (1_u64 << bits) {
            return Err(InspectionError::InvalidSelector(format!(
                "value {value} does not fit in {bits} bits"
            )));
        }
        Ok(Self { value, bits })
    }

    /// Converts this selector to the r-schc identity type.
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId::new(self.value, self.bits)
    }
}

/// Parses the exact `<value>/<bit-length>` syntax used by the console.
///
/// # Errors
///
/// Returns an error for malformed numbers, missing separators, invalid bit
/// lengths, or values that do not fit in the selected width.
pub fn parse_rule_selector(input: &str) -> Result<RuleSelector, InspectionError> {
    let (value, bits) = input
        .trim()
        .split_once('/')
        .ok_or_else(|| InspectionError::InvalidSelector("expected <value>/<bit-length>".into()))?;
    if value.is_empty() || bits.is_empty() || bits.contains('/') || value.contains('/') {
        return Err(InspectionError::InvalidSelector(
            "expected one numeric value and one numeric bit length".into(),
        ));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit())
        || !bits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(InspectionError::InvalidSelector(
            "value and bit length must be unsigned decimal numbers".into(),
        ));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| InspectionError::InvalidSelector("RuleID value is out of range".into()))?;
    let bits = bits
        .parse::<usize>()
        .map_err(|_| InspectionError::InvalidSelector("bit length is out of range".into()))?;
    RuleSelector::new(value, bits)
}

/// A rule summary intentionally omitting all field entries and target values.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleSummary {
    /// Exact `RuleID`.
    pub id: RuleSelector,
    /// Stable lowercase rule nature.
    pub nature: String,
}

/// One readable complete rule entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleEntry {
    /// Canonical entry index.
    pub entry_index: usize,
    /// Module-qualified or numeric fallback field identity.
    pub fid: String,
    /// Repeated field position.
    pub field_position: usize,
    /// Stable direction identifier.
    pub direction: String,
    /// Stable field length representation.
    pub length: String,
    /// Stable target value representation.
    pub target: String,
    /// Stable matching operator representation.
    pub matching: String,
    /// Stable compression/decompression action representation.
    pub cda: String,
}

/// A complete readable rule selected by both `RuleID` keys.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleDetail {
    /// Exact `RuleID`.
    pub id: RuleSelector,
    /// Stable lowercase rule nature.
    pub nature: String,
    /// Entries sorted by entry index.
    pub entries: Vec<RuleEntry>,
}

/// One consistent active-context status view.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContextStatus {
    /// Publication generation.
    pub generation: u64,
    /// Full local digest.
    pub digest: [u8; 32],
    /// Compact context tag.
    pub tag: ContextTag,
    /// Number of loaded rules.
    pub rule_count: usize,
}

impl ContextStatus {
    /// Reads all fields from one immutable snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &ContextSnapshot) -> Self {
        Self {
            generation: snapshot.generation(),
            digest: snapshot.digest(),
            tag: snapshot.tag(),
            rule_count: snapshot.rules().len(),
        }
    }
}

/// Result of a compact core-to-device context check.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContextCheckResult {
    /// Core's locally held tag.
    pub core_tag: ContextTag,
    /// Device's returned tag.
    pub device_tag: ContextTag,
    /// Whether the two tags are equal.
    pub equal: bool,
}

/// A protected request/response exchange and its existing link reports.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManagementExchange {
    /// Response CoAP payload.
    pub payload: Vec<u8>,
    /// Core-to-device compression report.
    pub request_report: LinkReport,
    /// Device-to-core decompression report.
    pub response_report: LinkReport,
}

/// Inspection-only CORECONF service rooted at `/schc`.
pub struct InspectionService {
    active: Arc<ActiveContext>,
    model: CoreconfModel,
    sid_registry: SidRegistry,
    handler: RequestHandler,
}

impl fmt::Debug for InspectionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectionService")
            .field("generation", &self.active.generation())
            .finish_non_exhaustive()
    }
}

impl InspectionService {
    /// Creates a service over the exact active-context backend.
    ///
    /// # Errors
    ///
    /// Returns an error when the active context's SID model cannot be loaded.
    pub fn new(active: Arc<ActiveContext>) -> Result<Self, InspectionError> {
        let model = CoreconfModel::from_sid_str(&active.recipe().sid_json)
            .map_err(|error| InspectionError::Datastore(error.to_string()))?;
        let sid_registry = SidRegistry::from_json_str(&active.recipe().sid_json)
            .map_err(|error| InspectionError::Datastore(error.to_string()))?;
        let datastore = Datastore::with_backend(model.composite_model().clone(), active.backend());
        Ok(Self {
            active,
            model,
            sid_registry,
            handler: RequestHandler::new(datastore),
        })
    }

    /// Returns the model used by the management datastore.
    #[must_use]
    pub const fn model(&self) -> &CoreconfModel {
        &self.model
    }

    /// Returns the SID registry used to decode SCHC rule details.
    #[must_use]
    pub const fn sid_registry(&self) -> &SidRegistry {
        &self.sid_registry
    }

    /// Returns the SID document defining the active management model.
    #[must_use]
    pub fn sid_json(&self) -> &str {
        self.active.recipe().sid_json.as_ref()
    }

    /// Reads local status from one active snapshot.
    #[must_use]
    pub fn status(&self) -> ContextStatus {
        let snapshot = self.active.snapshot();
        ContextStatus::from_snapshot(&snapshot)
    }

    /// Returns local summaries from one active snapshot.
    #[must_use]
    pub fn summaries(&self) -> Vec<RuleSummary> {
        let snapshot = self.active.snapshot();
        summaries_from_rules(snapshot.rules())
    }

    /// Returns one local complete rule selected by both keys.
    ///
    /// # Errors
    ///
    /// Returns an error when no rule matches or when the selector is
    /// ambiguous.
    pub fn detail(&self, selector: RuleSelector) -> Result<RuleDetail, InspectionError> {
        let snapshot = self.active.snapshot();
        let mut matches = snapshot
            .rules()
            .iter()
            .filter(|rule| rule.id() == selector.rule_id());
        let Some(rule) = matches.next() else {
            return Err(InspectionError::MissingRule {
                value: selector.value,
                bits: selector.bits,
            });
        };
        if matches.next().is_some() {
            return Err(InspectionError::AmbiguousRule {
                value: selector.value,
                bits: selector.bits,
                matches: 2,
            });
        }
        Ok(detail_from_rule(rule))
    }

    /// Handles one complete logical CoAP datagram without mutating context.
    ///
    /// GET and FETCH are delegated to rustconf.  Every mutation method is
    /// rejected before the mutable request handler is called.
    ///
    /// # Errors
    ///
    /// Returns an error when the CoAP datagram is malformed or the response
    /// cannot be serialized.
    pub fn handle_datagram(&mut self, datagram: &[u8]) -> Result<Vec<u8>, InspectionError> {
        let request = Packet::from_bytes(datagram)
            .map_err(|error| InspectionError::Coap(error.to_string()))?;
        if is_mutation(&request) {
            let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                coreconf_runtime::coap_types::Method::Fetch,
            );
            return packet_without_content_format(&request, response);
        }
        if !matches!(
            request.header.code,
            MessageClass::Request(RequestType::Get | RequestType::Fetch)
        ) {
            let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                coreconf_runtime::coap_types::Method::Fetch,
            );
            return packet_without_content_format(&request, response);
        }
        if request
            .get_option(CoapOption::UriPath)
            .map_or(true, |segments| {
                segments.iter().any(|segment| segment.as_slice() != b"schc")
            })
        {
            let response = coreconf_runtime::coap_types::Response::not_found("/schc");
            return packet_without_content_format(&request, response);
        }

        if matches!(
            request.header.code,
            MessageClass::Request(RequestType::Fetch)
        ) && request.payload.first() == Some(&CONTEXT_CHECK_MARKER)
        {
            return self.handle_context_check(&request);
        }

        let request = packet_to_request(&request, "schc").map_err(|response| {
            InspectionError::Coap(format!("CORECONF request rejected with {}", response.code))
        })?;
        let response = self.handler.handle(&request);
        packet_without_content_format(&datagram_packet(&request, datagram)?, response)
    }

    fn handle_context_check(&self, request: &Packet) -> Result<Vec<u8>, InspectionError> {
        if request.payload.len() != 1 + crate::CONTEXT_TAG_LEN {
            let response = coreconf_runtime::coap_types::Response::error(
                ResponseCode::BadRequest,
                "context check payload must contain marker and eight-byte tag",
            );
            return packet_without_content_format(request, response);
        }
        let mut core_bytes = [0_u8; crate::CONTEXT_TAG_LEN];
        core_bytes.copy_from_slice(&request.payload[1..]);
        let core_tag = ContextTag::new(core_bytes);
        let device_tag = self.active.snapshot().tag();
        let mut payload = vec![CONTEXT_CHECK_MARKER];
        if core_tag == device_tag {
            payload.push(CONTEXT_CHECK_EQUAL);
        } else {
            payload.push(CONTEXT_CHECK_MISMATCH);
            payload.extend_from_slice(&device_tag.bytes());
        }
        let response = coreconf_runtime::coap_types::Response::content(
            payload,
            coreconf_runtime::coap_types::ContentFormat::YangDataCbor,
        );
        packet_without_content_format(request, response)
    }
}

fn datagram_packet(
    request: &coreconf_runtime::coap_types::Request,
    original: &[u8],
) -> Result<Packet, InspectionError> {
    let _ = request;
    Packet::from_bytes(original).map_err(|error| InspectionError::Coap(error.to_string()))
}

fn packet_without_content_format(
    request: &Packet,
    response: coreconf_runtime::coap_types::Response,
) -> Result<Vec<u8>, InspectionError> {
    let mut packet = response_to_packet(request, response);
    packet.clear_option(CoapOption::ContentFormat);
    packet
        .to_bytes()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

fn is_mutation(packet: &Packet) -> bool {
    matches!(
        packet.header.code,
        MessageClass::Request(
            RequestType::IPatch | RequestType::Patch | RequestType::Post | RequestType::Delete
        )
    )
}

/// Builds a compact context-check CoAP request payload.
///
/// # Panics
///
/// Panics only if the fixed marker request cannot be serialized.
#[must_use]
pub fn context_check_request(tag: ContextTag, message_id: u16, token: &[u8]) -> Vec<u8> {
    let mut packet = base_request(RequestType::Fetch, message_id, token);
    packet.payload.push(CONTEXT_CHECK_MARKER);
    packet.payload.extend_from_slice(&tag.bytes());
    packet
        .to_bytes()
        .expect("context-check request is representable")
}

/// Parses a compact context-check CoAP response.
///
/// # Errors
///
/// Returns an error when the response is malformed, not 2.05 Content, or
/// contains a marker or payload length that is not part of the compact format.
pub fn context_check_response(
    datagram: &[u8],
    core_tag: ContextTag,
) -> Result<ContextCheckResult, InspectionError> {
    let packet =
        Packet::from_bytes(datagram).map_err(|error| InspectionError::Coap(error.to_string()))?;
    if packet.header.code != MessageClass::Response(ResponseType::Content) {
        return Err(InspectionError::UnexpectedResponse(format!(
            "expected 2.05 Content, got {:?}",
            packet.header.code
        )));
    }
    decode_context_check_payload(&packet.payload, core_tag)
}

/// Parses the compact context-check response payload returned by a validated
/// management exchange.
///
/// # Errors
///
/// Returns an error when the payload marker or result shape is invalid.
pub fn decode_context_check_payload(
    payload: &[u8],
    core_tag: ContextTag,
) -> Result<ContextCheckResult, InspectionError> {
    if payload.len() != 2 && payload.len() != 2 + crate::CONTEXT_TAG_LEN {
        return Err(InspectionError::UnexpectedResponse(
            "context-check response has invalid length".into(),
        ));
    }
    if payload[0] != CONTEXT_CHECK_MARKER {
        return Err(InspectionError::UnexpectedResponse(
            "context-check marker mismatch".into(),
        ));
    }
    match payload[1] {
        CONTEXT_CHECK_EQUAL if payload.len() == 2 => Ok(ContextCheckResult {
            core_tag,
            device_tag: core_tag,
            equal: true,
        }),
        CONTEXT_CHECK_MISMATCH if payload.len() == 2 + crate::CONTEXT_TAG_LEN => {
            let mut bytes = [0_u8; crate::CONTEXT_TAG_LEN];
            bytes.copy_from_slice(&payload[2..]);
            Ok(ContextCheckResult {
                core_tag,
                device_tag: ContextTag::new(bytes),
                equal: false,
            })
        }
        _ => Err(InspectionError::UnexpectedResponse(
            "invalid context-check result marker".into(),
        )),
    }
}

/// Decodes the exact projected rule-summary FETCH response from a device.
///
/// The model is required because ordinary CORECONF instance paths do not mark
/// integer list keys. The returned values are taken exclusively from the
/// response payload.
///
/// # Errors
///
/// Returns an error for unknown paths, duplicate or missing leaves, mismatched
/// key pairs, unexpected full fields, or malformed leaf values.
pub fn decode_rule_list_payload(
    payload: &[u8],
    model: &CoreconfModel,
) -> Result<Vec<RuleSummary>, InspectionError> {
    let instances = decode_instances_with_model(model.composite_model(), payload)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    if instances.is_empty() {
        return Err(InspectionError::UnexpectedResponse(
            "rule-list response contained no summary leaves".into(),
        ));
    }

    let mut summaries =
        std::collections::BTreeMap::<RuleSelector, std::collections::BTreeMap<i64, String>>::new();
    for instance in instances {
        let leaf_sid = instance.path.absolute_sid().ok_or_else(|| {
            InspectionError::UnexpectedResponse("rule-list response contained an empty path".into())
        })?;
        if !matches!(
            leaf_sid,
            RULE_ID_VALUE_SID | RULE_ID_LENGTH_SID | RULE_NATURE_SID
        ) {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-list response contained unexpected SID {leaf_sid}"
            )));
        }
        validate_rule_instance_path(&instance.path, leaf_sid, None)?;
        let keys = rule_key_values(&instance.path)?;
        let bits = usize::try_from(keys[1]).map_err(|_| {
            InspectionError::UnexpectedResponse("RuleID bit length is out of range".into())
        })?;
        let selector = RuleSelector::new(keys[0], bits)?;
        let value = instance.value.ok_or_else(|| {
            InspectionError::UnexpectedResponse(
                "rule-list response contained a deleted leaf".into(),
            )
        })?;
        if value.is_object() || value.is_array() || value.is_null() {
            return Err(InspectionError::UnexpectedResponse(
                "rule-list response contained a projected full field".into(),
            ));
        }
        if leaf_sid == RULE_ID_VALUE_SID && value.as_u64() != Some(selector.value)
            || leaf_sid == RULE_ID_LENGTH_SID && value.as_u64() != Some(selector.bits as u64)
        {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-list response leaf SID {leaf_sid} disagreed with its RuleID keys"
            )));
        }
        let display = if leaf_sid == RULE_NATURE_SID {
            decode_nature_value(model.composite_model(), value)?
        } else {
            value.to_string()
        };
        let leaves = summaries.entry(selector).or_default();
        if leaves.insert(leaf_sid, display).is_some() {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-list response duplicated SID {leaf_sid} for RuleID {}/{}",
                selector.value, selector.bits
            )));
        }
    }

    let mut result = Vec::with_capacity(summaries.len());
    for (selector, leaves) in summaries {
        if leaves.len() != 3
            || !leaves.contains_key(&RULE_ID_VALUE_SID)
            || !leaves.contains_key(&RULE_ID_LENGTH_SID)
            || !leaves.contains_key(&RULE_NATURE_SID)
        {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-list response is missing a summary leaf for RuleID {}/{}",
                selector.value, selector.bits
            )));
        }
        result.push(RuleSummary {
            id: selector,
            nature: leaves
                .get(&RULE_NATURE_SID)
                .cloned()
                .ok_or_else(|| InspectionError::UnexpectedResponse("missing rule nature".into()))?,
        });
    }
    Ok(result)
}

/// Decodes the exact complete selected-rule FETCH response from a device.
///
/// This decoder reconstructs a typed rule from the response using the SID
/// model and registry, rather than consulting the caller's local context.
///
/// # Errors
///
/// Returns an error for a wrong key pair, multiple or projected instances,
/// incomplete rule fields, or unexpected model fields.
pub fn decode_rule_detail_payload(
    payload: &[u8],
    model: &CoreconfModel,
    sid_registry: &SidRegistry,
    sid_json: &str,
    selector: RuleSelector,
) -> Result<RuleDetail, InspectionError> {
    let instances = decode_instances_with_model(model.composite_model(), payload)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    if instances.len() != 1 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-get response contained {} instances, expected one",
            instances.len()
        )));
    }
    let instance = &instances[0];
    validate_rule_instance_path(&instance.path, RULE_LIST_SID, Some(selector))?;
    let raw_value = instance.value.clone().ok_or_else(|| {
        InspectionError::UnexpectedResponse("rule-get response contained a deleted rule".into())
    })?;
    let rule_value = model
        .composite_model()
        .sid_value_to_identifier_value_at_path(raw_value, "/ietf-schc:schc/rule")
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    validate_model_shape(model.composite_model(), &rule_value, "/ietf-schc:schc/rule")?;
    let rule_object = rule_value.as_object().ok_or_else(|| {
        InspectionError::UnexpectedResponse(
            "rule-get response did not contain a complete rule object".into(),
        )
    })?;
    for field in ["rule-id-value", "rule-id-length", "rule-nature"] {
        if !rule_object.contains_key(field) {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-get response is missing required field '{field}'"
            )));
        }
    }
    let response_selector = RuleSelector::new(
        rule_object
            .get("rule-id-value")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                InspectionError::UnexpectedResponse("rule-id-value is not numeric".into())
            })?,
        rule_object
            .get("rule-id-length")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                InspectionError::UnexpectedResponse("rule-id-length is not numeric".into())
            })?,
    )?;
    if response_selector != selector {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-get response selected RuleID {}/{} instead of {}/{}",
            response_selector.value, response_selector.bits, selector.value, selector.bits
        )));
    }

    let cbor = encode_remote_rule(sid_json, &rule_value)?;
    let context = RuleContext::from_cbor_slice(&cbor, sid_registry.clone())
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    let rules = context.rules().rules();
    if rules.len() != 1 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-get response reconstructed {} rules, expected one",
            rules.len()
        )));
    }
    if rules[0].id() != selector.rule_id() {
        return Err(InspectionError::UnexpectedResponse(
            "rule-get response reconstructed the wrong RuleID".into(),
        ));
    }
    Ok(detail_from_rule(&rules[0]))
}

fn rule_key_values(
    path: &coreconf_model::instance_id::InstancePath,
) -> Result<[u64; 2], InspectionError> {
    let keys = path
        .components
        .iter()
        .filter_map(|component| match component {
            PathComponent::KeyValue(value) => value.as_u64(),
            PathComponent::SidDelta(_) => None,
        })
        .collect::<Vec<_>>();
    if keys.len() != 2 {
        return Err(InspectionError::UnexpectedResponse(
            "rule response did not contain exactly two RuleID keys".into(),
        ));
    }
    Ok([keys[0], keys[1]])
}

fn validate_rule_instance_path(
    path: &coreconf_model::instance_id::InstancePath,
    leaf_sid: i64,
    selector: Option<RuleSelector>,
) -> Result<(), InspectionError> {
    let mut absolute = 0_i64;
    let mut sids = Vec::new();
    let mut key_count = 0;
    for component in &path.components {
        match component {
            PathComponent::SidDelta(delta) => {
                absolute += delta;
                sids.push(absolute);
            }
            PathComponent::KeyValue(_) => key_count += 1,
        }
    }
    let expected_sids = if leaf_sid == RULE_LIST_SID {
        [2574, RULE_LIST_SID, 0]
    } else {
        [2574, RULE_LIST_SID, leaf_sid]
    };
    let expected_len = if leaf_sid == RULE_LIST_SID { 2 } else { 3 };
    if sids.len() != expected_len
        || sids.first().copied() != Some(expected_sids[0])
        || sids.get(1).copied() != Some(expected_sids[1])
        || (leaf_sid != RULE_LIST_SID && sids.get(2).copied() != Some(leaf_sid))
        || key_count != 2
    {
        return Err(InspectionError::UnexpectedResponse(
            "rule response contained an unexpected projected or full path".into(),
        ));
    }
    let keys = rule_key_values(path)?;
    if let Some(selector) = selector {
        if keys != [selector.value, selector.bits as u64] {
            return Err(InspectionError::UnexpectedResponse(
                "rule-get response did not carry the requested list keys".into(),
            ));
        }
    }
    Ok(())
}

fn decode_nature_value(model: &CompositeModel, value: Value) -> Result<String, InspectionError> {
    let value = model
        .sid_value_to_identifier_value_at_path(value, "/ietf-schc:schc/rule/rule-nature")
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    let identifier = match value {
        Value::String(value) => value,
        Value::Number(value) => model
            .get_identifier(value.as_i64().ok_or_else(|| {
                InspectionError::UnexpectedResponse("rule-nature SID is not an integer".into())
            })?)
            .ok_or_else(|| InspectionError::UnexpectedResponse("unknown rule-nature SID".into()))?
            .to_owned(),
        _ => {
            return Err(InspectionError::UnexpectedResponse(
                "rule-nature is not an identity value".into(),
            ));
        }
    };
    let suffix = identifier.rsplit(':').next().unwrap_or(&identifier);
    let nature = suffix.strip_prefix("nature-").unwrap_or(suffix).to_owned();
    if RuleNature::parse_identifier(&nature).is_none() {
        return Err(InspectionError::UnexpectedResponse(format!(
            "unknown rule nature '{identifier}'"
        )));
    }
    Ok(nature)
}

fn validate_model_shape(
    model: &CompositeModel,
    value: &Value,
    path: &str,
) -> Result<(), InspectionError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}/{key}");
                if model.get_sid(&child_path).is_none() {
                    return Err(InspectionError::UnexpectedResponse(format!(
                        "rule-get response contained unexpected field '{child_path}'"
                    )));
                }
                validate_model_shape(model, child, &child_path)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_model_shape(model, child, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn encode_remote_rule(sid_json: &str, rule_value: &Value) -> Result<Vec<u8>, InspectionError> {
    let tree = json!({"ietf-schc:schc": {"rule": [rule_value]}});
    crate::canonical_sor_from_tree(sid_json, &tree)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))
}

/// Builds a normal CORECONF FETCH for the minimal rule-list projection.
///
/// # Panics
///
/// Panics only if fixed numeric identifiers cannot be serialized.
#[must_use]
pub fn rule_list_request(message_id: u16, token: &[u8]) -> Vec<u8> {
    let mut packet = base_request(RequestType::Fetch, message_id, token);
    for sid in [RULE_ID_VALUE_SID, RULE_ID_LENGTH_SID, RULE_NATURE_SID] {
        ciborium::ser::into_writer(&CborValue::Integer(sid.into()), &mut packet.payload)
            .expect("rule-list identifier is representable");
    }
    packet
        .to_bytes()
        .expect("rule-list request is representable")
}

/// Builds a normal CORECONF FETCH for exactly one keyed rule instance.
///
/// # Panics
///
/// Panics only if fixed numeric identifiers cannot be serialized.
#[must_use]
pub fn rule_get_request(selector: RuleSelector, message_id: u16, token: &[u8]) -> Vec<u8> {
    let mut packet = base_request(RequestType::Fetch, message_id, token);
    let path = CborValue::Array(vec![
        CborValue::Integer(RULE_LIST_SID.into()),
        CborValue::Integer(selector.value.into()),
        CborValue::Integer(selector.bits.into()),
    ]);
    ciborium::ser::into_writer(&path, &mut packet.payload)
        .expect("rule-get identifier is representable");
    packet
        .to_bytes()
        .expect("rule-get request is representable")
}

fn base_request(method: RequestType, message_id: u16, token: &[u8]) -> Packet {
    let mut packet = Packet::new();
    packet.header.message_id = message_id;
    packet.header.code = MessageClass::Request(method);
    packet.header.set_type(MessageType::Confirmable);
    packet.set_token(token.to_vec());
    packet.add_option(CoapOption::UriPath, b"schc".to_vec());
    packet
}

/// Performs one protected management exchange and verifies route and identity.
///
/// # Errors
///
/// Returns an error when SCHC rejects the packet, logical routing is invalid,
/// or the response does not correlate and carry 2.05 Content.
pub fn exchange_management(
    link: &SchcLink,
    raw_link: &RawUdpLink,
    coap_datagram: &[u8],
) -> Result<ManagementExchange, InspectionError> {
    let request = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        APPLICATION_PORT,
        MANAGEMENT_PORT,
        coap_datagram,
    )
    .map_err(|error| InspectionError::Coap(error.to_string()))?;
    let encoded = link.encode(TrafficOrigin::Management, &request)?;
    if encoded.report().rule_id != RuleId::new(16, 8) {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management request selected RuleID {}/{} instead of 16/8",
            encoded.report().rule_id.value(),
            encoded.report().rule_id.bit_len()
        )));
    }
    raw_link.send_frame(encoded.frame())?;
    let datagram = raw_link.recv()?;
    let decoded = link.decode(datagram.bytes())?;
    if decoded.route() != TrafficRoute::ProtectedManagement
        || decoded.rule_id() != RuleId::new(17, 8)
    {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management response selected {:?} instead of protected 17/8",
            decoded.rule_id()
        )));
    }
    let response = decoded.packet();
    if response.source() != DEVICE_LOGICAL_ADDRESS
        || response.destination() != CORE_LOGICAL_ADDRESS
        || response.source_port() != MANAGEMENT_PORT
        || response.destination_port() != APPLICATION_PORT
    {
        return Err(InspectionError::UnexpectedResponse(
            "management response logical orientation is invalid".into(),
        ));
    }
    let request_message = request.coap_message();
    let response_message = response.coap_message();
    if request_message.message_id() != response_message.message_id()
        || request_message.token() != response_message.token()
    {
        return Err(InspectionError::Correlation(
            "CoAP message ID or token mismatch".into(),
        ));
    }
    if response_message.code() != 69 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "expected CoAP 2.05 Content, got {}",
            response_message.code()
        )));
    }
    Ok(ManagementExchange {
        payload: response.coap_payload().to_vec(),
        request_report: encoded.report().clone(),
        response_report: decoded.report().clone(),
    })
}

/// Formats summaries as stable scriptable lines.
#[must_use]
pub fn format_rule_list(summaries: &[RuleSummary]) -> Vec<String> {
    let mut sorted = summaries.to_vec();
    sorted.sort_by_key(|summary| (summary.id.value, summary.id.bits));
    sorted
        .into_iter()
        .map(|summary| {
            format!(
                "RULE {}/{} nature={}",
                summary.id.value, summary.id.bits, summary.nature
            )
        })
        .collect()
}

/// Formats one rule with entries ordered by entry index.
#[must_use]
pub fn format_rule_detail(detail: &RuleDetail) -> Vec<String> {
    let mut lines = vec![format!(
        "RULE {}/{} nature={}",
        detail.id.value, detail.id.bits, detail.nature
    )];
    let mut entries = detail.entries.clone();
    entries.sort_by_key(|entry| entry.entry_index);
    lines.extend(entries.into_iter().map(|entry| {
        format!(
            "ENTRY {} fid={} fp={} di={} length={} tv={} mo={} cda={}",
            entry.entry_index,
            entry.fid,
            entry.field_position,
            entry.direction,
            entry.length,
            entry.target,
            entry.matching,
            entry.cda
        )
    }));
    lines
}

fn summaries_from_rules(rules: &[Rule]) -> Vec<RuleSummary> {
    rules
        .iter()
        .map(|rule| RuleSummary {
            id: RuleSelector {
                value: rule.id().value(),
                bits: rule.id().bit_len(),
            },
            nature: rule.nature().as_str().to_owned(),
        })
        .collect()
}

fn detail_from_rule(rule: &Rule) -> RuleDetail {
    let mut entries = rule
        .fields()
        .iter()
        .map(entry_from_rule)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.entry_index);
    RuleDetail {
        id: RuleSelector {
            value: rule.id().value(),
            bits: rule.id().bit_len(),
        },
        nature: rule.nature().as_str().to_owned(),
        entries,
    }
}

fn entry_from_rule(field: &schc_core::rule::FieldRule) -> RuleEntry {
    RuleEntry {
        entry_index: field.entry_index,
        fid: field_name(&field.field),
        field_position: field.field_position,
        direction: direction_name(field.direction),
        length: length_name(&field.length),
        target: target_name(&field.target),
        matching: matching_name(field.matching),
        cda: cda_name(field.action),
    }
}

fn field_name(field: &FieldRef) -> String {
    match field {
        FieldRef::Ipv6(name)
        | FieldRef::Udp(name)
        | FieldRef::Coap(name)
        | FieldRef::Icmpv6(name) => (*name).to_owned(),
        FieldRef::CoapOption { number } => format!("coap-option({number})"),
        FieldRef::Unused => "fid-unused".into(),
        FieldRef::Payload => "fid-payload".into(),
        FieldRef::SyntheticCoapMarker => "fid-coap-payload-marker".into(),
        FieldRef::UnknownSid(sid) => format!("sid:{sid}"),
    }
}

fn direction_name(direction: DirectionSelector) -> String {
    match direction {
        DirectionSelector::Bidirectional => "bi",
        DirectionSelector::Up => "up",
        DirectionSelector::Down => "down",
    }
    .into()
}

fn length_name(length: &FieldLength) -> String {
    match length {
        FieldLength::FixedBits(bits) => bits.to_string(),
        FieldLength::VariableBytes => "variable-bytes".into(),
        FieldLength::VariableBits => "variable-bits".into(),
        FieldLength::TokenLength => "token-length".into(),
        FieldLength::FromPreviousField { entry_index, unit } => format!(
            "from-entry-{entry_index}/{}",
            match unit {
                schc_core::rule::LengthUnit::Bytes => "bytes",
                schc_core::rule::LengthUnit::Bits => "bits",
            }
        ),
        FieldLength::FunctionSid(sid) => format!("sid:{sid}"),
    }
}

fn target_name(target: &TargetValue) -> String {
    match target {
        TargetValue::None => "-".into(),
        TargetValue::Bytes(bytes) => hex_bytes(bytes),
        TargetValue::Mapping(values) => {
            let values = values
                .iter()
                .map(|value| hex_bytes(value))
                .collect::<Vec<_>>();
            format!("[{}]", values.join(","))
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::from("0x");
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn matching_name(matching: MatchingOperator) -> String {
    match matching {
        MatchingOperator::Equal => "equal".into(),
        MatchingOperator::Ignore => "ignore".into(),
        MatchingOperator::Msb(bits) => format!("msb({bits})"),
        MatchingOperator::MatchMapping => "match-mapping".into(),
    }
}

fn cda_name(cda: Cda) -> String {
    match cda {
        Cda::NotSent => "not-sent",
        Cda::ValueSent => "value-sent",
        Cda::MappingSent => "mapping-sent",
        Cda::Lsb => "lsb",
        Cda::Compute => "compute",
        Cda::DeviceIid => "deviid",
        Cda::AppIid => "appiid",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_parser_is_strict() {
        assert_eq!(
            parse_rule_selector("20/8").unwrap(),
            RuleSelector::new(20, 8).unwrap()
        );
        assert!(parse_rule_selector("20").is_err());
        assert!(parse_rule_selector("20/0").is_err());
        assert!(parse_rule_selector("256/8").is_err());
        assert!(parse_rule_selector("20/8/1").is_err());
    }

    #[test]
    fn unknown_numeric_field_sid_has_readable_fallback() {
        assert_eq!(field_name(&FieldRef::UnknownSid(99999)), "sid:99999");
        assert_eq!(
            field_name(&FieldRef::CoapOption { number: 11 }),
            "coap-option(11)"
        );
    }
}
