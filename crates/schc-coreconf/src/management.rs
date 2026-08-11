//! Protected SCHC context inspection and targeted management updates.
//!
//! The wire service uses ordinary CORECONF FETCH payloads for rule inspection
//! and one strict root iPATCH shape for detached, validated target updates.
//! Context checks use a compact marker and eight-byte tag because the fixed
//! management rules do not describe an `ETag` option.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;
use std::sync::Arc;

use ciborium::value::Value as CborValue;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType, ResponseType};
use coreconf_model::instance_id::{
    decode_instances_with_model, decode_instances_with_model_to_identifier_at_path,
    encode_identifiers, Instance, InstancePath, PathComponent,
};
use coreconf_model::{CompositeModel, CoreconfModel};
use coreconf_runtime::coap_types::{ContentFormat, Interface, Method, Request};
use coreconf_runtime::request_handler::RequestHandler;
use coreconf_runtime::transport::coap_lite::{packet_to_request, response_to_packet};
use coreconf_runtime::PredicatePath;
use coreconf_runtime::{Datastore, ResponseCode};
use schc_core::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Rule, RuleContext, RuleId,
    RuleNature, SidRegistry, TargetValue,
};
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    ActiveContext, ContextSnapshot, ContextTag, Ipv6UdpCoapPacket, LinkError, LinkReport,
    PreparedContext, RawUdpLink, SchcLink, TrafficOrigin, TrafficRoute, CORE_LOGICAL_ADDRESS,
    DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

/// Marker used as the first byte of the compact context-check FETCH payload.
pub const CONTEXT_CHECK_MARKER: u8 = 0xC6;
const CONTEXT_CHECK_EQUAL: u8 = 0;
const CONTEXT_CHECK_MISMATCH: u8 = 1;
const SCHC_ROOT_SID: i64 = 2574;
const RULE_LIST_SID: i64 = 2597;
const RULE_ID_LENGTH_SID: i64 = 2598;
const RULE_ID_VALUE_SID: i64 = 2599;
const RULE_ENTRY_LIST_SID: i64 = 2620;
const RULE_ENTRY_INDEX_SID: i64 = 2621;
const FIELD_LENGTH_SID: i64 = 2625;
const TARGET_VALUE_LIST_SID: i64 = 2629;
const TARGET_VALUE_INDEX_SID: i64 = 2630;
const TARGET_VALUE_VALUE_SID: i64 = 2631;
const MATCHING_OPERATOR_SID: i64 = 2632;
const CDA_SID: i64 = 2636;
const DUPLICATE_RULE_SID: i64 = 2680;
const DUPLICATE_INPUT_SID: i64 = 2681;
const DUPLICATE_FROM_SID: i64 = 2682;
const DUPLICATE_FROM_LENGTH_SID: i64 = 2683;
const DUPLICATE_FROM_VALUE_SID: i64 = 2684;
const DUPLICATE_IPATCH_SID: i64 = 2685;
const DUPLICATE_TO_SID: i64 = 2686;
const DUPLICATE_TO_LENGTH_SID: i64 = 2687;
const DUPLICATE_TO_VALUE_SID: i64 = 2688;

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
    /// A targeted rule-update command was malformed.
    #[error("invalid rule update command: {0}")]
    InvalidUpdate(String),
    /// No entry matched a targeted update selector.
    #[error("RuleID {rule} has no entry matching {selector}")]
    MissingEntry {
        /// Exact `RuleID` of the rule searched.
        rule: RuleSelector,
        /// Human-readable selector description.
        selector: String,
    },
    /// More than one entry matched a targeted update selector.
    #[error(
        "RuleID {rule} selector {selector} was ambiguous; matching entries:\n{readable_matches}"
    )]
    AmbiguousEntry {
        /// Exact `RuleID` of the rule searched.
        rule: RuleSelector,
        /// Human-readable selector description.
        selector: String,
        /// Complete entries that matched, in canonical order.
        matches: Vec<RuleEntry>,
        /// Stable formatted representation of the matching entries.
        readable_matches: String,
    },
    /// A target-value update could not be converted to the selected shape.
    #[error("invalid targeted rule update: {0}")]
    InvalidTarget(String),
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

impl fmt::Display for RuleSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.value, self.bits)
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

/// Parses a complete targeted rule-update command.
///
/// The accepted syntax is `rule update <value>/<bits>` followed by exactly
/// one selector (`entry=<index>` or `fid=<name>` with optional `fp=<position>`
/// and `di=<direction>`), exactly one `tv=<value>`, and optional
/// `--if-match`. Arguments are single whitespace-delimited tokens; target
/// value type conversion is deliberately deferred to the update layer.
///
/// # Errors
///
/// Returns an error for a malformed `RuleID`, missing or duplicate arguments,
/// unknown keys, malformed numeric or direction values, or mixed exact and
/// human selector forms.
#[allow(clippy::too_many_lines)]
pub fn parse_rule_update_command(input: &str) -> Result<RuleUpdateRequest, InspectionError> {
    let mut words = input.split_whitespace();
    if words.next() != Some("rule") || words.next() != Some("update") {
        return Err(invalid_update("expected 'rule update <value>/<bits> ...'"));
    }
    let rule_token = words
        .next()
        .ok_or_else(|| invalid_update("missing RuleID; expected <value>/<bits>"))?;
    let rule = parse_rule_selector(rule_token)
        .map_err(|error| invalid_update(format!("invalid RuleID: {error}")))?;

    let mut entry_index = None;
    let mut fid = None;
    let mut field_position = None;
    let mut direction = None;
    let mut target_value = None;
    let mut if_match = false;

    for argument in words {
        if argument == "--if-match" {
            if if_match {
                return Err(invalid_update("duplicate '--if-match' flag"));
            }
            if_match = true;
            continue;
        }
        let Some((key, value)) = argument.split_once('=') else {
            return Err(invalid_update(format!(
                "malformed argument '{argument}'; expected key=value"
            )));
        };
        if key.is_empty() || value.is_empty() || value.contains('=') {
            return Err(invalid_update(format!(
                "malformed argument '{argument}'; expected one non-empty key and value"
            )));
        }
        match key {
            "entry" => {
                if entry_index.is_some() {
                    return Err(invalid_update("duplicate 'entry' argument"));
                }
                entry_index = Some(parse_unsigned_argument(value, "entry")?);
            }
            "fid" => {
                if fid.is_some() {
                    return Err(invalid_update("duplicate 'fid' argument"));
                }
                if !valid_fid_token(value) {
                    return Err(invalid_update(
                        "fid must be a readable non-empty field name",
                    ));
                }
                fid = Some(value.to_owned());
            }
            "fp" => {
                if field_position.is_some() {
                    return Err(invalid_update("duplicate 'fp' argument"));
                }
                let position = parse_unsigned_argument(value, "fp")?;
                if position == 0 {
                    return Err(invalid_update("fp must be a one-based field position"));
                }
                field_position = Some(position);
            }
            "di" => {
                if direction.is_some() {
                    return Err(invalid_update("duplicate 'di' argument"));
                }
                if !matches!(value, "bi" | "up" | "down") {
                    return Err(invalid_update("di must be one of 'bi', 'up', or 'down'"));
                }
                direction = Some(value.to_owned());
            }
            "tv" => {
                if target_value.is_some() {
                    return Err(invalid_update("duplicate 'tv' argument"));
                }
                if value.chars().any(char::is_control) {
                    return Err(invalid_update("tv must not contain control characters"));
                }
                target_value = Some(value.to_owned());
            }
            _ => return Err(invalid_update(format!("unknown update argument '{key}'"))),
        }
    }

    let target_value =
        target_value.ok_or_else(|| invalid_update("exactly one 'tv' is required"))?;
    let entry = match (entry_index, fid) {
        (Some(entry_index), None) => {
            if field_position.is_some() || direction.is_some() {
                return Err(invalid_update(
                    "exact 'entry' cannot be combined with 'fp' or 'di'",
                ));
            }
            RuleEntrySelector::Entry { entry_index }
        }
        (None, Some(fid)) => RuleEntrySelector::Field {
            fid,
            field_position,
            direction,
        },
        (Some(_), Some(_)) => {
            return Err(invalid_update("entry and fid selectors cannot be combined"));
        }
        (None, None) => {
            if field_position.is_some() || direction.is_some() {
                return Err(invalid_update("fp and di require a fid selector"));
            }
            return Err(invalid_update(
                "exactly one of 'entry' or 'fid' is required",
            ));
        }
    };

    Ok(RuleUpdateRequest {
        rule,
        entry,
        target_value,
        if_match,
    })
}

fn invalid_update(message: impl Into<String>) -> InspectionError {
    InspectionError::InvalidUpdate(message.into())
}

/// One entry-index-based override in a duplicate-rule request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleDuplicateOverride {
    /// Stable zero-based source entry index.
    pub entry_index: usize,
    /// Optional decimal target value replacement.
    pub target_value: Option<String>,
    /// Optional matching-operator identity.
    pub matching_operator: Option<String>,
    /// Optional compression/decompression action identity.
    pub cda: Option<String>,
}

/// A parsed atomic duplicate-rule request.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleDuplicateRequest {
    /// Existing ordinary source rule.
    pub source: RuleSelector,
    /// New destination rule.
    pub destination: RuleSelector,
    /// Zero or more entry-index overrides.
    pub overrides: Vec<RuleDuplicateOverride>,
}

/// One decoded override shown by a duplicate-rule packet report.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DuplicateRpcOverride {
    /// Stable source entry index.
    pub entry_index: usize,
    /// Decoded target value, when the override carries one.
    pub target_value: Option<String>,
    /// Decoded matching-operator identity, when present.
    pub matching_operator: Option<String>,
    /// Decoded CDA identity, when present.
    pub cda: Option<String>,
}

/// Read-only exact byte accounting for a modeled duplicate-rule RPC.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DuplicateRpcCost {
    /// Source selector.
    pub source: RuleSelector,
    /// Destination selector.
    pub destination: RuleSelector,
    /// Complete RPC payload bytes.
    pub payload_bytes: usize,
    /// Fixed selector and operation bytes with no overrides.
    pub fixed_bytes: usize,
    /// Override framing and identity bytes, excluding target contents.
    pub variable_framing_bytes: usize,
    /// Raw target-value contents, excluding CBOR byte-string headers.
    pub target_value_bytes: usize,
    /// Decoded override groups.
    pub overrides: Vec<DuplicateRpcOverride>,
}

/// Result of processing a duplicate-rule operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DuplicateRuleResult {
    /// A new destination was validated and published.
    Applied {
        /// New active-context generation.
        generation: u64,
        /// New active-context tag.
        tag: ContextTag,
    },
    /// The requested deterministic destination was already installed.
    Idempotent {
        /// Existing active-context generation.
        generation: u64,
        /// Existing active-context tag.
        tag: ContextTag,
    },
}

/// Parses the compact duplicate-rule console syntax.
///
/// The syntax is `rule duplicate <source>/<bits> <destination>/<bits>` followed
/// by zero or more groups of `entry=INDEX`, `tv=VALUE`, `mo=ID`, and `cda=ID`.
/// Each `entry=INDEX` starts one group, each group must contain at least one
/// leaf, and each leaf occurs at most once per group.
/// Target replacements accept unsigned decimal values only when replacing an
/// existing fixed-width binary target.
/// `mo=` and `cda=` accept only the currently supported identity names.
///
/// # Errors
///
/// Returns an error for malformed selectors, incomplete groups, duplicate
/// leaves, or unsupported arguments.
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn parse_rule_duplicate_command(input: &str) -> Result<RuleDuplicateRequest, InspectionError> {
    let mut words = input.split_whitespace();
    if words.next() != Some("rule") || words.next() != Some("duplicate") {
        return Err(InspectionError::InvalidUpdate(
            "expected 'rule duplicate <source>/<bits> <destination>/<bits> ...'".into(),
        ));
    }
    let source = words
        .next()
        .ok_or_else(|| invalid_update("missing duplicate source RuleID"))
        .and_then(parse_rule_selector)
        .map_err(|error| invalid_update(format!("invalid source RuleID: {error}")))?;
    let destination = words
        .next()
        .ok_or_else(|| invalid_update("missing duplicate destination RuleID"))
        .and_then(parse_rule_selector)
        .map_err(|error| invalid_update(format!("invalid destination RuleID: {error}")))?;

    let mut overrides = Vec::new();
    let mut current: Option<RuleDuplicateOverride> = None;
    for argument in words {
        let (kind, value) = argument.split_once('=').ok_or_else(|| {
            invalid_update(format!(
                "malformed duplicate argument '{argument}'; expected key=value"
            ))
        })?;
        if value.is_empty() {
            return Err(invalid_update(format!(
                "duplicate argument '{kind}' has an empty value"
            )));
        }
        match kind {
            "entry" => {
                if let Some(previous) = current.take() {
                    if previous.target_value.is_none()
                        && previous.matching_operator.is_none()
                        && previous.cda.is_none()
                    {
                        return Err(invalid_update(format!(
                            "entry {} has no override leaves",
                            previous.entry_index
                        )));
                    }
                    overrides.push(previous);
                }
                let entry_index = parse_unsigned_argument(value, "entry")?;
                if overrides
                    .iter()
                    .any(|candidate| candidate.entry_index == entry_index)
                {
                    return Err(invalid_update(format!(
                        "duplicate override entry={entry_index}"
                    )));
                }
                current = Some(RuleDuplicateOverride {
                    entry_index,
                    target_value: None,
                    matching_operator: None,
                    cda: None,
                });
            }
            "tv" | "mo" | "cda" => {
                let current_override = current.as_mut().ok_or_else(|| {
                    invalid_update(format!("'{kind}' must follow an entry=INDEX"))
                })?;
                match kind {
                    "tv" if current_override
                        .target_value
                        .replace(value.to_owned())
                        .is_some() =>
                    {
                        return Err(invalid_update("duplicate tv in one override"));
                    }
                    "mo" if current_override
                        .matching_operator
                        .replace(value.to_owned())
                        .is_some() =>
                    {
                        return Err(invalid_update("duplicate mo in one override"));
                    }
                    "cda" if current_override.cda.replace(value.to_owned()).is_some() => {
                        return Err(invalid_update("duplicate cda in one override"));
                    }
                    _ => {}
                }
            }
            _ => {
                return Err(invalid_update(format!(
                    "unknown duplicate argument '{kind}'"
                )))
            }
        }
    }
    if let Some(previous) = current {
        if previous.target_value.is_none()
            && previous.matching_operator.is_none()
            && previous.cda.is_none()
        {
            return Err(invalid_update(format!(
                "entry {} has no override leaves",
                previous.entry_index
            )));
        }
        overrides.push(previous);
    }
    Ok(RuleDuplicateRequest {
        source,
        destination,
        overrides,
    })
}

fn parse_unsigned_argument(value: &str, key: &str) -> Result<usize, InspectionError> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_update(format!(
            "{key} must be an unsigned decimal number"
        )));
    }
    value.parse::<usize>().map_err(|_| {
        invalid_update(format!(
            "{key} is out of range for a canonical entry position"
        ))
    })
}

fn valid_fid_token(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
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

/// A selector for one entry in a complete rule.
///
/// `Entry` addresses the canonical zero-based entry index directly. `Field`
/// addresses the readable FID and optionally narrows repeated FIDs by field
/// position and direction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RuleEntrySelector {
    /// Selects exactly one canonical zero-based entry index.
    Entry {
        /// Canonical zero-based entry index.
        entry_index: usize,
    },
    /// Selects an entry by readable FID and optional discriminators.
    Field {
        /// Readable field identifier as entered by the operator.
        fid: String,
        /// Optional one-based field position.
        field_position: Option<usize>,
        /// Optional stable direction identifier (`bi`, `up`, or `down`).
        direction: Option<String>,
    },
}

impl RuleEntrySelector {
    /// Constructs an exact canonical entry selector.
    #[must_use]
    pub const fn entry(entry_index: usize) -> Self {
        Self::Entry { entry_index }
    }

    /// Constructs a human FID selector.
    #[must_use]
    pub fn field(
        fid: impl Into<String>,
        field_position: Option<usize>,
        direction: Option<String>,
    ) -> Self {
        Self::Field {
            fid: fid.into(),
            field_position,
            direction,
        }
    }

    /// Returns a stable readable representation suitable for errors and logs.
    #[must_use]
    pub fn description(&self) -> String {
        use std::fmt::Write as _;

        match self {
            Self::Entry { entry_index } => format!("entry={entry_index}"),
            Self::Field {
                fid,
                field_position,
                direction,
            } => {
                let mut result = format!("fid={fid}");
                if let Some(position) = field_position {
                    let _ = write!(result, " fp={position}");
                }
                if let Some(direction) = direction {
                    let _ = write!(result, " di={direction}");
                }
                result
            }
        }
    }
}

/// A parsed, not-yet-applied targeted rule update command.
///
/// This type intentionally stores the target value in its command spelling.
/// Its field-specific conversion and validation belong to the later iPATCH
/// and candidate-publication layer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleUpdateRequest {
    /// Exact `RuleID` containing both numeric value and encoded bit length.
    pub rule: RuleSelector,
    /// Exact or human entry selector.
    pub entry: RuleEntrySelector,
    /// The one target-value change requested by `tv=`.
    pub target_value: String,
    /// Whether the later exchange must use the current context tag as a
    /// precondition.
    pub if_match: bool,
}

impl RuleUpdateRequest {
    /// Resolves this request against one complete inspected rule.
    ///
    /// The returned value is the canonical zero-based entry index. No update,
    /// value conversion, transport, or context mutation is performed.
    ///
    /// # Errors
    ///
    /// Returns an error when the detail has a different `RuleID`, no entry
    /// matches, or the human selector matches more than one entry.
    pub fn resolve_entry_index(&self, detail: &RuleDetail) -> Result<usize, InspectionError> {
        if detail.id != self.rule {
            return Err(InspectionError::InvalidUpdate(format!(
                "rule detail is {}/{} but update targets {}/{}",
                detail.id.value, detail.id.bits, self.rule.value, self.rule.bits
            )));
        }
        detail.resolve_entry_index(&self.entry)
    }

    /// Resolves and converts this request into one SID-based update.
    ///
    /// The returned value and path are ready for a root CORECONF iPATCH
    /// request. The operation remains detached and does not mutate `tree` or
    /// any active context.
    ///
    /// # Errors
    ///
    /// Returns an error when entry resolution, model shape, or target-value
    /// conversion fails.
    pub fn resolve_target_value(
        &self,
        detail: &RuleDetail,
        tree: &Value,
        model: &CoreconfModel,
    ) -> Result<ResolvedRuleUpdate, InspectionError> {
        let entry_index = self.resolve_entry_index(detail)?;
        ResolvedRuleUpdate::from_request(self, entry_index, tree, model)
    }
}

/// One resolved target-value update in generic CORECONF instance form.
///
/// `value` is the SID-level wire value, not the identifier-level tree value.
/// For the SCHC binary target-value leaf this is a CBOR/JSON array of byte
/// numbers. `path` contains every list key required by the pinned SCHC SID
/// model: `RuleID` value, `RuleID` bit length, entry index, and target-value
/// index.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedRuleUpdate {
    /// Original parsed request, including the optional If-Match flag.
    pub request: RuleUpdateRequest,
    /// Canonical zero-based entry index selected by the request.
    pub entry_index: usize,
    /// Existing target-value list index selected from the complete tree.
    pub target_value_index: usize,
    /// Exact SID-based CORECONF instance path to `target-value/value`.
    pub path: InstancePath,
    /// Exactly one replacement value in SID-level wire representation.
    pub value: Value,
}

impl ResolvedRuleUpdate {
    /// Builds one resolved update from an already resolved entry index.
    ///
    /// This constructor performs no mutation. It validates the complete tree,
    /// requires one existing target-value list member, and converts the
    /// operator's decimal `tv=` spelling to the existing binary width without
    /// truncation.
    ///
    /// # Errors
    ///
    /// Returns an error when the pinned model shape is unavailable, the rule
    /// or entry is absent or duplicated, the target list is not one member,
    /// or the target value is not a valid unsigned value for its shape.
    #[allow(clippy::too_many_lines)]
    pub fn from_request(
        request: &RuleUpdateRequest,
        entry_index: usize,
        tree: &Value,
        model: &CoreconfModel,
    ) -> Result<Self, InspectionError> {
        let composite = model.composite_model();
        validate_update_model_shape(composite)?;
        let root_key = tree_key_for_sid(composite, SCHC_ROOT_SID)?;
        let rule_key = tree_key_for_sid(composite, RULE_LIST_SID)?;
        let entry_key = tree_key_for_sid(composite, RULE_ENTRY_LIST_SID)?;
        let target_value_key = tree_key_for_sid(composite, TARGET_VALUE_LIST_SID)?;
        let rule_value_key = tree_key_for_sid(composite, RULE_ID_VALUE_SID)?;
        let rule_length_key = tree_key_for_sid(composite, RULE_ID_LENGTH_SID)?;
        let entry_index_key = tree_key_for_sid(composite, RULE_ENTRY_INDEX_SID)?;
        let target_index_key = tree_key_for_sid(composite, TARGET_VALUE_INDEX_SID)?;
        let target_value_leaf_key = tree_key_for_sid(composite, TARGET_VALUE_VALUE_SID)?;

        let root = tree
            .get(&root_key)
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_target("complete tree is missing the SCHC root"))?;
        let rules = root
            .get(&rule_key)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_target("complete tree is missing the rule list"))?;
        let matching_rules = rules
            .iter()
            .filter(|rule| {
                rule.get(&rule_value_key).and_then(Value::as_u64) == Some(request.rule.value)
                    && rule.get(&rule_length_key).and_then(Value::as_u64)
                        == Some(request.rule.bits as u64)
            })
            .collect::<Vec<_>>();
        let rule = match matching_rules.as_slice() {
            [] => {
                return Err(InspectionError::MissingRule {
                    value: request.rule.value,
                    bits: request.rule.bits,
                });
            }
            [rule] => *rule,
            _ => {
                return Err(InspectionError::AmbiguousRule {
                    value: request.rule.value,
                    bits: request.rule.bits,
                    matches: matching_rules.len(),
                });
            }
        };
        let entries = rule
            .get(&entry_key)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_target("selected rule is missing the entry list"))?;
        let matching_entries = entries
            .iter()
            .filter(|entry| {
                entry.get(&entry_index_key).and_then(Value::as_u64) == Some(entry_index as u64)
            })
            .collect::<Vec<_>>();
        let entry = match matching_entries.as_slice() {
            [] => {
                return Err(InspectionError::MissingEntry {
                    rule: request.rule,
                    selector: format!("entry={entry_index}"),
                });
            }
            [entry] => *entry,
            _ => {
                return Err(InspectionError::InvalidTarget(format!(
                    "entry {entry_index} occurs more than once in RuleID {}",
                    request.rule
                )));
            }
        };
        let target_values = entry
            .get(&target_value_key)
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_target(format!(
                    "entry {entry_index} is missing its target-value list"
                ))
            })?;
        if target_values.len() != 1 {
            return Err(invalid_target(format!(
                "entry {entry_index} target-value list has {} members; exactly one is required",
                target_values.len()
            )));
        }
        let target_member = &target_values[0];
        let target_value_index = target_member
            .get(&target_index_key)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| invalid_target("target-value member has no numeric index"))?;
        let current_identifier_value = target_member
            .get(&target_value_leaf_key)
            .ok_or_else(|| invalid_target("target-value member has no value"))?;
        let current_wire_value = composite
            .identifier_value_to_sid_value_at_path(
                current_identifier_value.clone(),
                composite
                    .get_identifier(TARGET_VALUE_VALUE_SID)
                    .ok_or_else(|| invalid_target("target-value/value SID is unavailable"))?,
            )
            .map_err(|error| invalid_target(format!("current target value is invalid: {error}")))?;
        let current_bytes = binary_bytes(&current_wire_value)?;
        let field_length = entry
            .get(&tree_key_for_sid(composite, FIELD_LENGTH_SID)?)
            .ok_or_else(|| invalid_target("selected entry has no field-length"))?;
        let replacement =
            numeric_target_value(&request.target_value, &current_bytes, field_length)?;
        let value_path = composite
            .get_identifier(TARGET_VALUE_VALUE_SID)
            .ok_or_else(|| invalid_target("target-value/value SID is unavailable"))?;
        composite
            .sid_value_to_identifier_value_at_path(replacement.clone(), value_path)
            .map_err(|error| {
                invalid_target(format!("replacement target value is invalid: {error}"))
            })?;

        let path = target_value_path(request.rule, entry_index, target_value_index)?;
        Ok(Self {
            request: request.clone(),
            entry_index,
            target_value_index,
            path,
            value: replacement,
        })
    }

    /// Returns the one CORECONF instance operation represented by this update.
    #[must_use]
    pub fn instance(&self) -> Instance {
        Instance::new(self.path.clone(), self.value.clone())
    }

    /// Encodes exactly one root iPATCH instance operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the generic CORECONF instance encoder rejects the
    /// path or value.
    pub fn ipatch_payload(&self) -> Result<Vec<u8>, InspectionError> {
        let path = serde_value_to_cbor(&self.path.to_cbor_value())?;
        let value = CborValue::Bytes(binary_bytes(&self.value)?);
        let instance = CborValue::Map(vec![(path, value)]);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&instance, &mut payload)
            .map_err(|error| invalid_target(format!("iPATCH instance encoding failed: {error}")))?;
        Ok(payload)
    }

    /// Constructs the generic root iPATCH request for this update.
    ///
    /// The request uses `YangInstancesCborSeq` (wire value 142) and an empty
    /// root path, as required by the runtime's instance-sequence iPATCH handler.
    ///
    /// This request abstraction cannot carry CoAP options. Updates parsed
    /// with `--if-match` must use [`Self::ipatch_datagram`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance payload cannot be encoded or this
    /// update requires an If-Match option.
    pub fn ipatch_request(&self) -> Result<Request, InspectionError> {
        if self.request.if_match {
            return Err(invalid_target(
                "--if-match requires the CoAP ipatch_datagram builder",
            ));
        }
        Ok(Request::new(Method::IPatch)
            .with_payload(self.ipatch_payload()?, ContentFormat::YangInstancesCborSeq)
            .with_interface(Interface::Management))
    }

    /// Builds a complete CoAP datagram for this root iPATCH update.
    ///
    /// The datagram targets `/schc`, uses the management iPATCH method, and
    /// carries the exact payload from [`Self::ipatch_payload`]. If the parsed
    /// command included `--if-match`, `base_tag` is required and is encoded
    /// as exactly one If-Match option containing its eight raw tag bytes. A
    /// tag supplied for a default update is rejected rather than ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the precondition argument is inconsistent, the
    /// payload is invalid, or the CoAP datagram cannot be serialized.
    pub fn ipatch_datagram(
        &self,
        message_id: u16,
        token: &[u8],
        base_tag: Option<ContextTag>,
    ) -> Result<Vec<u8>, InspectionError> {
        match (self.request.if_match, base_tag) {
            (true, None) => {
                return Err(invalid_target("--if-match requires a base context tag"));
            }
            (false, Some(_)) => {
                return Err(invalid_target("a base context tag requires --if-match"));
            }
            (true, Some(_)) | (false, None) => {}
        }
        let mut packet = Packet::new();
        packet.header.message_id = message_id;
        packet.header.code = MessageClass::Request(RequestType::IPatch);
        packet.header.set_type(MessageType::Confirmable);
        // Protected management uses a zero-length token; the endpoint and
        // bounded CoAP MID provide the correlation key.
        let _ = token;
        packet.set_token(Vec::new());
        packet.add_option(CoapOption::UriPath, b"schc".to_vec());
        packet.add_option(CoapOption::ContentFormat, vec![142]);
        packet.payload = self.ipatch_payload()?;
        if let Some(tag) = base_tag {
            packet.add_option(CoapOption::IfMatch, tag.bytes().to_vec());
        }
        packet
            .to_bytes()
            .map_err(|error| InspectionError::Coap(error.to_string()))
    }
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

impl RuleDetail {
    /// Resolves an exact or human selector to one canonical entry index.
    ///
    /// FID comparisons use the same readable identity across the fixture
    /// spelling (`ipv6.app-iid`) and the r-schc spelling
    /// (`fid-ipv6-appiid`): case and punctuation are ignored, as is the
    /// optional `fid-` prefix. Missing field-position or direction
    /// discriminators are accepted only when the remaining selector is
    /// unique.
    ///
    /// # Errors
    ///
    /// Returns an error when no entry matches or when more than one entry
    /// matches. Ambiguous errors contain complete readable matching entries
    /// in canonical entry order.
    pub fn resolve_entry_index(
        &self,
        selector: &RuleEntrySelector,
    ) -> Result<usize, InspectionError> {
        let mut matches = self
            .entries
            .iter()
            .filter(|entry| entry_matches_selector(entry, selector))
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|entry| entry.entry_index);
        match matches.as_slice() {
            [] => Err(InspectionError::MissingEntry {
                rule: self.id,
                selector: selector.description(),
            }),
            [entry] => Ok(entry.entry_index),
            _ => {
                let readable_matches = matches
                    .iter()
                    .map(format_rule_entry)
                    .collect::<Vec<_>>()
                    .join("\n");
                Err(InspectionError::AmbiguousEntry {
                    rule: self.id,
                    selector: selector.description(),
                    matches,
                    readable_matches,
                })
            }
        }
    }
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

/// Bit-level accounting for one protected management SCHC report.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ManagementBitBreakdown {
    /// Bits used by the selected `RuleID`.
    pub rule_id_bits: usize,
    /// Bits used by the CoAP response-code mapping, when present.
    pub method_or_response_mapping_bits: usize,
    /// CoAP MID residue bits.
    pub mid_residue_bits: usize,
    /// Exact CORECONF CoAP payload bits, excluding its SCHC length prefix.
    pub payload_bits: usize,
    /// Bits used by the variable payload length prefix.
    pub payload_length_bits: usize,
    /// Bits used by dynamic management option values such as If-Match.
    pub option_residue_bits: usize,
    /// Zero padding bits in the sent frame's final byte.
    pub byte_padding_bits: usize,
    /// Residue bits not accounted for by the fields above; must be zero.
    pub unaccounted_residue_bits: usize,
}

impl ManagementBitBreakdown {
    /// Returns the protected management transport overhead.
    ///
    /// This is the exact `RuleID`, method/response mapping, and MID residue.
    /// The CORECONF payload, its variable-length prefix, dynamic options, and
    /// final byte padding are reported separately and are excluded.
    #[must_use]
    pub const fn transport_residue_bits(self) -> usize {
        self.rule_id_bits + self.method_or_response_mapping_bits + self.mid_residue_bits
    }
}

/// Computes and validates the bit accounting for one protected management report.
///
/// Fixed IPv6, UDP, CoAP, URI, and content-format fields are reconstructed by
/// the selected rule and therefore do not appear as residue. The selected rule
/// structure is retained in the report so this accounting cannot claim a
/// mapping or MID shape that differs from the loaded rule.
///
/// # Errors
///
/// Returns an error when the report is not protected management traffic, its
/// packet is invalid, its MID is outside the compressed range, its rule
/// structure is unavailable, or its bit accounting is inconsistent.
pub fn management_bit_breakdown(
    report: &LinkReport,
) -> Result<ManagementBitBreakdown, InspectionError> {
    if report.traffic_class != crate::TrafficClass::ProtectedManagement {
        return Err(InspectionError::UnexpectedResponse(
            "bit breakdown requires a protected management report".into(),
        ));
    }
    let packet = Ipv6UdpCoapPacket::parse(&report.packet_bytes)
        .map_err(|error| InspectionError::Coap(error.to_string()))?;
    let message = packet.coap_message();
    if message.message_id() >= 128 {
        return Err(InspectionError::UnexpectedResponse(
            "management MID is outside the 7-bit compressed range".into(),
        ));
    }
    let rule = report.management_rule.as_ref().ok_or_else(|| {
        InspectionError::UnexpectedResponse(
            "management report has no selected rule structure".into(),
        )
    })?;
    let mut method_or_response_mapping_bits = 0;
    let mut mid_residue_bits = 0;
    let mut payload_length_bits = 0;
    let mut option_residue_bits = 0;
    for field in rule.fields() {
        match &field.field {
            FieldRef::Coap("fid-coap-code") if field.action == Cda::MappingSent => {
                let TargetValue::Mapping(values) = &field.target else {
                    return Err(InspectionError::UnexpectedResponse(
                        "management code mapping has no mapping target".into(),
                    ));
                };
                method_or_response_mapping_bits = mapping_index_bits(values.len());
            }
            FieldRef::Coap("fid-coap-mid") => {
                let FieldLength::FixedBits(field_bits) = &field.length else {
                    return Err(InspectionError::UnexpectedResponse(
                        "management MID rule entry is not fixed-width".into(),
                    ));
                };
                mid_residue_bits = match (field.matching, field.action) {
                    (MatchingOperator::Msb(msb_bits), Cda::Lsb) => {
                        (*field_bits).checked_sub(msb_bits).ok_or_else(|| {
                            InspectionError::UnexpectedResponse(
                                "management MID MSB exceeds its field width".into(),
                            )
                        })?
                    }
                    (_, Cda::ValueSent) => *field_bits,
                    _ => 0,
                };
            }
            FieldRef::Payload if field.action == Cda::ValueSent => {
                payload_length_bits = variable_length_prefix_bits(message.payload().len());
            }
            FieldRef::CoapOption { number } if field.action == Cda::ValueSent => {
                option_residue_bits += message
                    .options()
                    .iter()
                    .filter(|option| u64::from(option.number()) == *number)
                    .map(|option| option.value().len() * 8)
                    .sum::<usize>();
            }
            _ => {}
        }
    }
    let payload_bits = message.payload().len() * 8;
    let rule_id_bits = report.rule_id.bit_len();
    let meaningful_bits = report.schc_bit_len.ok_or_else(|| {
        InspectionError::UnexpectedResponse("management report has no meaningful bit length".into())
    })?;
    let accounted_bits = rule_id_bits
        + method_or_response_mapping_bits
        + mid_residue_bits
        + payload_bits
        + payload_length_bits
        + option_residue_bits;
    if meaningful_bits != accounted_bits {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management report has {meaningful_bits} meaningful bits but accounted fields total {accounted_bits}"
        )));
    }
    let byte_padding_bits = report
        .padded_byte_len
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(meaningful_bits))
        .ok_or_else(|| {
            InspectionError::UnexpectedResponse("management report padding is invalid".into())
        })?;
    Ok(ManagementBitBreakdown {
        rule_id_bits,
        method_or_response_mapping_bits,
        mid_residue_bits,
        payload_bits,
        payload_length_bits,
        option_residue_bits,
        byte_padding_bits,
        unaccounted_residue_bits: meaningful_bits - accounted_bits,
    })
}

fn mapping_index_bits(mapping_len: usize) -> usize {
    if mapping_len <= 1 {
        return 0;
    }
    (usize::BITS - (mapping_len - 1).leading_zeros()) as usize
}

fn variable_length_prefix_bits(value: usize) -> usize {
    if value <= 14 {
        4
    } else if value <= 254 {
        12
    } else {
        28
    }
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

/// CORECONF management service rooted at `/schc`.
///
/// GET and FETCH provide inspection. The only accepted mutation is one root
/// iPATCH containing exactly one complete target-value replacement, which is
/// validated and published atomically after detached candidate construction.
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
        let datastore = Datastore::with_backend(model.composite_model().clone(), active.backend())
            .map_err(|error| InspectionError::Datastore(error.to_string()))?;
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
        self.detail_from_snapshot(&snapshot, selector)
    }

    /// Returns one complete rule from the supplied immutable active snapshot.
    ///
    /// This avoids resolving a selector against one snapshot and constructing
    /// its update against another when a caller is preparing a mutation.
    ///
    /// # Errors
    ///
    /// Returns an error when no rule matches or when the selector is
    /// ambiguous.
    pub fn detail_from_snapshot(
        &self,
        snapshot: &ContextSnapshot,
        selector: RuleSelector,
    ) -> Result<RuleDetail, InspectionError> {
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

    /// Resolves a parsed update request against the current local rule.
    ///
    /// This is an inspection-only operation. It does not convert a target
    /// value, construct an iPATCH, contact a device, or mutate the context.
    ///
    /// # Errors
    ///
    /// Returns the same `RuleID` or entry-selection errors as [`Self::detail`]
    /// and [`RuleUpdateRequest::resolve_entry_index`].
    pub fn resolve_update_entry(
        &self,
        request: &RuleUpdateRequest,
    ) -> Result<usize, InspectionError> {
        let detail = self.detail(request.rule)?;
        request.resolve_entry_index(&detail)
    }

    /// Builds one deterministic modeled duplicate-rule RPC payload.
    ///
    /// The outer value is the existing SID-modeled RPC input. Its binary
    /// `ipatch-sequence` contains one CORECONF instance map per override,
    /// using the stable entry-index key and SID paths for the changed leaves.
    ///
    /// # Errors
    ///
    /// Returns an error when the source or overrides are invalid, or the
    /// accepted CORECONF model rejects the encoding.
    pub fn duplicate_rule_payload(
        &self,
        request: &RuleDuplicateRequest,
    ) -> Result<Vec<u8>, InspectionError> {
        let snapshot = self.active.snapshot();
        let inner = duplicate_inner_payload(self.model.composite_model(), &snapshot, request)?;
        encode_duplicate_rpc_payload(&self.model, request, &inner)
    }

    /// Builds a complete NON POST duplicate-rule management datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when payload construction or CoAP serialization fails.
    pub fn duplicate_rule_datagram(
        &self,
        request: &RuleDuplicateRequest,
        message_id: u16,
    ) -> Result<Vec<u8>, InspectionError> {
        let payload = self.duplicate_rule_payload(request)?;
        let mut packet = base_request(RequestType::Post, message_id, &[]);
        packet.header.set_type(MessageType::NonConfirmable);
        packet.add_option(CoapOption::ContentFormat, vec![142]);
        packet.payload = payload;
        packet
            .to_bytes()
            .map_err(|error| InspectionError::Coap(error.to_string()))
    }

    /// Handles a duplicate-rule NON POST without creating a response.
    ///
    /// Other management requests are returned to the existing response path.
    ///
    /// # Errors
    ///
    /// Returns an error when the request or atomic candidate is invalid.
    pub fn handle_datagram_no_response(
        &mut self,
        datagram: &[u8],
    ) -> Result<Option<Vec<u8>>, InspectionError> {
        let packet = Packet::from_bytes(datagram)
            .map_err(|error| InspectionError::Coap(error.to_string()))?;
        if is_duplicate_rule_coap_shape(&packet) {
            let operation = decode_duplicate_operation(&self.model, &packet.payload)?;
            self.apply_duplicate_operation(&operation)?;
            return Ok(None);
        }
        Ok(Some(self.handle_datagram(datagram)?))
    }

    fn apply_duplicate_operation(
        &self,
        operation: &DecodedDuplicateOperation,
    ) -> Result<DuplicateRuleResult, InspectionError> {
        let _writer = self
            .active
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.active.snapshot();
        let expected = expected_duplicate_tree(
            &self.model,
            &snapshot,
            &operation.request,
            &operation.instances,
        )?;
        let destination = operation.request.destination.rule_id();
        let existing = snapshot
            .rules()
            .iter()
            .find(|rule| rule.id() == destination)
            .cloned();
        let expected_rule = find_tree_rule(
            &expected,
            self.model.composite_model(),
            operation.request.destination,
        )?
        .ok_or_else(|| invalid_duplicate("constructed destination rule is missing"))?;
        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_tree(
            recipe.sid_json.as_ref(),
            expected,
            recipe.device_id.clone(),
            recipe.profile.clone(),
            recipe.policy.clone(),
        )
        .map_err(|error| InspectionError::InvalidUpdate(error.to_string()))?;
        self.active
            .validate_candidate(&snapshot, &prepared)
            .map_err(|error| InspectionError::InvalidUpdate(error.to_string()))?;
        if existing.is_some() {
            let existing_tree_rule = find_tree_rule(
                snapshot.tree(),
                self.model.composite_model(),
                operation.request.destination,
            )?
            .ok_or_else(|| invalid_duplicate("existing destination rule is missing"))?;
            if existing_tree_rule != expected_rule {
                return Err(InspectionError::InvalidUpdate(format!(
                    "duplicate destination {} already exists with different contents",
                    operation.request.destination
                )));
            }
            return Ok(DuplicateRuleResult::Idempotent {
                generation: snapshot.generation(),
                tag: snapshot.tag(),
            });
        }
        self.active.publish_locked(&prepared);
        let after = self.active.snapshot();
        Ok(DuplicateRuleResult::Applied {
            generation: after.generation(),
            tag: after.tag(),
        })
    }

    /// Handles one complete logical CoAP datagram.
    ///
    /// GET and FETCH are delegated to rustconf. The supported root iPATCH is
    /// validated against one immutable snapshot and published only after the
    /// detached candidate passes complete context and runtime validation.
    /// Every other mutation method or shape is rejected before publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the CoAP datagram is malformed or the response
    /// cannot be serialized.
    pub fn handle_datagram(&mut self, datagram: &[u8]) -> Result<Vec<u8>, InspectionError> {
        let peek = Packet::from_bytes(datagram)
            .map_err(|error| InspectionError::Coap(error.to_string()))?;
        if is_duplicate_rule_coap_shape(&peek) {
            return Err(InspectionError::UnexpectedResponse(
                "duplicate-rule NON POST must use handle_datagram_no_response".into(),
            ));
        }
        let request = Packet::from_bytes(datagram)
            .map_err(|error| InspectionError::Coap(error.to_string()))?;
        if matches!(
            request.header.code,
            MessageClass::Request(RequestType::IPatch)
        ) {
            if request.payload.is_empty()
                && request.get_option(CoapOption::ContentFormat).is_none()
                && request.get_option(CoapOption::IfMatch).is_none()
            {
                let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                    coreconf_runtime::coap_types::Method::Fetch,
                );
                return packet_without_content_format(&request, response);
            }
            return self.handle_target_ipatch(&request);
        }
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
            .is_none_or(|segments| segments.iter().any(|segment| segment.as_slice() != b"schc"))
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

    fn handle_target_ipatch(&self, packet: &Packet) -> Result<Vec<u8>, InspectionError> {
        let request = match packet_to_request(packet, "schc") {
            Ok(request) => request,
            Err(response) => return packet_without_content_format(packet, response),
        };
        let if_match = match parse_if_match_option(packet) {
            Ok(if_match) => if_match,
            Err(error) if error.precondition_failed => {
                return packet_precondition_without_content_format(packet, &error.message)
            }
            Err(error) => {
                let response =
                    coreconf_runtime::coap_types::Response::error(error.code, &error.message);
                return packet_without_content_format(packet, response);
            }
        };
        let response = match self.apply_target_ipatch(&request, if_match) {
            Ok(response) => response,
            Err(error) if error.precondition_failed => {
                return packet_precondition_without_content_format(packet, &error.message)
            }
            Err(error) => coreconf_runtime::coap_types::Response::error(error.code, &error.message),
        };
        packet_without_content_format(packet, response)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_target_ipatch(
        &self,
        request: &Request,
        if_match: Option<ContextTag>,
    ) -> Result<coreconf_runtime::coap_types::Response, PatchFailure> {
        if request.interface != Some(Interface::Management) || !request.path.is_empty() {
            return Err(PatchFailure::bad(
                "targeted iPATCH must address the management root",
            ));
        }
        if request.content_format != Some(ContentFormat::YangInstancesCborSeq)
            || request.raw_content_format != Some(ContentFormat::YangInstancesCborSeq.as_u16())
        {
            return Err(PatchFailure::bad(
                "targeted iPATCH requires content format 142 (yang-instances+cbor-seq)",
            ));
        }
        if request.payload.is_empty() {
            return Err(PatchFailure::bad(
                "targeted iPATCH payload must contain one replacement",
            ));
        }
        validate_update_model_shape(self.model.composite_model())
            .map_err(|error| PatchFailure::internal(error.to_string()))?;
        let instances = decode_instances_with_model(self.model.composite_model(), &request.payload)
            .map_err(|error| PatchFailure::bad(format!("invalid iPATCH payload: {error}")))?;
        if instances.len() != 1 {
            return Err(PatchFailure::bad(format!(
                "targeted iPATCH must contain exactly one operation, got {}",
                instances.len()
            )));
        }
        let target = target_patch_from_instance(&instances[0])?;

        let _writer = self
            .active
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.active.snapshot();
        if if_match.is_some_and(|tag| tag != snapshot.tag()) {
            return Err(PatchFailure::precondition(
                "If-Match context tag does not match the current context",
            ));
        }
        let rule_id = target.selector.rule_id();
        if snapshot.protected_rules().contains(rule_id) {
            return Err(PatchFailure::conflict(format!(
                "RuleID {} is protected and immutable",
                target.selector
            )));
        }
        if !snapshot.rules().iter().any(|rule| rule.id() == rule_id) {
            return Err(PatchFailure::conflict(format!(
                "RuleID {} does not exist",
                target.selector
            )));
        }

        let mut candidate = Datastore::with_data(self.model.clone(), snapshot.tree().clone())
            .map_err(|error| {
                PatchFailure::conflict(format!(
                    "candidate datastore rejected the active tree: {error}"
                ))
            })?;
        let keys = target
            .path
            .components
            .iter()
            .filter_map(|component| match component {
                PathComponent::KeyValue(value) => Some(value.clone()),
                PathComponent::SidDelta(_) => None,
            })
            .collect::<Vec<_>>();
        let sid = target.path.absolute_sid().ok_or_else(|| {
            PatchFailure::bad("targeted iPATCH path has no target-value leaf SID")
        })?;
        let xpath = candidate
            .create_xpath(sid, &keys)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let parsed_xpath = PredicatePath::parse(&xpath)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let current_value = candidate
            .get_path(&xpath)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?
            .ok_or_else(|| PatchFailure::conflict("target-value leaf does not exist"))?;
        let composite = self.model.composite_model();
        let current_wire = composite
            .identifier_value_to_sid_value_at_path(current_value, &parsed_xpath.canonical_path)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let current_bytes = binary_bytes(&current_wire)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let entry_xpath = candidate
            .create_xpath(RULE_ENTRY_LIST_SID, &keys[..3])
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let entry_value = candidate
            .get_path(&entry_xpath)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?
            .ok_or_else(|| PatchFailure::conflict("target entry does not exist"))?;
        let field_length_key = tree_key_for_sid(composite, FIELD_LENGTH_SID)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let field_length = entry_value
            .get(&field_length_key)
            .and_then(Value::as_u64)
            .ok_or_else(|| PatchFailure::conflict("target entry has no numeric field-length"))?;
        if !binary_fits_field_length(&current_bytes, field_length) || field_length == 0 {
            return Err(PatchFailure::conflict(format!(
                "existing target value does not fit field length {field_length}"
            )));
        }
        let replacement_identifier = composite
            .sid_value_to_identifier_value_at_path(
                target.value.clone(),
                &parsed_xpath.canonical_path,
            )
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let replacement_wire = composite
            .identifier_value_to_sid_value_at_path(
                replacement_identifier.clone(),
                &parsed_xpath.canonical_path,
            )
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let replacement_bytes = binary_bytes(&replacement_wire)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        if replacement_bytes.len() != current_bytes.len() {
            return Err(PatchFailure::conflict(format!(
                "target-value replacement has {} bytes, expected {}",
                replacement_bytes.len(),
                current_bytes.len()
            )));
        }
        if !binary_fits_field_length(&replacement_bytes, field_length) {
            return Err(PatchFailure::conflict(format!(
                "target-value replacement does not fit field length {field_length}"
            )));
        }
        candidate
            .set_path(&xpath, replacement_identifier)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;

        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_tree(
            recipe.sid_json.as_ref(),
            candidate.get_all(),
            recipe.device_id.clone(),
            recipe.profile.clone(),
            recipe.policy.clone(),
        )
        .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        self.active
            .validate_candidate(&snapshot, &prepared)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        self.active.publish_locked(&prepared);
        Ok(coreconf_runtime::coap_types::Response::changed())
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
            coreconf_runtime::coap_types::ContentFormat::YangDataCborSid,
        );
        packet_without_content_format(request, response)
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum DuplicateLeaf {
    Target,
    MatchingOperator,
    Cda,
}

#[derive(Debug)]
struct DecodedDuplicateOperation {
    request: RuleDuplicateRequest,
    instances: Vec<Instance>,
    inner_payload: Vec<u8>,
}

fn invalid_duplicate(message: impl Into<String>) -> InspectionError {
    InspectionError::InvalidUpdate(format!("duplicate-rule: {}", message.into()))
}

/// Returns whether a decoded packet is the dedicated duplicate-rule request.
///
/// The exact protected `RuleID` is part of classification so a packet with a
/// duplicate-like CoAP shape under another protected `RuleID` cannot dispatch to
/// the duplicate operation.
#[must_use]
pub fn is_duplicate_rule_request(rule_id: RuleId, packet: &Packet) -> bool {
    rule_id == RuleId::new(29, 8) && is_duplicate_rule_coap_shape(packet)
}

fn is_duplicate_rule_coap_shape(packet: &Packet) -> bool {
    packet.header.code == MessageClass::Request(RequestType::Post)
        && packet.header.get_type() == MessageType::NonConfirmable
        && packet.get_token().is_empty()
        && packet.get_option(CoapOption::UriPath).is_some_and(|paths| {
            paths.len() == 1 && paths.front().is_some_and(|path| path.as_slice() == b"schc")
        })
        && packet
            .get_option(CoapOption::ContentFormat)
            .is_some_and(|formats| {
                formats.len() == 1
                    && formats
                        .front()
                        .is_some_and(|format| format.as_slice() == [142])
            })
}

fn validate_duplicate_model_shape(model: &CompositeModel) -> Result<(), InspectionError> {
    for sid in [
        DUPLICATE_RULE_SID,
        DUPLICATE_INPUT_SID,
        DUPLICATE_FROM_SID,
        DUPLICATE_FROM_LENGTH_SID,
        DUPLICATE_FROM_VALUE_SID,
        DUPLICATE_IPATCH_SID,
        DUPLICATE_TO_SID,
        DUPLICATE_TO_LENGTH_SID,
        DUPLICATE_TO_VALUE_SID,
        MATCHING_OPERATOR_SID,
        CDA_SID,
    ] {
        if model.get_identifier(sid).is_none() {
            return Err(invalid_duplicate(format!(
                "SID model is missing identifier {sid}"
            )));
        }
    }
    Ok(())
}

fn rule_key(model: &CompositeModel, sid: i64) -> Result<String, InspectionError> {
    model
        .get_identifier(sid)
        .and_then(|identifier| identifier.rsplit('/').next())
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_duplicate(format!("SID model is missing rule key {sid}")))
}

fn find_tree_rule(
    tree: &Value,
    model: &CompositeModel,
    selector: RuleSelector,
) -> Result<Option<Value>, InspectionError> {
    let root_key = rule_key(model, SCHC_ROOT_SID)?;
    let list_key = rule_key(model, RULE_LIST_SID)?;
    let value_key = rule_key(model, RULE_ID_VALUE_SID)?;
    let length_key = rule_key(model, RULE_ID_LENGTH_SID)?;
    Ok(tree
        .get(&root_key)
        .and_then(Value::as_object)
        .and_then(|root| root.get(&list_key))
        .and_then(Value::as_array)
        .and_then(|rules| {
            rules.iter().find(|rule| {
                rule.get(&value_key).and_then(Value::as_u64) == Some(selector.value)
                    && rule.get(&length_key).and_then(Value::as_u64) == Some(selector.bits as u64)
            })
        })
        .cloned())
}

fn set_tree_rule_key(
    rule: &mut Value,
    model: &CompositeModel,
    sid: i64,
    value: Value,
) -> Result<(), InspectionError> {
    let key = rule_key(model, sid)?;
    let object = rule
        .as_object_mut()
        .ok_or_else(|| invalid_duplicate("source rule is not an object"))?;
    object.insert(key, value);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn expected_duplicate_tree(
    model: &CoreconfModel,
    snapshot: &ContextSnapshot,
    request: &RuleDuplicateRequest,
    instances: &[Instance],
) -> Result<Value, InspectionError> {
    validate_duplicate_model_shape(model.composite_model())?;
    let source_rule = find_tree_rule(snapshot.tree(), model.composite_model(), request.source)?
        .ok_or(InspectionError::MissingRule {
            value: request.source.value,
            bits: request.source.bits,
        })?;
    let source_typed = snapshot
        .rules()
        .iter()
        .find(|rule| rule.id() == request.source.rule_id())
        .ok_or_else(|| invalid_duplicate("source rule is absent from the typed snapshot"))?;
    if source_typed.nature() == RuleNature::Management
        || snapshot
            .protected_rules()
            .contains(request.source.rule_id())
    {
        return Err(invalid_duplicate(
            "source RuleID is protected or management",
        ));
    }
    if snapshot
        .protected_rules()
        .contains(request.destination.rule_id())
    {
        return Err(invalid_duplicate("destination RuleID is protected"));
    }
    if request.source == request.destination {
        return Err(invalid_duplicate(
            "source and destination RuleIDs must differ",
        ));
    }

    let root_key = rule_key(model.composite_model(), SCHC_ROOT_SID)?;
    let list_key = rule_key(model.composite_model(), RULE_LIST_SID)?;
    let value_key = rule_key(model.composite_model(), RULE_ID_VALUE_SID)?;
    let length_key = rule_key(model.composite_model(), RULE_ID_LENGTH_SID)?;
    let mut destination_rule = source_rule;
    set_tree_rule_key(
        &mut destination_rule,
        model.composite_model(),
        RULE_ID_VALUE_SID,
        json!(request.destination.value),
    )?;
    set_tree_rule_key(
        &mut destination_rule,
        model.composite_model(),
        RULE_ID_LENGTH_SID,
        json!(request.destination.bits),
    )?;

    let mut candidate = snapshot.tree().clone();
    let rules = candidate
        .get_mut(&root_key)
        .and_then(Value::as_object_mut)
        .and_then(|root| root.get_mut(&list_key))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_duplicate("active tree is missing the rule list"))?;
    rules.retain(|rule| {
        !(rule.get(&value_key).and_then(Value::as_u64) == Some(request.destination.value)
            && rule.get(&length_key).and_then(Value::as_u64)
                == Some(request.destination.bits as u64))
    });
    rules.push(destination_rule);
    rules.sort_by(|left, right| {
        left.get(&length_key)
            .and_then(Value::as_u64)
            .unwrap_or_default()
            .cmp(
                &right
                    .get(&length_key)
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
            )
            .then_with(|| {
                left.get(&value_key)
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
                    .cmp(
                        &right
                            .get(&value_key)
                            .and_then(Value::as_u64)
                            .unwrap_or_default(),
                    )
            })
    });

    let mut datastore = Datastore::with_data(model.clone(), candidate)
        .map_err(|error| invalid_duplicate(format!("candidate tree is invalid: {error}")))?;
    let mut seen = BTreeSet::new();
    for instance in instances {
        let (entry_index, leaf) = duplicate_leaf_from_path(&instance.path, request.destination)?;
        let key = (entry_index, leaf);
        if !seen.insert(key) {
            return Err(invalid_duplicate(format!(
                "duplicate override for entry {entry_index} leaf {leaf:?}"
            )));
        }
        let value = instance
            .value
            .clone()
            .ok_or_else(|| invalid_duplicate("override values cannot delete leaves"))?;
        let sid = instance
            .path
            .absolute_sid()
            .ok_or_else(|| invalid_duplicate("override path has no leaf SID"))?;
        let keys = instance
            .path
            .components
            .iter()
            .filter_map(|component| match component {
                PathComponent::KeyValue(value) => Some(value.clone()),
                PathComponent::SidDelta(_) => None,
            })
            .collect::<Vec<_>>();
        let xpath = datastore
            .create_xpath(sid, &keys)
            .map_err(|error| invalid_duplicate(error.to_string()))?;
        datastore
            .set_path(&xpath, value)
            .map_err(|error| invalid_duplicate(error.to_string()))?;
    }
    Ok(datastore.get_all())
}

fn duplicate_leaf_from_path(
    path: &InstancePath,
    destination: RuleSelector,
) -> Result<(usize, DuplicateLeaf), InspectionError> {
    let mut absolute = 0_i64;
    let mut sids = Vec::new();
    let mut keys = Vec::new();
    for component in &path.components {
        match component {
            PathComponent::SidDelta(delta) => {
                absolute += delta;
                sids.push(absolute);
            }
            PathComponent::KeyValue(value) => keys.push(value.clone()),
        }
    }
    let Some(value) = keys.first().and_then(Value::as_u64) else {
        return Err(invalid_duplicate(
            "override path is missing destination value",
        ));
    };
    let Some(bits) = keys.get(1).and_then(Value::as_u64) else {
        return Err(invalid_duplicate(
            "override path is missing destination length",
        ));
    };
    if value != destination.value || bits != destination.bits as u64 {
        return Err(invalid_duplicate(
            "override path destination does not match RPC destination",
        ));
    }
    let Some(entry) = keys.get(2).and_then(Value::as_u64) else {
        return Err(invalid_duplicate("override path is missing entry-index"));
    };
    let entry =
        usize::try_from(entry).map_err(|_| invalid_duplicate("entry-index is too large"))?;
    let leaf = match sids.as_slice() {
        [2574, 2597, 2620, 2632] => DuplicateLeaf::MatchingOperator,
        [2574, 2597, 2620, 2636] => DuplicateLeaf::Cda,
        [2574, 2597, 2620, 2629, 2631] if keys.len() == 4 => DuplicateLeaf::Target,
        _ => {
            return Err(invalid_duplicate(
                "override path names an unsupported field",
            ))
        }
    };
    if matches!(leaf, DuplicateLeaf::Target) && keys.get(3).and_then(Value::as_u64) != Some(0) {
        return Err(invalid_duplicate("target-value index must be zero"));
    }
    Ok((entry, leaf))
}

fn duplicate_override_path(
    destination: RuleSelector,
    entry_index: usize,
    leaf: DuplicateLeaf,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    let mut previous = 0;
    for sid in [SCHC_ROOT_SID, RULE_LIST_SID] {
        push_sid(&mut path, &mut previous, sid)?;
    }
    path.push_key(json!(destination.value));
    path.push_key(json!(destination.bits));
    push_sid(&mut path, &mut previous, RULE_ENTRY_LIST_SID)?;
    path.push_key(json!(entry_index));
    match leaf {
        DuplicateLeaf::Target => {
            push_sid(&mut path, &mut previous, TARGET_VALUE_LIST_SID)?;
            path.push_key(json!(0));
            push_sid(&mut path, &mut previous, TARGET_VALUE_VALUE_SID)?;
        }
        DuplicateLeaf::MatchingOperator => {
            push_sid(&mut path, &mut previous, MATCHING_OPERATOR_SID)?;
        }
        DuplicateLeaf::Cda => {
            push_sid(&mut path, &mut previous, CDA_SID)?;
        }
    }
    Ok(path)
}

#[allow(clippy::too_many_lines)]
fn duplicate_inner_payload(
    model: &CompositeModel,
    snapshot: &ContextSnapshot,
    request: &RuleDuplicateRequest,
) -> Result<Vec<u8>, InspectionError> {
    find_tree_rule(snapshot.tree(), model, request.source)?.ok_or(
        InspectionError::MissingRule {
            value: request.source.value,
            bits: request.source.bits,
        },
    )?;
    let source_rule = snapshot
        .rules()
        .iter()
        .find(|rule| rule.id() == request.source.rule_id())
        .ok_or_else(|| invalid_duplicate("source rule is absent"))?;
    if source_rule.nature() == RuleNature::Management
        || snapshot
            .protected_rules()
            .contains(request.source.rule_id())
    {
        return Err(invalid_duplicate(
            "source RuleID is protected or management",
        ));
    }
    if snapshot
        .protected_rules()
        .contains(request.destination.rule_id())
    {
        return Err(invalid_duplicate("destination RuleID is protected"));
    }
    let detail = detail_from_rule(source_rule);
    let mut output = Vec::new();
    for override_ in &request.overrides {
        let entry = detail
            .entries
            .iter()
            .find(|entry| entry.entry_index == override_.entry_index)
            .ok_or_else(|| {
                invalid_duplicate(format!("unknown entry-index {}", override_.entry_index))
            })?;
        if override_.target_value.is_none()
            && override_.matching_operator.is_none()
            && override_.cda.is_none()
        {
            return Err(invalid_duplicate(format!(
                "entry {} has no override leaves",
                override_.entry_index
            )));
        }
        let mut fields = Vec::new();
        if let Some(target) = &override_.target_value {
            let current = source_rule
                .fields()
                .iter()
                .find(|field| field.entry_index == override_.entry_index)
                .and_then(|field| match &field.target {
                    TargetValue::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    invalid_duplicate("target override requires one binary source target")
                })?;
            let field_length = Value::Number(
                (entry.length.parse::<u64>().map_err(|_| {
                    invalid_duplicate("target override requires a fixed numeric field length")
                })?)
                .into(),
            );
            let bytes = binary_bytes(&numeric_target_value(target, &current, &field_length)?)?;
            let path = duplicate_override_path(
                request.destination,
                override_.entry_index,
                DuplicateLeaf::Target,
            )?;
            fields.push((path, CborValue::Bytes(bytes)));
        }
        if let Some(matching) = &override_.matching_operator {
            let identity = duplicate_identity_sid(model, matching, true)?;
            fields.push((
                duplicate_override_path(
                    request.destination,
                    override_.entry_index,
                    DuplicateLeaf::MatchingOperator,
                )?,
                CborValue::Integer(identity.into()),
            ));
        }
        if let Some(cda) = &override_.cda {
            let identity = duplicate_identity_sid(model, cda, false)?;
            fields.push((
                duplicate_override_path(
                    request.destination,
                    override_.entry_index,
                    DuplicateLeaf::Cda,
                )?,
                CborValue::Integer(identity.into()),
            ));
        }
        let entries = fields
            .into_iter()
            .map(|(path, value)| {
                let key =
                    coreconf_model::codec::json_to_cbor_value(model, &path.to_cbor_value(), 0)
                        .map_err(|error| invalid_duplicate(error.to_string()))?;
                Ok((key, value))
            })
            .collect::<Result<Vec<_>, InspectionError>>()?;
        ciborium::ser::into_writer(&CborValue::Map(entries), &mut output)
            .map_err(|error| invalid_duplicate(format!("override encoding failed: {error}")))?;
    }
    Ok(output)
}

fn duplicate_identity_sid(
    model: &CompositeModel,
    input: &str,
    matching: bool,
) -> Result<i64, InspectionError> {
    let allowed = if matching {
        [
            "equal",
            "ignore",
            "match-mapping",
            "mo-equal",
            "mo-ignore",
            "mo-match-mapping",
        ]
        .as_slice()
    } else {
        [
            "not-sent",
            "value-sent",
            "mapping-sent",
            "lsb",
            "compute",
            "deviid",
            "appiid",
            "cda-not-sent",
            "cda-value-sent",
            "cda-mapping-sent",
            "cda-lsb",
            "cda-compute",
            "cda-deviid",
            "cda-appiid",
        ]
        .as_slice()
    };
    if !allowed.contains(&input) {
        return Err(invalid_duplicate(format!(
            "invalid {} identity '{input}'",
            if matching { "matching operator" } else { "CDA" }
        )));
    }
    let canonical = if matching && !input.starts_with("mo-") {
        format!("mo-{input}")
    } else if !matching && !input.starts_with("cda-") {
        format!("cda-{input}")
    } else {
        input.to_owned()
    };
    model
        .identity_sid_for_value(&Value::String(canonical))
        .map_err(|error| invalid_duplicate(error.to_string()))
}

fn encode_duplicate_rpc_payload(
    model: &CoreconfModel,
    request: &RuleDuplicateRequest,
    inner: &[u8],
) -> Result<Vec<u8>, InspectionError> {
    validate_duplicate_model_shape(model.composite_model())?;
    let integer = |value: i64| CborValue::Integer(value.into());
    let uint = |value: u64| CborValue::Integer(value.into());
    let source_bits = u64::try_from(request.source.bits)
        .map_err(|_| invalid_duplicate("source RuleID length is too large"))?;
    let destination_bits = u64::try_from(request.destination.bits)
        .map_err(|_| invalid_duplicate("destination RuleID length is too large"))?;
    if request.source.value > u64::from(u32::MAX) || request.destination.value > u64::from(u32::MAX)
    {
        return Err(invalid_duplicate(
            "duplicate-rule RuleID values must fit the modeled uint32 selectors",
        ));
    }
    let from = CborValue::Map(vec![
        (integer(1), uint(source_bits)),
        (integer(2), uint(request.source.value)),
    ]);
    let to = CborValue::Map(vec![
        (integer(1), uint(destination_bits)),
        (integer(2), uint(request.destination.value)),
    ]);
    let mut input_entries = vec![
        (integer(1), from),
        (integer(4), CborValue::Bytes(inner.to_vec())),
        (integer(5), to),
    ];
    if inner.is_empty() {
        input_entries.remove(1);
    }
    let value = CborValue::Map(vec![(integer(1), CborValue::Map(input_entries))]);
    let root = CborValue::Map(vec![(integer(DUPLICATE_RULE_SID), value)]);
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&root, &mut payload)
        .map_err(|error| invalid_duplicate(format!("modeled RPC encoding failed: {error}")))?;
    Ok(payload)
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(first >> 2)] as char);
        output.push(ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(third & 0x3f)] as char
        } else {
            '='
        });
    }
    output
}

fn base64_decode(input: &str) -> Result<Vec<u8>, InspectionError> {
    if !input.len().is_multiple_of(4) {
        return Err(invalid_duplicate("ipatch-sequence is not canonical base64"));
    }
    let mut table = [255_u8; 256];
    for (index, byte) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[usize::from(*byte)] = u8::try_from(index).expect("base64 alphabet index fits u8");
    }
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let a = table[usize::from(chunk[0])];
        let b = table[usize::from(chunk[1])];
        if a == 255 || b == 255 {
            return Err(invalid_duplicate("ipatch-sequence contains invalid base64"));
        }
        let c = if chunk[2] == b'=' {
            0
        } else {
            table[usize::from(chunk[2])]
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            table[usize::from(chunk[3])]
        };
        if c == 255 || d == 255 || (chunk[2] == b'=' && chunk[3] != b'=') {
            return Err(invalid_duplicate(
                "ipatch-sequence contains invalid base64 padding",
            ));
        }
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    if base64_encode(&output) != input {
        return Err(invalid_duplicate("ipatch-sequence is not canonical base64"));
    }
    Ok(output)
}

fn decode_duplicate_operation(
    model: &CoreconfModel,
    payload: &[u8],
) -> Result<DecodedDuplicateOperation, InspectionError> {
    validate_duplicate_model_shape(model.composite_model())?;
    let outer = strict_one_cbor_map(payload)?;
    reject_duplicate_cbor_keys(&outer)?;
    let instances =
        decode_instances_with_model_to_identifier_at_path(model.composite_model(), payload, false)
            .map_err(|error| invalid_duplicate(format!("RPC payload decode failed: {error}")))?;
    if instances.len() != 1
        || instances[0].path.components != vec![PathComponent::SidDelta(DUPLICATE_RULE_SID)]
    {
        return Err(invalid_duplicate(
            "RPC payload must contain exactly one duplicate-rule instance",
        ));
    }
    let value = instances[0]
        .value
        .clone()
        .ok_or_else(|| invalid_duplicate("RPC input cannot be deleted"))?;
    let operation = value
        .as_object()
        .ok_or_else(|| invalid_duplicate("RPC operation value is not an object"))?;
    if operation.len() != 1 || !operation.contains_key("input") {
        return Err(invalid_duplicate(
            "RPC operation must contain exactly the input container",
        ));
    }
    let input = operation
        .get("input")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_duplicate("RPC input container is missing"))?;
    if input
        .keys()
        .any(|key| !matches!(key.as_str(), "from" | "to" | "ipatch-sequence"))
    {
        return Err(invalid_duplicate("RPC input contains an unknown field"));
    }
    let from = input
        .get("from")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_duplicate("RPC source selector is missing"))?;
    let to = input
        .get("to")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_duplicate("RPC destination selector is missing"))?;
    let selector = |object: &serde_json::Map<String, Value>,
                    label: &str|
     -> Result<RuleSelector, InspectionError> {
        if object.len() != 2
            || !object.contains_key("rule-id-value")
            || !object.contains_key("rule-id-length")
        {
            return Err(invalid_duplicate(format!(
                "RPC {label} selector has unsupported fields"
            )));
        }
        RuleSelector::new(
            object["rule-id-value"]
                .as_u64()
                .ok_or_else(|| invalid_duplicate(format!("RPC {label} value is invalid")))?,
            object["rule-id-length"]
                .as_u64()
                .and_then(|bits| usize::try_from(bits).ok())
                .ok_or_else(|| invalid_duplicate(format!("RPC {label} length is invalid")))?,
        )
        .map_err(|error| invalid_duplicate(error.to_string()))
    };
    let source = selector(from, "source")?;
    let destination = selector(to, "destination")?;
    let inner = input
        .get("ipatch-sequence")
        .map(|value| match value {
            Value::String(encoded) => base64_decode(encoded),
            _ => binary_bytes(value),
        })
        .transpose()?
        .unwrap_or_default();
    let inner_instances = decode_duplicate_inner(model.composite_model(), &inner, destination)?;
    let mut entries = BTreeSet::new();
    for instance in &inner_instances {
        let (entry, _) = duplicate_leaf_from_path(&instance.path, destination)?;
        entries.insert(entry);
    }
    let overrides = entries
        .into_iter()
        .map(|entry_index| RuleDuplicateOverride {
            entry_index,
            target_value: None,
            matching_operator: None,
            cda: None,
        })
        .collect();
    Ok(DecodedDuplicateOperation {
        request: RuleDuplicateRequest {
            source,
            destination,
            overrides,
        },
        instances: inner_instances,
        inner_payload: inner,
    })
}

/// Decodes the modeled duplicate RPC for read-only packet reporting.
///
/// This deliberately reuses the canonical duplicate decoder and never exposes
/// mutation or publication operations.
pub(crate) fn duplicate_rpc_cost(
    sid_json: &str,
    payload: &[u8],
) -> Result<DuplicateRpcCost, InspectionError> {
    let model = CoreconfModel::from_sid_str(sid_json)
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    let operation = decode_duplicate_operation(&model, payload)?;
    let fixed_request = RuleDuplicateRequest {
        source: operation.request.source,
        destination: operation.request.destination,
        overrides: Vec::new(),
    };
    let fixed_payload = encode_duplicate_rpc_payload(&model, &fixed_request, &[])?;
    let mut target_value_bytes = 0usize;
    let mut descriptions = BTreeMap::<usize, DuplicateRpcOverride>::new();
    let mut cursor = Cursor::new(operation.inner_payload.as_slice());
    let mut instance_index = 0usize;
    while usize::try_from(cursor.position())
        .is_ok_and(|position| position < operation.inner_payload.len())
    {
        let value: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|error| invalid_duplicate(format!("invalid override framing: {error}")))?;
        let CborValue::Map(entries) = value else {
            return Err(invalid_duplicate("override framing member is not a map"));
        };
        for (_, raw_value) in entries {
            let instance = operation.instances.get(instance_index).ok_or_else(|| {
                invalid_duplicate("override framing and decoded instances disagree")
            })?;
            instance_index += 1;
            let (entry_index, leaf) =
                duplicate_leaf_from_path(&instance.path, operation.request.destination)?;
            let description =
                descriptions
                    .entry(entry_index)
                    .or_insert_with(|| DuplicateRpcOverride {
                        entry_index,
                        target_value: None,
                        matching_operator: None,
                        cda: None,
                    });
            match leaf {
                DuplicateLeaf::Target => {
                    let CborValue::Bytes(bytes) = raw_value else {
                        return Err(invalid_duplicate(
                            "target override is not a CBOR byte string",
                        ));
                    };
                    target_value_bytes = target_value_bytes
                        .checked_add(bytes.len())
                        .ok_or_else(|| invalid_duplicate("target-value byte cost overflow"))?;
                    description.target_value = Some(target_bytes_label(&bytes));
                }
                DuplicateLeaf::MatchingOperator => {
                    description.matching_operator = instance.value.as_ref().map(json_value_label);
                }
                DuplicateLeaf::Cda => {
                    description.cda = instance.value.as_ref().map(json_value_label);
                }
            }
        }
    }
    if instance_index != operation.instances.len() {
        return Err(invalid_duplicate(
            "decoded override instances were not fully accounted",
        ));
    }
    let fixed_and_targets = fixed_payload
        .len()
        .checked_add(target_value_bytes)
        .ok_or_else(|| invalid_duplicate("duplicate RPC byte cost overflow"))?;
    let variable_framing_bytes = payload
        .len()
        .checked_sub(fixed_and_targets)
        .ok_or_else(|| {
            invalid_duplicate("duplicate RPC payload is smaller than fixed and target costs")
        })?;
    Ok(DuplicateRpcCost {
        source: operation.request.source,
        destination: operation.request.destination,
        payload_bytes: payload.len(),
        fixed_bytes: fixed_payload.len(),
        variable_framing_bytes,
        target_value_bytes,
        overrides: descriptions.into_values().collect(),
    })
}

fn json_value_label(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn target_bytes_label(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        let mut value = 0_u64;
        for byte in bytes {
            value = value.saturating_mul(256).saturating_add(u64::from(*byte));
        }
        value.to_string()
    } else {
        format!("{} B", bytes.len())
    }
}

fn decode_duplicate_inner(
    model: &CompositeModel,
    bytes: &[u8],
    destination: RuleSelector,
) -> Result<Vec<Instance>, InspectionError> {
    let mut cursor = Cursor::new(bytes);
    let mut instances = Vec::new();
    let mut groups = BTreeSet::new();
    while usize::try_from(cursor.position()).is_ok_and(|position| position < bytes.len()) {
        let start = usize::try_from(cursor.position())
            .map_err(|_| invalid_duplicate("ipatch-sequence is too large"))?;
        let value: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|error| invalid_duplicate(format!("invalid ipatch-sequence CBOR: {error}")))?;
        let end = usize::try_from(cursor.position())
            .map_err(|_| invalid_duplicate("ipatch-sequence is too large"))?;
        let CborValue::Map(entries) = &value else {
            return Err(invalid_duplicate("ipatch-sequence members must be maps"));
        };
        if entries.is_empty() || entries.len() > 3 {
            return Err(invalid_duplicate(
                "each override map must contain one to three leaves",
            ));
        }
        reject_duplicate_cbor_keys(&value)?;
        let mut canonical = Vec::new();
        ciborium::ser::into_writer(&value, &mut canonical)
            .map_err(|error| invalid_duplicate(error.to_string()))?;
        if canonical != bytes[start..end] {
            return Err(invalid_duplicate("noncanonical ipatch-sequence map"));
        }
        let member = &bytes[start..end];
        let decoded = decode_instances_with_model_to_identifier_at_path(model, member, false)
            .map_err(|error| invalid_duplicate(format!("invalid override value: {error}")))?;
        if decoded.len() != entries.len() {
            return Err(invalid_duplicate("override map did not decode completely"));
        }
        let mut seen = BTreeSet::new();
        let mut group_entries = BTreeSet::new();
        for instance in decoded {
            let (entry, leaf) = duplicate_leaf_from_path(&instance.path, destination)?;
            if !seen.insert((entry, leaf)) {
                return Err(invalid_duplicate("duplicate override leaf"));
            }
            group_entries.insert(entry);
            instances.push(instance);
        }
        // One map is one override group. A second map for the same entry
        // would make the entry-index override ambiguous rather than merging
        // two independently ordered operations.
        if group_entries.iter().any(|entry| groups.contains(entry)) {
            return Err(invalid_duplicate("duplicate entry-index override group"));
        }
        groups.extend(group_entries);
    }
    Ok(instances)
}

fn strict_one_cbor_map(bytes: &[u8]) -> Result<CborValue, InspectionError> {
    let mut cursor = Cursor::new(bytes);
    let value: CborValue = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| invalid_duplicate(format!("invalid RPC CBOR: {error}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_duplicate("trailing values after RPC instance"));
    }
    if !matches!(value, CborValue::Map(_)) {
        return Err(invalid_duplicate("RPC payload root must be a map"));
    }
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(&value, &mut canonical)
        .map_err(|error| invalid_duplicate(format!("RPC canonical encoding failed: {error}")))?;
    if canonical != bytes {
        return Err(invalid_duplicate("noncanonical RPC CBOR"));
    }
    Ok(value)
}

fn reject_duplicate_cbor_keys(value: &CborValue) -> Result<(), InspectionError> {
    match value {
        CborValue::Array(values) => values.iter().try_for_each(reject_duplicate_cbor_keys),
        CborValue::Map(entries) => {
            for (index, (key, value)) in entries.iter().enumerate() {
                if entries[..index].iter().any(|(previous, _)| previous == key) {
                    return Err(invalid_duplicate("duplicate CBOR map key"));
                }
                reject_duplicate_cbor_keys(key)?;
                reject_duplicate_cbor_keys(value)?;
            }
            Ok(())
        }
        CborValue::Tag(_, value) => reject_duplicate_cbor_keys(value),
        _ => Ok(()),
    }
}

#[derive(Debug)]
struct PatchFailure {
    code: ResponseCode,
    message: String,
    precondition_failed: bool,
}

impl PatchFailure {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            code: ResponseCode::BadRequest,
            message: message.into(),
            precondition_failed: false,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: ResponseCode::Conflict,
            message: message.into(),
            precondition_failed: false,
        }
    }

    fn precondition(message: impl Into<String>) -> Self {
        Self {
            code: ResponseCode::Conflict,
            message: message.into(),
            precondition_failed: true,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: ResponseCode::InternalServerError,
            message: message.into(),
            precondition_failed: false,
        }
    }
}

fn parse_if_match_option(packet: &Packet) -> Result<Option<ContextTag>, PatchFailure> {
    let Some(values) = packet.get_option(CoapOption::IfMatch) else {
        return Ok(None);
    };
    if values.len() != 1 {
        return Err(PatchFailure::bad(
            "targeted iPATCH must contain zero or one If-Match option",
        ));
    }
    let bytes = values
        .front()
        .ok_or_else(|| PatchFailure::bad("If-Match option is empty"))?;
    if bytes.len() != crate::CONTEXT_TAG_LEN {
        return Err(PatchFailure::bad(format!(
            "If-Match option must contain exactly {} bytes",
            crate::CONTEXT_TAG_LEN
        )));
    }
    let mut tag_bytes = [0_u8; crate::CONTEXT_TAG_LEN];
    tag_bytes.copy_from_slice(bytes);
    Ok(Some(ContextTag::new(tag_bytes)))
}

#[derive(Debug)]
struct TargetPatch {
    selector: RuleSelector,
    path: InstancePath,
    value: Value,
}

fn target_patch_from_instance(instance: &Instance) -> Result<TargetPatch, PatchFailure> {
    let components = &instance.path.components;
    if components.len() != 9 {
        return Err(PatchFailure::bad(
            "targeted iPATCH path must contain the complete rule, entry, and target-value keys",
        ));
    }
    let Some(PathComponent::SidDelta(root_delta)) = components.first() else {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the SCHC root",
        ));
    };
    let Some(PathComponent::SidDelta(rule_delta)) = components.get(1) else {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the rule list",
        ));
    };
    if *root_delta != SCHC_ROOT_SID || *rule_delta != RULE_LIST_SID - SCHC_ROOT_SID {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is not rooted at the complete rule list",
        ));
    }
    let rule_value = patch_key_u64(components.get(2), "RuleID value")?;
    let rule_bits = patch_key_u64(components.get(3), "RuleID bit length")?;
    let selector = RuleSelector::new(
        rule_value,
        usize::try_from(rule_bits)
            .map_err(|_| PatchFailure::bad("RuleID bit length is out of range"))?,
    )
    .map_err(|error| PatchFailure::bad(error.to_string()))?;
    let Some(PathComponent::SidDelta(entry_list_delta)) = components.get(4) else {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the entry list",
        ));
    };
    if *entry_list_delta != RULE_ENTRY_LIST_SID - RULE_LIST_SID {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the canonical entry list",
        ));
    }
    let entry_index = patch_key_usize(components.get(5), "entry index")?;
    let Some(PathComponent::SidDelta(target_list_delta)) = components.get(6) else {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the target-value list",
        ));
    };
    if *target_list_delta != TARGET_VALUE_LIST_SID - RULE_ENTRY_LIST_SID {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the canonical target-value list",
        ));
    }
    let target_value_index = patch_key_usize(components.get(7), "target-value index")?;
    let Some(PathComponent::SidDelta(target_leaf_delta)) = components.get(8) else {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is missing the target-value leaf",
        ));
    };
    if *target_leaf_delta != TARGET_VALUE_VALUE_SID - TARGET_VALUE_LIST_SID {
        return Err(PatchFailure::bad(
            "targeted iPATCH path names an unsupported leaf",
        ));
    }
    let expected_path = target_value_path(selector, entry_index, target_value_index)
        .map_err(|error| PatchFailure::bad(error.to_string()))?;
    if instance.path != expected_path {
        return Err(PatchFailure::bad(
            "targeted iPATCH path is not the canonical target-value instance path",
        ));
    }
    let value = instance
        .value
        .clone()
        .ok_or_else(|| PatchFailure::bad("targeted iPATCH cannot delete the target-value leaf"))?;
    Ok(TargetPatch {
        selector,
        path: instance.path.clone(),
        value,
    })
}

fn patch_key_u64(component: Option<&PathComponent>, name: &str) -> Result<u64, PatchFailure> {
    let Some(PathComponent::KeyValue(value)) = component else {
        return Err(PatchFailure::bad(format!(
            "targeted iPATCH is missing the {name} key"
        )));
    };
    value.as_u64().ok_or_else(|| {
        PatchFailure::bad(format!(
            "targeted iPATCH {name} key must be an unsigned integer"
        ))
    })
}

fn patch_key_usize(component: Option<&PathComponent>, name: &str) -> Result<usize, PatchFailure> {
    usize::try_from(patch_key_u64(component, name)?)
        .map_err(|_| PatchFailure::bad(format!("targeted iPATCH {name} key is out of range")))
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
        .to_bytes_unlimited()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

fn packet_precondition_without_content_format(
    request: &Packet,
    message: &str,
) -> Result<Vec<u8>, InspectionError> {
    let response = coreconf_runtime::coap_types::Response::error(ResponseCode::Conflict, message);
    let mut packet = response_to_packet(request, response);
    packet.header.code = MessageClass::Response(ResponseType::PreconditionFailed);
    packet.clear_option(CoapOption::ContentFormat);
    packet
        .to_bytes_unlimited()
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

/// Decodes one complete SCHC-root FETCH response into deterministic rule
/// summaries.
///
/// The request selects the unambiguous `/ietf-schc:schc` container, so the
/// response must contain exactly one canonical root instance. The returned
/// root value is converted and validated through the SID model before its
/// complete rule array is summarized.
///
/// # Errors
///
/// Returns an error for deleted or extra instances, a wrong path, malformed
/// model data, missing rule fields, invalid `RuleIDs`, duplicate `RuleIDs`, or an
/// invalid rule nature.
pub fn decode_rule_list_payload(
    payload: &[u8],
    model: &CoreconfModel,
) -> Result<Vec<RuleSummary>, InspectionError> {
    let instances = decode_instances_with_model(model.composite_model(), payload)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    if instances.len() != 1 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-list response contained {} instances, expected one root container",
            instances.len()
        )));
    }
    let instance = &instances[0];
    validate_root_instance_path(&instance.path)?;
    let raw_root = instance.value.clone().ok_or_else(|| {
        InspectionError::UnexpectedResponse("rule-list response contained a deleted root".into())
    })?;
    if raw_root.is_null() {
        return Err(InspectionError::UnexpectedResponse(
            "rule-list response contained a null root".into(),
        ));
    }
    let root = model
        .composite_model()
        .sid_value_to_identifier_value_at_path(raw_root, "/ietf-schc:schc")
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    let tree = json!({"ietf-schc:schc": root});
    model
        .composite_model()
        .validate_identifier_value(&tree)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    let rules = tree
        .get("ietf-schc:schc")
        .and_then(|root| root.get("rule"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            InspectionError::UnexpectedResponse(
                "rule-list response root did not contain a rule array".into(),
            )
        })?;

    let mut summaries = std::collections::BTreeMap::new();
    for rule in rules {
        let rule = rule.as_object().ok_or_else(|| {
            InspectionError::UnexpectedResponse(
                "rule-list response contained a non-object rule".into(),
            )
        })?;
        let value = rule
            .get("rule-id-value")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                InspectionError::UnexpectedResponse(
                    "rule-list response rule-id-value is not numeric".into(),
                )
            })?;
        let bits = rule
            .get("rule-id-length")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                InspectionError::UnexpectedResponse(
                    "rule-list response rule-id-length is not numeric".into(),
                )
            })?;
        let selector = RuleSelector::new(value, bits)?;
        let nature = decode_nature_value(
            model.composite_model(),
            rule.get("rule-nature").cloned().ok_or_else(|| {
                InspectionError::UnexpectedResponse(
                    "rule-list response is missing rule-nature".into(),
                )
            })?,
        )?;
        if summaries.insert(selector, nature).is_some() {
            return Err(InspectionError::UnexpectedResponse(format!(
                "rule-list response duplicated RuleID {}/{}",
                selector.value, selector.bits
            )));
        }
    }

    Ok(summaries
        .into_iter()
        .map(|(id, nature)| RuleSummary { id, nature })
        .collect())
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

fn validate_root_instance_path(path: &InstancePath) -> Result<(), InspectionError> {
    if path.components.len() != 1
        || !matches!(
            path.components.first(),
            Some(PathComponent::SidDelta(SCHC_ROOT_SID))
        )
    {
        return Err(InspectionError::UnexpectedResponse(
            "rule-list response did not contain the canonical SCHC root instance".into(),
        ));
    }
    Ok(())
}

fn management_instance_path(
    selector: Option<RuleSelector>,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    path.push_delta(SCHC_ROOT_SID)
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    if let Some(selector) = selector {
        path.push_delta(RULE_LIST_SID - SCHC_ROOT_SID)
            .map_err(|error| InspectionError::Datastore(error.to_string()))?;
        path.push_key(json!(selector.value));
        path.push_key(json!(selector.bits));
    }
    Ok(path)
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
    let value = if value.is_string() {
        value
    } else {
        model
            .sid_value_to_identifier_value_at_path(value, "/ietf-schc:schc/rule/rule-nature")
            .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?
    };
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

/// Builds a normal CORECONF FETCH for the unambiguous SCHC root container.
///
/// The request carries exactly one root identifier and
/// `application/yang-identifiers+cbor-seq` (141).
///
/// # Errors
///
/// Returns an error if the fixed root path or CoAP datagram cannot be
/// represented.
pub fn rule_list_request(message_id: u16, token: &[u8]) -> Result<Vec<u8>, InspectionError> {
    let path = management_instance_path(None)?;
    let mut packet = base_request(RequestType::Fetch, message_id, token);
    packet.add_option(CoapOption::ContentFormat, vec![141]);
    packet.payload = encode_identifiers(std::slice::from_ref(&path))
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    packet
        .to_bytes()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

/// Builds a normal CORECONF FETCH for exactly one keyed rule instance.
///
/// The request carries the canonical SCHC root, rule-list SID, and both
/// `RuleID` value and width keys with format 141.
///
/// # Errors
///
/// Returns an error if the fixed path or CoAP datagram cannot be represented.
pub fn rule_get_request(
    selector: RuleSelector,
    message_id: u16,
    token: &[u8],
) -> Result<Vec<u8>, InspectionError> {
    let path = management_instance_path(Some(selector))?;
    let mut packet = base_request(RequestType::Fetch, message_id, token);
    packet.add_option(CoapOption::ContentFormat, vec![141]);
    packet.payload = encode_identifiers(std::slice::from_ref(&path))
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    packet
        .to_bytes()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

fn base_request(method: RequestType, message_id: u16, _token: &[u8]) -> Packet {
    let mut packet = Packet::new();
    packet.header.message_id = message_id;
    packet.header.code = MessageClass::Request(method);
    packet.header.set_type(MessageType::Confirmable);
    // Protected management uses a zero-length token; the endpoint and bounded
    // CoAP MID provide the correlation key.
    packet.set_token(Vec::new());
    packet.add_option(CoapOption::UriPath, b"schc".to_vec());
    packet
}

/// Performs the protected management transport and returns the response code.
///
/// # Errors
///
/// Returns an error when SCHC rejects the packet, logical routing is invalid,
/// or the response does not correlate.
fn exchange_management_response(
    link: &SchcLink,
    raw_link: &RawUdpLink,
    coap_datagram: &[u8],
) -> Result<(u8, ManagementExchange), InspectionError> {
    let request = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        coap_datagram,
    )
    .map_err(|error| InspectionError::Coap(error.to_string()))?;
    let encoded = link.encode(TrafficOrigin::Management, &request)?;
    if !matches!(
        encoded.report().rule_id,
        id if [16_u64, 26, 27, 28].contains(&id.value()) && id.bit_len() == 8
    ) {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management request selected unsupported protected RuleID {}/{}",
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
        || response.destination_port() != MANAGEMENT_PORT
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
    let code = response_message.code();
    Ok((
        code,
        ManagementExchange {
            payload: response.coap_payload().to_vec(),
            request_report: encoded.report().clone(),
            response_report: decoded.report().clone(),
        },
    ))
}

/// Performs one protected management exchange and requires 2.05 Content.
///
/// # Errors
///
/// Returns an error when SCHC rejects the packet, logical routing is invalid,
/// the response does not correlate, or the response is not 2.05 Content.
pub fn exchange_management(
    link: &SchcLink,
    raw_link: &RawUdpLink,
    coap_datagram: &[u8],
) -> Result<ManagementExchange, InspectionError> {
    let (code, exchange) = exchange_management_response(link, raw_link, coap_datagram)?;
    if code != 69 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "expected CoAP 2.05 Content, got {code}"
        )));
    }
    Ok(exchange)
}

/// Performs one protected management exchange and returns the validated CoAP
/// response code for mutation callers.
///
/// Unlike [`exchange_management`], this accepts both successful and rejected
/// device responses so the caller can distinguish a real 2.04 Changed
/// acknowledgement from a device-side rejection.
///
/// # Errors
///
/// Returns an error when SCHC rejects the packet, logical routing is invalid,
/// or the response does not correlate.
pub fn exchange_management_update(
    link: &SchcLink,
    raw_link: &RawUdpLink,
    coap_datagram: &[u8],
) -> Result<(u8, ManagementExchange), InspectionError> {
    exchange_management_response(link, raw_link, coap_datagram)
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
    lines.extend(entries.into_iter().map(|entry| format_rule_entry(&entry)));
    lines
}

fn format_rule_entry(entry: &RuleEntry) -> String {
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
}

fn entry_matches_selector(entry: &RuleEntry, selector: &RuleEntrySelector) -> bool {
    match selector {
        RuleEntrySelector::Entry { entry_index } => entry.entry_index == *entry_index,
        RuleEntrySelector::Field {
            fid,
            field_position,
            direction,
        } => {
            normalize_fid(&entry.fid) == normalize_fid(fid)
                && field_position.is_none_or(|position| position == entry.field_position)
                && direction
                    .as_deref()
                    .is_none_or(|selected| selected == entry.direction)
        }
    }
}

fn normalize_fid(fid: &str) -> String {
    let fid = fid.trim().to_ascii_lowercase();
    let fid = fid.strip_prefix("fid-").unwrap_or(&fid);
    fid.chars().filter(char::is_ascii_alphanumeric).collect()
}

fn invalid_target(message: impl Into<String>) -> InspectionError {
    InspectionError::InvalidTarget(message.into())
}

fn validate_update_model_shape(model: &CompositeModel) -> Result<(), InspectionError> {
    for sid in [
        SCHC_ROOT_SID,
        RULE_LIST_SID,
        RULE_ID_LENGTH_SID,
        RULE_ID_VALUE_SID,
        RULE_ENTRY_LIST_SID,
        RULE_ENTRY_INDEX_SID,
        FIELD_LENGTH_SID,
        TARGET_VALUE_LIST_SID,
        TARGET_VALUE_INDEX_SID,
        TARGET_VALUE_VALUE_SID,
    ] {
        if model.get_identifier(sid).is_none() {
            return Err(invalid_target(format!(
                "SID model is missing identifier {sid}"
            )));
        }
    }
    require_list_keys(
        model,
        RULE_LIST_SID,
        &[RULE_ID_VALUE_SID, RULE_ID_LENGTH_SID],
    )?;
    require_list_keys(model, RULE_ENTRY_LIST_SID, &[RULE_ENTRY_INDEX_SID])?;
    require_list_keys(model, TARGET_VALUE_LIST_SID, &[TARGET_VALUE_INDEX_SID])?;
    Ok(())
}

fn require_list_keys(
    model: &CompositeModel,
    list_sid: i64,
    expected: &[i64],
) -> Result<(), InspectionError> {
    let Some(keys) = model.get_keys(list_sid) else {
        return Err(invalid_target(format!(
            "SID {list_sid} has no list key mapping"
        )));
    };
    if keys.as_slice() != expected {
        return Err(invalid_target(format!(
            "SID {list_sid} list keys are {keys:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

fn tree_key_for_sid(model: &CompositeModel, sid: i64) -> Result<String, InspectionError> {
    let identifier = model
        .get_identifier(sid)
        .ok_or_else(|| invalid_target(format!("SID model is missing identifier {sid}")))?;
    let key = identifier.rsplit('/').next().unwrap_or(identifier);
    if key.is_empty() {
        return Err(invalid_target(format!("SID {sid} has an empty tree key")));
    }
    Ok(key.to_owned())
}

fn serde_value_to_cbor(value: &Value) -> Result<CborValue, InspectionError> {
    match value {
        Value::Null => Ok(CborValue::Null),
        Value::Bool(value) => Ok(CborValue::Bool(*value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(CborValue::Integer(value.into()))
            } else if let Some(value) = value.as_u64() {
                Ok(CborValue::Integer(value.into()))
            } else if let Some(value) = value.as_f64() {
                Ok(CborValue::Float(value))
            } else {
                Err(invalid_target("path contains an invalid number"))
            }
        }
        Value::String(value) => Ok(CborValue::Text(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(serde_value_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(CborValue::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((CborValue::Text(key.clone()), serde_value_to_cbor(value)?)))
            .collect::<Result<Vec<_>, InspectionError>>()
            .map(CborValue::Map),
    }
}

fn binary_bytes(value: &Value) -> Result<Vec<u8>, InspectionError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid_target("target-value/value is not a binary byte array"))?;
    values
        .iter()
        .map(|value| {
            let byte = value
                .as_u64()
                .ok_or_else(|| invalid_target("target-value/value contains a non-byte"))?;
            u8::try_from(byte)
                .map_err(|_| invalid_target("target-value/value contains an out-of-range byte"))
        })
        .collect()
}

fn binary_fits_field_length(bytes: &[u8], field_length: u64) -> bool {
    let Some(storage_bits) = u64::try_from(bytes.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
    else {
        return false;
    };
    if field_length == 0 || field_length > storage_bits {
        return false;
    }
    let excess_bits = storage_bits - field_length;
    let whole_bytes = usize::try_from(excess_bits / 8).unwrap_or(usize::MAX);
    if bytes.iter().take(whole_bytes).any(|byte| *byte != 0) {
        return false;
    }
    let remaining_bits = excess_bits % 8;
    if remaining_bits == 0 || whole_bytes >= bytes.len() {
        return true;
    }
    bytes[whole_bytes] & (0xff_u8 << (8 - remaining_bits)) == 0
}

fn numeric_target_value(
    input: &str,
    current_bytes: &[u8],
    field_length: &Value,
) -> Result<Value, InspectionError> {
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_target(
            "tv must be an unsigned decimal value for a binary target",
        ));
    }
    let number = input
        .parse::<u64>()
        .map_err(|_| invalid_target("tv is out of range for an unsigned target value"))?;
    if current_bytes.is_empty() {
        return Err(invalid_target(
            "existing target value has no byte width to preserve",
        ));
    }
    let storage_bits = current_bytes
        .len()
        .checked_mul(8)
        .ok_or_else(|| invalid_target("existing target value byte width is too large"))?;
    if storage_bits < 64 && number >= (1_u64 << storage_bits) {
        return Err(invalid_target(format!(
            "tv={input} does not fit existing target width of {storage_bits} bits"
        )));
    }
    if let Some(bits) = field_length.as_u64() {
        if bits == 0 {
            return Err(invalid_target("selected field has a zero-bit length"));
        }
        if bits < 64 && number >= (1_u64 << bits) {
            return Err(invalid_target(format!(
                "tv={input} does not fit selected field length of {bits} bits"
            )));
        }
    }
    let mut bytes = vec![0_u8; current_bytes.len()];
    let mut remaining = number;
    for byte in bytes.iter_mut().rev() {
        *byte = (remaining & 0xff) as u8;
        remaining >>= 8;
    }
    if remaining != 0 {
        return Err(invalid_target(format!(
            "tv={input} does not fit existing target width of {storage_bits} bits"
        )));
    }
    Ok(Value::Array(
        bytes
            .into_iter()
            .map(|byte| Value::Number(byte.into()))
            .collect(),
    ))
}

fn target_value_path(
    rule: RuleSelector,
    entry_index: usize,
    target_value_index: usize,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    let mut previous_sid = 0;
    push_sid(&mut path, &mut previous_sid, SCHC_ROOT_SID)?;
    push_sid(&mut path, &mut previous_sid, RULE_LIST_SID)?;
    path.push_key(json!(rule.value));
    path.push_key(json!(rule.bits));
    push_sid(&mut path, &mut previous_sid, RULE_ENTRY_LIST_SID)?;
    path.push_key(json!(entry_index));
    push_sid(&mut path, &mut previous_sid, TARGET_VALUE_LIST_SID)?;
    path.push_key(json!(target_value_index));
    push_sid(&mut path, &mut previous_sid, TARGET_VALUE_VALUE_SID)?;
    Ok(path)
}

fn push_sid(
    path: &mut InstancePath,
    previous_sid: &mut i64,
    sid: i64,
) -> Result<(), InspectionError> {
    path.push_delta(sid - *previous_sid).map_err(|error| {
        invalid_target(format!("target-value path construction failed: {error}"))
    })?;
    *previous_sid = sid;
    Ok(())
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
