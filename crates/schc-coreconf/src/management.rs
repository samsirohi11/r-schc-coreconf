//! Protected SCHC context inspection and targeted management updates.
//!
//! The wire service uses ordinary CORECONF FETCH payloads for rule inspection
//! and one strict root iPATCH shape for detached, validated target updates.
//! Context checks use a compact marker and eight-byte tag because the fixed
//! management rules do not describe an `ETag` option.

use std::fmt;
use std::sync::Arc;

use ciborium::value::Value as CborValue;
use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType, ResponseType};
use coreconf_model::instance_id::{
    decode_instances_with_model, Instance, InstancePath, PathComponent,
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
    PreparedContext, RawUdpLink, SchcLink, TrafficOrigin, TrafficRoute, APPLICATION_PORT,
    CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

/// Marker used as the first byte of the compact context-check FETCH payload.
pub const CONTEXT_CHECK_MARKER: u8 = 0xC6;
const CONTEXT_CHECK_EQUAL: u8 = 0;
const CONTEXT_CHECK_MISMATCH: u8 = 1;
const SCHC_ROOT_SID: i64 = 2574;
const RULE_LIST_SID: i64 = 2597;
const RULE_ID_LENGTH_SID: i64 = 2598;
const RULE_ID_VALUE_SID: i64 = 2599;
const RULE_NATURE_SID: i64 = 2600;
const RULE_ENTRY_LIST_SID: i64 = 2620;
const RULE_ENTRY_INDEX_SID: i64 = 2621;
const FIELD_LENGTH_SID: i64 = 2625;
const TARGET_VALUE_LIST_SID: i64 = 2629;
const TARGET_VALUE_INDEX_SID: i64 = 2630;
const TARGET_VALUE_VALUE_SID: i64 = 2631;

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

        let path = target_value_path(request.rule, entry_index, target_value_index);
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
    /// The request uses `YangDataCbor` and an empty root path, as required by
    /// the runtime's instance-sequence iPATCH handler.
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
            .with_payload(self.ipatch_payload()?, ContentFormat::YangDataCbor)
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
        packet.set_token(token.to_vec());
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
        if request.content_format != Some(ContentFormat::YangDataCbor) {
            return Err(PatchFailure::bad("targeted iPATCH requires yang-data+cbor"));
        }
        if !matches!(request.raw_content_format, Some(140 | 142)) {
            return Err(PatchFailure::bad(
                "targeted iPATCH requires content format 140 or 142 (yang-data+cbor)",
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

        let mut candidate = Datastore::with_data(self.model.clone(), snapshot.tree().clone());
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
            coreconf_runtime::coap_types::ContentFormat::YangDataCbor,
        );
        packet_without_content_format(request, response)
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
    let expected_path = target_value_path(selector, entry_index, target_value_index);
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
        .to_bytes()
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
                && field_position.map_or(true, |position| position == entry.field_position)
                && direction
                    .as_deref()
                    .map_or(true, |selected| selected == entry.direction)
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
) -> InstancePath {
    let mut path = InstancePath::new();
    let mut previous_sid = 0;
    push_sid(&mut path, &mut previous_sid, SCHC_ROOT_SID);
    push_sid(&mut path, &mut previous_sid, RULE_LIST_SID);
    path.push_key(json!(rule.value));
    path.push_key(json!(rule.bits));
    push_sid(&mut path, &mut previous_sid, RULE_ENTRY_LIST_SID);
    path.push_key(json!(entry_index));
    push_sid(&mut path, &mut previous_sid, TARGET_VALUE_LIST_SID);
    path.push_key(json!(target_value_index));
    push_sid(&mut path, &mut previous_sid, TARGET_VALUE_VALUE_SID);
    path
}

fn push_sid(path: &mut InstancePath, previous_sid: &mut i64, sid: i64) {
    path.push_delta(sid - *previous_sid);
    *previous_sid = sid;
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
