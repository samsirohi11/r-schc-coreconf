//! Protected SCHC context inspection and targeted management updates.
//!
//! The wire service uses ordinary CORECONF FETCH payloads for rule inspection
//! and one strict root iPATCH shape for detached, validated target updates.
//! Context checks use a compact marker and eight-byte tag because the fixed
//! management rules do not describe an `ETag` option.
//! CoAP correlation supports empty or generated opaque tokens at this boundary.
//! The current SCHC profile selects [`TokenPolicy::Empty`] because its
//! management rules do not carry arbitrary token bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
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
    Cda, Direction, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Rule, RuleContext,
    RuleId, RuleNature, SidRegistry, TargetValue,
};
use schc_runtime::SchcFrame;
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    ActiveContext, ContextSnapshot, ContextTag, DynamicRuleIdNamespace, Ipv6UdpCoapPacket,
    Ipv6UdpPacket, LinkError, LinkReport, PreparedContext, RuleIdTreeError, SchcLink,
    TrafficOrigin, TrafficRoute, CORE_LOGICAL_ADDRESS, DEVICE_LOGICAL_ADDRESS, MANAGEMENT_PORT,
};

mod duplicate;
pub(crate) use duplicate::duplicate_rpc_cost;
pub use duplicate::is_duplicate_rule_datagram;
use duplicate::{
    decode_duplicate_operation, duplicate_inner_payload, encode_duplicate_rpc_payload,
    expected_duplicate_tree, find_tree_rule, flow_overrides, has_application_payload,
    has_complete_flow_fields, invalid_duplicate, is_duplicate_rule_coap_shape,
    DecodedDuplicateOperation, FlowChangeCandidate,
};

/// Marker used as the first byte of the compact context-check FETCH payload.
pub const CONTEXT_CHECK_MARKER: u8 = 0xC6;
const CONTEXT_CHECK_EQUAL: u8 = 0;
const CONTEXT_CHECK_MISMATCH: u8 = 1;

#[derive(Clone, Copy)]
struct ModelSids {
    root: i64,
    rule: i64,
    rule_id_length: i64,
    rule_id_value: i64,
    entry: i64,
    entry_index: i64,
    field_length: i64,
    target: i64,
    target_index: i64,
    target_value: i64,
    duplicate_rule: i64,
    duplicate_input: i64,
    duplicate_from: i64,
    duplicate_from_length: i64,
    duplicate_from_value: i64,
    duplicate_ipatch: i64,
    duplicate_to: i64,
    duplicate_to_length: i64,
    duplicate_to_value: i64,
    matching_operator: i64,
    cda: i64,
}

impl ModelSids {
    fn resolve(model: &CompositeModel) -> Result<Self, InspectionError> {
        let sid = |path: &str| {
            model
                .get_sid(path)
                .ok_or_else(|| invalid_target(format!("SID model is missing identifier {path}")))
        };
        Ok(Self {
            root: sid("/ietf-schc:schc")?,
            rule: sid("/ietf-schc:schc/rule")?,
            rule_id_length: sid("/ietf-schc:schc/rule/rule-id-length")?,
            rule_id_value: sid("/ietf-schc:schc/rule/rule-id-value")?,
            entry: sid("/ietf-schc:schc/rule/entry-universal")?,
            entry_index: sid("/ietf-schc:schc/rule/entry-universal/entry-index")?,
            field_length: sid("/ietf-schc:schc/rule/entry-universal/field-length")?,
            target: sid("/ietf-schc:schc/rule/entry-universal/target-value")?,
            target_index: sid("/ietf-schc:schc/rule/entry-universal/target-value/index")?,
            target_value: sid("/ietf-schc:schc/rule/entry-universal/target-value/value")?,
            duplicate_rule: sid("/ietf-schc:duplicate-rule")?,
            duplicate_input: sid("/ietf-schc:duplicate-rule/input")?,
            duplicate_from: sid("/ietf-schc:duplicate-rule/input/from")?,
            duplicate_from_length: sid("/ietf-schc:duplicate-rule/input/from/rule-id-length")?,
            duplicate_from_value: sid("/ietf-schc:duplicate-rule/input/from/rule-id-value")?,
            duplicate_ipatch: sid("/ietf-schc:duplicate-rule/input/ipatch-sequence")?,
            duplicate_to: sid("/ietf-schc:duplicate-rule/input/to")?,
            duplicate_to_length: sid("/ietf-schc:duplicate-rule/input/to/rule-id-length")?,
            duplicate_to_value: sid("/ietf-schc:duplicate-rule/input/to/rule-id-value")?,
            matching_operator: sid("/ietf-schc:schc/rule/entry-universal/matching-operator")?,
            cda: sid("/ietf-schc:schc/rule/entry-universal/comp-decomp-action")?,
        })
    }
}

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
    /// A CoAP token exceeded the protocol's eight-byte limit.
    #[error("invalid CoAP token: {0}")]
    InvalidToken(String),
    /// A protected link operation failed.
    #[error("management SCHC link error: {0}")]
    Link(#[from] LinkError),
    /// The protected response did not match its request.
    #[error("management response correlation failed: {0}")]
    Correlation(String),
    /// The remote endpoint returned unexpected content.
    #[error("unexpected management response: {0}")]
    UnexpectedResponse(String),
    /// Automatic flow management requires an explicit dynamic `RuleID` tree.
    #[error("automatic flow management requires an explicit dynamic RuleID namespace")]
    MissingDynamicRuleIdNamespace,
    /// The configured dynamic `RuleID` tree rejected allocation or validation.
    #[error("dynamic RuleID allocation failed: {0}")]
    RuleIdTree(#[from] RuleIdTreeError),
    /// A flow contains a field that cannot be represented by the duplicate
    /// target-value operation.
    #[error("flow cannot be represented by duplicate-rule management: {0}")]
    UnrepresentableFlow(String),
}

const MAX_COAP_TOKEN_LEN: usize = 8;
const COAP_CONFIRMABLE: u8 = 0;
const COAP_NON_CONFIRMABLE: u8 = 1;
const COAP_ACKNOWLEDGEMENT: u8 = 2;

/// The validated opaque token carried by a CoAP exchange.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CoapToken(Vec<u8>);

impl CoapToken {
    /// Creates a token after enforcing CoAP's zero-to-eight-byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError::InvalidToken`] when the token is longer
    /// than eight bytes.
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, InspectionError> {
        let bytes = bytes.as_ref();
        if bytes.len() > MAX_COAP_TOKEN_LEN {
            return Err(InspectionError::InvalidToken(format!(
                "length must be at most {MAX_COAP_TOKEN_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the empty CoAP token.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns whether this token is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Identifies one CoAP exchange by message ID and token.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ExchangeId {
    message_id: u16,
    token: CoapToken,
}

impl ExchangeId {
    /// Creates an exchange identifier after validating its token.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError::InvalidToken`] when the token is longer
    /// than eight bytes.
    pub fn new(message_id: u16, token: impl AsRef<[u8]>) -> Result<Self, InspectionError> {
        Ok(Self {
            message_id,
            token: CoapToken::new(token)?,
        })
    }

    /// Builds an exchange identifier from a parsed CoAP message.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError::InvalidToken`] when the message token is
    /// outside the validated CoAP range.
    pub fn from_message(message: &crate::CoapMessage) -> Result<Self, InspectionError> {
        Self::new(message.message_id(), message.token())
    }

    /// Returns the CoAP message ID.
    #[must_use]
    pub const fn message_id(&self) -> u16 {
        self.message_id
    }

    /// Returns the validated CoAP token.
    #[must_use]
    pub const fn token(&self) -> &CoapToken {
        &self.token
    }

    /// Returns whether a response's exchange identity is valid for a CoAP
    /// message type. Confirmable and non-confirmable separate responses may
    /// use a new MID; a piggybacked acknowledgement must keep the request
    /// MID. All supported response forms must retain the token.
    #[must_use]
    fn matches_response(&self, response: &Self, message_type: u8) -> bool {
        self.token == response.token
            && match message_type {
                COAP_CONFIRMABLE | COAP_NON_CONFIRMABLE => true,
                COAP_ACKNOWLEDGEMENT => self.message_id == response.message_id,
                _ => false,
            }
    }
}

static NEXT_GENERATED_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Selects the token policy used when a management request crosses the CoAP
/// boundary.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum TokenPolicy {
    /// Use the empty token required by the current compact SCHC profile.
    #[default]
    Empty,
    /// Generate a process-local eight-byte opaque token.
    ///
    /// This mode is a CoAP-boundary capability. The current management SCHC
    /// rules still reject arbitrary nonempty tokens, so callers must select
    /// it only with a profile that transports token bytes.
    Generated,
}

impl TokenPolicy {
    /// Produces the token selected by this policy.
    #[must_use]
    fn token(self) -> CoapToken {
        match self {
            Self::Empty => CoapToken::empty(),
            Self::Generated => {
                let sequence = NEXT_GENERATED_TOKEN.fetch_add(1, Ordering::Relaxed);
                CoapToken(sequence.to_be_bytes().to_vec())
            }
        }
    }
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

/// Direction of a logical IPv6/UDP flow relative to the SCHC device.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FlowDirection {
    /// The logical packet travels from the device toward the application.
    Uplink,
    /// The logical packet travels from the application toward the device.
    Downlink,
}

impl FlowDirection {
    fn schc_direction(self) -> Direction {
        match self {
            Self::Uplink => Direction::Up,
            Self::Downlink => Direction::Down,
        }
    }

    fn link_role(self) -> crate::LinkRole {
        match self {
            Self::Uplink => crate::LinkRole::Device,
            Self::Downlink => crate::LinkRole::Core,
        }
    }
}

/// Result of planning one logical flow change against the active context.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FlowChange {
    /// The current application context already contains a matching rule.
    AlreadyMatches {
        /// Existing matching rule.
        rule: RuleSelector,
    },
    /// A duplicate operation is required to install a matching rule.
    Duplicate {
        /// Existing application parent selected by the planner.
        parent: RuleSelector,
        /// Complete operation with an automatically allocated destination.
        request: RuleDuplicateRequest,
    },
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
        let sids = validate_update_model_shape(composite)?;
        let root_key = tree_key_for_sid(composite, sids.root)?;
        let rule_key = tree_key_for_sid(composite, sids.rule)?;
        let entry_key = tree_key_for_sid(composite, sids.entry)?;
        let target_value_key = tree_key_for_sid(composite, sids.target)?;
        let rule_value_key = tree_key_for_sid(composite, sids.rule_id_value)?;
        let rule_length_key = tree_key_for_sid(composite, sids.rule_id_length)?;
        let entry_index_key = tree_key_for_sid(composite, sids.entry_index)?;
        let target_index_key = tree_key_for_sid(composite, sids.target_index)?;
        let target_value_leaf_key = tree_key_for_sid(composite, sids.target_value)?;

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
                    .get_identifier(sids.target_value)
                    .ok_or_else(|| invalid_target("target-value/value SID is unavailable"))?,
            )
            .map_err(|error| invalid_target(format!("current target value is invalid: {error}")))?;
        let current_bytes = binary_bytes(&current_wire_value)?;
        let field_length = entry
            .get(&tree_key_for_sid(composite, sids.field_length)?)
            .ok_or_else(|| invalid_target("selected entry has no field-length"))?;
        let replacement =
            numeric_target_value(&request.target_value, &current_bytes, field_length)?;
        let value_path = composite
            .get_identifier(sids.target_value)
            .ok_or_else(|| invalid_target("target-value/value SID is unavailable"))?;
        composite
            .sid_value_to_identifier_value_at_path(replacement.clone(), value_path)
            .map_err(|error| {
                invalid_target(format!("replacement target value is invalid: {error}"))
            })?;

        let path = target_value_path(sids, request.rule, entry_index, target_value_index)?;
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
    /// Compact context tag.
    pub tag: ContextTag,
    /// Number of loaded rules.
    pub rule_count: usize,
    /// Context-level management guard period, when configured.
    pub guard_period: Option<crate::GuardPeriod>,
}

impl ContextStatus {
    /// Reads all fields from one immutable snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &ContextSnapshot) -> Self {
        Self {
            generation: snapshot.generation(),
            tag: snapshot.tag(),
            rule_count: snapshot.rules().len(),
            guard_period: snapshot.guard_period(),
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
                payload_length_bits = payload_prefix_bits(&field.length, message.payload().len());
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

fn payload_prefix_bits(length: &FieldLength, payload_len: usize) -> usize {
    match length {
        FieldLength::VariableBytes | FieldLength::VariableBits => {
            variable_length_prefix_bits(payload_len)
        }
        FieldLength::FixedBits(_)
        | FieldLength::Remaining
        | FieldLength::TokenLength
        | FieldLength::FromPreviousField { .. }
        | FieldLength::FunctionSid(_) => 0,
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
        let mut packet = base_request(RequestType::Post, message_id);
        packet.header.set_type(MessageType::NonConfirmable);
        packet.add_option(CoapOption::ContentFormat, vec![142]);
        packet.payload = payload;
        packet
            .to_bytes()
            .map_err(|error| InspectionError::Coap(error.to_string()))
    }

    /// Plans the smallest duplicate-rule operation for one logical flow.
    ///
    /// The current authoritative snapshot is inspected once. An existing
    /// application rule that already encodes the packet is reported as
    /// [`FlowChange::AlreadyMatches`]. Otherwise, each eligible application
    /// rule is considered as a parent, with the destination allocated by
    /// the active profile-owned `RuleID` tree. Candidates are ranked by the actual duplicate-rule
    /// management wire length, then by the number of complete changed entries,
    /// and finally by stable source `RuleID` order.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet is malformed, allocation is exhausted,
    /// or no existing application rule can represent the flow change.
    pub fn flow_change(
        &self,
        packet: &Ipv6UdpPacket,
        direction: FlowDirection,
    ) -> Result<FlowChange, InspectionError> {
        let snapshot = self.active.snapshot();
        let dynamic_rule_ids = snapshot
            .dynamic_rule_ids()
            .ok_or(InspectionError::MissingDynamicRuleIdNamespace)?
            .clone();
        self.flow_change_impl(packet, direction, &dynamic_rule_ids)
    }

    #[allow(clippy::too_many_lines)]
    fn flow_change_impl(
        &self,
        packet: &Ipv6UdpPacket,
        direction: FlowDirection,
        dynamic_rule_ids: &DynamicRuleIdNamespace,
    ) -> Result<FlowChange, InspectionError> {
        let snapshot = self.active.snapshot();
        if let Some(rule) = self.existing_application_match(&snapshot, packet, direction)? {
            return Ok(FlowChange::AlreadyMatches { rule });
        }
        let dynamic_destination = dynamic_rule_ids
            .allocate(snapshot.rules().iter().map(Rule::id))
            .map_err(InspectionError::RuleIdTree)?;
        let mut candidates = Vec::new();
        for parent in snapshot.rules() {
            if parent.nature() != RuleNature::Compression
                || snapshot.protected_rules().contains(parent.id())
                || !has_application_payload(parent)
                || !has_complete_flow_fields(parent)
            {
                continue;
            }
            let Some(overrides) = flow_overrides(parent, packet, direction)? else {
                continue;
            };
            let source = RuleSelector::new(parent.id().value(), parent.id().bit_len())?;
            if overrides.is_empty() {
                continue;
            }
            let destination =
                RuleSelector::new(dynamic_destination.value(), dynamic_destination.bit_len())?;
            let request = RuleDuplicateRequest {
                source,
                destination,
                overrides,
            };
            let Ok(management_wire_bytes) = self.duplicate_rule_wire_bytes(&request) else {
                continue;
            };
            let Ok(payload) = self.duplicate_rule_payload(&request) else {
                continue;
            };
            let Ok(operation) = decode_duplicate_operation(&self.model, &payload) else {
                continue;
            };
            let Ok(tree) = expected_duplicate_tree(
                &self.model,
                &snapshot,
                &operation.request,
                &operation.instances,
            ) else {
                continue;
            };
            let recipe = self.active.recipe();
            let prepared = PreparedContext::from_tree_for_recipe(recipe, tree);
            let Ok(prepared) = prepared else {
                continue;
            };
            let candidate_link = SchcLink::new(
                Arc::new(ActiveContext::new(prepared)),
                direction.link_role(),
            );
            if candidate_link
                .encode_bytes(TrafficOrigin::Application, packet.as_bytes())
                .is_err()
            {
                continue;
            }
            candidates.push(FlowChangeCandidate {
                request,
                management_wire_bytes,
            });
        }

        candidates.sort_by(|left, right| {
            left.management_wire_bytes
                .cmp(&right.management_wire_bytes)
                .then_with(|| {
                    left.request
                        .overrides
                        .len()
                        .cmp(&right.request.overrides.len())
                })
                .then_with(|| left.request.source.cmp(&right.request.source))
        });
        let Some(candidate) = candidates.into_iter().next() else {
            return Err(InspectionError::UnrepresentableFlow(
                "no application parent can represent the IPv6/UDP fields".into(),
            ));
        };
        Ok(FlowChange::Duplicate {
            parent: candidate.request.source,
            request: candidate.request,
        })
    }

    fn existing_application_match(
        &self,
        snapshot: &ContextSnapshot,
        packet: &Ipv6UdpPacket,
        direction: FlowDirection,
    ) -> Result<Option<RuleSelector>, InspectionError> {
        let link = SchcLink::new(Arc::clone(&self.active), direction.link_role());
        for parent in snapshot.rules() {
            if parent.nature() != RuleNature::Compression
                || snapshot.protected_rules().contains(parent.id())
                || !has_application_payload(parent)
                || !has_complete_flow_fields(parent)
            {
                continue;
            }
            let Some(overrides) = flow_overrides(parent, packet, direction)? else {
                continue;
            };
            if overrides.is_empty() {
                let source = RuleSelector::new(parent.id().value(), parent.id().bit_len())?;
                let Ok(encoded) = link.encode_bytes(TrafficOrigin::Application, packet.as_bytes())
                else {
                    continue;
                };
                if encoded.report().rule_id == source.rule_id() {
                    return Ok(Some(source));
                }
            }
        }
        Ok(None)
    }

    fn duplicate_rule_wire_bytes(
        &self,
        request: &RuleDuplicateRequest,
    ) -> Result<usize, InspectionError> {
        let datagram = self.duplicate_rule_datagram(request, 0)?;
        let packet = Ipv6UdpCoapPacket::new(
            CORE_LOGICAL_ADDRESS,
            DEVICE_LOGICAL_ADDRESS,
            MANAGEMENT_PORT,
            MANAGEMENT_PORT,
            &datagram,
        )
        .map_err(|error| InspectionError::Coap(error.to_string()))?;
        let link = SchcLink::new(Arc::clone(&self.active), crate::LinkRole::Core);
        Ok(link
            .encode(TrafficOrigin::Management, &packet)?
            .frame()
            .bytes()
            .len())
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
        if let Some(namespace) = snapshot.dynamic_rule_ids() {
            if existing.is_none() && !namespace.accepts(destination) {
                return Err(invalid_duplicate(format!(
                    "new duplicate destination {} is outside the configured dynamic RuleID namespace",
                    operation.request.destination
                )));
            }
        }
        let expected_rule = find_tree_rule(
            &expected,
            self.model.composite_model(),
            operation.request.destination,
        )?
        .ok_or_else(|| invalid_duplicate("constructed destination rule is missing"))?;
        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_tree_for_recipe(recipe, expected)
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
        let packet = Packet::from_bytes(datagram)
            .map_err(|error| InspectionError::Coap(error.to_string()))?;
        if is_duplicate_rule_coap_shape(&packet) {
            return Err(InspectionError::UnexpectedResponse(
                "duplicate-rule NON POST must use handle_datagram_no_response".into(),
            ));
        }
        if matches!(
            packet.header.code,
            MessageClass::Request(RequestType::IPatch)
        ) {
            if packet.payload.is_empty()
                && packet.get_option(CoapOption::ContentFormat).is_none()
                && packet.get_option(CoapOption::IfMatch).is_none()
            {
                let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                    coreconf_runtime::coap_types::Method::Fetch,
                );
                return packet_without_content_format(&packet, response);
            }
            return self.handle_target_ipatch(&packet);
        }
        if is_mutation(&packet) {
            let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                coreconf_runtime::coap_types::Method::Fetch,
            );
            return packet_without_content_format(&packet, response);
        }
        if !matches!(
            packet.header.code,
            MessageClass::Request(RequestType::Get | RequestType::Fetch)
        ) {
            let response = coreconf_runtime::coap_types::Response::method_not_allowed(
                coreconf_runtime::coap_types::Method::Fetch,
            );
            return packet_without_content_format(&packet, response);
        }
        if packet
            .get_option(CoapOption::UriPath)
            .is_none_or(|segments| segments.iter().any(|segment| segment.as_slice() != b"schc"))
        {
            let response = coreconf_runtime::coap_types::Response::not_found("/schc");
            return packet_without_content_format(&packet, response);
        }

        if matches!(
            packet.header.code,
            MessageClass::Request(RequestType::Fetch)
        ) && packet.payload.first() == Some(&CONTEXT_CHECK_MARKER)
        {
            return self.handle_context_check(&packet);
        }

        let coreconf_request = packet_to_request(&packet, "schc").map_err(|response| {
            InspectionError::Coap(format!("CORECONF request rejected with {}", response.code))
        })?;
        let response = self.handler.handle(&coreconf_request);
        packet_without_content_format(&packet, response)
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
        let sids = validate_update_model_shape(self.model.composite_model())
            .map_err(|error| PatchFailure::internal(error.to_string()))?;
        let instances = decode_instances_with_model(self.model.composite_model(), &request.payload)
            .map_err(|error| PatchFailure::bad(format!("invalid iPATCH payload: {error}")))?;
        if instances.len() != 1 {
            return Err(PatchFailure::bad(format!(
                "targeted iPATCH must contain exactly one operation, got {}",
                instances.len()
            )));
        }
        let target = target_patch_from_instance(&instances[0], sids)?;

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
            .components()
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
            .create_xpath(sids.entry, &keys[..3])
            .map_err(|error| PatchFailure::conflict(error.to_string()))?;
        let entry_value = candidate
            .get_path(&entry_xpath)
            .map_err(|error| PatchFailure::conflict(error.to_string()))?
            .ok_or_else(|| PatchFailure::conflict("target entry does not exist"))?;
        let field_length_key = tree_key_for_sid(composite, sids.field_length)
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
        let prepared = PreparedContext::from_tree_for_recipe(recipe, candidate.get_all())
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

fn target_patch_from_instance(
    instance: &Instance,
    sids: ModelSids,
) -> Result<TargetPatch, PatchFailure> {
    let components = instance.path.components();
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
    if *root_delta != sids.root || *rule_delta != sids.rule - sids.root {
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
    if *entry_list_delta != sids.entry - sids.rule {
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
    if *target_list_delta != sids.target - sids.entry {
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
    if *target_leaf_delta != sids.target_value - sids.target {
        return Err(PatchFailure::bad(
            "targeted iPATCH path names an unsupported leaf",
        ));
    }
    let expected_path = target_value_path(sids, selector, entry_index, target_value_index)
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
pub fn context_check_request(tag: ContextTag, message_id: u16) -> Vec<u8> {
    let mut packet = base_request(RequestType::Fetch, message_id);
    packet.payload.push(CONTEXT_CHECK_MARKER);
    packet.payload.extend_from_slice(&tag.bytes());
    packet
        .to_bytes()
        .expect("context-check request is representable")
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
    let sids = ModelSids::resolve(model.composite_model())?;
    let instances = decode_instances_with_model(model.composite_model(), payload)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    if instances.len() != 1 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-list response contained {} instances, expected one root container",
            instances.len()
        )));
    }
    let instance = &instances[0];
    validate_root_instance_path(&instance.path, sids.root)?;
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
    let sids = ModelSids::resolve(model.composite_model())?;
    let instances = decode_instances_with_model(model.composite_model(), payload)
        .map_err(|error| InspectionError::UnexpectedResponse(error.to_string()))?;
    if instances.len() != 1 {
        return Err(InspectionError::UnexpectedResponse(format!(
            "rule-get response contained {} instances, expected one",
            instances.len()
        )));
    }
    let instance = &instances[0];
    validate_rule_instance_path(
        &instance.path,
        sids.root,
        sids.rule,
        sids.rule,
        Some(selector),
    )?;
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

fn validate_root_instance_path(path: &InstancePath, root_sid: i64) -> Result<(), InspectionError> {
    if path.components().len() != 1
        || !matches!(
            path.components().first(),
            Some(PathComponent::SidDelta(sid)) if *sid == root_sid
        )
    {
        return Err(InspectionError::UnexpectedResponse(
            "rule-list response did not contain the canonical SCHC root instance".into(),
        ));
    }
    Ok(())
}

fn management_instance_path(
    root_sid: i64,
    rule_sid: i64,
    selector: Option<RuleSelector>,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    path.push_delta(root_sid)
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    if let Some(selector) = selector {
        let rule_delta = rule_sid
            .checked_sub(root_sid)
            .ok_or_else(|| InspectionError::Datastore("rule-list SID delta overflows".into()))?;
        path.push_delta(rule_delta)
            .map_err(|error| InspectionError::Datastore(error.to_string()))?;
        path.push_key(json!(selector.value));
        path.push_key(json!(selector.bits));
    }
    Ok(path)
}

fn model_request_sids(sid_json: &str) -> Result<(i64, i64), InspectionError> {
    let model = CoreconfModel::from_sid_str(sid_json)
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    let composite = model.composite_model();
    let root = composite
        .get_sid("/ietf-schc:schc")
        .ok_or_else(|| invalid_target("SID model is missing identifier /ietf-schc:schc"))?;
    let rule = composite
        .get_sid("/ietf-schc:schc/rule")
        .ok_or_else(|| invalid_target("SID model is missing identifier /ietf-schc:schc/rule"))?;
    Ok((root, rule))
}

fn rule_request(
    root_sid: i64,
    rule_sid: i64,
    selector: Option<RuleSelector>,
    message_id: u16,
) -> Result<Vec<u8>, InspectionError> {
    let path = management_instance_path(root_sid, rule_sid, selector)?;
    let mut packet = base_request(RequestType::Fetch, message_id);
    packet.add_option(CoapOption::ContentFormat, vec![141]);
    packet.payload = encode_identifiers(std::slice::from_ref(&path))
        .map_err(|error| InspectionError::Datastore(error.to_string()))?;
    packet
        .to_bytes()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

fn rule_key_values(
    path: &coreconf_model::instance_id::InstancePath,
) -> Result<[u64; 2], InspectionError> {
    let keys = path
        .components()
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
    root_sid: i64,
    rule_sid: i64,
    leaf_sid: i64,
    selector: Option<RuleSelector>,
) -> Result<(), InspectionError> {
    let mut absolute = 0_i64;
    let mut sids = Vec::new();
    let mut key_count = 0;
    for component in path.components() {
        match component {
            PathComponent::SidDelta(delta) => {
                absolute += delta;
                sids.push(absolute);
            }
            PathComponent::KeyValue(_) => key_count += 1,
        }
    }
    let expected_sids = if leaf_sid == rule_sid {
        [root_sid, rule_sid, 0]
    } else {
        [root_sid, rule_sid, leaf_sid]
    };
    let expected_len = if leaf_sid == rule_sid { 2 } else { 3 };
    if sids.len() != expected_len
        || sids.first().copied() != Some(expected_sids[0])
        || sids.get(1).copied() != Some(expected_sids[1])
        || (leaf_sid != rule_sid && sids.get(2).copied() != Some(leaf_sid))
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

/// Builds a CORECONF FETCH for the unambiguous SCHC root container.
///
/// # Errors
///
/// Returns an error if the fixed root path or CoAP datagram cannot be
/// represented.
pub fn rule_list_request(sid_json: &str, message_id: u16) -> Result<Vec<u8>, InspectionError> {
    let (root_sid, rule_sid) = model_request_sids(sid_json)?;
    rule_request(root_sid, rule_sid, None, message_id)
}

/// Builds a keyed rule FETCH using the root and rule-list SIDs from `sid_json`.
///
/// # Errors
///
/// Returns an error if the SID document or resulting CoAP datagram is invalid.
pub fn rule_get_request(
    sid_json: &str,
    selector: RuleSelector,
    message_id: u16,
) -> Result<Vec<u8>, InspectionError> {
    let (root_sid, rule_sid) = model_request_sids(sid_json)?;
    rule_request(root_sid, rule_sid, Some(selector), message_id)
}

fn base_request(method: RequestType, message_id: u16) -> Packet {
    let mut packet = Packet::new();
    packet.header.message_id = message_id;
    packet.header.code = MessageClass::Request(method);
    packet.header.set_type(MessageType::Confirmable);
    packet.set_token(Vec::new());
    packet.add_option(CoapOption::UriPath, b"schc".to_vec());
    packet
}

fn apply_token_policy(
    coap_datagram: &[u8],
    token_policy: TokenPolicy,
) -> Result<Vec<u8>, InspectionError> {
    let mut packet = Packet::from_bytes(coap_datagram)
        .map_err(|error| InspectionError::Coap(error.to_string()))?;
    packet.set_token(token_policy.token().as_bytes().to_vec());
    packet
        .to_bytes()
        .map_err(|error| InspectionError::Coap(error.to_string()))
}

/// An encoded protected management request awaiting transport and response
/// validation.
///
/// The value owns the exact SCHC frame and the request correlation identity, but
/// does not own any transport.  It can therefore be sent by a caller that
/// also reads and routes unrelated raw link frames.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreparedManagementRequest {
    frame: SchcFrame,
    report: LinkReport,
    exchange_id: ExchangeId,
}

impl PreparedManagementRequest {
    /// Returns the exact padded SCHC frame selected during preparation.
    #[must_use]
    pub const fn frame(&self) -> &SchcFrame {
        &self.frame
    }

    /// Returns the compression report for the prepared request.
    #[must_use]
    pub const fn report(&self) -> &LinkReport {
        &self.report
    }

    /// Returns the CoAP identity required to correlate a response.
    #[must_use]
    pub const fn exchange_id(&self) -> &ExchangeId {
        &self.exchange_id
    }
}

/// Builds and SCHC-encodes one protected management request.
///
/// The logical packet is always oriented from the core management endpoint
/// (`2001:db8::2:8724`) to the device management endpoint
/// (`2001:db8::1:8724`). The profile-selected duplicate-rule path is
/// deliberately not accepted here.
///
/// This function performs no transport operations.  The returned value owns
/// the exact frame and retains the request correlation information for
/// [`validate_management_response`]. The selected token policy is applied to
/// the serialized CoAP request before SCHC encoding. The current compact
/// profile supports only [`TokenPolicy::Empty`].
///
/// # Errors
///
/// Returns an error when the datagram cannot form a logical packet, SCHC
/// encoding fails, or the selected rule is not protected by the active
/// context profile.
pub fn prepare_management_request(
    link: &SchcLink,
    coap_datagram: &[u8],
    token_policy: TokenPolicy,
) -> Result<PreparedManagementRequest, InspectionError> {
    if is_duplicate_rule_datagram(coap_datagram) {
        return Err(InspectionError::UnexpectedResponse(
            "duplicate-rule NON POST is one-way and is not prepared for response tracking".into(),
        ));
    }
    let wire_datagram = apply_token_policy(coap_datagram, token_policy)?;
    let request = Ipv6UdpCoapPacket::new(
        CORE_LOGICAL_ADDRESS,
        DEVICE_LOGICAL_ADDRESS,
        MANAGEMENT_PORT,
        MANAGEMENT_PORT,
        &wire_datagram,
    )
    .map_err(|error| InspectionError::Coap(error.to_string()))?;
    let encoded = link.encode(TrafficOrigin::Management, &request)?;
    if encoded.report().traffic_class != crate::TrafficClass::ProtectedManagement {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management request selected unsupported protected RuleID {}/{}",
            encoded.report().rule_id.value(),
            encoded.report().rule_id.bit_len()
        )));
    }
    let report = encoded.report().clone();
    let frame = encoded.into_frame();
    let exchange_id = ExchangeId::from_message(request.coap_message())?;
    Ok(PreparedManagementRequest {
        frame,
        report,
        exchange_id,
    })
}

/// Validates one already decoded response against a prepared request.
///
/// Validation requires protected-management route, the exact device-to-core
/// logical orientation and management ports, and a matching CoAP token with
/// the message-type-specific MID rule. No transport operation is performed.
///
/// # Errors
///
/// Returns an error when the decoded traffic is not a protected management
/// response for this request, when its logical orientation is invalid, or when
/// its CoAP MID or token does not correlate with the request.
pub fn validate_management_response(
    prepared: &PreparedManagementRequest,
    decoded: &crate::LinkDecoded,
) -> Result<(u8, ManagementExchange), InspectionError> {
    if decoded.route() != TrafficRoute::ProtectedManagement {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management response selected {:?} instead of protected management",
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
    let response_message = response.coap_message();
    let code = response_message.code();
    if !(2..=5).contains(&(code >> 5)) {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management response has non-response CoAP code {code}"
        )));
    }
    let response_exchange = ExchangeId::from_message(response_message)?;
    let response_type = response.coap_message_type();
    if !matches!(
        response_type,
        COAP_CONFIRMABLE | COAP_NON_CONFIRMABLE | COAP_ACKNOWLEDGEMENT
    ) {
        return Err(InspectionError::UnexpectedResponse(format!(
            "management response has unsupported CoAP message type {response_type}"
        )));
    }
    if !prepared
        .exchange_id
        .matches_response(&response_exchange, response_type)
    {
        return Err(InspectionError::Correlation(
            "CoAP message ID or token mismatch".into(),
        ));
    }
    Ok((
        code,
        ManagementExchange {
            payload: response.coap_payload().to_vec(),
            request_report: prepared.report.clone(),
            response_report: decoded.report().clone(),
        },
    ))
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

fn validate_update_model_shape(model: &CompositeModel) -> Result<ModelSids, InspectionError> {
    let sids = ModelSids::resolve(model)?;
    require_list_keys(model, sids.rule, &[sids.rule_id_value, sids.rule_id_length])?;
    require_list_keys(model, sids.entry, &[sids.entry_index])?;
    require_list_keys(model, sids.target, &[sids.target_index])?;
    Ok(sids)
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

pub(crate) fn binary_bytes(value: &Value) -> Result<Vec<u8>, InspectionError> {
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

pub(crate) fn numeric_target_value(
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
    sids: ModelSids,
    rule: RuleSelector,
    entry_index: usize,
    target_value_index: usize,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    let mut previous_sid = 0;
    push_sid(&mut path, &mut previous_sid, sids.root)?;
    push_sid(&mut path, &mut previous_sid, sids.rule)?;
    path.push_key(json!(rule.value));
    path.push_key(json!(rule.bits));
    push_sid(&mut path, &mut previous_sid, sids.entry)?;
    path.push_key(json!(entry_index));
    push_sid(&mut path, &mut previous_sid, sids.target)?;
    path.push_key(json!(target_value_index));
    push_sid(&mut path, &mut previous_sid, sids.target_value)?;
    Ok(path)
}

pub(crate) fn push_sid(
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

pub(crate) fn detail_from_rule(rule: &Rule) -> RuleDetail {
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
        FieldLength::Remaining => "remaining".into(),
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

    fn shifted_sid_json() -> String {
        let mut document: Value = serde_json::from_str(include_str!(
            "../../../fixtures/demo/ietf-schc@2026-09-22.sid"
        ))
        .expect("SID JSON");
        let replacements = [
            ("/ietf-schc:schc", 2815),
            ("/ietf-schc:schc/rule", 2840),
            ("/ietf-schc:duplicate-rule/input", 2918),
            ("/ietf-schc:duplicate-rule/input/from", 2920),
            ("/ietf-schc:duplicate-rule/input/from/rule-id-length", 2923),
            ("/ietf-schc:duplicate-rule/input/from/rule-id-value", 2926),
            ("/ietf-schc:duplicate-rule/input/ipatch-sequence", 2930),
            ("/ietf-schc:duplicate-rule/input/to", 2934),
            ("/ietf-schc:duplicate-rule/input/to/rule-id-length", 2937),
            ("/ietf-schc:duplicate-rule/input/to/rule-id-value", 2940),
        ];
        let items = document
            .get_mut("ietf-sid-file:sid-file")
            .and_then(Value::as_object_mut)
            .and_then(|sid| sid.get_mut("item"))
            .and_then(Value::as_array_mut)
            .expect("SID items");
        for item in items {
            let Some(identifier) = item.get("identifier").and_then(Value::as_str) else {
                continue;
            };
            if let Some((_, sid)) = replacements.iter().find(|(path, _)| *path == identifier) {
                item["sid"] = json!(*sid);
            }
        }
        serde_json::to_string(&document).expect("shifted SID JSON")
    }

    fn map_value(entries: &[(CborValue, CborValue)], key: i64) -> &CborValue {
        entries
            .iter()
            .find(|(candidate, _)| *candidate == CborValue::Integer(key.into()))
            .map(|(_, value)| value)
            .expect("CBOR map key")
    }

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

    #[test]
    fn duplicate_rpc_encoder_uses_model_relative_sids() {
        let sid_json = shifted_sid_json();
        let model = CoreconfModel::from_sid_str(&sid_json).expect("shifted model");
        let request = RuleDuplicateRequest {
            source: RuleSelector::new(20, 8).expect("source"),
            destination: RuleSelector::new(22, 8).expect("destination"),
            overrides: Vec::new(),
        };
        let payload = duplicate::encode_duplicate_rpc_payload(&model, &request, &[])
            .expect("duplicate payload");
        let CborValue::Map(root) =
            ciborium::de::from_reader(std::io::Cursor::new(payload)).expect("CBOR")
        else {
            panic!("RPC root is not a map");
        };
        let CborValue::Map(operation) = map_value(&root, 2906) else {
            panic!("RPC operation is not a map");
        };
        let CborValue::Map(input) = map_value(operation, 12) else {
            panic!("RPC input is not a map");
        };
        let CborValue::Map(from) = map_value(input, 2) else {
            panic!("RPC from is not a map");
        };
        let CborValue::Map(to) = map_value(input, 16) else {
            panic!("RPC to is not a map");
        };
        let _ = map_value(from, 3);
        let _ = map_value(from, 6);
        let _ = map_value(to, 3);
        let _ = map_value(to, 6);
    }

    #[test]
    fn model_aware_rule_fetch_builders_use_shifted_sids() {
        let sid_json = shifted_sid_json();
        let list = Packet::from_bytes(&rule_list_request(&sid_json, 1).expect("rule list request"))
            .expect("rule list packet");
        assert_eq!(
            InstancePath::decode_cbor(&list.payload)
                .expect("rule list path")
                .components(),
            vec![PathComponent::SidDelta(2815)]
        );

        let get = Packet::from_bytes(
            &rule_get_request(&sid_json, RuleSelector::new(20, 8).expect("selector"), 2)
                .expect("rule get request"),
        )
        .expect("rule get packet");
        assert_eq!(
            InstancePath::decode_cbor(&get.payload)
                .expect("rule get path")
                .components(),
            vec![
                PathComponent::SidDelta(2815),
                PathComponent::SidDelta(25),
                PathComponent::SidDelta(20),
                PathComponent::SidDelta(8),
            ]
        );
    }

    #[test]
    fn token_policy_keeps_the_current_profile_empty_and_generates_valid_tokens() {
        let empty = TokenPolicy::Empty.token();
        assert!(empty.is_empty());

        let first = TokenPolicy::Generated.token();
        let second = TokenPolicy::Generated.token();
        assert_eq!(first.as_bytes().len(), 8);
        assert_eq!(second.as_bytes().len(), 8);
        assert_ne!(first, second);
    }

    #[test]
    fn exchange_id_round_trips_a_supported_nonempty_token() {
        let message = crate::CoapMessage::from_parts(
            1,
            COAP_CONFIRMABLE,
            1,
            0x1234,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            Vec::new(),
            b"payload".to_vec(),
        )
        .expect("CoAP message");
        let exchange = ExchangeId::from_message(&message).expect("exchange ID");
        assert_eq!(exchange.message_id(), 0x1234);
        assert_eq!(exchange.token().as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            exchange,
            ExchangeId::new(0x1234, exchange.token().as_bytes()).expect("same exchange ID")
        );
    }

    #[test]
    fn exchange_id_rejects_wrong_tokens_and_applies_coap_mid_rules() {
        assert!(matches!(
            ExchangeId::new(0, [0; 9]),
            Err(InspectionError::InvalidToken(_))
        ));
        let request = ExchangeId::new(7, [0xa1, 0xb2]).expect("request exchange ID");
        let same = ExchangeId::new(7, [0xa1, 0xb2]).expect("same exchange ID");
        let separate = ExchangeId::new(8, [0xa1, 0xb2]).expect("separate exchange ID");
        let wrong_token = ExchangeId::new(7, [0xa1, 0xc3]).expect("wrong-token exchange ID");

        assert!(request.matches_response(&same, COAP_ACKNOWLEDGEMENT));
        assert!(!request.matches_response(&separate, COAP_ACKNOWLEDGEMENT));
        assert!(request.matches_response(&separate, COAP_CONFIRMABLE));
        assert!(request.matches_response(&separate, COAP_NON_CONFIRMABLE));
        assert!(!request.matches_response(&wrong_token, COAP_CONFIRMABLE));
        assert!(!request.matches_response(&same, 3));
    }

    #[test]
    fn apply_token_policy_rewrites_the_coap_boundary_without_changing_request_shape() {
        let request = base_request(RequestType::Fetch, 19)
            .to_bytes()
            .expect("request");
        let rewritten = apply_token_policy(&request, TokenPolicy::Generated).expect("rewrite");
        let packet = Packet::from_bytes(&rewritten).expect("rewritten packet");
        assert_eq!(packet.header.message_id, 19);
        assert_eq!(packet.get_token().len(), 8);
        assert_eq!(
            packet
                .get_option(CoapOption::UriPath)
                .and_then(|paths| paths.front()),
            Some(&b"schc".to_vec())
        );
    }
}
