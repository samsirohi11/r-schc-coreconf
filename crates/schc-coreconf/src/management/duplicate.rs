use super::{
    binary_bytes, decode_instances_with_model_to_identifier_at_path, detail_from_rule, json,
    numeric_target_value, push_sid, BTreeMap, BTreeSet, CborValue, CoapOption, CompositeModel,
    ContextSnapshot, CoreconfModel, Cursor, Datastore, DuplicateRpcCost, DuplicateRpcOverride,
    FieldLength, FieldRef, FlowDirection, InspectionError, Instance, InstancePath, Ipv6UdpPacket,
    MatchingOperator, MessageClass, MessageType, ModelSids, Packet, PathComponent, RequestType,
    Rule, RuleDuplicateOverride, RuleDuplicateRequest, RuleNature, RuleSelector, TargetValue,
    Value,
};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum DuplicateLeaf {
    Target,
    MatchingOperator,
    Cda,
}

#[derive(Debug)]
pub(crate) struct FlowChangeCandidate {
    pub(crate) request: RuleDuplicateRequest,
    pub(crate) management_wire_bytes: usize,
}

pub(crate) fn has_application_payload(rule: &Rule) -> bool {
    rule.fields().iter().any(|field| {
        matches!(
            field.field,
            FieldRef::Payload | FieldRef::Udp("fid-udp-payload")
        )
    })
}

/// Returns whether a rule models the complete seven-field flow identity used
/// by the generic IPv6/UDP workload.  Header-only fallback rules can still
/// encode a packet, but they are not suitable parents for a concrete flow
/// duplicate and must not make an otherwise new flow look already installed.
pub(crate) fn has_complete_flow_fields(rule: &Rule) -> bool {
    let mut seen = [false; 7];
    for field in rule.fields() {
        if field.matching == MatchingOperator::Ignore
            || !matches!(field.target, TargetValue::Bytes(_))
        {
            continue;
        }
        let index = match field.field {
            FieldRef::Ipv6("fid-ipv6-flowlabel") => 0,
            FieldRef::Ipv6("fid-ipv6-devprefix") => 1,
            FieldRef::Ipv6("fid-ipv6-deviid") => 2,
            FieldRef::Ipv6("fid-ipv6-appprefix") => 3,
            FieldRef::Ipv6("fid-ipv6-appiid") => 4,
            FieldRef::Udp("fid-udp-dev-port") => 5,
            FieldRef::Udp("fid-udp-app-port") => 6,
            _ => continue,
        };
        seen[index] = true;
    }
    seen.into_iter().all(|present| present)
}

pub(crate) fn flow_overrides(
    parent: &Rule,
    packet: &Ipv6UdpPacket,
    direction: FlowDirection,
) -> Result<Option<Vec<RuleDuplicateOverride>>, InspectionError> {
    let schc_direction = direction.schc_direction();
    let mut overrides = Vec::new();
    for field in parent.fields() {
        if !field.direction.accepts(schc_direction) || field.matching == MatchingOperator::Ignore {
            continue;
        }
        let Some((actual, bits)) = logical_field_value(packet, direction, &field.field) else {
            if matches!(field.target, TargetValue::None) {
                continue;
            }
            return Ok(None);
        };
        let target_matches = match &field.target {
            TargetValue::None => false,
            TargetValue::Bytes(target) => target_matches(&actual, target, bits, field.matching),
            TargetValue::Mapping(targets) => targets
                .iter()
                .any(|target| target_matches(&actual, target, bits, field.matching)),
        };
        if target_matches {
            continue;
        }
        if !matches!(field.target, TargetValue::Bytes(_))
            || !matches!(field.length, FieldLength::FixedBits(_))
            || bits > 64
        {
            return Ok(None);
        }
        let value = bytes_to_u64(&actual).ok_or_else(|| {
            InspectionError::UnrepresentableFlow(format!(
                "entry {} exceeds 64 bits",
                field.entry_index
            ))
        })?;
        overrides.push(RuleDuplicateOverride {
            entry_index: field.entry_index,
            target_value: Some(value.to_string()),
            matching_operator: None,
            cda: None,
        });
    }
    overrides.sort_by_key(|override_| override_.entry_index);
    Ok(Some(overrides))
}

fn logical_field_value(
    packet: &Ipv6UdpPacket,
    direction: FlowDirection,
    field: &FieldRef,
) -> Option<(Vec<u8>, usize)> {
    let (device, application, device_port, application_port) = match direction {
        FlowDirection::Uplink => (
            packet.source(),
            packet.destination(),
            packet.source_port(),
            packet.destination_port(),
        ),
        FlowDirection::Downlink => (
            packet.destination(),
            packet.source(),
            packet.destination_port(),
            packet.source_port(),
        ),
    };
    let integer = |value: u64, bits: usize| Some((integer_bytes(value, bits), bits));
    match field {
        FieldRef::Ipv6(name) => match *name {
            "fid-ipv6-version" => integer(6, 4),
            "fid-ipv6-trafficclass" => integer(u64::from(packet.traffic_class()), 8),
            "fid-ipv6-flowlabel" => integer(u64::from(packet.flow_label()), 20),
            "fid-ipv6-payload-length" => integer(u64::from(packet.ipv6_payload_length()), 16),
            "fid-ipv6-nextheader" => integer(u64::from(packet.next_header()), 8),
            "fid-ipv6-hoplimit" => integer(u64::from(packet.hop_limit()), 8),
            "fid-ipv6-devprefix" => Some((device.octets()[..8].to_vec(), 64)),
            "fid-ipv6-deviid" => Some((device.octets()[8..].to_vec(), 64)),
            "fid-ipv6-appprefix" => Some((application.octets()[..8].to_vec(), 64)),
            "fid-ipv6-appiid" => Some((application.octets()[8..].to_vec(), 64)),
            _ => None,
        },
        FieldRef::Udp(name) => match *name {
            "fid-udp-dev-port" => integer(u64::from(device_port), 16),
            "fid-udp-app-port" => integer(u64::from(application_port), 16),
            "fid-udp-length" => integer(u64::from(packet.udp_length()), 16),
            "fid-udp-checksum" => integer(u64::from(packet.udp_checksum()), 16),
            _ => None,
        },
        _ => None,
    }
}

fn integer_bytes(value: u64, bits: usize) -> Vec<u8> {
    let length = bits.div_ceil(8);
    let bytes = value.to_be_bytes();
    bytes[bytes.len() - length..].to_vec()
}

fn bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut value = 0_u64;
    for byte in bytes {
        value = value.checked_shl(8)? | u64::from(*byte);
    }
    Some(value)
}

fn target_matches(actual: &[u8], target: &[u8], bits: usize, matching: MatchingOperator) -> bool {
    if matching == MatchingOperator::Equal {
        return bytes_to_u64(actual) == bytes_to_u64(target);
    }
    let compare_bits = match matching {
        MatchingOperator::Msb(prefix) => prefix.min(bits),
        _ => bits,
    };
    (0..compare_bits).all(|index| bit_at(actual, index) == bit_at(target, index))
}

fn bit_at(bytes: &[u8], index: usize) -> bool {
    bytes
        .get(index / 8)
        .is_some_and(|byte| byte & (0x80 >> (index % 8)) != 0)
}

#[derive(Debug)]
pub(crate) struct DecodedDuplicateOperation {
    pub(crate) request: RuleDuplicateRequest,
    pub(crate) instances: Vec<Instance>,
    pub(crate) inner_payload: Vec<u8>,
}

pub(crate) fn invalid_duplicate(message: impl Into<String>) -> InspectionError {
    InspectionError::InvalidUpdate(format!("duplicate-rule: {}", message.into()))
}

pub(crate) fn is_duplicate_rule_coap_shape(packet: &Packet) -> bool {
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

/// Returns whether a raw CORECONF datagram is a duplicate-rule request.
///
/// This semantic check deliberately does not assume a particular configured
/// `RuleID`; the protected rule is selected by the active context's loaded
/// `RuleNature::Management` classification.
#[must_use]
pub fn is_duplicate_rule_datagram(datagram: &[u8]) -> bool {
    Packet::from_bytes(datagram)
        .ok()
        .is_some_and(|packet| is_duplicate_rule_coap_shape(&packet))
}

fn validate_duplicate_model_shape(model: &CompositeModel) -> Result<ModelSids, InspectionError> {
    let sids = ModelSids::resolve(model)?;
    for sid in [
        sids.duplicate_rule,
        sids.duplicate_input,
        sids.duplicate_from,
        sids.duplicate_from_length,
        sids.duplicate_from_value,
        sids.duplicate_ipatch,
        sids.duplicate_to,
        sids.duplicate_to_length,
        sids.duplicate_to_value,
        sids.matching_operator,
        sids.cda,
    ] {
        if model.get_identifier(sid).is_none() {
            return Err(invalid_duplicate(format!(
                "SID model is missing identifier {sid}"
            )));
        }
    }
    Ok(sids)
}

fn rule_key(model: &CompositeModel, sid: i64) -> Result<String, InspectionError> {
    model
        .get_identifier(sid)
        .and_then(|identifier| identifier.rsplit('/').next())
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_duplicate(format!("SID model is missing rule key {sid}")))
}

pub(crate) fn find_tree_rule(
    tree: &Value,
    model: &CompositeModel,
    selector: RuleSelector,
) -> Result<Option<Value>, InspectionError> {
    let sids = ModelSids::resolve(model)?;
    let root_key = rule_key(model, sids.root)?;
    let list_key = rule_key(model, sids.rule)?;
    let value_key = rule_key(model, sids.rule_id_value)?;
    let length_key = rule_key(model, sids.rule_id_length)?;
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
pub(crate) fn expected_duplicate_tree(
    model: &CoreconfModel,
    snapshot: &ContextSnapshot,
    request: &RuleDuplicateRequest,
    instances: &[Instance],
) -> Result<Value, InspectionError> {
    let sids = validate_duplicate_model_shape(model.composite_model())?;
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

    let root_key = rule_key(model.composite_model(), sids.root)?;
    let list_key = rule_key(model.composite_model(), sids.rule)?;
    let value_key = rule_key(model.composite_model(), sids.rule_id_value)?;
    let length_key = rule_key(model.composite_model(), sids.rule_id_length)?;
    let mut destination_rule = source_rule;
    set_tree_rule_key(
        &mut destination_rule,
        model.composite_model(),
        sids.rule_id_value,
        json!(request.destination.value),
    )?;
    set_tree_rule_key(
        &mut destination_rule,
        model.composite_model(),
        sids.rule_id_length,
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
        let (entry_index, leaf) =
            duplicate_leaf_from_path(&instance.path, request.destination, &sids)?;
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
            .components()
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
    sids: &ModelSids,
) -> Result<(usize, DuplicateLeaf), InspectionError> {
    let mut absolute = 0_i64;
    let mut path_sids = Vec::new();
    let mut keys = Vec::new();
    for component in path.components() {
        match component {
            PathComponent::SidDelta(delta) => {
                absolute += delta;
                path_sids.push(absolute);
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
    let leaf = match path_sids.as_slice() {
        [root, rule, entry, matching]
            if [*root, *rule, *entry, *matching]
                == [sids.root, sids.rule, sids.entry, sids.matching_operator] =>
        {
            DuplicateLeaf::MatchingOperator
        }
        [root, rule, entry, cda]
            if [*root, *rule, *entry, *cda] == [sids.root, sids.rule, sids.entry, sids.cda] =>
        {
            DuplicateLeaf::Cda
        }
        [root, rule, entry, target, target_value]
            if [*root, *rule, *entry, *target, *target_value]
                == [
                    sids.root,
                    sids.rule,
                    sids.entry,
                    sids.target,
                    sids.target_value,
                ]
                && keys.len() == 4 =>
        {
            DuplicateLeaf::Target
        }
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
    sids: &ModelSids,
) -> Result<InstancePath, InspectionError> {
    let mut path = InstancePath::new();
    let mut previous = 0;
    for sid in [sids.root, sids.rule] {
        push_sid(&mut path, &mut previous, sid)?;
    }
    path.push_key(json!(destination.value));
    path.push_key(json!(destination.bits));
    push_sid(&mut path, &mut previous, sids.entry)?;
    path.push_key(json!(entry_index));
    match leaf {
        DuplicateLeaf::Target => {
            push_sid(&mut path, &mut previous, sids.target)?;
            path.push_key(json!(0));
            push_sid(&mut path, &mut previous, sids.target_value)?;
        }
        DuplicateLeaf::MatchingOperator => {
            push_sid(&mut path, &mut previous, sids.matching_operator)?;
        }
        DuplicateLeaf::Cda => {
            push_sid(&mut path, &mut previous, sids.cda)?;
        }
    }
    Ok(path)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn duplicate_inner_payload(
    model: &CompositeModel,
    snapshot: &ContextSnapshot,
    request: &RuleDuplicateRequest,
) -> Result<Vec<u8>, InspectionError> {
    let sids = validate_duplicate_model_shape(model)?;
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
                &sids,
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
                    &sids,
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
                    &sids,
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

pub(crate) fn encode_duplicate_rpc_payload(
    model: &CoreconfModel,
    request: &RuleDuplicateRequest,
    inner: &[u8],
) -> Result<Vec<u8>, InspectionError> {
    let sids = validate_duplicate_model_shape(model.composite_model())?;
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
    let sid_delta = |child: i64, parent: i64, name: &str| {
        child
            .checked_sub(parent)
            .ok_or_else(|| invalid_duplicate(format!("{name} SID delta overflows")))
    };
    let input_key = sid_delta(sids.duplicate_input, sids.duplicate_rule, "input")?;
    let from_key = sid_delta(sids.duplicate_from, sids.duplicate_input, "from")?;
    let from_length_key = sid_delta(
        sids.duplicate_from_length,
        sids.duplicate_from,
        "from/rule-id-length",
    )?;
    let from_value_key = sid_delta(
        sids.duplicate_from_value,
        sids.duplicate_from,
        "from/rule-id-value",
    )?;
    let ipatch_key = sid_delta(
        sids.duplicate_ipatch,
        sids.duplicate_input,
        "ipatch-sequence",
    )?;
    let to_key = sid_delta(sids.duplicate_to, sids.duplicate_input, "to")?;
    let to_length_key = sid_delta(
        sids.duplicate_to_length,
        sids.duplicate_to,
        "to/rule-id-length",
    )?;
    let to_value_key = sid_delta(
        sids.duplicate_to_value,
        sids.duplicate_to,
        "to/rule-id-value",
    )?;
    let from = CborValue::Map(vec![
        (integer(from_length_key), uint(source_bits)),
        (integer(from_value_key), uint(request.source.value)),
    ]);
    let to = CborValue::Map(vec![
        (integer(to_length_key), uint(destination_bits)),
        (integer(to_value_key), uint(request.destination.value)),
    ]);
    let mut input_entries = vec![
        (integer(from_key), from),
        (integer(ipatch_key), CborValue::Bytes(inner.to_vec())),
        (integer(to_key), to),
    ];
    if inner.is_empty() {
        input_entries.remove(1);
    }
    let value = CborValue::Map(vec![(integer(input_key), CborValue::Map(input_entries))]);
    let root = CborValue::Map(vec![(integer(sids.duplicate_rule), value)]);
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

pub(crate) fn decode_duplicate_operation(
    model: &CoreconfModel,
    payload: &[u8],
) -> Result<DecodedDuplicateOperation, InspectionError> {
    let sids = validate_duplicate_model_shape(model.composite_model())?;
    let outer = strict_one_cbor_map(payload)?;
    reject_duplicate_cbor_keys(&outer)?;
    let instances =
        decode_instances_with_model_to_identifier_at_path(model.composite_model(), payload, false)
            .map_err(|error| invalid_duplicate(format!("RPC payload decode failed: {error}")))?;
    if instances.len() != 1
        || instances[0].path.components() != [PathComponent::SidDelta(sids.duplicate_rule)]
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
    let inner_instances =
        decode_duplicate_inner(model.composite_model(), &inner, destination, &sids)?;
    let mut entries = BTreeSet::new();
    for instance in &inner_instances {
        let (entry, _) = duplicate_leaf_from_path(&instance.path, destination, &sids)?;
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
    let sids = validate_duplicate_model_shape(model.composite_model())?;
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
                duplicate_leaf_from_path(&instance.path, operation.request.destination, &sids)?;
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
    sids: &ModelSids,
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
            let (entry, leaf) = duplicate_leaf_from_path(&instance.path, destination, sids)?;
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
