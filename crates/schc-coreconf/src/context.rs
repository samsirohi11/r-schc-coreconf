use std::fmt;
use std::io::Cursor;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use ciborium::value::Value as CborValue;
use coreconf_model::{CoreconfError, CoreconfModel};
use coreconf_runtime::Backend;
use schc_core::{Rule, RuleContext, RuleId, SidRegistry};
use schc_runtime::{DeviceId, DeviceProfile, Runtime};
use serde_json::Value;

use crate::codec::{
    digest_context, encode_tree, ensure_schc_root, normalize_tree, strict_cbor_value,
};
use crate::policy::ProtectedRules;
use crate::{ContextError, ContextProfile, DynamicRuleIdNamespace, Result};

/// Number of bytes in a compact context tag.
pub const CONTEXT_TAG_LEN: usize = 8;

/// The context-level management guard period retained from the SCHC model.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GuardPeriod {
    /// Duration of one guard-period tick.
    pub ticks_duration: u8,
    /// Number of ticks in the guard period.
    pub ticks_numbers: u16,
}

/// A compact stable identifier for one canonical SCHC context.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextTag([u8; CONTEXT_TAG_LEN]);

impl ContextTag {
    pub(crate) const fn from_bytes(bytes: [u8; CONTEXT_TAG_LEN]) -> Self {
        Self(bytes)
    }

    /// Creates a tag from its exact eight-byte representation.
    #[must_use]
    pub const fn new(bytes: [u8; CONTEXT_TAG_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the exact bytes of this tag.
    #[must_use]
    pub const fn bytes(self) -> [u8; CONTEXT_TAG_LEN] {
        self.0
    }

    /// Returns the lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;
        let mut output = String::with_capacity(CONTEXT_TAG_LEN * 2);
        for byte in self.0 {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}

impl fmt::Display for ContextTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ContextTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContextTag")
            .field(&self.to_hex())
            .finish()
    }
}

/// A fully loaded, canonical SCHC/rustconf context before runtime binding.
#[derive(Debug, Clone)]
pub struct LoadedContext {
    model: CoreconfModel,
    sid_registry: SidRegistry,
    rule_context: RuleContext,
    tree: Value,
    sor: Vec<u8>,
    protected: ProtectedRules,
    guard_period: Option<GuardPeriod>,
}

impl LoadedContext {
    /// Loads a complete context with automatic management-rule protection.
    ///
    /// # Errors
    ///
    /// Returns an error when either model rejects the SID/SoR input, when the
    /// input is not complete strict CBOR, or when SCHC semantic validation
    /// fails.
    pub fn from_sor(sid_json: &str, sor: &[u8]) -> Result<Self> {
        let model = CoreconfModel::from_sid_str(sid_json)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let sid_registry = SidRegistry::from_json_str(sid_json)
            .map_err(|error| ContextError::Schc(error.to_string()))?;
        let value = strict_cbor_value(sor)?;
        let root_sid = model
            .composite_model()
            .get_sid("/ietf-schc:schc")
            .ok_or_else(|| {
                ContextError::Model("SID model is missing /ietf-schc:schc".to_owned())
            })?;
        ensure_schc_root(&value, root_sid)?;
        // Use rustconf's model conversion directly, then normalize all
        // ordered SCHC lists before emitting the canonical complete SoR.
        let initial_tree = model
            .to_value(sor)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let initial_tree = normalize_tree(initial_tree)?;
        let canonical_sor = encode_tree(&model, &initial_tree)?;
        strict_cbor_value(&canonical_sor)?;
        let canonical_tree = model
            .to_value(&canonical_sor)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let canonical_tree = normalize_tree(canonical_tree)?;
        if canonical_tree != initial_tree {
            return Err(ContextError::Model(
                "canonical tree does not round-trip through rustconf".to_owned(),
            ));
        }

        let rule_context = RuleContext::from_cbor_slice(&canonical_sor, sid_registry.clone())
            .map_err(|error| ContextError::Schc(error.to_string()))?;
        let protected = ProtectedRules::derive(&rule_context)?;
        let guard_period = guard_period_from_tree(&canonical_tree)?;
        Ok(Self {
            model,
            sid_registry,
            rule_context,
            tree: canonical_tree,
            sor: canonical_sor,
            protected,
            guard_period,
        })
    }

    /// Returns the rustconf model used for this context.
    #[must_use]
    pub const fn model(&self) -> &CoreconfModel {
        &self.model
    }

    /// Returns the r-schc SID registry used for this context.
    #[must_use]
    pub const fn sid_registry(&self) -> &SidRegistry {
        &self.sid_registry
    }

    /// Returns the typed r-schc context.
    #[must_use]
    pub const fn rule_context(&self) -> &RuleContext {
        &self.rule_context
    }

    /// Returns the canonical identifier-keyed datastore tree.
    #[must_use]
    pub const fn tree(&self) -> &Value {
        &self.tree
    }

    /// Returns canonical complete `SoR` bytes.
    #[must_use]
    pub fn sor(&self) -> &[u8] {
        &self.sor
    }

    /// Returns the derived immutable protected rules.
    #[must_use]
    pub const fn protected_rules(&self) -> &ProtectedRules {
        &self.protected
    }

    /// Returns the configured guard period when its optional tick count is
    /// present. An omitted tick duration uses the YANG default of 20.
    #[must_use]
    pub const fn guard_period(&self) -> Option<GuardPeriod> {
        self.guard_period
    }
}

fn guard_period_from_tree(tree: &Value) -> Result<Option<GuardPeriod>> {
    let Some(context) = tree
        .get("ietf-schc:context")
        .or_else(|| tree.get("context"))
    else {
        return Ok(None);
    };
    let Some(period) = context.get("guard-period") else {
        return Ok(None);
    };
    let Some(period) = period.as_object() else {
        return Err(ContextError::Model(
            "guard-period is not an object".to_owned(),
        ));
    };
    let duration = match period.get("ticks-duration") {
        None => 20,
        Some(value) => value
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| {
                ContextError::Model("guard-period/ticks-duration is not uint8".to_owned())
            })?,
    };
    let Some(numbers_value) = period.get("ticks-numbers") else {
        // The YANG leaf is optional and has no default. Keep the existing
        // public API's concrete GuardPeriod shape without inventing zero.
        return Ok(None);
    };
    let numbers = numbers_value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| {
            ContextError::Model("guard-period/ticks-numbers is not uint16".to_owned())
        })?;
    Ok(Some(GuardPeriod {
        ticks_duration: duration,
        ticks_numbers: numbers,
    }))
}

#[cfg(test)]
mod guard_period_tests {
    use super::{cbor_i64, guard_period_from_tree, GuardPeriod, LoadedContext};
    use ciborium::value::Value as CborValue;
    use serde_json::json;

    const SID: &str = include_str!("../../../fixtures/demo/ietf-schc@2026-09-22.sid");
    const SOR: &[u8] = include_bytes!("../../../fixtures/demo/initial.sor");

    #[test]
    fn guard_period_accepts_schema_boundaries() {
        assert_eq!(
            guard_period_from_tree(&json!({
                "ietf-schc:context": {
                    "guard-period": {
                        "ticks-duration": 255,
                        "ticks-numbers": 65535
                    }
                }
            }))
            .expect("guard period"),
            Some(GuardPeriod {
                ticks_duration: 255,
                ticks_numbers: 65535
            })
        );
    }

    #[test]
    fn guard_period_rejects_ticks_duration_above_uint8() {
        let error = guard_period_from_tree(&json!({
            "ietf-schc:context": {
                "guard-period": {
                    "ticks-duration": 256,
                    "ticks-numbers": 0
                }
            }
        }))
        .expect_err("ticks-duration 256 must be rejected");
        assert!(error.to_string().contains("ticks-duration is not uint8"));
    }

    #[test]
    fn guard_period_rejects_malformed_present_leaves() {
        let cases = [
            (
                json!({"ticks-duration": null, "ticks-numbers": 0}),
                "ticks-duration",
            ),
            (
                json!({"ticks-duration": "20", "ticks-numbers": 0}),
                "ticks-duration",
            ),
            (
                json!({"ticks-duration": -1, "ticks-numbers": 0}),
                "ticks-duration",
            ),
            (
                json!({"ticks-duration": 20, "ticks-numbers": null}),
                "ticks-numbers",
            ),
            (
                json!({"ticks-duration": 20, "ticks-numbers": "0"}),
                "ticks-numbers",
            ),
            (
                json!({"ticks-duration": 20, "ticks-numbers": -1}),
                "ticks-numbers",
            ),
            (
                json!({"ticks-duration": 20, "ticks-numbers": 65536}),
                "ticks-numbers",
            ),
        ];
        for (period, leaf) in cases {
            let error = guard_period_from_tree(&json!({
                "ietf-schc:context": {"guard-period": period}
            }))
            .expect_err("malformed guard-period leaf must be rejected");
            assert!(error.to_string().contains(&format!("{leaf} is not")));
        }
    }

    #[test]
    fn guard_period_rejects_non_object_container() {
        let error = guard_period_from_tree(&json!({
            "ietf-schc:context": {"guard-period": []}
        }))
        .expect_err("non-object guard-period must be rejected");
        assert!(error.to_string().contains("guard-period is not an object"));
    }

    #[test]
    fn guard_period_without_tick_count_is_not_materialized() {
        assert_eq!(
            guard_period_from_tree(&json!({
                "ietf-schc:context": {
                    "guard-period": {
                        "ticks-duration": 20
                    }
                }
            }))
            .expect("guard period"),
            None
        );
    }

    #[test]
    fn loaded_context_uses_default_duration_when_guard_duration_is_omitted() {
        let mut sor: CborValue =
            ciborium::de::from_reader(std::io::Cursor::new(SOR)).expect("demo SoR");
        let CborValue::Map(root) = &mut sor else {
            panic!("demo SoR root is not a map");
        };
        let context = root
            .iter_mut()
            .find_map(|(key, value)| (cbor_i64(key) == Some(2801)).then_some(value))
            .expect("demo context");
        let CborValue::Map(context) = context else {
            panic!("demo context is not a map");
        };
        let guard_period = context
            .iter_mut()
            .find_map(|(key, value)| (cbor_i64(key) == Some(1)).then_some(value))
            .expect("demo guard period");
        let CborValue::Map(guard_period) = guard_period else {
            panic!("demo guard period is not a map");
        };
        guard_period.retain(|(key, _)| cbor_i64(key) != Some(1));

        let mut partial_sor = Vec::new();
        ciborium::ser::into_writer(&sor, &mut partial_sor).expect("partial demo SoR");
        let loaded = LoadedContext::from_sor(SID, &partial_sor).expect("default duration");
        assert_eq!(
            loaded.guard_period(),
            Some(GuardPeriod {
                ticks_duration: 20,
                ticks_numbers: 10,
            })
        );
        assert!(loaded
            .tree()
            .get("ietf-schc:context")
            .and_then(|context| context.get("guard-period"))
            .and_then(|period| period.get("ticks-duration"))
            .is_none());
    }
}

/// Construction parameters shared by initial and candidate contexts.
#[derive(Debug, Clone)]
pub(crate) struct ContextRecipe {
    pub(crate) sid_json: Arc<str>,
    pub(crate) device_id: DeviceId,
    pub(crate) profile: DeviceProfile,
    pub(crate) dynamic_rule_ids: Option<DynamicRuleIdNamespace>,
    pub(crate) context_profile: Option<ContextProfile>,
}

enum ContextSource<'a> {
    Sor(&'a [u8]),
    Tree(Value),
}

impl ContextSource<'_> {
    fn load(self, sid_json: &str) -> Result<LoadedContext> {
        match self {
            Self::Sor(sor) => LoadedContext::from_sor(sid_json, sor),
            Self::Tree(tree) => {
                let model = CoreconfModel::from_sid_str(sid_json)
                    .map_err(|error| ContextError::Model(error.to_string()))?;
                let canonical_tree = normalize_tree(tree.clone())?;
                if canonical_tree != tree {
                    return Err(ContextError::NonCanonicalCandidate);
                }
                let sor = encode_tree(&model, &canonical_tree)?;
                let loaded = LoadedContext::from_sor(sid_json, &sor)?;
                if loaded.tree() != &canonical_tree {
                    return Err(ContextError::NonCanonicalCandidate);
                }
                Ok(loaded)
            }
        }
    }
}

fn context_recipe(
    sid_json: &str,
    device_id: DeviceId,
    profile: DeviceProfile,
    dynamic_rule_ids: Option<DynamicRuleIdNamespace>,
    context_profile: Option<ContextProfile>,
) -> ContextRecipe {
    ContextRecipe {
        sid_json: Arc::from(sid_json),
        device_id,
        profile,
        dynamic_rule_ids,
        context_profile,
    }
}

struct ContextData {
    tree: Arc<Value>,
    sor: Arc<[u8]>,
    // The full runtime serves protected management traffic; application
    // traffic uses the filtered runtime below.
    runtime: Arc<Runtime>,
    application_runtime: Arc<Runtime>,
    application_rule_ids: Arc<[RuleId]>,
    protected: ProtectedRules,
    guard_period: Option<GuardPeriod>,
    rule_ids: Arc<[RuleId]>,
    rules: Arc<[Rule]>,
    digest: [u8; 32],
    tag: ContextTag,
}

impl fmt::Debug for ContextData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextData")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

/// A prepared context bound to one canonical tree, `SoR`, runtime, and context identity.
#[derive(Debug, Clone)]
pub struct PreparedContext {
    pub(crate) recipe: ContextRecipe,
    data: Arc<ContextData>,
}

impl PreparedContext {
    /// Builds an initial prepared context from complete `SoR` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when SID/SoR loading, SCHC validation, or runtime
    /// construction fails.
    pub fn from_sor(
        sid_json: &str,
        sor: &[u8],
        device_id: DeviceId,
        profile: DeviceProfile,
    ) -> Result<Self> {
        Self::from_source(
            context_recipe(sid_json, device_id, profile, None, None),
            ContextSource::Sor(sor),
        )
    }

    /// Builds an initial context from a mechanism-owned context profile.
    ///
    /// The profile supplies the explicit dynamic `RuleID` namespace. D-IPT
    /// callers therefore do not select either `RuleID` values or lengths.
    ///
    /// # Errors
    ///
    /// Returns an error when profile validation, SID/SoR loading, or runtime
    /// construction fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_sor_with_context_profile(
        sid_json: &str,
        sor: &[u8],
        device_id: DeviceId,
        profile: DeviceProfile,
        context_profile: ContextProfile,
    ) -> Result<Self> {
        let context_profile = context_profile.validate()?;
        Self::from_source(
            context_recipe(
                sid_json,
                device_id,
                profile,
                context_profile.dynamic_rule_ids.clone(),
                Some(context_profile),
            ),
            ContextSource::Sor(sor),
        )
    }

    /// Builds a prepared context from an identifier-keyed canonical tree.
    ///
    /// A candidate must already use canonical list ordering. This strictness
    /// prevents the rustconf datastore tree from diverging from the active
    /// SCHC snapshot after a successful publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the tree is not canonical, cannot be encoded, is
    /// not a complete SCHC context, or cannot construct the runtime.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_tree(
        sid_json: &str,
        tree: Value,
        device_id: DeviceId,
        profile: DeviceProfile,
    ) -> Result<Self> {
        Self::from_source(
            context_recipe(sid_json, device_id, profile, None, None),
            ContextSource::Tree(tree),
        )
    }

    pub(crate) fn from_tree_for_recipe(recipe: &ContextRecipe, tree: Value) -> Result<Self> {
        Self::from_source(recipe.clone(), ContextSource::Tree(tree))
    }

    fn from_source(recipe: ContextRecipe, source: ContextSource<'_>) -> Result<Self> {
        let loaded = source.load(recipe.sid_json.as_ref())?;
        Self::from_loaded(recipe, loaded)
    }

    fn from_loaded(mut recipe: ContextRecipe, loaded: LoadedContext) -> Result<Self> {
        if let Some(dynamic_rule_ids) = &mut recipe.dynamic_rule_ids {
            *dynamic_rule_ids = dynamic_rule_ids.validate()?;
            for rule in loaded.rule_context.rules().rules() {
                if crate::allocation::overlaps(rule.id(), dynamic_rule_ids.prefix().rule_id())
                    && !dynamic_rule_ids.accepts(rule.id())
                {
                    return Err(ContextError::RuleIdTree(
                        crate::RuleIdTreeError::Collision {
                            value: rule.id().value(),
                            length: rule.id().bit_len(),
                        },
                    ));
                }
            }
        }
        let runtime = Runtime::new(
            recipe.device_id.clone(),
            loaded.rule_context.clone(),
            recipe.profile.clone(),
        )
        .map_err(|error| ContextError::Runtime(error.to_string()))?;
        let (application_runtime, application_rule_ids) = application_runtime(
            &loaded.sor,
            &loaded.model,
            &loaded.sid_registry,
            &loaded.protected,
            loaded.rule_context.clone(),
            recipe.device_id.clone(),
            recipe.profile.clone(),
        )?;
        let digest = digest_context(&loaded.tree, &loaded.sor)?;
        let tag = crate::codec::context_tag(digest);
        let rules: Arc<[Rule]> = Arc::from(loaded.rule_context.rules().rules().to_vec());
        let rule_ids = Arc::from(rules.iter().map(Rule::id).collect::<Vec<_>>());
        let data = ContextData {
            tree: Arc::new(loaded.tree),
            sor: Arc::from(loaded.sor),
            runtime: Arc::new(runtime),
            application_runtime: Arc::new(application_runtime),
            application_rule_ids,
            protected: loaded.protected,
            guard_period: loaded.guard_period,
            rule_ids,
            rules,
            digest,
            tag,
        };
        Ok(Self {
            recipe,
            data: Arc::new(data),
        })
    }

    /// Returns the canonical datastore tree without exposing mutable storage.
    #[must_use]
    pub fn tree(&self) -> &Value {
        self.data.tree.as_ref()
    }

    /// Returns canonical complete `SoR` bytes.
    #[must_use]
    pub fn sor(&self) -> &[u8] {
        self.data.sor.as_ref()
    }

    /// Returns the fully built schc-runtime runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.data.runtime.as_ref()
    }

    /// Returns the runtime as an immutable shared allocation.
    #[must_use]
    pub fn runtime_arc(&self) -> Arc<Runtime> {
        Arc::clone(&self.data.runtime)
    }

    fn digest(&self) -> [u8; 32] {
        self.data.digest
    }

    /// Returns the compact eight-byte context tag.
    #[must_use]
    pub fn tag(&self) -> ContextTag {
        self.data.tag
    }

    /// Returns protected rules captured by this preparation.
    #[must_use]
    pub fn protected_rules(&self) -> &ProtectedRules {
        &self.data.protected
    }

    /// Returns the configured guard period when its optional tick count is
    /// present. An omitted tick duration uses the YANG default of 20.
    #[must_use]
    pub fn guard_period(&self) -> Option<GuardPeriod> {
        self.data.guard_period
    }

    /// Returns protected `RuleIDs` captured by this preparation.
    #[must_use]
    pub fn protected_rule_ids(&self) -> Vec<RuleId> {
        self.data.protected.ids()
    }

    /// Returns the explicit dynamic `RuleID` namespace, when configured.
    #[must_use]
    pub fn dynamic_rule_ids(&self) -> Option<&DynamicRuleIdNamespace> {
        self.recipe.dynamic_rule_ids.as_ref()
    }

    /// Returns the mechanism-owned context profile, when one was supplied.
    #[must_use]
    pub fn context_profile(&self) -> Option<&ContextProfile> {
        self.recipe.context_profile.as_ref()
    }
}

fn application_runtime(
    sor: &[u8],
    model: &CoreconfModel,
    sid_registry: &SidRegistry,
    protected: &ProtectedRules,
    rule_context: RuleContext,
    device_id: DeviceId,
    profile: DeviceProfile,
) -> Result<(Runtime, Arc<[RuleId]>)> {
    if protected.ids().is_empty() {
        let ids = Arc::from(
            rule_context
                .rules()
                .rules()
                .iter()
                .map(Rule::id)
                .collect::<Vec<_>>(),
        );
        let runtime = Runtime::new(device_id, rule_context, profile)
            .map_err(|error| ContextError::Runtime(error.to_string()))?;
        return Ok((runtime, ids));
    }
    let mut filtered: CborValue = ciborium::de::from_reader(Cursor::new(sor))
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    let composite = model.composite_model();
    let root_sid = composite
        .get_sid("/ietf-schc:schc")
        .ok_or_else(|| ContextError::Model("SID model is missing /ietf-schc:schc".to_owned()))?;
    let rule_sid = composite.get_sid("/ietf-schc:schc/rule").ok_or_else(|| {
        ContextError::Model("SID model is missing /ietf-schc:schc/rule".to_owned())
    })?;
    let rule_id_length_sid = composite
        .get_sid("/ietf-schc:schc/rule/rule-id-length")
        .ok_or_else(|| ContextError::Model("SID model is missing rule-id-length".to_owned()))?;
    let rule_id_value_sid = composite
        .get_sid("/ietf-schc:schc/rule/rule-id-value")
        .ok_or_else(|| ContextError::Model("SID model is missing rule-id-value".to_owned()))?;
    let rule_delta = rule_sid
        .checked_sub(root_sid)
        .ok_or_else(|| ContextError::Model("rule SID precedes the SCHC root SID".to_owned()))?;
    let rule_id_length_delta = rule_id_length_sid.checked_sub(rule_sid).ok_or_else(|| {
        ContextError::Model("rule-id-length SID precedes the rule SID".to_owned())
    })?;
    let rule_id_value_delta = rule_id_value_sid
        .checked_sub(rule_sid)
        .ok_or_else(|| ContextError::Model("rule-id-value SID precedes the rule SID".to_owned()))?;
    let Some(root) = cbor_map_value_mut(&mut filtered, root_sid) else {
        return Err(ContextError::Cbor(
            "missing SCHC root in canonical SoR".to_owned(),
        ));
    };
    let Some(rules) = cbor_map_value_mut(root, rule_delta).and_then(CborValue::as_array_mut) else {
        return Err(ContextError::Cbor(
            "missing rule list in canonical SoR".to_owned(),
        ));
    };
    rules.retain(|rule| {
        let value = cbor_map_value(rule, rule_id_value_delta).and_then(cbor_u64);
        let length = cbor_map_value(rule, rule_id_length_delta).and_then(cbor_u64);
        match (value, length.and_then(|bits| usize::try_from(bits).ok())) {
            (Some(value), Some(bits)) => !protected.contains(RuleId::new(value, bits)),
            _ => true,
        }
    });
    let mut filtered_sor = Vec::new();
    ciborium::ser::into_writer(&filtered, &mut filtered_sor)
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    let filtered_context = RuleContext::from_cbor_slice(&filtered_sor, sid_registry.clone())
        .map_err(|error| ContextError::Schc(error.to_string()))?;
    let ids = Arc::from(
        filtered_context
            .rules()
            .rules()
            .iter()
            .map(Rule::id)
            .collect::<Vec<_>>(),
    );
    let runtime = Runtime::new(device_id, filtered_context, profile)
        .map_err(|error| ContextError::Runtime(error.to_string()))?;
    Ok((runtime, ids))
}

fn cbor_map_value(value: &CborValue, sid: i64) -> Option<&CborValue> {
    let CborValue::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (cbor_i64(key) == Some(sid)).then_some(value))
}

fn cbor_map_value_mut(value: &mut CborValue, sid: i64) -> Option<&mut CborValue> {
    let CborValue::Map(entries) = value else {
        return None;
    };
    entries
        .iter_mut()
        .find_map(|(key, value)| (cbor_i64(key) == Some(sid)).then_some(value))
}

fn cbor_i64(value: &CborValue) -> Option<i64> {
    let CborValue::Integer(integer) = value else {
        return None;
    };
    i64::try_from(*integer).ok()
}

fn cbor_u64(value: &CborValue) -> Option<u64> {
    let CborValue::Integer(integer) = value else {
        return None;
    };
    u64::try_from(*integer).ok()
}

/// The immutable tuple published by [`ActiveContext`].
#[derive(Debug)]
pub struct ContextSnapshot {
    data: Arc<ContextData>,
    generation: u64,
    dynamic_rule_ids: Option<DynamicRuleIdNamespace>,
    context_profile: Option<ContextProfile>,
}

impl ContextSnapshot {
    pub(crate) fn from_prepared(prepared: &PreparedContext, generation: u64) -> Self {
        Self {
            data: Arc::clone(&prepared.data),
            generation,
            dynamic_rule_ids: prepared.recipe.dynamic_rule_ids.clone(),
            context_profile: prepared.recipe.context_profile.clone(),
        }
    }

    /// Returns the canonical datastore tree.
    #[must_use]
    pub fn tree(&self) -> &Value {
        self.data.tree.as_ref()
    }

    /// Returns canonical complete `SoR` bytes.
    #[must_use]
    pub fn sor(&self) -> &[u8] {
        self.data.sor.as_ref()
    }

    /// Returns the fully built schc-runtime runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.data.runtime.as_ref()
    }

    /// Returns the shared runtime allocation.
    #[must_use]
    pub fn runtime_arc(&self) -> Arc<Runtime> {
        Arc::clone(&self.data.runtime)
    }

    pub(crate) fn application_runtime(&self) -> &Runtime {
        self.data.application_runtime.as_ref()
    }

    pub(crate) fn contains_application_rule_id(&self, id: RuleId) -> bool {
        self.data.application_rule_ids.contains(&id)
    }

    /// Returns the monotonic publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn digest(&self) -> [u8; 32] {
        self.data.digest
    }

    /// Returns the compact eight-byte context tag.
    #[must_use]
    pub fn tag(&self) -> ContextTag {
        self.data.tag
    }

    /// Returns all rules in deterministic canonical order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.data.rules
    }

    /// Returns protected rules in this snapshot.
    #[must_use]
    pub fn protected_rules(&self) -> &ProtectedRules {
        &self.data.protected
    }

    /// Returns the configured guard period when its optional tick count is
    /// present. An omitted tick duration uses the YANG default of 20.
    #[must_use]
    pub fn guard_period(&self) -> Option<GuardPeriod> {
        self.data.guard_period
    }

    /// Returns whether this snapshot contains the exact `RuleID`.
    #[must_use]
    pub fn contains_rule_id(&self, id: RuleId) -> bool {
        self.data.rule_ids.contains(&id)
    }

    /// Returns the explicit dynamic `RuleID` namespace, when configured.
    #[must_use]
    pub fn dynamic_rule_ids(&self) -> Option<&DynamicRuleIdNamespace> {
        self.dynamic_rule_ids.as_ref()
    }

    /// Returns the mechanism-owned context profile, when one was supplied.
    #[must_use]
    pub fn context_profile(&self) -> Option<&ContextProfile> {
        self.context_profile.as_ref()
    }
}

/// Atomic immutable active-context publisher and rustconf backend source.
///
/// The `ArcSwap` is private by design. An [`ActiveContextBackend`] reads from
/// this publisher and validates complete candidate trees while holding the
/// writer lock, then publishes one immutable tuple. There is no detached
/// datastore tree or pending transaction state.
pub struct ActiveContext {
    snapshot: ArcSwap<ContextSnapshot>,
    recipe: ContextRecipe,
    pub(crate) writer: Mutex<()>,
}

impl fmt::Debug for ActiveContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveContext")
            .field("generation", &self.snapshot.load().generation())
            .field("tag", &self.snapshot.load().tag())
            .finish_non_exhaustive()
    }
}

impl ActiveContext {
    /// Creates an active context with generation one.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(prepared: PreparedContext) -> Self {
        let recipe = prepared.recipe.clone();
        let snapshot = ContextSnapshot::from_prepared(&prepared, 1);
        Self {
            snapshot: ArcSwap::from_pointee(snapshot),
            recipe,
            writer: Mutex::new(()),
        }
    }

    /// Loads one immutable snapshot. All tuple members come from this value.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ContextSnapshot> {
        self.snapshot.load_full()
    }

    /// Returns the current generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.snapshot.load().generation()
    }

    fn digest(&self) -> [u8; 32] {
        self.snapshot.load().digest()
    }

    /// Returns the current compact eight-byte context tag.
    #[must_use]
    pub fn tag(&self) -> ContextTag {
        self.snapshot.load().tag()
    }

    /// Returns the current configured guard period when its optional tick count
    /// is present. An omitted tick duration uses the YANG default of 20.
    #[must_use]
    pub fn guard_period(&self) -> Option<GuardPeriod> {
        self.snapshot.load().guard_period()
    }

    /// Returns the current canonical tree as a detached value.
    #[must_use]
    pub fn tree(&self) -> Value {
        self.snapshot.load().tree().clone()
    }

    /// Returns current canonical complete `SoR` bytes as a detached value.
    #[must_use]
    pub fn sor(&self) -> Vec<u8> {
        self.snapshot.load().sor().to_vec()
    }

    /// Creates a rustconf backend whose datastore tree is this active context.
    ///
    /// Construct a rustconf [`coreconf_runtime::Datastore`] with the returned
    /// backend, rather than copying [`Self::tree`]. Each backend handle tracks
    /// the snapshot it read and rejects a stale replacement, so concurrent
    /// request handlers cannot overwrite a later publication.
    #[must_use]
    pub fn backend(self: &Arc<Self>) -> ActiveContextBackend {
        ActiveContextBackend {
            active: Arc::clone(self),
            observed: Mutex::new(Some(self.digest())),
        }
    }

    pub(crate) fn publish_locked(&self, prepared: &PreparedContext) {
        let generation = self
            .snapshot
            .load()
            .generation()
            .checked_add(1)
            .expect("active context generation exhausted");
        self.snapshot.store(Arc::new(ContextSnapshot::from_prepared(
            prepared, generation,
        )));
    }

    pub(crate) fn recipe(&self) -> &ContextRecipe {
        &self.recipe
    }

    pub(crate) fn validate_candidate(
        &self,
        current: &ContextSnapshot,
        prepared: &PreparedContext,
    ) -> Result<()> {
        if prepared.recipe.sid_json != self.recipe.sid_json
            || prepared.recipe.device_id != self.recipe.device_id
            || prepared.recipe.profile != self.recipe.profile
            || prepared.recipe.dynamic_rule_ids != self.recipe.dynamic_rule_ids
            || prepared.recipe.context_profile != self.recipe.context_profile
        {
            return Err(ContextError::CandidateRecipeMismatch);
        }
        let canonical_sor = crate::canonical_sor_from_tree(&self.recipe.sid_json, prepared.tree())?;
        if canonical_sor != prepared.sor() {
            return Err(ContextError::NonCanonicalCandidate);
        }
        current
            .protected_rules()
            .enforce(prepared.protected_rules())
    }
}

/// A rustconf [`coreconf_runtime::Backend`] backed by one [`ActiveContext`].
///
/// Reads return the active snapshot's canonical tree. Replacements use
/// compare-and-swap semantics: the backend records the digest observed by its
/// last read (or at backend construction), acquires the active writer lock,
/// rebuilds and validates the full candidate context, and publishes only after
/// all checks and runtime construction succeed. A failed replacement records no
/// pending candidate and leaves the previous immutable tuple untouched.
pub struct ActiveContextBackend {
    active: Arc<ActiveContext>,
    observed: Mutex<Option<[u8; 32]>>,
}

impl fmt::Debug for ActiveContextBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveContextBackend")
            .field("active_generation", &self.active.generation())
            .finish_non_exhaustive()
    }
}

impl Backend for ActiveContextBackend {
    fn read_tree(&self) -> Value {
        let snapshot = self.active.snapshot();
        *lock_observed(&self.observed) = Some(snapshot.digest());
        snapshot.tree().clone()
    }

    fn replace_tree(&mut self, next: Value) -> coreconf_model::Result<()> {
        let mut observed = lock_observed(&self.observed);
        let _writer = lock_writer(&self.active.writer);
        let current = self.active.snapshot();
        if *observed != Some(current.digest()) {
            return Err(CoreconfError::ValidationError(
                "active context changed while candidate was being built".to_owned(),
            ));
        }

        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_tree_for_recipe(recipe, next)
            .map_err(|error| backend_error(&error))?;
        self.active
            .validate_candidate(&current, &prepared)
            .map_err(|error| backend_error(&error))?;
        self.active.publish_locked(&prepared);
        *observed = Some(prepared.digest());
        Ok(())
    }
}

fn backend_error(error: &ContextError) -> CoreconfError {
    CoreconfError::ValidationError(format!("schc-coreconf backend rejected candidate: {error}"))
}

fn lock_observed(state: &Mutex<Option<[u8; 32]>>) -> MutexGuard<'_, Option<[u8; 32]>> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_writer(state: &Mutex<()>) -> MutexGuard<'_, ()> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
