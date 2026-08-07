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
use crate::policy::{ProtectedRules, ProtectionPolicy};
use crate::{ContextError, Result};

/// Number of bytes in a compact context tag.
pub const CONTEXT_TAG_LEN: usize = 8;

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
        Self::from_sor_with_policy(sid_json, sor, ProtectionPolicy::default())
    }

    /// Loads a complete context with explicit and automatic protected rules.
    ///
    /// # Errors
    ///
    /// Returns an error when either model rejects the SID/SoR input, when the
    /// input is not complete strict CBOR, when SCHC semantic validation fails,
    /// or when an explicit protected rule is absent.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_sor_with_policy(
        sid_json: &str,
        sor: &[u8],
        policy: ProtectionPolicy,
    ) -> Result<Self> {
        let model = CoreconfModel::from_sid_str(sid_json)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let sid_registry = SidRegistry::from_json_str(sid_json)
            .map_err(|error| ContextError::Schc(error.to_string()))?;
        let value = strict_cbor_value(sor)?;
        ensure_schc_root(&value)?;
        let rustconf_sor = rustconf_compatible_sor(&value)?;

        // Use rustconf's model conversion, then normalize all ordered SCHC
        // lists before emitting the canonical complete SoR. The accepted
        // rustconf codec resolves identityrefs from their numeric SID values
        // and deliberately rejects the SCHC identityref tag, so only its
        // private conversion view removes tag 45. The canonical wire value
        // remains tagged through encode_tree's restoration step.
        let initial_tree = model
            .to_value(&rustconf_sor)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let initial_tree = normalize_tree(initial_tree)?;
        let canonical_sor = encode_tree(&model, &initial_tree)?;
        let canonical_value = strict_cbor_value(&canonical_sor)?;
        let canonical_rustconf_sor = rustconf_compatible_sor(&canonical_value)?;
        let canonical_tree = model
            .to_value(&canonical_rustconf_sor)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let canonical_tree = normalize_tree(canonical_tree)?;
        if canonical_tree != initial_tree {
            return Err(ContextError::Model(
                "canonical tree does not round-trip through rustconf".to_owned(),
            ));
        }

        let rule_context = RuleContext::from_cbor_slice(&canonical_sor, sid_registry.clone())
            .map_err(|error| ContextError::Schc(error.to_string()))?;
        let protected = ProtectedRules::derive(&rule_context, &policy)?;
        Ok(Self {
            model,
            sid_registry,
            rule_context,
            tree: canonical_tree,
            sor: canonical_sor,
            protected,
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
}

fn rustconf_compatible_sor(value: &CborValue) -> Result<Vec<u8>> {
    let value = strip_identityref_tags(value.clone());
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes)
        .map_err(|error| ContextError::Cbor(error.to_string()))?;
    let _ = strict_cbor_value(&bytes)?;
    Ok(bytes)
}

fn strip_identityref_tags(value: CborValue) -> CborValue {
    match value {
        CborValue::Array(values) => {
            CborValue::Array(values.into_iter().map(strip_identityref_tags).collect())
        }
        CborValue::Map(entries) => CborValue::Map(
            entries
                .into_iter()
                .map(|(key, value)| (strip_identityref_tags(key), strip_identityref_tags(value)))
                .collect(),
        ),
        CborValue::Tag(45, value) => strip_identityref_tags(*value),
        CborValue::Tag(tag, value) => CborValue::Tag(tag, Box::new(strip_identityref_tags(*value))),
        other => other,
    }
}

/// Construction parameters shared by initial and candidate contexts.
#[derive(Debug, Clone)]
pub(crate) struct ContextRecipe {
    pub(crate) sid_json: Arc<str>,
    pub(crate) device_id: DeviceId,
    pub(crate) profile: DeviceProfile,
    pub(crate) policy: ProtectionPolicy,
}

/// A prepared context bound to one canonical tree, `SoR`, runtime, and digest.
#[derive(Debug, Clone)]
pub struct PreparedContext {
    pub(crate) recipe: ContextRecipe,
    pub(crate) tree: Arc<Value>,
    pub(crate) sor: Arc<[u8]>,
    runtime: Arc<Runtime>,
    application_runtime: Arc<Runtime>,
    pub(crate) application_rule_ids: Arc<[RuleId]>,
    pub(crate) protected: ProtectedRules,
    pub(crate) rule_ids: Arc<[RuleId]>,
    pub(crate) rules: Arc<[Rule]>,
    digest: [u8; 32],
    tag: ContextTag,
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
        Self::from_sor_with_policy(
            sid_json,
            sor,
            device_id,
            profile,
            ProtectionPolicy::default(),
        )
    }

    /// Builds an initial prepared context with explicit protected `RuleIDs`.
    ///
    /// # Errors
    ///
    /// Returns an error when SID/SoR loading, SCHC validation, explicit
    /// protected-rule derivation, or runtime construction fails.
    pub fn from_sor_with_policy(
        sid_json: &str,
        sor: &[u8],
        device_id: DeviceId,
        profile: DeviceProfile,
        policy: ProtectionPolicy,
    ) -> Result<Self> {
        let loaded = LoadedContext::from_sor_with_policy(sid_json, sor, policy.clone())?;
        Self::from_loaded(
            ContextRecipe {
                sid_json: Arc::from(sid_json),
                device_id,
                profile,
                policy,
            },
            loaded,
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
        policy: ProtectionPolicy,
    ) -> Result<Self> {
        let model = CoreconfModel::from_sid_str(sid_json)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let canonical_tree = normalize_tree(tree.clone())?;
        if canonical_tree != tree {
            return Err(ContextError::NonCanonicalCandidate);
        }
        let sor = encode_tree(&model, &canonical_tree)?;
        let loaded = LoadedContext::from_sor_with_policy(sid_json, &sor, policy.clone())?;
        if loaded.tree != canonical_tree {
            return Err(ContextError::NonCanonicalCandidate);
        }
        Self::from_loaded(
            ContextRecipe {
                sid_json: Arc::from(sid_json),
                device_id,
                profile,
                policy,
            },
            loaded,
        )
    }

    fn from_loaded(recipe: ContextRecipe, loaded: LoadedContext) -> Result<Self> {
        let runtime = Runtime::new(
            recipe.device_id.clone(),
            loaded.rule_context.clone(),
            recipe.profile.clone(),
        )
        .map_err(|error| ContextError::Runtime(error.to_string()))?;
        let (application_runtime, application_rule_ids) = application_runtime(
            &loaded.sor,
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
        Ok(Self {
            recipe,
            tree: Arc::new(loaded.tree),
            sor: Arc::from(loaded.sor),
            runtime: Arc::new(runtime),
            application_runtime: Arc::new(application_runtime),
            application_rule_ids,
            protected: loaded.protected,
            rule_ids,
            rules,
            digest,
            tag,
        })
    }

    /// Returns the canonical datastore tree without exposing mutable storage.
    #[must_use]
    pub fn tree(&self) -> &Value {
        self.tree.as_ref()
    }

    /// Returns canonical complete `SoR` bytes.
    #[must_use]
    pub fn sor(&self) -> &[u8] {
        self.sor.as_ref()
    }

    /// Returns the fully built schc-runtime runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.runtime.as_ref()
    }

    /// Returns the runtime as an immutable shared allocation.
    #[must_use]
    pub fn runtime_arc(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    /// Returns the deterministic domain-separated SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the compact eight-byte context tag.
    #[must_use]
    pub const fn tag(&self) -> ContextTag {
        self.tag
    }

    /// Returns protected rules captured by this preparation.
    #[must_use]
    pub const fn protected_rules(&self) -> &ProtectedRules {
        &self.protected
    }

    /// Returns protected `RuleIDs` captured by this preparation.
    #[must_use]
    pub fn protected_rule_ids(&self) -> Vec<RuleId> {
        self.protected.ids()
    }

    /// Returns a copy of the digest as a hexadecimal string.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(self.digest.len() * 2);
        for byte in self.digest {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}

const SCHC_ROOT_SID: i64 = 2574;
const RULE_LIST_SID: i64 = 23;
const RULE_ID_LENGTH_SID: i64 = 1;
const RULE_ID_VALUE_SID: i64 = 2;

fn application_runtime(
    sor: &[u8],
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
    let Some(root) = cbor_map_value_mut(&mut filtered, SCHC_ROOT_SID) else {
        return Err(ContextError::Cbor(
            "missing SCHC root in canonical SoR".to_owned(),
        ));
    };
    let Some(rules) = cbor_map_value_mut(root, RULE_LIST_SID).and_then(CborValue::as_array_mut)
    else {
        return Err(ContextError::Cbor(
            "missing rule list in canonical SoR".to_owned(),
        ));
    };
    rules.retain(|rule| {
        let value = cbor_map_value(rule, RULE_ID_VALUE_SID).and_then(cbor_u64);
        let length = cbor_map_value(rule, RULE_ID_LENGTH_SID).and_then(cbor_u64);
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
    tree: Arc<Value>,
    sor: Arc<[u8]>,
    runtime: Arc<Runtime>,
    application_runtime: Arc<Runtime>,
    application_rule_ids: Arc<[RuleId]>,
    generation: u64,
    digest: [u8; 32],
    protected: ProtectedRules,
    rule_ids: Arc<[RuleId]>,
    rules: Arc<[Rule]>,
    tag: ContextTag,
}

impl ContextSnapshot {
    pub(crate) fn from_prepared(prepared: &PreparedContext, generation: u64) -> Self {
        Self {
            tree: Arc::clone(&prepared.tree),
            sor: Arc::clone(&prepared.sor),
            runtime: Arc::clone(&prepared.runtime),
            application_runtime: Arc::clone(&prepared.application_runtime),
            application_rule_ids: Arc::clone(&prepared.application_rule_ids),
            generation,
            digest: prepared.digest,
            protected: prepared.protected.clone(),
            rule_ids: Arc::clone(&prepared.rule_ids),
            rules: Arc::clone(&prepared.rules),
            tag: prepared.tag,
        }
    }

    /// Returns the canonical datastore tree.
    #[must_use]
    pub fn tree(&self) -> &Value {
        self.tree.as_ref()
    }

    /// Returns canonical complete `SoR` bytes.
    #[must_use]
    pub fn sor(&self) -> &[u8] {
        self.sor.as_ref()
    }

    /// Returns the fully built schc-runtime runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        self.runtime.as_ref()
    }

    /// Returns the shared runtime allocation.
    #[must_use]
    pub fn runtime_arc(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    pub(crate) fn application_runtime(&self) -> &Runtime {
        self.application_runtime.as_ref()
    }

    pub(crate) fn contains_application_rule_id(&self, id: RuleId) -> bool {
        self.application_rule_ids.contains(&id)
    }

    /// Returns the monotonic publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the deterministic context digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the compact eight-byte context tag.
    #[must_use]
    pub const fn tag(&self) -> ContextTag {
        self.tag
    }

    /// Returns all rules in deterministic canonical order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns protected rules in this snapshot.
    #[must_use]
    pub const fn protected_rules(&self) -> &ProtectedRules {
        &self.protected
    }

    /// Returns whether this snapshot contains the exact `RuleID`.
    #[must_use]
    pub fn contains_rule_id(&self, id: RuleId) -> bool {
        self.rule_ids.contains(&id)
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
            .field("digest", &self.snapshot.load().digest())
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

    /// Returns the current digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.snapshot.load().digest()
    }

    /// Returns the current compact eight-byte context tag.
    #[must_use]
    pub fn tag(&self) -> ContextTag {
        self.snapshot.load().tag()
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
            || prepared.recipe.policy != self.recipe.policy
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
        let prepared = PreparedContext::from_tree(
            &recipe.sid_json,
            next,
            recipe.device_id.clone(),
            recipe.profile.clone(),
            recipe.policy.clone(),
        )
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
