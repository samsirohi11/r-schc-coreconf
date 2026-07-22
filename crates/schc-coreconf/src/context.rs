use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use coreconf_model::{CoreconfError, CoreconfModel};
use coreconf_runtime::Backend;
use schc_core::{RuleContext, RuleId, SidRegistry};
use schc_runtime::{DeviceId, DeviceProfile, Runtime};
use serde_json::Value;

use crate::codec::{
    digest_context, encode_tree, ensure_schc_root, normalize_tree, strict_cbor_value,
};
use crate::policy::{ProtectedRules, ProtectionPolicy};
use crate::{ContextError, Result};

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

        // Use rustconf's model conversion, then normalize all ordered SCHC
        // lists before emitting the canonical complete SoR.
        let initial_tree = model
            .to_value(sor)
            .map_err(|error| ContextError::Model(error.to_string()))?;
        let initial_tree = normalize_tree(initial_tree)?;
        let canonical_sor = encode_tree(&model, &initial_tree)?;
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
    pub(crate) protected: ProtectedRules,
    digest: [u8; 32],
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
        let digest = digest_context(&loaded.tree, &loaded.sor)?;
        Ok(Self {
            recipe,
            tree: Arc::new(loaded.tree),
            sor: Arc::from(loaded.sor),
            runtime: Arc::new(runtime),
            protected: loaded.protected,
            digest,
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

/// The immutable tuple published by [`ActiveContext`].
#[derive(Debug)]
pub struct ContextSnapshot {
    tree: Arc<Value>,
    sor: Arc<[u8]>,
    runtime: Arc<Runtime>,
    generation: u64,
    digest: [u8; 32],
    protected: ProtectedRules,
}

impl ContextSnapshot {
    pub(crate) fn from_prepared(prepared: &PreparedContext, generation: u64) -> Self {
        Self {
            tree: Arc::clone(&prepared.tree),
            sor: Arc::clone(&prepared.sor),
            runtime: Arc::clone(&prepared.runtime),
            generation,
            digest: prepared.digest,
            protected: prepared.protected.clone(),
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

    /// Returns protected rules in this snapshot.
    #[must_use]
    pub const fn protected_rules(&self) -> &ProtectedRules {
        &self.protected
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
