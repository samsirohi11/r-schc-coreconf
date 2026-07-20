use std::fmt;
use std::mem;
use std::sync::{Arc, Mutex, MutexGuard};

use coreconf_model::CoreconfError;
use coreconf_runtime::{TransactionContext, TransactionParticipant};
use serde_json::Value;

use crate::context::{ActiveContext, PreparedContext};
use crate::{ContextError, Result};

/// Shared transaction reservation state for every participant of one context.
///
/// Rustconf has no abort callback. A `Pending` value therefore remains present
/// until `post_commit` publishes it or a caller explicitly invokes
/// [`ContextParticipant::reset_transaction`] after a failed backend operation.
#[derive(Debug)]
pub(crate) enum TransactionState {
    Idle,
    Prepared(PreparedContext),
    Pending(PreparedContext),
}

/// Local-only rustconf transaction participant for an immediate root iPATCH.
///
/// Every participant created from, or cloned for, one [`ActiveContext`] shares
/// that context's single reservation state. Preparation, validation, and
/// publication are serialized so a backend transaction cannot lose a candidate
/// or publish a duplicate generation.
pub struct ContextParticipant {
    active: Arc<ActiveContext>,
}

impl Clone for ContextParticipant {
    fn clone(&self) -> Self {
        Self {
            active: Arc::clone(&self.active),
        }
    }
}

impl fmt::Debug for ContextParticipant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextParticipant")
            .field("active_generation", &self.active.generation())
            .finish_non_exhaustive()
    }
}

impl ContextParticipant {
    /// Creates a participant attached to an active context.
    #[must_use]
    pub fn new(active: Arc<ActiveContext>) -> Self {
        Self { active }
    }

    /// Returns the attached active context.
    #[must_use]
    pub fn active(&self) -> &Arc<ActiveContext> {
        &self.active
    }

    /// Prepares a context for the next matching root iPATCH.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PreparationBusy`] when this active context
    /// already has a prepared or backend-pending reservation.
    pub fn prepare(&self, prepared: PreparedContext) -> Result<()> {
        let mut state = lock_transaction(&self.active.transaction);
        if !matches!(*state, TransactionState::Idle) {
            return Err(ContextError::PreparationBusy);
        }
        *state = TransactionState::Prepared(prepared.with_base_digest(self.active.digest()));
        Ok(())
    }

    /// Builds and prepares a canonical tree for the next root iPATCH.
    ///
    /// # Errors
    ///
    /// Returns a context-construction error for an invalid candidate or
    /// [`ContextError::PreparationBusy`] when another reservation is live.
    pub fn prepare_tree(&self, tree: Value) -> Result<()> {
        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_tree(
            &recipe.sid_json,
            tree,
            recipe.device_id.clone(),
            recipe.profile.clone(),
            recipe.policy.clone(),
        )?;
        self.prepare(prepared)
    }

    /// Builds and prepares complete `SoR` bytes for the next root iPATCH.
    ///
    /// # Errors
    ///
    /// Returns a context-construction error for invalid `SoR` bytes or
    /// [`ContextError::PreparationBusy`] when another reservation is live.
    pub fn prepare_sor(&self, sor: &[u8]) -> Result<()> {
        let recipe = self.active.recipe();
        let prepared = PreparedContext::from_sor_with_policy(
            &recipe.sid_json,
            sor,
            recipe.device_id.clone(),
            recipe.profile.clone(),
            recipe.policy.clone(),
        )?;
        self.prepare(prepared)
    }

    /// Clears a prepared reservation that has not entered backend commit.
    ///
    /// A pending backend reservation is deliberately left untouched. Since
    /// rustconf has no abort callback, callers must use
    /// [`Self::reset_transaction`] explicitly after confirming that the
    /// backend failed and no post-commit callback can still arrive.
    pub fn clear_prepared(&self) {
        let mut state = lock_transaction(&self.active.transaction);
        if matches!(*state, TransactionState::Prepared(_)) {
            *state = TransactionState::Idle;
        }
    }

    /// Explicitly resets a prepared or backend-pending reservation.
    ///
    /// This is manual recovery for a backend failure because rustconf provides
    /// no abort callback. Call it only after confirming that the associated
    /// transaction cannot later invoke `post_commit`; clearing a live pending
    /// transaction would intentionally discard its committed candidate.
    pub fn reset_transaction(&self) {
        let mut state = lock_transaction(&self.active.transaction);
        *state = TransactionState::Idle;
    }

    /// Returns whether one preparation is waiting for a transaction.
    #[must_use]
    pub fn has_prepared(&self) -> bool {
        let state = lock_transaction(&self.active.transaction);
        matches!(*state, TransactionState::Prepared(_))
    }

    /// Returns whether a backend transaction has committed its candidate but
    /// has not yet delivered `post_commit`.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        let state = lock_transaction(&self.active.transaction);
        matches!(*state, TransactionState::Pending(_))
    }
}

impl TransactionParticipant for ContextParticipant {
    fn pre_commit(&self, context: &TransactionContext<'_>) -> coreconf_model::Result<()> {
        let mut state = lock_transaction(&self.active.transaction);
        let prepared = match &*state {
            TransactionState::Idle => {
                return Err(transaction_error(&ContextError::UnsupportedTransaction(
                    "no prepared context for root iPATCH".to_owned(),
                )))
            }
            TransactionState::Pending(_) => {
                return Err(transaction_error(&ContextError::PreparationBusy))
            }
            TransactionState::Prepared(prepared) if prepared.tree() != context.candidate_tree() => {
                // Another participant must not consume or clear a live
                // reservation for a different candidate.
                return Err(transaction_error(&ContextError::PreparationBusy));
            }
            TransactionState::Prepared(_) => {
                match mem::replace(&mut *state, TransactionState::Idle) {
                    TransactionState::Prepared(prepared) => prepared,
                    TransactionState::Idle | TransactionState::Pending(_) => unreachable!(),
                }
            }
        };

        if context.request().method != coreconf_runtime::Method::IPatch
            || !context.request().path.is_empty()
            || context.request().interface == Some(coreconf_runtime::Interface::Streaming)
        {
            return Err(transaction_error(&ContextError::UnsupportedTransaction(
                "participant accepts only a local root management iPATCH".to_owned(),
            )));
        }
        if let Err(error) = self.active.validate_prepared(&prepared) {
            return Err(transaction_error(&error));
        }
        *state = TransactionState::Pending(prepared);
        Ok(())
    }

    fn post_commit(&self, context: &TransactionContext<'_>) {
        let mut state = lock_transaction(&self.active.transaction);
        let matches_candidate = matches!(
            &*state,
            TransactionState::Pending(prepared) if prepared.tree() == context.candidate_tree()
        );
        if !matches_candidate {
            return;
        }
        let pending = mem::replace(&mut *state, TransactionState::Idle);
        if let TransactionState::Pending(prepared) = pending {
            self.active.publish_locked(&prepared);
        }
    }
}

fn transaction_error(error: &ContextError) -> CoreconfError {
    CoreconfError::ValidationError(format!("schc-coreconf transaction rejected: {error}"))
}

fn lock_transaction(state: &Mutex<TransactionState>) -> MutexGuard<'_, TransactionState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
