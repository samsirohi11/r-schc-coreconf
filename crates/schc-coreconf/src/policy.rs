use std::cmp::Ordering;

use schc_core::{Rule, RuleContext, RuleId, RuleNature};

use crate::{ContextError, Result};

/// Explicit protected `RuleIDs` in addition to rules whose nature is management.
///
/// The default policy derives protected IDs from `nature-management` rules.
/// Explicit IDs are useful for the deterministic demonstration fixture because
/// rule2sor 0.1.0 emits compression nature for its `OpenSCHC` `Compression`
/// entries and has no management-nature JSON key.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ProtectionPolicy {
    pub(crate) ids: Vec<RuleId>,
}

impl ProtectionPolicy {
    /// Creates a policy from explicit `RuleIDs`.
    #[must_use]
    pub fn from_rule_ids(ids: impl IntoIterator<Item = RuleId>) -> Self {
        let mut ids: Vec<_> = ids.into_iter().collect();
        ids.sort_by(rule_id_order);
        ids.dedup_by(|left, right| left == right);
        Self { ids }
    }

    /// Returns explicit protected `RuleIDs` in deterministic order.
    #[must_use]
    pub fn rule_ids(&self) -> &[RuleId] {
        &self.ids
    }
}

/// One immutable protected rule and its complete SCHC definition.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProtectedRule {
    pub(crate) id: RuleId,
    pub(crate) rule: Rule,
}

impl ProtectedRule {
    /// Returns the protected `RuleID`.
    #[must_use]
    pub const fn id(&self) -> RuleId {
        self.id
    }

    /// Returns the protected rule definition.
    #[must_use]
    pub const fn rule(&self) -> &Rule {
        &self.rule
    }
}

/// The protected-rule set derived from one complete SCHC context.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProtectedRules {
    pub(crate) rules: Vec<ProtectedRule>,
}

impl ProtectedRules {
    /// Derives policy from management-nature rules and explicit protected IDs.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MissingProtectedRule`] when an explicitly
    /// protected `RuleID` is absent from the context.
    pub fn derive(context: &RuleContext, policy: &ProtectionPolicy) -> Result<Self> {
        let mut ids = policy.ids.clone();
        ids.extend(
            context
                .rules()
                .rules()
                .iter()
                .filter(|rule| rule.nature() == RuleNature::Management)
                .map(Rule::id),
        );
        ids.sort_by(rule_id_order);
        ids.dedup_by(|left, right| left == right);

        let mut rules = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(rule) = context.find_rule(id).cloned() else {
                return Err(ContextError::MissingProtectedRule {
                    value: id.value(),
                    bit_len: id.bit_len(),
                });
            };
            rules.push(ProtectedRule { id, rule });
        }
        Ok(Self { rules })
    }

    /// Returns protected rules in deterministic `RuleID` order.
    #[must_use]
    pub fn rules(&self) -> &[ProtectedRule] {
        &self.rules
    }

    /// Returns protected `RuleIDs` in deterministic order.
    #[must_use]
    pub fn ids(&self) -> Vec<RuleId> {
        self.rules.iter().map(|rule| rule.id).collect()
    }

    /// Returns whether the exact `RuleID`, including its bit length, is protected.
    #[must_use]
    pub fn contains(&self, id: RuleId) -> bool {
        self.rules.iter().any(|rule| rule.id == id)
    }

    pub(crate) fn enforce(&self, candidate: &Self) -> Result<()> {
        if self.rules.len() != candidate.rules.len() {
            return Err(ContextError::ProtectedRuleChanged(format!(
                "protected RuleID set changed from {:?} to {:?}",
                self.ids(),
                candidate.ids()
            )));
        }
        for expected in &self.rules {
            let Some(actual) = candidate.rules.iter().find(|rule| rule.id == expected.id) else {
                return Err(ContextError::ProtectedRuleChanged(format!(
                    "RuleID {}/{} was deleted or re-identified",
                    expected.id.value(),
                    expected.id.bit_len()
                )));
            };
            if actual.rule != expected.rule {
                return Err(ContextError::ProtectedRuleChanged(format!(
                    "RuleID {}/{} content or nature differs",
                    expected.id.value(),
                    expected.id.bit_len()
                )));
            }
        }
        Ok(())
    }
}

pub(crate) fn rule_id_order(left: &RuleId, right: &RuleId) -> Ordering {
    left.bit_len()
        .cmp(&right.bit_len())
        .then_with(|| left.value().cmp(&right.value()))
}
