//! Deterministic allocation of variable-length SCHC `RuleIDs`.

use schc_core::RuleId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProtectionPolicy;

/// The mechanism profile that owns protected and dynamically allocated
/// `RuleID` identities for a managed context.
///
/// The SCHC `SoR` remains authoritative for rule definitions and all
/// pre-provisioned identities. This small sidecar profile only describes the
/// policy-owned roles that cannot be inferred safely from unused branches.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextProfile {
    /// Rule identities reserved for CORECONF management traffic.
    #[serde(default)]
    pub protected_rule_ids: Vec<RuleIdSpec>,
    /// Explicit dynamic namespace, when automatic rule creation is enabled.
    #[serde(default)]
    pub dynamic_rule_ids: Option<DynamicRuleIdNamespace>,
}

impl ContextProfile {
    /// Parses a profile from its JSON representation.
    ///
    /// # Errors
    ///
    /// Returns the JSON parser error when the profile is malformed.
    pub fn from_json_str(input: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(input)
    }

    /// Validates the profile and returns a normalized copy.
    ///
    /// # Errors
    ///
    /// Returns an error when a protected identity or dynamic namespace is
    /// not a valid RFC 9363 `(RuleID value, RuleID length)` pair, or when the
    /// dynamic namespace has no valid configured leaf depth.
    ///
    /// The current SCHC codec supports only explicit `RuleIDs` with lengths
    /// 1..=32. RFC 9363 also defines length 0 for an implicit `RuleID`, but the
    /// codec does not currently implement that representation.
    pub fn validate(&self) -> Result<Self, RuleIdTreeError> {
        let mut protected_rule_ids = Vec::with_capacity(self.protected_rule_ids.len());
        for id in &self.protected_rule_ids {
            protected_rule_ids.push(RuleIdSpec::new(id.value, id.length)?);
        }
        protected_rule_ids.sort_by_key(|id| (id.length, id.value));
        protected_rule_ids.dedup();
        let dynamic_rule_ids = self
            .dynamic_rule_ids
            .as_ref()
            .map(DynamicRuleIdNamespace::validate)
            .transpose()?;
        Ok(Self {
            protected_rule_ids,
            dynamic_rule_ids,
        })
    }

    /// Converts the profile's protected identities into the internal policy.
    pub(crate) fn protection_policy(&self) -> ProtectionPolicy {
        ProtectionPolicy::from_rule_ids(self.protected_rule_ids.iter().map(|id| id.rule_id()))
    }
}

/// A `RuleID` value and its encoded bit length, as defined by RFC 9363.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuleIdSpec {
    /// Numeric value of the `RuleID` bits.
    pub value: u64,
    /// Number of encoded `RuleID` bits.
    #[serde(alias = "bit_len")]
    pub length: usize,
}

impl RuleIdSpec {
    /// Creates a validated explicit `RuleID` specification.
    ///
    /// Length 0 is the RFC 9363 implicit `RuleID` form, which is not supported
    /// by the current codec. This profile API therefore accepts only the
    /// explicit 1..=32-bit form.
    ///
    /// # Errors
    ///
    /// Returns an error when the value does not fit in the requested length.
    pub fn new(value: u64, length: usize) -> Result<Self, RuleIdTreeError> {
        if !(1..=32).contains(&length) {
            return Err(RuleIdTreeError::Invalid(format!(
                "explicit RuleID length must be between 1 and 32, got {length}"
            )));
        }
        if value >= (1_u64 << length) {
            return Err(RuleIdTreeError::Invalid(format!(
                "RuleID value {value} does not fit in {length} bits"
            )));
        }
        Ok(Self { value, length })
    }

    /// Converts this specification to the codec's `(value, length)` type.
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId::new(self.value, self.length)
    }
}

/// Explicit dynamic portion of a profile-defined `RuleID` tree.
///
/// `prefix` is a reserved internal branch, not an allocated `RuleID`. New
/// rules are leaves at one of `allowed_lengths`. Explicit leaf depths are
/// required because unused `RuleID` branches cannot safely be inferred to be
/// dynamic while a profile may add static rules later.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicRuleIdNamespace {
    /// Reserved prefix of the dynamic subtree.
    pub prefix: RuleIdSpec,
    /// Valid leaf depths for dynamically allocated `RuleIDs`.
    pub allowed_lengths: Vec<usize>,
}

impl DynamicRuleIdNamespace {
    /// Validates the namespace shape and returns a normalized copy.
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix or one of the leaf depths is invalid.
    pub fn validate(&self) -> Result<Self, RuleIdTreeError> {
        let prefix = RuleIdSpec::new(self.prefix.value, self.prefix.length)?;
        let mut allowed_lengths = self.allowed_lengths.clone();
        allowed_lengths.sort_unstable();
        allowed_lengths.dedup();
        if allowed_lengths.is_empty() {
            return Err(RuleIdTreeError::Invalid(
                "dynamic RuleID namespace requires at least one allowed length".into(),
            ));
        }
        for length in &allowed_lengths {
            if !(prefix.length + 1..=32).contains(length) {
                return Err(RuleIdTreeError::Invalid(format!(
                    "dynamic RuleID length {length} is outside prefix depth {}..=32",
                    prefix.length
                )));
            }
        }
        Ok(Self {
            prefix,
            allowed_lengths,
        })
    }

    /// Returns the first free valid leaf in tree order.
    ///
    /// # Errors
    ///
    /// Returns an error when the namespace is invalid, collides with an
    /// existing branch, or has no free leaf.
    pub fn allocate<I>(&self, occupied: I) -> Result<RuleId, RuleIdTreeError>
    where
        I: IntoIterator<Item = RuleId>,
    {
        let namespace = self.validate()?;
        let occupied: Vec<_> = occupied.into_iter().collect();
        if occupied
            .iter()
            .any(|id| overlaps(*id, namespace.prefix.rule_id()) && !namespace.accepts(*id))
        {
            return Err(RuleIdTreeError::Collision {
                value: namespace.prefix.value,
                length: namespace.prefix.length,
            });
        }

        for length in namespace.allowed_lengths {
            let suffix_bits = length - namespace.prefix.length;
            let suffix_count = if suffix_bits == 64 {
                u64::MAX
            } else {
                1_u64 << suffix_bits
            };
            let prefix_value = if suffix_bits == 64 {
                0
            } else {
                namespace
                    .prefix
                    .value
                    .checked_shl(u32::try_from(suffix_bits).map_err(|_| {
                        RuleIdTreeError::Invalid("dynamic RuleID prefix overflows".into())
                    })?)
                    .ok_or_else(|| {
                        RuleIdTreeError::Invalid("dynamic RuleID prefix overflows".into())
                    })?
            };
            for suffix in 0..suffix_count {
                let value = prefix_value | suffix;
                let candidate = RuleId::new(value, length);
                if occupied.iter().all(|id| !overlaps(*id, candidate)) {
                    return Ok(candidate);
                }
            }
        }
        Err(RuleIdTreeError::Exhausted)
    }

    /// Returns whether a `RuleID` belongs to this namespace at a permitted leaf depth.
    #[must_use]
    pub fn accepts(&self, id: RuleId) -> bool {
        self.validate().is_ok_and(|namespace| {
            namespace.allowed_lengths.contains(&id.bit_len())
                && is_prefix(namespace.prefix.rule_id(), id)
        })
    }

    /// Returns the normalized prefix and permitted depths.
    #[must_use]
    pub fn prefix(&self) -> RuleIdSpec {
        self.prefix
    }
}

/// Errors raised while validating or allocating a `RuleID` tree.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum RuleIdTreeError {
    /// The profile contains an invalid `RuleID` tree shape.
    #[error("invalid RuleID tree configuration: {0}")]
    Invalid(String),
    /// The reserved namespace overlaps a configured `RuleID`.
    #[error("RuleID tree namespace overlaps existing RuleID {value}/{length}")]
    Collision {
        /// Overlapping `RuleID` value.
        value: u64,
        /// Overlapping `RuleID` length.
        length: usize,
    },
    /// No configured leaf remains available.
    #[error("dynamic RuleID namespace is exhausted")]
    Exhausted,
}

/// Returns true when either `RuleID` is a prefix of the other.
#[must_use]
pub fn overlaps(left: RuleId, right: RuleId) -> bool {
    is_prefix(left, right) || is_prefix(right, left)
}

fn is_prefix(prefix: RuleId, value: RuleId) -> bool {
    if prefix.bit_len() > value.bit_len() {
        return false;
    }
    let suffix = value.bit_len() - prefix.bit_len();
    if suffix == 64 {
        return prefix.value() == 0;
    }
    value.value() >> suffix == prefix.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn namespace(lengths: &[usize]) -> DynamicRuleIdNamespace {
        DynamicRuleIdNamespace {
            prefix: RuleIdSpec {
                value: 0,
                length: 1,
            },
            allowed_lengths: lengths.to_vec(),
        }
    }

    #[test]
    fn allocates_shortest_leaf_then_lowest_pattern() {
        let tree = namespace(&[4, 3]);
        assert_eq!(tree.allocate([]).unwrap(), RuleId::new(0, 3));
        assert_eq!(
            tree.allocate([RuleId::new(0, 3)]).unwrap(),
            RuleId::new(1, 3)
        );
    }

    #[test]
    fn rejects_reserved_prefix_collision() {
        let tree = namespace(&[4]);
        assert!(matches!(
            tree.allocate([RuleId::new(0, 1)]),
            Err(RuleIdTreeError::Collision { .. })
        ));
        assert!(matches!(
            tree.allocate([RuleId::new(0, 2)]),
            Err(RuleIdTreeError::Collision { .. })
        ));
    }

    #[test]
    fn accepts_existing_dynamic_leaf_and_allocates_next() {
        let tree = namespace(&[4]);
        assert_eq!(
            tree.allocate([RuleId::new(0, 4)]).unwrap(),
            RuleId::new(1, 4)
        );
    }

    #[test]
    fn reports_exhaustion() {
        let tree = namespace(&[2]);
        assert!(matches!(
            tree.allocate([
                RuleId::new(0, 2),
                RuleId::new(1, 2),
                RuleId::new(2, 2),
                RuleId::new(3, 2)
            ]),
            Err(RuleIdTreeError::Exhausted)
        ));
    }

    #[test]
    fn profile_parses_explicit_protection_and_dynamic_namespace() {
        let profile = ContextProfile::from_json_str(
            r#"{
                "protected_rule_ids": [{"value": 63, "length": 6}],
                "dynamic_rule_ids": {
                    "prefix": {"value": 0, "length": 1},
                    "allowed_lengths": [4]
                }
            }"#,
        )
        .expect("profile JSON");
        let profile = profile.validate().expect("valid profile");
        assert_eq!(profile.protected_rule_ids[0].rule_id(), RuleId::new(63, 6));
        assert!(profile
            .dynamic_rule_ids
            .as_ref()
            .expect("dynamic namespace")
            .accepts(RuleId::new(0, 4)));
    }

    #[test]
    fn rejects_implicit_rule_id_length() {
        assert!(matches!(
            RuleIdSpec::new(0, 0),
            Err(RuleIdTreeError::Invalid(message)) if message.contains("between 1 and 32")
        ));
    }

    #[test]
    fn rejects_rule_id_length_above_rfc9363_range() {
        assert!(matches!(
            RuleIdSpec::new(0, 33),
            Err(RuleIdTreeError::Invalid(message)) if message.contains("between 1 and 32")
        ));
    }

    #[test]
    fn allocates_shortest_leaf_before_deeper_mixed_depth_leaf() {
        let tree = namespace(&[5, 3]);
        assert_eq!(tree.allocate([]).unwrap(), RuleId::new(0, 3));
        assert_eq!(
            tree.allocate([RuleId::new(0, 3)]).unwrap(),
            RuleId::new(1, 3)
        );
    }

    #[test]
    fn rejects_existing_rule_that_makes_dynamic_leaf_ambiguous() {
        let tree = namespace(&[4]);
        assert!(matches!(
            tree.allocate([RuleId::new(0, 3)]),
            Err(RuleIdTreeError::Collision { .. })
        ));
    }
}
