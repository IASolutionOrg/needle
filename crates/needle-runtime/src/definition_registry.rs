use crate::{
    BuiltInActionCoverage, built_in_action_contracts, dependency_intersection_definition_digest,
    fast_validity_definition_digest,
};
use needle_core::{
    DefinitionHandle, DefinitionKind, DefinitionSet, DefinitionSetEntry,
    built_in_predicate_contracts, need_grammar_definition_digest, need_ir_definition_digest,
};
use std::sync::OnceLock;

pub fn active_definition_set() -> &'static DefinitionSet {
    static ACTIVE: OnceLock<DefinitionSet> = OnceLock::new();
    ACTIVE.get_or_init(|| {
        build_active_definition_set().expect("built-in definition set must be canonical")
    })
}

fn build_active_definition_set() -> Result<DefinitionSet, needle_core::DefinitionGenerationError> {
    let mut entries = Vec::with_capacity(44);
    let grammar = need_grammar_definition_digest();
    entries.push(DefinitionSetEntry::new(
        DefinitionKind::NeedGrammar,
        DefinitionHandle::new("needle.need.text-grammar")?,
        Some(grammar),
        None,
        None,
        grammar,
    )?);
    let need_ir = need_ir_definition_digest();
    entries.push(DefinitionSetEntry::new(
        DefinitionKind::NeedGrammar,
        DefinitionHandle::new("needle.need.ir")?,
        Some(need_ir),
        None,
        None,
        need_ir,
    )?);

    for predicate in built_in_predicate_contracts() {
        entries.push(DefinitionSetEntry::new(
            DefinitionKind::PredicateContract,
            DefinitionHandle::new(format!("needle.predicate.{}", predicate.predicate.as_str()))?,
            Some(predicate.definition_digest),
            None,
            None,
            predicate.definition_digest,
        )?);
    }

    for definition in built_in_action_contracts() {
        let action_handle = DefinitionHandle::new(definition.contract.id.as_str())?;
        entries.push(DefinitionSetEntry::new(
            DefinitionKind::ActionContract,
            action_handle.clone(),
            Some(definition.contract.semantic_definition_digest),
            Some(definition.contract.validation_definition_digest),
            Some(definition.contract.operational_policy_digest),
            definition.contract.definition_digest,
        )?);
        entries.push(DefinitionSetEntry::new(
            DefinitionKind::ArtifactContract,
            DefinitionHandle::new(format!(
                "{}@{}",
                definition.output_contract_id, definition.output_contract_revision
            ))?,
            Some(definition.output_contract_definition_digest),
            None,
            None,
            definition.output_contract_definition_digest,
        )?);
        entries.push(DefinitionSetEntry::new(
            DefinitionKind::ValidatorDefinition,
            action_handle.clone(),
            None,
            Some(definition.validator_definition_digest),
            None,
            definition.validator_definition_digest,
        )?);
        if let BuiltInActionCoverage::Partitioned { policy_definition_digest } = definition.coverage
        {
            entries.push(DefinitionSetEntry::new(
                DefinitionKind::PartitionPolicy,
                action_handle,
                Some(policy_definition_digest),
                Some(policy_definition_digest),
                None,
                policy_definition_digest,
            )?);
        }
    }

    let dependency_intersection = dependency_intersection_definition_digest();
    entries.push(DefinitionSetEntry::new(
        DefinitionKind::WorldCompatibilityRule,
        DefinitionHandle::new("needle.validity.dependency-intersection")?,
        None,
        None,
        Some(dependency_intersection),
        dependency_intersection,
    )?);
    let fast_validity = fast_validity_definition_digest();
    entries.push(DefinitionSetEntry::new(
        DefinitionKind::WorldCompatibilityRule,
        DefinitionHandle::new("needle.validity.fast-path")?,
        None,
        None,
        Some(fast_validity),
        fast_validity,
    )?);

    DefinitionSet::new(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use needle_core::Digest;
    use std::collections::BTreeMap;

    #[test]
    fn active_set_covers_every_current_definition_and_no_future_placeholder() {
        let set = active_definition_set();
        assert!(set.is_canonical());
        assert_eq!(set.entries.len(), 44);

        let counts = set.entries.iter().fold(BTreeMap::new(), |mut counts, entry| {
            *counts.entry(entry.kind).or_insert(0usize) += 1;
            counts
        });
        assert_eq!(counts.get(&DefinitionKind::NeedGrammar), Some(&2));
        assert_eq!(counts.get(&DefinitionKind::PredicateContract), Some(&3));
        assert_eq!(counts.get(&DefinitionKind::ActionContract), Some(&11));
        assert_eq!(counts.get(&DefinitionKind::ArtifactContract), Some(&11));
        assert_eq!(counts.get(&DefinitionKind::ValidatorDefinition), Some(&11));
        assert_eq!(counts.get(&DefinitionKind::PartitionPolicy), Some(&4));
        assert_eq!(counts.get(&DefinitionKind::WorldCompatibilityRule), Some(&2));
        let world_rules = set
            .entries
            .iter()
            .filter(|entry| entry.kind == DefinitionKind::WorldCompatibilityRule)
            .collect::<Vec<_>>();
        let intersection = world_rules
            .iter()
            .find(|entry| entry.handle.as_str() == "needle.validity.dependency-intersection")
            .unwrap();
        assert_eq!(intersection.handle.as_str(), "needle.validity.dependency-intersection");
        assert_eq!(intersection.semantic_definition_digest, None);
        assert_eq!(intersection.validation_definition_digest, None);
        assert_eq!(
            intersection.operational_definition_digest,
            Some(dependency_intersection_definition_digest())
        );
        assert_eq!(intersection.definition_digest, dependency_intersection_definition_digest());
        let fast_validity = world_rules
            .iter()
            .find(|entry| entry.handle.as_str() == "needle.validity.fast-path")
            .unwrap();
        assert_eq!(fast_validity.semantic_definition_digest, None);
        assert_eq!(fast_validity.validation_definition_digest, None);
        assert_eq!(
            fast_validity.operational_definition_digest,
            Some(fast_validity_definition_digest())
        );
        assert_eq!(fast_validity.definition_digest, fast_validity_definition_digest());
        for future in [
            DefinitionKind::PartitionScheme,
            DefinitionKind::ManifestTransition,
            DefinitionKind::MergePolicy,
            DefinitionKind::RefreshPolicy,
            DefinitionKind::DerivationRule,
            DefinitionKind::CompletenessOracle,
        ] {
            assert_eq!(counts.get(&future), None);
        }

        for action in built_in_action_contracts() {
            let entry = set
                .entries
                .iter()
                .find(|entry| {
                    entry.kind == DefinitionKind::ActionContract
                        && entry.handle.as_str() == action.contract.id.as_str()
                })
                .unwrap();
            assert_eq!(
                entry.semantic_definition_digest,
                Some(action.contract.semantic_definition_digest)
            );
            assert_eq!(
                entry.validation_definition_digest,
                Some(action.contract.validation_definition_digest)
            );
            assert_eq!(
                entry.operational_definition_digest,
                Some(action.contract.operational_policy_digest)
            );
            assert_eq!(entry.definition_digest, action.contract.definition_digest);
        }
    }

    #[test]
    fn active_set_is_stable_and_content_addressed() {
        assert_eq!(active_definition_set(), &build_active_definition_set().unwrap());
        assert_eq!(
            active_definition_set().audit_digest,
            Digest::parse("b3:231332fdd8aee9eb008f65c882236a7b370dcf70ec27bbecdfa62f9758e105da")
                .unwrap()
        );
    }
}
