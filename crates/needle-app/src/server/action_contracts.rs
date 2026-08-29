use needle_runtime::{
    BUILT_IN_ACTION_COUNT, BuiltInActionCoverage, built_in_action_contracts,
    built_in_partition_for_action,
};
use serde_json::{Value, json};

pub(super) fn control_plane_envelope() -> Value {
    let items = built_in_action_contracts()
        .iter()
        .map(|definition| {
            let coverage = match &definition.coverage {
                BuiltInActionCoverage::SemanticPredicate(contract) => json!({
                    "kind": "semantic_predicate",
                    "predicate": contract.predicate.as_str(),
                    "definition_digest": contract.definition_digest,
                }),
                BuiltInActionCoverage::Opaque { semantic_definition_digest } => json!({
                    "kind": "opaque",
                    "semantic_definition_digest": semantic_definition_digest,
                }),
                BuiltInActionCoverage::Partitioned { policy_definition_digest } => {
                    let partition = built_in_partition_for_action(&definition.contract.id)
                        .expect("partitioned built-in action has a partition definition");
                    json!({
                        "kind": "partitioned",
                        "declared_policy_authority_digest": policy_definition_digest,
                        "scheme": {
                            "id": partition.scheme.id,
                            "kind": partition.scheme.kind,
                            "key_scope": partition.scheme.key_scope,
                            "key_schema": partition.scheme.key_schema,
                            "maximum_key_bytes": partition.scheme.maximum_key_bytes,
                            "definition_digest": partition.scheme.definition_digest
                        },
                        "policy": {
                            "id": partition.policy.id,
                            "manifest_validator": partition.policy.manifest_validator,
                            "maximum_partitions": partition.policy.maximum_partitions,
                            "maximum_manifest_bytes": partition.policy.maximum_manifest_bytes,
                            "overlap_policy": partition.policy.overlap_policy,
                            "closure_policy": partition.policy.closure_policy,
                            "definition_digest": partition.policy.definition_digest
                        },
                        "adapter_definition_digest": partition.adapter_definition_digest,
                        "fixed_mode": partition.initial_mode
                    })
                }
            };
            json!({
                "id": definition.contract.id,
                "coverage": coverage,
                "artifact_kind": definition.artifact_kind.0,
                "output_contract": {
                    "id": definition.output_contract_id,
                    "revision": definition.output_contract_revision,
                    "schema": definition.output_schema_id,
                    "definition_digest": definition.output_contract_definition_digest
                },
                "validator_definition_digest": definition.validator_definition_digest,
                "effect_class": definition.contract.effect_class,
                "reuse_modes": definition.contract.reuse_modes,
                "default_dispatch_policy": definition.contract.default_dispatch_policy,
                "initial_mode": definition.initial_mode,
                "definition_digests": {
                    "semantic": definition.contract.semantic_definition_digest,
                    "validation": definition.contract.validation_definition_digest,
                    "operational": definition.contract.operational_policy_digest,
                    "complete": definition.contract.definition_digest
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": "needle.action-contract-catalog/3",
        "status": "shadow_only",
        "items": items,
        "bounded": {"limit": BUILT_IN_ACTION_COUNT}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_catalog_is_bounded_complete_and_shadow_only() {
        let catalog = control_plane_envelope();
        let items = catalog["items"].as_array().unwrap();

        assert_eq!(catalog["schema"], "needle.action-contract-catalog/3");
        assert_eq!(catalog["status"], "shadow_only");
        assert_eq!(catalog["bounded"]["limit"], BUILT_IN_ACTION_COUNT);
        assert_eq!(items.len(), BUILT_IN_ACTION_COUNT);
        assert_eq!(items[0]["id"], "needle.location.resolve");
        assert_eq!(items[1]["id"], "needle.flow.trace");
        assert_eq!(items[2]["id"], "needle.tests.plan");
        assert_eq!(items[3]["id"], "needle.tests.inventory");
        assert_eq!(items[3]["coverage"]["kind"], "partitioned");
        assert_eq!(items[3]["coverage"]["fixed_mode"], "shadow");
        assert_eq!(items[3]["coverage"]["scheme"]["id"], "needle.tests.inventory.target");
        assert_eq!(items[3]["coverage"]["policy"]["closure_policy"], "closed_required");
        assert_eq!(items[4]["id"], "needle.architecture.describe");
        assert_eq!(items[4]["coverage"]["kind"], "partitioned");
        assert_eq!(items[4]["effect_class"], "derived-analysis");
        assert_eq!(items[4]["output_contract"]["schema"], "needle.architecture-brief/1");
        assert_eq!(items[5]["id"], "needle.change.impact");
        assert_eq!(items[5]["coverage"]["kind"], "partitioned");
        assert_eq!(items[5]["effect_class"], "derived-analysis");
        assert_eq!(items[5]["output_contract"]["schema"], "needle.change-impact/1");
        assert_eq!(items[6]["id"], "needle.patch.propose");
        assert_eq!(items[6]["coverage"]["kind"], "opaque");
        assert_eq!(items[7]["id"], "needle.tests.execute");
        assert_eq!(items[8]["id"], "needle.review.diff");
        assert_eq!(items[9]["id"], "needle.patch.verify");
        assert_eq!(items[10]["id"], "needle.patch.apply");
        assert_eq!(items[10]["reuse_modes"], json!(["never"]));
        assert!(items.iter().all(|item| item["initial_mode"] == "shadow"));
        assert_eq!(items[3]["reuse_modes"], json!(["exact", "project", "assemble", "refresh"]));
        assert!(items.iter().all(|item| {
            item["reuse_modes"].as_array().is_some_and(|modes| !modes.is_empty())
                && item["definition_digests"]["complete"].as_str().is_some()
        }));
    }
}
