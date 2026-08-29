use super::{LifecycleExploreActionResolver, LifecycleExploreActionResolverOutcome};
use crate::action_resolution::{
    ShadowActionResolutionProjectionInput, project_shadow_action_resolutions,
};
use crate::lifecycle_action_plan::validate_lifecycle_explore_action_plan_need;
use crate::{LifecycleChangeContext, RuntimeStore, SemanticResolver};
use needle_core::LifecycleExploreActionPlan;

/// Store-backed, artifact-only Shadow resolver for lifecycle Explore plans.
///
/// It reuses the existing semantic freshness and proof machinery, but disables
/// claim reuse and cannot authorize a lifecycle transition or worker bypass.
pub struct SemanticLifecycleExploreActionResolver {
    store: RuntimeStore,
    resolver: SemanticResolver,
}

impl SemanticLifecycleExploreActionResolver {
    pub fn new(store: RuntimeStore) -> Self {
        let resolver = SemanticResolver::new(store.clone());
        Self { store, resolver }
    }
}

impl LifecycleExploreActionResolver for SemanticLifecycleExploreActionResolver {
    fn resolve(
        &self,
        plan: &LifecycleExploreActionPlan,
        change: &LifecycleChangeContext,
    ) -> LifecycleExploreActionResolverOutcome {
        if plan.repository_id() != change.repository_id
            || plan.source_snapshot() != Some(change.source_snapshot)
        {
            return LifecycleExploreActionResolverOutcome::Invalid;
        }
        let need = match self.store.need(&plan.fragment.root_need.to_string()) {
            Ok(Some(need)) => need,
            Ok(None) => return LifecycleExploreActionResolverOutcome::Unavailable,
            Err(_) => return LifecycleExploreActionResolverOutcome::Unavailable,
        };
        let request = match validate_lifecycle_explore_action_plan_need(plan, &need) {
            Ok(request) => request,
            Err(_) => return LifecycleExploreActionResolverOutcome::Invalid,
        };
        let repository_root = match self.store.repository_root_for_need(&need.id.to_string()) {
            Ok(Some(root)) => root,
            Ok(None) => return LifecycleExploreActionResolverOutcome::Unavailable,
            Err(_) => return LifecycleExploreActionResolverOutcome::Unavailable,
        };
        let mut decision = match self.resolver.resolve_for_route_actions_artifact_only(
            &need,
            &request.key,
            &repository_root,
            change.source_snapshot,
            &plan.actions,
        ) {
            Ok(decision) => decision,
            Err(_) => return LifecycleExploreActionResolverOutcome::Unavailable,
        };
        if decision.claim_advisory.is_some()
            || decision.claim_certificate.is_some()
            || decision.claim_material.is_some()
        {
            return LifecycleExploreActionResolverOutcome::Invalid;
        }
        let (Some(selected_plan), Some(descriptors)) =
            (decision.plan.as_ref(), decision.action_descriptors.take())
        else {
            return LifecycleExploreActionResolverOutcome::Miss;
        };
        if selected_plan.covered_mask == 0 {
            return LifecycleExploreActionResolverOutcome::Miss;
        }
        match project_shadow_action_resolutions(ShadowActionResolutionProjectionInput {
            request: &request,
            need: &need,
            fragment: &plan.fragment,
            repository_id: change.repository_id,
            source_snapshot_digest: change.source_snapshot,
            descriptors,
            plan: selected_plan,
            sufficiency_certificate: decision
                .certificate
                .as_ref()
                .map(|certificate| certificate.id),
        }) {
            Ok(summaries) => LifecycleExploreActionResolverOutcome::Resolved(summaries),
            Err(_) => LifecycleExploreActionResolverOutcome::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_validation::validate_semantic_artifact;
    use crate::{NeedShadowWrite, compile_lifecycle_explore_action_plan};
    use needle_core::{
        ChangeRequest, Digest, LocationRole, NeedIr, NeedRequest, SemanticLocation,
        SemanticWorkerArtifact, built_in_route_contracts, compile_need, need_fragment,
    };
    use std::fs;
    use std::time::Instant;

    #[test]
    fn store_backed_resolver_projects_fresh_action_artifact_without_authority() {
        let root = std::env::temp_dir().join(format!(
            "needle-lifecycle-action-resolver-{}-{}",
            std::process::id(),
            Digest::blake3(format!("{:?}", Instant::now())).to_hex()
        ));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        let store = RuntimeStore::new(root.join("needle.sqlite3"));
        store.initialize().unwrap();
        store
            .record_session_start(
                "lifecycle-action-session",
                Digest::blake3(b"lifecycle-action-profile"),
                None,
                root.to_str(),
            )
            .unwrap();

        let ir = NeedIr::parse(
            "@@need\n\
             @route locate.implementation\n\
             @subject symbol:\"answer\"\n\
             @require implementation-location selection=primary granularity=exact-location polarity=positive\n\
             @world source=current features=default\n\
             \n\
             Locate the answer implementation.\n\
             @@end",
        )
        .unwrap()
        .unwrap();
        let route = built_in_route_contracts()
            .into_iter()
            .find(|contract| contract.route.as_str() == "locate.implementation")
            .unwrap();
        let repository_id = Digest::blake3(b"lifecycle-action-repository");
        let source_snapshot = Digest::blake3(b"lifecycle-action-source");
        let need = compile_need(&ir, repository_id, &route).unwrap();
        let fragment = need_fragment(&need, need.required.clone(), Vec::new());
        store
            .record_need_shadow(NeedShadowWrite {
                session_id: "lifecycle-action-session",
                turn_id: "lifecycle-action-turn",
                transport_digest: ir.transport_digest(),
                parser_definition_digest: Digest::blake3(b"lifecycle-action-parser"),
                prompt_profile_digest: Digest::blake3(b"lifecycle-action-profile"),
                need_ir: &ir,
                need: &need,
                fragments: std::slice::from_ref(&fragment),
            })
            .unwrap();
        let request = NeedRequest { key: route.route.clone(), body: ir.body.clone() };
        let plan = compile_lifecycle_explore_action_plan(
            &request,
            &need,
            &fragment,
            repository_id,
            source_snapshot,
        )
        .unwrap();
        let action_request = &plan.actions[0];
        let validated = validate_semantic_artifact(
            &fragment,
            &SemanticWorkerArtifact::CodeLocation {
                locations: vec![SemanticLocation {
                    role: LocationRole::Primary,
                    path: "src/lib.rs".to_owned(),
                    symbol: Some("answer".to_owned()),
                    byte_start: None,
                    byte_end: None,
                }],
                gaps: Vec::new(),
            },
            &root,
            action_request.semantic_id().digest(),
        )
        .unwrap();
        store
            .publish_action_artifact(action_request, &validated.artifact, &validated.certificate)
            .unwrap();
        let change_request = ChangeRequest {
            task: "Locate answer.".to_owned(),
            acceptance_criteria: Vec::new(),
            allowed_paths: Vec::new(),
            artifact_ids: Vec::new(),
            claim_ids: Vec::new(),
            constraints: Vec::new(),
        };
        let change = LifecycleChangeContext {
            request_digest: change_request.digest(source_snapshot),
            request: change_request,
            repository_id,
            source_snapshot,
        };

        let outcome =
            SemanticLifecycleExploreActionResolver::new(store.clone()).resolve(&plan, &change);

        let LifecycleExploreActionResolverOutcome::Resolved(summaries) = outcome else {
            panic!("fresh action artifact must produce a Shadow resolution");
        };
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].action_contract, action_request.contract);
        assert_eq!(summaries[0].authority, crate::ShadowActionResolutionAuthority::Shadow);

        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
