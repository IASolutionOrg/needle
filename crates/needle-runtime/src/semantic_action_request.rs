use crate::BuiltInActionDefinition;
use needle_core::{ActionRequest, ArtifactRequest, Digest, NeedFragment, NeedRequest};

pub(crate) fn build_semantic_action_request(
    request: &NeedRequest,
    fragment: &NeedFragment,
    repository_id: Digest,
    source_snapshot_digest: Digest,
    definition: &BuiltInActionDefinition,
) -> Result<ActionRequest, String> {
    ActionRequest::new(
        &definition.contract,
        ArtifactRequest {
            contract_id: definition.output_contract_id.to_owned(),
            contract_revision: definition.output_contract_revision,
            repository_id,
            source_snapshot_digest,
            route_key: request.key.clone(),
            normalized_request: request.body.clone(),
            semantic_fragment_id: Some(fragment.id),
            input_artifact_ids: fragment
                .semantic_inputs
                .iter()
                .map(|artifact| artifact.digest())
                .collect(),
        },
        definition.contract.default_dispatch_policy,
        request.key.clone(),
        fragment.root_need,
    )
    .map_err(|error| error.to_string())
}
