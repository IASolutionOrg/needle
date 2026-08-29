use crate::semantic_validation::artifact_and_certificate_are_fresh_from_root;
use arrayvec::ArrayVec;
use needle_core::{
    Artifact, ArtifactId, ArtifactValidationCertificate, ArtifactValidationCertificateId,
    CacheScope, CanonicalHasher, Digest, MAX_DERIVATION_DEPTH, MAX_NEED_INPUTS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::OnceLock;

pub const INPUT_ARTIFACT_STATE_FORMAT_REVISION: u16 = 1;

/// Maximum number of unique input artifacts reachable below one root artifact.
/// This is the complete eight-way tree allowed by the current derivation depth.
pub const MAX_INPUT_ARTIFACT_STATE_NODES: usize = 584;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactGraphValidityState {
    pub root_artifact: ArtifactId,
    pub root_validation_certificate: ArtifactValidationCertificateId,
    pub semantic_world_digest: Digest,
    pub source_snapshot_digest: Digest,
    pub input_artifact_state_digest: Digest,
    pub validated_input_count: usize,
    pub definition_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactGraphRevalidationReason {
    ArtifactPairInvalid { artifact: ArtifactId },
    ArtifactFilesystemStale { artifact: ArtifactId },
    SnapshotSourceMissing { artifact: ArtifactId },
    SemanticWorldMismatch { artifact: ArtifactId },
    MissingInputArtifact { artifact: ArtifactId },
    MissingInputCertificate { artifact: ArtifactId },
    DuplicateInputArtifact { artifact: ArtifactId },
    InputArtifactBound { artifact: ArtifactId },
    GraphNodeBound,
    DerivationDepthBound,
    DerivationCycle,
    UnreachableGraphNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactGraphValidity {
    Fresh { state: ArtifactGraphValidityState },
    RequiresRevalidation { reason: ArtifactGraphRevalidationReason },
}

#[derive(Clone, Debug)]
pub(crate) struct ArtifactGraphNode {
    pub artifact: Artifact,
    pub certificate: ArtifactValidationCertificate,
    pub has_current_source: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ArtifactGraphSnapshot {
    pub root: ArtifactId,
    pub source_snapshot_digest: Digest,
    pub nodes: BTreeMap<ArtifactId, ArtifactGraphNode>,
}

pub fn input_artifact_state_definition_digest() -> Digest {
    static DIGEST: OnceLock<Digest> = OnceLock::new();
    *DIGEST.get_or_init(|| {
        let mut hasher = CanonicalHasher::new(b"input-artifact-state-definition-v1");
        hasher.field_u16(INPUT_ARTIFACT_STATE_FORMAT_REVISION);
        hasher.field_u32(MAX_NEED_INPUTS.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_DERIVATION_DEPTH.try_into().unwrap_or(u32::MAX));
        hasher.field_u32(MAX_INPUT_ARTIFACT_STATE_NODES.try_into().unwrap_or(u32::MAX));
        hasher.field_str("canonical-sorted-unique-input-artifact-ids");
        hasher.field_str("current-validator-and-filesystem-evidence");
        hasher.field_str("snapshot-exact-current-source-observation");
        hasher.field_str("single-semantic-world");
        hasher.field_str("cycle-and-unreachable-node-rejection");
        hasher.finish()
    })
}

pub fn empty_input_artifact_state_digest() -> Digest {
    let mut hasher = CanonicalHasher::new(b"input-artifact-state-v1");
    hasher.field_u16(0);
    hasher.finish()
}

pub(crate) fn validate_artifact_graph_snapshot(
    snapshot: &ArtifactGraphSnapshot,
    repository_root: &std::path::Path,
) -> ArtifactGraphValidity {
    validate_artifact_graph_snapshot_with_root_policy(snapshot, repository_root, true)
}

pub(crate) fn validate_artifact_input_graph_snapshot(
    snapshot: &ArtifactGraphSnapshot,
    repository_root: &std::path::Path,
) -> ArtifactGraphValidity {
    validate_artifact_graph_snapshot_with_root_policy(snapshot, repository_root, false)
}

fn validate_artifact_graph_snapshot_with_root_policy(
    snapshot: &ArtifactGraphSnapshot,
    repository_root: &std::path::Path,
    validate_root_filesystem: bool,
) -> ArtifactGraphValidity {
    let Some(root) = snapshot.nodes.get(&snapshot.root) else {
        return revalidation(ArtifactGraphRevalidationReason::ArtifactPairInvalid {
            artifact: snapshot.root,
        });
    };
    if snapshot.nodes.len().saturating_sub(1) > MAX_INPUT_ARTIFACT_STATE_NODES {
        return revalidation(ArtifactGraphRevalidationReason::GraphNodeBound);
    }
    let Ok(canonical_repository_root) = fs::canonicalize(repository_root) else {
        return revalidation(ArtifactGraphRevalidationReason::ArtifactFilesystemStale {
            artifact: snapshot.root,
        });
    };

    let root_world = root.certificate.coverage.world.id();
    for (artifact_id, node) in &snapshot.nodes {
        if node.artifact.id != artifact_id.digest() || node.certificate.artifact != *artifact_id {
            return revalidation(ArtifactGraphRevalidationReason::ArtifactPairInvalid {
                artifact: *artifact_id,
            });
        }
        if node.certificate.input_artifacts.len() > MAX_NEED_INPUTS {
            return revalidation(ArtifactGraphRevalidationReason::InputArtifactBound {
                artifact: *artifact_id,
            });
        }
        let Ok(inputs) = canonical_inputs(&node.certificate.input_artifacts) else {
            return revalidation(ArtifactGraphRevalidationReason::DuplicateInputArtifact {
                artifact: *artifact_id,
            });
        };
        if let Some(missing) = inputs.iter().find(|input| !snapshot.nodes.contains_key(input)) {
            return revalidation(ArtifactGraphRevalidationReason::MissingInputArtifact {
                artifact: *missing,
            });
        }
        if node.certificate.coverage.world.id() != root_world {
            return revalidation(ArtifactGraphRevalidationReason::SemanticWorldMismatch {
                artifact: *artifact_id,
            });
        }
        let validate_filesystem = validate_root_filesystem || *artifact_id != snapshot.root;
        if validate_filesystem
            && node.artifact.contract.cache_scope == CacheScope::SnapshotExact
            && !node.has_current_source
        {
            return revalidation(ArtifactGraphRevalidationReason::SnapshotSourceMissing {
                artifact: *artifact_id,
            });
        }
        if validate_filesystem
            && !artifact_and_certificate_are_fresh_from_root(
                &node.artifact,
                &node.certificate,
                &canonical_repository_root,
            )
        {
            return revalidation(ArtifactGraphRevalidationReason::ArtifactFilesystemStale {
                artifact: *artifact_id,
            });
        }
    }

    let root_inputs = match canonical_inputs(&root.certificate.input_artifacts) {
        Ok(inputs) => inputs,
        Err(()) => {
            return revalidation(ArtifactGraphRevalidationReason::DuplicateInputArtifact {
                artifact: snapshot.root,
            });
        }
    };
    if root_inputs.is_empty() {
        if snapshot.nodes.len() != 1 {
            return revalidation(ArtifactGraphRevalidationReason::UnreachableGraphNode);
        }
        return ArtifactGraphValidity::Fresh {
            state: validity_state(snapshot, root, empty_input_artifact_state_digest(), 0),
        };
    }

    let mut visiting = BTreeSet::new();
    let mut memo = BTreeMap::new();
    let mut input_state = CanonicalHasher::new(b"input-artifact-state-v1");
    input_state.field_u16(root_inputs.len().try_into().unwrap_or(u16::MAX));
    for input in &root_inputs {
        let (digest, height) = match digest_input_node(*input, snapshot, &mut visiting, &mut memo) {
            Ok(value) => value,
            Err(reason) => return revalidation(reason),
        };
        if height.saturating_add(1) > MAX_DERIVATION_DEPTH {
            return revalidation(ArtifactGraphRevalidationReason::DerivationDepthBound);
        }
        input_state.field_digest(input.digest());
        input_state.field_digest(digest);
    }
    if memo.len() != snapshot.nodes.len().saturating_sub(1) {
        return revalidation(ArtifactGraphRevalidationReason::UnreachableGraphNode);
    }

    ArtifactGraphValidity::Fresh {
        state: validity_state(snapshot, root, input_state.finish(), memo.len()),
    }
}

fn digest_input_node(
    artifact_id: ArtifactId,
    snapshot: &ArtifactGraphSnapshot,
    visiting: &mut BTreeSet<ArtifactId>,
    memo: &mut BTreeMap<ArtifactId, (Digest, usize)>,
) -> Result<(Digest, usize), ArtifactGraphRevalidationReason> {
    if let Some(value) = memo.get(&artifact_id) {
        return Ok(*value);
    }
    if !visiting.insert(artifact_id) {
        return Err(ArtifactGraphRevalidationReason::DerivationCycle);
    }
    let node = snapshot
        .nodes
        .get(&artifact_id)
        .ok_or(ArtifactGraphRevalidationReason::MissingInputArtifact { artifact: artifact_id })?;
    let inputs = canonical_inputs(&node.certificate.input_artifacts).map_err(|()| {
        ArtifactGraphRevalidationReason::DuplicateInputArtifact { artifact: artifact_id }
    })?;
    let mut height = 0_usize;
    let mut hasher = CanonicalHasher::new(b"input-artifact-state-node-v1");
    hasher.field_digest(artifact_id.digest());
    hasher.field_digest(node.certificate.id.digest());
    hasher.field_digest(node.certificate.coverage.world.id());
    hasher.field_digest(node.certificate.coverage.dependency_manifest_digest);
    hasher.field_u16(inputs.len().try_into().unwrap_or(u16::MAX));
    for input in inputs {
        let (child_digest, child_height) = digest_input_node(input, snapshot, visiting, memo)?;
        height = height.max(child_height.saturating_add(1));
        hasher.field_digest(input.digest());
        hasher.field_digest(child_digest);
    }
    visiting.remove(&artifact_id);
    let result = (hasher.finish(), height);
    memo.insert(artifact_id, result);
    Ok(result)
}

fn canonical_inputs(inputs: &[ArtifactId]) -> Result<ArrayVec<ArtifactId, MAX_NEED_INPUTS>, ()> {
    let mut canonical = ArrayVec::new();
    canonical.try_extend_from_slice(inputs).map_err(|_| ())?;
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(());
    }
    Ok(canonical)
}

fn validity_state(
    snapshot: &ArtifactGraphSnapshot,
    root: &ArtifactGraphNode,
    input_artifact_state_digest: Digest,
    validated_input_count: usize,
) -> ArtifactGraphValidityState {
    ArtifactGraphValidityState {
        root_artifact: snapshot.root,
        root_validation_certificate: root.certificate.id,
        semantic_world_digest: root.certificate.coverage.world.id(),
        source_snapshot_digest: snapshot.source_snapshot_digest,
        input_artifact_state_digest,
        validated_input_count,
        definition_digest: input_artifact_state_definition_digest(),
    }
}

fn revalidation(reason: ArtifactGraphRevalidationReason) -> ArtifactGraphValidity {
    ArtifactGraphValidity::RequiresRevalidation { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        built_in_action_for_artifact_kind, manifest_digest,
        semantic_validation::validation_certificate_id,
    };
    use needle_core::{
        ArtifactContract, ArtifactKind, CoverageEntry, CoverageManifest, Dependency,
        DependencyManifest, Facet, LocationRole, Obligation, PredicateKind, SemanticLocation,
        SemanticWorkerArtifact, SemanticWorld, SubjectId,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(label: &str) -> Digest {
        Digest::blake3(label)
    }

    fn temporary_repository() -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("needle-input-state-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn node(root: &Path, label: &str, inputs: Vec<ArtifactId>) -> (ArtifactId, ArtifactGraphNode) {
        let path = format!("{label}.rs");
        fs::write(root.join(&path), label.as_bytes()).unwrap();
        let kind = ArtifactKind::code_location();
        let action = built_in_action_for_artifact_kind(&kind).unwrap();
        let contract = ArtifactContract::semantic(
            action.output_contract_id,
            action.output_contract_revision,
            kind.clone(),
            CacheScope::WorktreeSemantic,
        );
        let payload = SemanticWorkerArtifact::CodeLocation {
            locations: vec![SemanticLocation {
                role: LocationRole::Primary,
                path: path.clone(),
                symbol: Some(label.to_owned()),
                byte_start: Some(0),
                byte_end: Some(1),
            }],
            gaps: Vec::new(),
        };
        let artifact_id = payload.canonical_artifact_id(contract.definition_digest).unwrap();
        let obligation = Obligation::new(
            PredicateKind::ImplementationLocation,
            SubjectId::new(digest(&format!("subject-{label}"))),
            vec![
                Facet { key: "granularity".to_owned(), value: "exact-location".to_owned() },
                Facet { key: "polarity".to_owned(), value: "positive".to_owned() },
                Facet { key: "selection".to_owned(), value: "primary".to_owned() },
            ],
        );
        let dependency_manifest = DependencyManifest {
            scope: CacheScope::WorktreeSemantic,
            observed_files_complete: true,
            dependencies: vec![Dependency {
                path: path.clone(),
                content_digest: Digest::blake3(label.as_bytes()),
                byte_start: None,
                byte_end: None,
                claims: vec![obligation.id.to_string()],
            }],
            gaps: Vec::new(),
        };
        let dependency_manifest_digest = manifest_digest(&dependency_manifest);
        let coverage = CoverageManifest {
            entries: vec![CoverageEntry { obligation, evidence: vec![path] }],
            world: SemanticWorld {
                repository_lineage: digest("repository"),
                source_selector: "worktree".to_owned(),
                platform: "windows".to_owned(),
                features: "default".to_owned(),
                configuration: None,
                toolchain: None,
            },
            dependency_manifest_digest,
        };
        let validator_definition = crate::validator_definition(&kind);
        let certificate_id = validation_certificate_id(
            artifact_id,
            &inputs,
            &[],
            &coverage,
            validator_definition,
            None,
        );
        let certificate = ArtifactValidationCertificate {
            id: certificate_id,
            artifact: artifact_id,
            input_artifacts: inputs,
            evidence_ids: Vec::new(),
            test_plan_evidence: None,
            coverage,
            validator_definition,
            dependency_checks_digest: dependency_manifest_digest,
            issued_unix_ms: 1,
        };
        let artifact = Artifact {
            id: artifact_id.digest(),
            request_id: digest(&format!("request-{label}")),
            contract,
            payload: serde_json::to_value(payload).unwrap(),
            dependency_manifest,
            validations: Vec::new(),
            created_unix_ms: 1,
        };
        (artifact_id, ArtifactGraphNode { artifact, certificate, has_current_source: true })
    }

    fn replace_inputs(node: &mut ArtifactGraphNode, inputs: Vec<ArtifactId>) {
        node.certificate.input_artifacts = inputs;
        node.certificate.id = validation_certificate_id(
            node.certificate.artifact,
            &node.certificate.input_artifacts,
            &node.certificate.evidence_ids,
            &node.certificate.coverage,
            node.certificate.validator_definition,
            node.certificate.test_plan_evidence,
        );
    }

    fn fresh_state(result: ArtifactGraphValidity) -> ArtifactGraphValidityState {
        match result {
            ArtifactGraphValidity::Fresh { state } => state,
            other => panic!("expected fresh graph, got {other:?}"),
        }
    }

    #[test]
    fn empty_and_definition_digests_are_stable() {
        assert_eq!(
            empty_input_artifact_state_digest(),
            Digest::parse("b3:69b305640b1f253d9d1a8545b4d8b8cdb30d9714f3cd92b34e16ba4af6fa0c2e")
                .unwrap()
        );
        assert_eq!(
            input_artifact_state_definition_digest(),
            Digest::parse("b3:d2d99383b136a76c545007f14e1ca70b83059e1f183cc1b0b5c517fe62b8f4b4")
                .unwrap()
        );
    }

    #[test]
    fn canonical_order_and_shared_dag_produce_one_state() {
        let root_path = temporary_repository();
        let (shared_id, shared) = node(&root_path, "shared", Vec::new());
        let (left_id, left) = node(&root_path, "left", vec![shared_id]);
        let (right_id, right) = node(&root_path, "right", vec![shared_id]);
        let (root_id, root) = node(&root_path, "root", vec![right_id, left_id]);
        let nodes = BTreeMap::from([
            (root_id, root.clone()),
            (left_id, left),
            (right_id, right),
            (shared_id, shared),
        ]);
        let first = fresh_state(validate_artifact_graph_snapshot(
            &ArtifactGraphSnapshot {
                root: root_id,
                source_snapshot_digest: digest("source"),
                nodes: nodes.clone(),
            },
            &root_path,
        ));
        let mut reordered = nodes;
        replace_inputs(reordered.get_mut(&root_id).unwrap(), vec![left_id, right_id]);
        let second = fresh_state(validate_artifact_graph_snapshot(
            &ArtifactGraphSnapshot {
                root: root_id,
                source_snapshot_digest: digest("source"),
                nodes: reordered,
            },
            &root_path,
        ));
        assert_eq!(first.input_artifact_state_digest, second.input_artifact_state_digest);
        assert_eq!(first.validated_input_count, 3);
        fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn duplicate_cycle_and_depth_overflow_fail_closed() {
        let duplicate_root = temporary_repository();
        let (leaf_id, leaf) = node(&duplicate_root, "leaf", Vec::new());
        let (root_id, root) = node(&duplicate_root, "root", vec![leaf_id, leaf_id]);
        let duplicate = validate_artifact_graph_snapshot(
            &ArtifactGraphSnapshot {
                root: root_id,
                source_snapshot_digest: digest("source"),
                nodes: BTreeMap::from([(root_id, root), (leaf_id, leaf)]),
            },
            &duplicate_root,
        );
        assert_eq!(
            duplicate,
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::DuplicateInputArtifact {
                    artifact: root_id
                }
            }
        );
        fs::remove_dir_all(duplicate_root).unwrap();

        let cycle_root = temporary_repository();
        let (left_id, mut left) = node(&cycle_root, "left", Vec::new());
        let (right_id, right) = node(&cycle_root, "right", vec![left_id]);
        replace_inputs(&mut left, vec![right_id]);
        let cycle = validate_artifact_graph_snapshot(
            &ArtifactGraphSnapshot {
                root: left_id,
                source_snapshot_digest: digest("source"),
                nodes: BTreeMap::from([(left_id, left), (right_id, right)]),
            },
            &cycle_root,
        );
        assert_eq!(
            cycle,
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::DerivationCycle
            }
        );
        fs::remove_dir_all(cycle_root).unwrap();

        let depth_root = temporary_repository();
        let (four_id, four) = node(&depth_root, "four", Vec::new());
        let (three_id, three) = node(&depth_root, "three", vec![four_id]);
        let (two_id, two) = node(&depth_root, "two", vec![three_id]);
        let (one_id, one) = node(&depth_root, "one", vec![two_id]);
        let (root_id, root) = node(&depth_root, "root", vec![one_id]);
        let depth = validate_artifact_graph_snapshot(
            &ArtifactGraphSnapshot {
                root: root_id,
                source_snapshot_digest: digest("source"),
                nodes: BTreeMap::from([
                    (root_id, root),
                    (one_id, one),
                    (two_id, two),
                    (three_id, three),
                    (four_id, four),
                ]),
            },
            &depth_root,
        );
        assert_eq!(
            depth,
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::DerivationDepthBound
            }
        );
        fs::remove_dir_all(depth_root).unwrap();
    }

    #[test]
    fn bounds_missing_nodes_world_and_snapshot_source_fail_closed() {
        let root_path = temporary_repository();
        let (leaf_id, leaf) = node(&root_path, "leaf", Vec::new());
        let (root_id, mut root) = node(&root_path, "root", vec![leaf_id]);

        replace_inputs(&mut root, vec![leaf_id; MAX_NEED_INPUTS + 1]);
        assert_eq!(
            validate_artifact_graph_snapshot(
                &ArtifactGraphSnapshot {
                    root: root_id,
                    source_snapshot_digest: digest("source"),
                    nodes: BTreeMap::from([(root_id, root.clone()), (leaf_id, leaf.clone())]),
                },
                &root_path,
            ),
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::InputArtifactBound { artifact: root_id }
            }
        );

        let missing_id = ArtifactId::new(digest("missing"));
        replace_inputs(&mut root, vec![missing_id]);
        assert_eq!(
            validate_artifact_graph_snapshot(
                &ArtifactGraphSnapshot {
                    root: root_id,
                    source_snapshot_digest: digest("source"),
                    nodes: BTreeMap::from([(root_id, root.clone())]),
                },
                &root_path,
            ),
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::MissingInputArtifact {
                    artifact: missing_id
                }
            }
        );

        replace_inputs(&mut root, vec![leaf_id]);
        let mut wrong_world = leaf.clone();
        wrong_world.certificate.coverage.world.platform = "other".to_owned();
        assert_eq!(
            validate_artifact_graph_snapshot(
                &ArtifactGraphSnapshot {
                    root: root_id,
                    source_snapshot_digest: digest("source"),
                    nodes: BTreeMap::from([(root_id, root.clone()), (leaf_id, wrong_world)]),
                },
                &root_path,
            ),
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::SemanticWorldMismatch {
                    artifact: leaf_id
                }
            }
        );

        let mut snapshot_exact = leaf.clone();
        snapshot_exact.artifact.contract.cache_scope = CacheScope::SnapshotExact;
        snapshot_exact.has_current_source = false;
        assert_eq!(
            validate_artifact_graph_snapshot(
                &ArtifactGraphSnapshot {
                    root: leaf_id,
                    source_snapshot_digest: digest("source"),
                    nodes: BTreeMap::from([(leaf_id, snapshot_exact)]),
                },
                &root_path,
            ),
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::SnapshotSourceMissing {
                    artifact: leaf_id
                }
            }
        );

        let mut oversized = BTreeMap::from([(root_id, root)]);
        for index in 0..=MAX_INPUT_ARTIFACT_STATE_NODES {
            oversized.insert(ArtifactId::new(Digest::blake3(index.to_le_bytes())), leaf.clone());
        }
        assert_eq!(
            validate_artifact_graph_snapshot(
                &ArtifactGraphSnapshot {
                    root: root_id,
                    source_snapshot_digest: digest("source"),
                    nodes: oversized,
                },
                &root_path,
            ),
            ArtifactGraphValidity::RequiresRevalidation {
                reason: ArtifactGraphRevalidationReason::GraphNodeBound
            }
        );
        fs::remove_dir_all(root_path).unwrap();
    }
}
