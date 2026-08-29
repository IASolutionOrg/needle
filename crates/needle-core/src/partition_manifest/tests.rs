use super::*;
use crate::{CapabilityMode, SemanticWorld, validate_reuse_descriptor_coverage};
use serde_json::json;

fn digest(label: impl AsRef<[u8]>) -> Digest {
    Digest::blake3(label)
}

fn scheme(scope: PartitionKeyScope) -> PartitionScheme {
    PartitionScheme::new(
        PartitionSchemeId::new("needle.package").unwrap(),
        PartitionSchemeKind::ProviderDefined {
            provider: ProviderId::new("provider.external-index").unwrap(),
        },
        scope,
        SchemaId::new("opaque.package.v1").unwrap(),
        64,
    )
    .unwrap()
}

fn binding(label: &str) -> ManifestBinding {
    let semantic_inputs = vec![SemanticInputBinding::ByArtifact {
        artifact: ArtifactId::new(digest(format!("input-{label}"))),
    }];
    ManifestBinding::new(
        ArtifactRequestId::new(digest(format!("request-{label}"))),
        ActionContractId::new("needle.change-impact").unwrap(),
        "needle.semantic.change-impact",
        semantic_input_set_digest(&semantic_inputs).unwrap(),
        coverage(label).world.id(),
        digest("repository"),
        label,
        digest(format!("definitions-{label}")),
    )
    .unwrap()
}

fn coverage(label: &str) -> CoverageManifest {
    CoverageManifest {
        entries: Vec::new(),
        world: SemanticWorld {
            repository_lineage: digest("repository"),
            source_selector: label.to_owned(),
            platform: "any".to_owned(),
            features: "default".to_owned(),
            configuration: None,
            toolchain: None,
        },
        dependency_manifest_digest: digest(format!("dependencies-{label}")),
    }
}

#[test]
fn partition_entry_allows_empty_predicate_coverage_without_weakening_reuse_descriptors() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let coverage = coverage("current");
    assert!(validate_reuse_descriptor_coverage(&coverage).is_err());
    assert!(
        PartitionEntry::new(
            OpaquePartitionKey::new(&scheme, b"package-a".to_vec(), None).unwrap(),
            PartitionRole::Component,
            digest("payload"),
            coverage,
            digest("dependencies-current"),
            Vec::new(),
            Vec::new(),
        )
        .is_ok()
    );
}

#[test]
fn semantic_input_set_digest_requires_canonical_bounded_bindings() {
    let first = SemanticInputBinding::ByArtifact { artifact: ArtifactId::new(digest("a")) };
    let second = SemanticInputBinding::ByArtifact { artifact: ArtifactId::new(digest("b")) };
    let mut canonical = vec![first.clone(), second];
    canonical.sort_unstable();
    assert_eq!(
        semantic_input_set_digest(&canonical).unwrap(),
        semantic_input_set_digest(&canonical).unwrap()
    );
    assert!(semantic_input_set_digest(&[first.clone(), first]).is_err());
    assert!(
        semantic_input_set_digest(
            &(0..=MAX_NEED_INPUTS)
                .map(|index| SemanticInputBinding::ByArtifact {
                    artifact: ArtifactId::new(digest(index.to_le_bytes())),
                })
                .collect::<Vec<_>>()
        )
        .is_err()
    );
}

fn entry(scheme: &PartitionScheme, key: &[u8], label: &str) -> PartitionEntry {
    entry_for_world(scheme, key, label, label)
}

fn entry_for_world(
    scheme: &PartitionScheme,
    key: &[u8],
    label: &str,
    world_label: &str,
) -> PartitionEntry {
    PartitionEntry::new(
        OpaquePartitionKey::new(
            scheme,
            key.to_vec(),
            Some(PartitionDisplay::new(format!("Package {label}")).unwrap()),
        )
        .unwrap(),
        PartitionRole::Component,
        digest(format!("payload-{label}")),
        coverage(world_label),
        digest(format!("dependencies-{world_label}")),
        vec![SemanticInputBinding::ByArtifact {
            artifact: ArtifactId::new(digest(format!("input-{label}"))),
        }],
        vec![ArtifactId::new(digest(format!("validated-{label}")))],
    )
    .unwrap()
}

fn manifest(
    scheme: &PartitionScheme,
    binding: ManifestBinding,
    keys: &[(&[u8], &str)],
) -> PartitionManifest {
    let request = binding.action_request;
    let world_label = binding.source_selector.clone();
    PartitionManifest::new(
        scheme,
        binding,
        ManifestProvenance::RequestBound { request },
        ManifestClosure::Closed,
        keys.iter().map(|(key, label)| entry_for_world(scheme, key, label, &world_label)).collect(),
        None,
    )
    .unwrap()
}

fn policy(scheme: &PartitionScheme) -> PartitionPolicy {
    PartitionPolicy::new(
        PartitionPolicyId::new("needle.change-impact.packages").unwrap(),
        vec![scheme.id.clone()],
        ValidatorId::new("needle.partition-manifest.v1").unwrap(),
        64,
        MAX_PARTITION_MANIFEST_WIRE_BYTES as u32,
        PartitionOverlapPolicy::ValidatorDefined,
        ManifestClosurePolicy::ClosedRequired,
    )
    .unwrap()
}

fn refs(manifest: &PartitionManifest) -> Vec<PartitionRef> {
    manifest.entries.iter().map(|entry| PartitionRef::new(manifest.id, entry.key.digest)).collect()
}

#[test]
fn scheme_and_opaque_key_are_canonical_while_display_is_non_semantic() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    assert!(scheme.is_canonical());
    let first = OpaquePartitionKey::new(
        &scheme,
        b"package-a".to_vec(),
        Some(PartitionDisplay::new("Package A").unwrap()),
    )
    .unwrap();
    let second = OpaquePartitionKey::new(
        &scheme,
        b"package-a".to_vec(),
        Some(PartitionDisplay::new("Renamed label").unwrap()),
    )
    .unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.value, second.value);
    assert_ne!(first.display, second.display);
    first.validate_against_scheme(&scheme).unwrap();

    let other_scheme = PartitionScheme::new(
        PartitionSchemeId::new("needle.other").unwrap(),
        PartitionSchemeKind::ContractDefined,
        PartitionKeyScope::ManifestLocal,
        SchemaId::new("opaque.other.v1").unwrap(),
        64,
    )
    .unwrap();
    assert_eq!(
        first.validate_against_scheme(&other_scheme),
        Err(PartitionManifestError::SchemeMismatch)
    );

    assert!(matches!(
        OpaquePartitionKey::new(&scheme, vec![0; 65], None),
        Err(PartitionManifestError::PartitionKey)
    ));
}

#[test]
fn manifest_constructor_is_order_independent_and_decode_rejects_tamper() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let binding = binding("current");
    let first = manifest(&scheme, binding.clone(), &[(b"b", "b"), (b"a", "a")]);
    let second = manifest(&scheme, binding, &[(b"a", "a"), (b"b", "b")]);
    assert_eq!(first, second);
    assert!(first.is_canonical(&scheme));
    assert_eq!(
        scheme.definition_digest,
        Digest::parse("b3:9a6f40d6920586af7c9b33a0c2449fac6314d1fcaedb39d97e103833fbfb92c8")
            .unwrap()
    );
    assert_eq!(
        first.definition_digest,
        Digest::parse("b3:db9e3d0bb0f2fc955fb2e384c8587680fb0b74b4feb0a4273167ae605cdd2822")
            .unwrap()
    );
    assert_eq!(
        first.id.digest(),
        Digest::parse("b3:936c406c0c5a16960318c58575465fc0db178e1b86dbc199d0763441f1d5ac56")
            .unwrap()
    );

    let bytes = serde_json::to_vec(&first).unwrap();
    assert_eq!(PartitionManifest::decode_json(&bytes, &scheme).unwrap(), first);

    let mut tampered = serde_json::to_value(&first).unwrap();
    tampered["entries"][0]["payload_digest"] = json!(digest("tampered"));
    assert!(
        PartitionManifest::decode_json(&serde_json::to_vec(&tampered).unwrap(), &scheme).is_err()
    );

    let mut dependency_tamper = serde_json::to_value(&first).unwrap();
    dependency_tamper["entries"][0]["dependencies"] = json!(digest("tampered-dependencies"));
    assert!(
        PartitionManifest::decode_json(&serde_json::to_vec(&dependency_tamper).unwrap(), &scheme)
            .is_err()
    );

    let mut unknown = serde_json::to_value(&first).unwrap();
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(
        PartitionManifest::decode_json(&serde_json::to_vec(&unknown).unwrap(), &scheme).is_err()
    );

    let mut revision = first.clone();
    revision.format_revision += 1;
    assert!(matches!(
        revision.validate_against_scheme(&scheme),
        Err(PartitionManifestError::FormatRevision { .. })
    ));
}

#[test]
fn empty_manifest_is_valid_only_when_closed_and_cannot_satisfy_projection() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let binding = binding("empty");
    let closed = PartitionManifest::new(
        &scheme,
        binding.clone(),
        ManifestProvenance::RequestBound { request: binding.action_request },
        ManifestClosure::Closed,
        Vec::new(),
        None,
    )
    .unwrap();
    closed.validate_against_scheme(&scheme).unwrap();
    policy(&scheme).accepts(&closed, &scheme).unwrap();
    assert_eq!(
        validate_partition_projection(&policy(&scheme), &scheme, &closed, &binding, &[]),
        Err(PartitionManifestError::PartitionReference)
    );

    assert_eq!(
        PartitionManifest::new(
            &scheme,
            binding.clone(),
            ManifestProvenance::RequestBound { request: binding.action_request },
            ManifestClosure::Open,
            Vec::new(),
            None,
        ),
        Err(PartitionManifestError::EmptyOpenManifest)
    );
}

#[test]
fn manifest_certificate_is_shadow_only_canonical_and_exactly_bound() {
    let scheme = scheme(PartitionKeyScope::LineageStable);
    let accepted_manifest = manifest(&scheme, binding("certificate"), &[(b"a", "a")]);
    let policy = policy(&scheme);
    let certificate = PartitionManifestValidationCertificate::new(
        &accepted_manifest,
        &scheme,
        &policy,
        digest("declared-policy"),
        digest("validator-definition"),
        digest("adapter-definition"),
        digest("source-payload"),
        digest("source-certificate"),
        42,
    )
    .unwrap();
    certificate.validate_against_manifest(&accepted_manifest, &scheme, &policy).unwrap();

    let bytes = serde_json::to_vec(&certificate).unwrap();
    assert_eq!(PartitionManifestValidationCertificate::decode_json(&bytes).unwrap(), certificate);

    let mut authority_tamper = certificate.clone();
    authority_tamper.issued_mode = CapabilityMode::Authoritative;
    assert_eq!(authority_tamper.validate(), Err(PartitionManifestError::CertificateAuthority));

    let other = manifest(&scheme, binding("other-certificate"), &[(b"a", "a")]);
    assert_eq!(
        certificate.validate_against_manifest(&other, &scheme, &policy),
        Err(PartitionManifestError::CertificateBinding)
    );

    let mut digest_tamper = certificate.clone();
    digest_tamper.source_payload_digest = digest("other-source");
    assert!(matches!(digest_tamper.validate(), Err(PartitionManifestError::Digest { .. })));
}

#[test]
fn display_mutation_does_not_change_manifest_semantic_identity() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let manifest = manifest(&scheme, binding("current"), &[(b"a", "a")]);
    let mut relabelled = manifest.clone();
    relabelled.entries[0].key.display = Some(PartitionDisplay::new("Human label only").unwrap());
    relabelled.validate_against_scheme(&scheme).unwrap();
    assert_eq!(manifest.id, relabelled.id);
    assert_eq!(manifest.definition_digest, relabelled.definition_digest);
}

#[test]
fn constructors_reject_duplicate_keys_schemes_and_provenance_mismatch() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let current_binding = binding("current");
    assert!(matches!(
        PartitionManifest::new(
            &scheme,
            current_binding.clone(),
            ManifestProvenance::RequestBound { request: current_binding.action_request },
            ManifestClosure::Closed,
            vec![entry(&scheme, b"same", "first"), entry(&scheme, b"same", "second")],
            None,
        ),
        Err(PartitionManifestError::NonCanonicalSet { field: "partition_manifest.entries" })
    ));
    assert_eq!(
        PartitionPolicy::new(
            PartitionPolicyId::new("needle.duplicate").unwrap(),
            vec![scheme.id.clone(), scheme.id.clone()],
            ValidatorId::new("needle.partition-manifest.v1").unwrap(),
            2,
            4_096,
            PartitionOverlapPolicy::Disjoint,
            ManifestClosurePolicy::OpenAllowed,
        ),
        Err(PartitionManifestError::NonCanonicalSet { field: "partition_policy.allowed_schemes" })
    );
    assert_eq!(
        PartitionManifest::new(
            &scheme,
            current_binding,
            ManifestProvenance::RequestBound {
                request: ArtifactRequestId::new(digest("wrong-request")),
            },
            ManifestClosure::Closed,
            vec![entry(&scheme, b"a", "a")],
            None,
        ),
        Err(PartitionManifestError::ProvenanceBinding)
    );

    let parent = PartitionManifestId::new(digest("parent"));
    assert_eq!(
        ManifestProvenance::derived(DerivationRuleId::new(digest("rule")), vec![parent, parent],),
        Err(PartitionManifestError::NonCanonicalSet { field: "manifest_provenance.parents" })
    );
}

#[test]
fn manifest_rejects_entry_world_and_dependency_binding_mismatches() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let binding = binding("current");

    let mut wrong_world = entry(&scheme, b"world", "current");
    wrong_world.coverage.world.source_selector = "other".to_owned();
    assert_eq!(
        PartitionManifest::new(
            &scheme,
            binding.clone(),
            ManifestProvenance::RequestBound { request: binding.action_request },
            ManifestClosure::Closed,
            vec![wrong_world],
            None,
        ),
        Err(PartitionManifestError::BindingMismatch)
    );

    let mut wrong_dependencies = entry(&scheme, b"dependencies", "current");
    wrong_dependencies.dependencies = digest("other-dependencies");
    assert!(matches!(
        PartitionManifest::new(
            &scheme,
            binding.clone(),
            ManifestProvenance::RequestBound { request: binding.action_request },
            ManifestClosure::Closed,
            vec![wrong_dependencies],
            None,
        ),
        Err(PartitionManifestError::Coverage(_))
    ));
}

#[test]
fn bounded_deserialization_rejects_oversized_key_text_and_input_vectors() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let manifest = manifest(&scheme, binding("current"), &[(b"a", "a")]);

    let mut key = serde_json::to_value(&manifest.entries[0].key).unwrap();
    key["value"] = json!(vec![0_u8; MAX_PARTITION_KEY_BYTES + 1]);
    assert!(serde_json::from_value::<OpaquePartitionKey>(key).is_err());

    let mut display = serde_json::to_value(&manifest.entries[0].key).unwrap();
    display["display"]["label"] = json!("x".repeat(MAX_PARTITION_DISPLAY_BYTES + 1));
    assert!(serde_json::from_value::<OpaquePartitionKey>(display).is_err());

    let mut entry = serde_json::to_value(&manifest.entries[0]).unwrap();
    let input = serde_json::to_value(SemanticInputBinding::ByArtifact {
        artifact: ArtifactId::new(digest("overflow")),
    })
    .unwrap();
    entry["semantic_input_bindings"] = serde_json::Value::Array(vec![input; MAX_NEED_INPUTS + 1]);
    assert!(serde_json::from_value::<PartitionEntry>(entry).is_err());

    let mut world = serde_json::to_value(&manifest.entries[0]).unwrap();
    world["coverage"]["world"]["source_selector"] = json!("x".repeat(crate::MAX_NEED_IR_BYTES + 1));
    assert!(serde_json::from_value::<PartitionEntry>(world).is_err());

    let mut action_contract = serde_json::to_value(&manifest.binding).unwrap();
    action_contract["action_contract"] = json!("a".repeat(crate::MAX_ACTION_CONTRACT_ID_BYTES + 1));
    assert!(serde_json::from_value::<ManifestBinding>(action_contract).is_err());
}

#[test]
fn policy_enforces_scheme_closure_partition_and_wire_bounds() {
    let scheme = scheme(PartitionKeyScope::LineageStable);
    let closed_manifest = manifest(&scheme, binding("current"), &[(b"a", "a")]);
    let policy = policy(&scheme);
    policy.accepts(&closed_manifest, &scheme).unwrap();

    let open_binding = binding("open");
    let open_manifest = PartitionManifest::new(
        &scheme,
        open_binding.clone(),
        ManifestProvenance::RequestBound { request: open_binding.action_request },
        ManifestClosure::Open,
        vec![entry(&scheme, b"a", "open")],
        None,
    )
    .unwrap();
    assert_eq!(
        policy.accepts(&open_manifest, &scheme),
        Err(PartitionManifestError::ClosureRequired)
    );

    let tiny = PartitionPolicy::new(
        PartitionPolicyId::new("needle.tiny").unwrap(),
        vec![scheme.id.clone()],
        ValidatorId::new("needle.partition-manifest.v1").unwrap(),
        1,
        64,
        PartitionOverlapPolicy::Disjoint,
        ManifestClosurePolicy::OpenAllowed,
    )
    .unwrap();
    let canonical = manifest(&scheme, binding("current"), &[(b"a", "a")]);
    let bytes = serde_json::to_vec(&canonical).unwrap();
    assert!(matches!(
        tiny.decode_manifest_json(&bytes, &scheme),
        Err(PartitionManifestError::Bound { field: "partition_manifest.wire_bytes", .. })
    ));
}

#[test]
fn exact_needs_no_manifest_while_project_requires_explicit_bound_refs() {
    assert!(!partition_manifest_required(ReuseMode::Exact));
    assert!(partition_manifest_required(ReuseMode::Project));
    assert!(partition_manifest_required(ReuseMode::Assemble));
    assert!(partition_manifest_required(ReuseMode::Refresh));
    assert!(!partition_manifest_required(ReuseMode::Never));

    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let current_binding = binding("current");
    let manifest = manifest(&scheme, current_binding.clone(), &[(b"a", "a")]);
    let policy = policy(&scheme);
    let partitions = refs(&manifest);
    validate_partition_projection(&policy, &scheme, &manifest, &current_binding, &partitions)
        .unwrap();

    assert_eq!(
        validate_partition_projection(&policy, &scheme, &manifest, &current_binding, &[]),
        Err(PartitionManifestError::PartitionReference)
    );
    let unknown = [PartitionRef::new(manifest.id, digest("unknown"))];
    assert_eq!(
        validate_partition_projection(&policy, &scheme, &manifest, &current_binding, &unknown),
        Err(PartitionManifestError::PartitionReference)
    );
    assert_eq!(
        validate_partition_projection(
            &policy,
            &scheme,
            &manifest,
            &binding("different"),
            &partitions,
        ),
        Err(PartitionManifestError::BindingMismatch)
    );
}

#[test]
fn same_manifest_assembly_is_pure_and_rejects_transition_metadata() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let binding = binding("current");
    let manifest = manifest(&scheme, binding.clone(), &[(b"a", "a"), (b"b", "b")]);
    let policy = policy(&scheme);
    let partitions = refs(&manifest);
    validate_partition_assembly(&policy, &scheme, &[&manifest], &binding, &partitions, None)
        .unwrap();

    let transition = ManifestTransition::new(
        PartitionManifestId::new(digest("prior")),
        manifest.id,
        digest("delta"),
        vec![PartitionKeyMapping {
            prior: PartitionRef::new(PartitionManifestId::new(digest("prior")), digest("old")),
            current: partitions[0],
        }],
        ManifestProvenance::RequestBound { request: binding.action_request },
        ValidatorId::new("needle.transition.v1").unwrap(),
    )
    .unwrap();
    assert_eq!(
        validate_partition_assembly(
            &policy,
            &scheme,
            &[&manifest],
            &binding,
            &partitions,
            Some(&transition),
        ),
        Err(PartitionManifestError::UnexpectedTransition)
    );
}

#[test]
fn manifest_local_cross_manifest_assembly_requires_explicit_accepted_mapping() {
    let scheme = scheme(PartitionKeyScope::ManifestLocal);
    let prior = manifest(&scheme, binding("prior"), &[(b"same-opaque-key", "prior")]);
    let current_binding = binding("current");
    let current = manifest(&scheme, current_binding.clone(), &[(b"same-opaque-key", "current")]);
    let policy = policy(&scheme);
    let mut selected = vec![refs(&prior)[0], refs(&current)[0]];
    selected.sort_unstable();

    assert_eq!(
        validate_partition_assembly(
            &policy,
            &scheme,
            &[&prior, &current],
            &current_binding,
            &selected,
            None,
        ),
        Err(PartitionManifestError::MissingTransition)
    );

    let transition = ManifestTransition::new(
        prior.id,
        current.id,
        digest("delta"),
        vec![PartitionKeyMapping { prior: selected[0], current: selected[1] }],
        ManifestProvenance::RequestBound { request: current_binding.action_request },
        ValidatorId::new("needle.transition.v1").unwrap(),
    )
    .unwrap();
    validate_partition_assembly(
        &policy,
        &scheme,
        &[&prior, &current],
        &current_binding,
        &selected,
        Some(&transition),
    )
    .unwrap();

    let unmapped = ManifestTransition::new(
        prior.id,
        current.id,
        digest("delta"),
        vec![PartitionKeyMapping {
            prior: PartitionRef::new(prior.id, digest("other-prior")),
            current: PartitionRef::new(current.id, digest("other-current")),
        }],
        ManifestProvenance::RequestBound { request: current_binding.action_request },
        ValidatorId::new("needle.transition.v1").unwrap(),
    )
    .unwrap();
    assert_eq!(
        validate_partition_assembly(
            &policy,
            &scheme,
            &[&prior, &current],
            &current_binding,
            &selected,
            Some(&unmapped),
        ),
        Err(PartitionManifestError::UnmappedCrossManifestPartition)
    );
}

#[test]
fn transitions_are_canonical_one_to_one_and_tamper_evident() {
    let prior = PartitionManifestId::new(digest("prior"));
    let current = PartitionManifestId::new(digest("current"));
    let first = PartitionKeyMapping {
        prior: PartitionRef::new(prior, digest("prior-a")),
        current: PartitionRef::new(current, digest("current-a")),
    };
    let second = PartitionKeyMapping {
        prior: PartitionRef::new(prior, digest("prior-b")),
        current: PartitionRef::new(current, digest("current-b")),
    };
    let provenance = ManifestProvenance::ProviderAttested {
        provider: ProviderId::new("provider.external-index").unwrap(),
        attestation: digest("attestation"),
    };
    let validator = ValidatorId::new("needle.transition.v1").unwrap();
    let a = ManifestTransition::new(
        prior,
        current,
        digest("delta"),
        vec![second, first],
        provenance.clone(),
        validator.clone(),
    )
    .unwrap();
    let b = ManifestTransition::new(
        prior,
        current,
        digest("delta"),
        vec![first, second],
        provenance.clone(),
        validator.clone(),
    )
    .unwrap();
    assert_eq!(a, b);
    assert!(a.is_canonical());
    assert_eq!(ManifestTransition::decode_json(&serde_json::to_vec(&a).unwrap()).unwrap(), a);

    let mut unknown = serde_json::to_value(&a).unwrap();
    unknown.as_object_mut().unwrap().insert("unknown".to_owned(), json!(true));
    assert!(ManifestTransition::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let duplicate_current = PartitionKeyMapping {
        prior: PartitionRef::new(prior, digest("prior-c")),
        current: first.current,
    };
    assert_eq!(
        ManifestTransition::new(
            prior,
            current,
            digest("delta"),
            vec![first, duplicate_current],
            provenance,
            validator,
        ),
        Err(PartitionManifestError::TransitionMappingAmbiguous)
    );

    let mut tampered = a;
    tampered.state_delta = digest("tampered");
    assert!(matches!(tampered.validate(), Err(PartitionManifestError::Digest { .. })));
    tampered.format_revision += 1;
    assert!(matches!(
        tampered.validate(),
        Err(PartitionManifestError::FormatRevision { record: "manifest_transition", .. })
    ));
}

#[test]
fn provenance_is_audited_but_never_collapses_manifest_identity() {
    let scheme = scheme(PartitionKeyScope::ProviderStable);
    let binding = binding("current");
    let request_bound = manifest(&scheme, binding.clone(), &[(b"a", "a")]);
    let provider = PartitionManifest::new(
        &scheme,
        binding,
        ManifestProvenance::ProviderAttested {
            provider: ProviderId::new("provider.external-index").unwrap(),
            attestation: digest("attestation"),
        },
        ManifestClosure::Closed,
        vec![entry_for_world(&scheme, b"a", "a", "current")],
        None,
    )
    .unwrap();
    assert_ne!(request_bound.id, provider.id);
    assert_ne!(request_bound.definition_digest, provider.definition_digest);
}
