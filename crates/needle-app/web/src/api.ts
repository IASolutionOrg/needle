import { useEffect } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

export type ApprovalDecision = "accept" | "decline" | "cancel"

export interface ApprovalRequest {
  host: "codex" | "antigravity"
  worker_role: RoleProfileRole | null
  role_profile: {
    profile_id: string
    revision: number
    definition_digest: string
  } | null
  allowances: EffectiveWorkerAllowancesV1 | null
  operation:
    | "command_execution"
    | "filesystem_change"
    | "network_access"
    | "mcp_invocation"
    | "external_effect"
  id: string
  thread_id: string
  turn_id: string
  item_id: string
  argv: string[]
  command_display: string | null
  cwd: string
  reason: string | null
  requested_permissions: {
    write_paths: string[]
    read_paths: string[]
    network: boolean
    raw: unknown
  }
  route: string
  repository_id: string
  repository_root: string
  expires_unix_ms: number
  classification:
    | "pending_user"
    | "pending_ai_eligible"
    | "rejected_file_change"
    | "rejected_network"
    | "rejected_unparseable"
    | "rejected_policy_mismatch"
    | "expired"
    | { auto_approved_test: { policy_id: string } }
    | { auto_approved_read_only: { policy_id: string } }
  payload_digest: string
  payload_digest_revision: number
  automation_advice: {
    policy_digest: string
    input_digest: string
    evaluator_host: "codex" | "antigravity"
    model: string
    reasoning: string
    decision: boolean
    input_tokens: number | null
    output_tokens: number | null
    evaluated_unix_ms: number
  } | null
  decision: ApprovalDecision | null
  decision_source: "auto_policy" | "ai_policy" | "web_user" | "timeout" | "runtime" | null
}

export interface RouteDefinition {
  id: string
  enabled: boolean
  priority: number
  preset_id: string
  definition_digest: string
}

export interface PlanNode {
  id: string
  operator_id: string
  depends_on: string[]
}

export interface RoutePlan {
  id: string
  revision: number
  definition_digest: string
  nodes: PlanNode[]
}

export interface ActionContractSummary {
  id: string
  coverage:
    | {
        kind: "semantic_predicate"
        predicate: "implementation-location" | "runtime-flow" | "focused-tests"
        definition_digest: string
      }
    | {
        kind: "partitioned"
        declared_policy_authority_digest: string
        scheme: {
          id: string
          kind: { kind: string; provider?: string }
          key_scope: "manifest_local" | "lineage_stable" | "provider_stable"
          key_schema: string
          maximum_key_bytes: number
          definition_digest: string
        }
        policy: {
          id: string
          manifest_validator: string
          maximum_partitions: number
          maximum_manifest_bytes: number
          overlap_policy: "disjoint" | "validator_defined"
          closure_policy: "open_allowed" | "closed_required"
          definition_digest: string
        }
        adapter_definition_digest: string
        fixed_mode: "shadow"
      }
  artifact_kind: string
  output_contract: {
    id: string
    revision: number
    schema: string
    definition_digest: string
  }
  validator_definition_digest: string
  effect_class:
    | "pure-evidence"
    | "derived-analysis"
    | "transform-proposal"
    | "execution-evidence"
    | "external-read"
    | "external-effect"
  reuse_modes: Array<"exact" | "project" | "assemble" | "refresh" | "never">
  default_dispatch_policy: {
    completion: "reuse-allowed" | "exact-reuse-only" | "fresh-required"
    evidence: "standard" | "independent-evidence-required"
    prior_artifacts: "contract-defined" | "advisory-only" | "forbidden"
    persistence: "persistent" | "ephemeral" | "no-store"
  }
  initial_mode: "disabled" | "shadow" | "advisory" | "authoritative"
  definition_digests: {
    semantic: string
    validation: string
    operational: string
    complete: string
  }
}

export interface ActionContractCatalog {
  schema: "needle.action-contract-catalog/3"
  status: "shadow_only"
  items: ActionContractSummary[]
  bounded: { limit: number }
}

export interface PartitionManifestSummary {
  manifest: string
  certificate: string
  action_request: string
  action_contract: string
  output_contract: string
  scheme: string
  repository: string
  closure: "open" | "closed"
  entry_count: number
  created_unix_ms: number
}

export interface PartitionManifestInspection {
  schema: "needle.partition-manifest-inspection/1"
  status: "shadow_only"
  items: PartitionManifestSummary[]
  bounded: { limit: number; maximum: number }
}

export type RefreshEconomicDecision =
  | { selection: "refresh" }
  | {
      selection: "full_compute"
      reason:
        | "missing_cost_evidence"
        | "below_minimum_net_value"
        | "missing_latency_evidence"
        | "refresh_latency_budget_exceeded"
    }

export interface RefreshEconomicAssessment {
  format_revision: number
  definition_digest: string
  request: string
  action_contract: string
  candidate_definition_digest: string
  operator_definition_digest: string
  execution_scope_digest: string
  policy: {
    format_revision: number
    action_operational_policy_digest: string
    refresh_policy_definition_digest: string
    minimum_expected_net_microusd: string
    maximum_refresh_latency_micros: number | null
    definition_digest: string
  }
  evidence: {
    format_revision: number
    request: string
    action_contract: string
    candidate_definition_digest: string
    operator_definition_digest: string
    execution_scope_digest: string
    basis:
      | "paired_observed"
      | "benchmark_derived"
      | "historical_estimate"
      | "configured_static"
    evidence_digest: string
    pricing_revision: string | null
    estimated_fresh_total_microusd: string
    estimated_refresh_total_microusd: string
    estimated_refresh_latency_micros: number | null
    definition_digest: string
  } | null
  expected_net_microusd: string | null
  decision: RefreshEconomicDecision
  authority: "shadow"
}

export interface RefreshEconomicInspection {
  schema: "needle.refresh-economic-inspection/1"
  status: "shadow_audit_only"
  items: Array<{
    assessment: RefreshEconomicAssessment
    selected_refresh_attempt: string | null
    recorded_unix_ms: number
  }>
  bounded: { limit: number; maximum: number }
}

export interface SettingsConfig {
  worker_model: string
  worker_reasoning: string
  worker_timeout_seconds: number
  evidence_failure_policy: "discard_invalid_fact" | "repair_once"
  trusted_test_execution: boolean
  multi_need_enabled: boolean
  continue_working_enabled: boolean
  max_needs_per_task: number
  max_workers_per_task: number
  pending_main_tools: "allow_and_taint"
  resolver_concurrency: number
}

export type ModelPolicy =
  | {
      fixed_order: {
        profiles: WorkerProfile[]
        repair_once: boolean
        native_fallback: boolean
      }
    }
  | {
      cheapest_validated_first: {
        promoted_profiles: WorkerProfile[]
        native_fallback: boolean
      }
    }

export type ModelPolicyInput =
  | {
      fixed_order: {
        profiles: Array<{
          model: string
          reasoning: string
          service_tier: string | null
        }>
        repair_once: boolean
        native_fallback: boolean
      }
    }

  | {
      cheapest_validated_first: {
        profiles: Array<{
          model: string
          reasoning: string
          service_tier: string | null
        }>
        native_fallback: boolean
      }
    }

export interface ApprovalAutomationPolicy {
  schema: "needle.approval-automation-policy/1"
  mode: "disabled" | "advisory" | "decide"
  evaluator_host: "codex"
  model: string
  reasoning: "none" | "low" | "medium" | "high" | "xhigh" | "max"
  timeout_seconds: number
}

export interface ControlPlane {
  schema: string
  activation: ActivationStatus
  integrations: {
    desktop_skill: DesktopSkillStatus
  }
  runtime: {
    status: string
    transport: string
    sandbox: string
    approval_policy: string
    storage: string
    external_telemetry: boolean
  }
  phases: Array<{ id: number; name: string; available: boolean }>
  routes: RouteDefinition[]
  plans: RoutePlan[]
  settings: SettingsConfig | null
  settings_digest: string | null
  approval_automation: ApprovalAutomationPolicy | null
  approval_automation_digest: string | null
  model_policy: ModelPolicy | null
  model_policy_digest: string | null
  role_profiles?: {
    schema: string
    status: "host_neutral_role_profiles"
    capability: "worker_hosts"
    codex: { available: boolean; execution_binding: boolean }
    antigravity: { available: boolean; execution_binding: boolean; reason: string }
    items: RoleProfileSummary[]
    bounded: { limit: number }
  }
  cache: Array<{
    identity_digest: string
    logical_digest: string
    source_digest: string
    created_unix_ms: number
    hit_count: number
  }>
  artifacts: Array<{
    id: string
    request_id: string
    contract_id: string
    kind: string
    scope: "snapshot_exact" | "worktree_semantic"
    dependency_count: number
    validation_count: number
    created_unix_ms: number
  }>
  worker_runs: number
  execution_attempts: number
  command_evidence: number
  pending_approvals: number
  route_promotions: Array<{
    route_key: string
    worker_profile_digest: string
    evidence_digest: string
    promoted_unix_ms: number
  }>
  changes: ChangeWorkflow[]
  semantic: {
    format_revision: number
    action_contracts?: ActionContractCatalog
    partition_manifests?: PartitionManifestInspection
    refresh_economics?: RefreshEconomicInspection
    needs: SemanticNeed[]
    subjects: SemanticSubject[]
    capabilities: CapabilityClass[]
    predicate_contracts: PredicateContract[]
    route_contracts: RouteContractDefinition[]
    selected_plans: SelectedProofPlan[]
    proofs: SufficiencyProof[]
    proof_accounting: ProofAccountingRecord[]
    need_steps: NeedStepEnvelope[]
    metrics: {
      authoritative_full_reuse: number
      authoritative_partial_reuse: number
      worker_avoided: number
      proof_overhead_micros: number
      stale_candidates: number
      active_contradictions: number
    }
  }
  cost_observations: unknown[]
}

export type ActivationScope =
  { kind: "global" } | { kind: "repository"; repository_root: string }

export interface ActivationRecord {
  scope: ActivationScope
  enabled: boolean
  role_profile_id: string | null
  generation: number
  state_digest: string
  created_unix_ms: number
  updated_unix_ms: number
}

export interface ActivationStatus {
  enabled: boolean
  effective_scope: ActivationScope | null
  role_profile_id: string | null
  global: ActivationRecord | null
  repository: ActivationRecord | null
}

export interface DesktopSkillStatus {
  installed: boolean | null
  managed: boolean | null
  ready: boolean
  error: string | null
}

export type PatchOperation = "create" | "update" | "delete"
export type VerificationStatus =
  "not_requested" | "verified" | "rejected" | "repairable" | "inconclusive"

export interface ChangedFile {
  path: string
  operation: PatchOperation
}

export interface ChangeAttempt {
  role: "patcher" | "verifier"
  patch_id: string | null
  attempt: Record<string, unknown>
  usage: {
    input_tokens?: number | null
    cached_input_tokens?: number | null
    output_tokens?: number | null
    duration_ms?: number | null
  }
  cost_microusd: number | null
  created_unix_ms: number
}

export interface VerificationArtifact {
  id: string
  change_id: string
  patch_id: string
  verdict: VerificationStatus
  acceptance_coverage: Array<{
    criterion: string
    status: "addressed" | "partial" | "unaddressed"
    evidence: string
  }>
  findings: string[]
  test_evidence_ids: string[]
  /** Additive v2 projection; old artifacts omit this field. */
  test_plan_results?: Array<{
    plan_digest: string
    runner: string
    argv: string[]
    cwd_relative: string
    test_identifier: string
    expected: boolean
    available: boolean
    executed: boolean
    passed: boolean
    evidence_id?: string | null
    failure_reason?: string | null
  }>
  test_plans_over_cap?: boolean
  verifier_definition: string
  created_unix_ms: number
}

export interface ChangeApplyRecord {
  id: string
  change_id: string
  patch_id: string
  repository_root: string
  pre_snapshot: string
  post_snapshot: string | null
  status:
    | "applying"
    | "applied"
    | "rolled_back"
    | "rollback_failed"
    | "recovery_conflict"
  created_unix_ms: number
  completed_unix_ms: number | null
}

export interface ChangeWorkflow {
  change_id: string
  patch_id: string
  revision: number
  state: string
  attempts: ChangeAttempt[]
  verification: VerificationArtifact | null
  applies: ChangeApplyRecord[]
}

export interface ChangeListItem {
  change_id: string
  state: string
  patch_id: string
  revision: number
  summary: string
  changed_files: ChangedFile[]
  change_digest: string
  created_unix_ms: number
}

export interface ChangeDetail {
  change: {
    request: {
      task: string
      acceptance_criteria: string[]
      constraints: string[]
    }
    state: string
    patch: {
      id: string
      change_id: string
      revision: number
      summary: string
      files: ChangedFile[]
      residual_risks: string[]
    }
  }
  verification: VerificationArtifact | null
  attempts: ChangeAttempt[]
  applies: ChangeApplyRecord[]
  change_digest: string
  apply_allowed: boolean
}

export type LifecyclePhase =
  "explore" | "implement" | "test" | "review" | "verify" | "apply"

export type LifecycleStatus =
  | "active"
  | "repair_reserved"
  | "awaiting_approval"
  | "approved"
  | "applying"
  | "completed"
  | "failed"
  | "cancelled"
  | "inconclusive"
  | "rolled_back"

export interface LifecycleStartProfile {
  profile_id: string
  role: "explorer" | "implementer" | "test_runner" | "reviewer" | "verifier"
  revision: number
  definition_digest: string
}

export interface LifecycleStartNeed {
  need_id: string
  route: string
  required_predicates: string[]
  need_definition_digest: string
  action_plan_definition_digest: string
}

export interface LifecycleStartTestPlan {
  artifact_id: string
  plan_digest: string
  certificate_digest: string
  issued_unix_ms: number
}

export interface LifecycleBudget {
  max_worker_turns: number
  max_output_tokens: number
  max_cost_microusd: number
  max_concurrent_workers: number
}

export interface LifecycleStartPreflight {
  schema: "needle.lifecycle-start-preflight/1"
  repository_id: string
  source_snapshot: string
  watcher_uncertain: boolean
  eligible: boolean
  blockers: string[]
  profiles: LifecycleStartProfile[]
  needs: LifecycleStartNeed[]
  test_plans: LifecycleStartTestPlan[]
  max_selected_test_plans: number
  default_budget: LifecycleBudget
}

export interface LifecycleProfileSelection {
  profile_id: string
  definition_digest: string
}

export interface LifecycleCreateInput {
  operation_id: string
  expected_source_snapshot: string
  need_id: string
  change: {
    task: string
    acceptance_criteria: string[]
    allowed_paths: Array<{ path: string; scope: "exact" | "subtree" }>
    artifact_ids: string[]
    claim_ids: string[]
    constraints: string[]
  }
  profiles: {
    explore: LifecycleProfileSelection
    implement: LifecycleProfileSelection
    test: LifecycleProfileSelection
    review: LifecycleProfileSelection
    verify: LifecycleProfileSelection
  }
  budget: Omit<LifecycleBudget, "max_concurrent_workers">
  test_plan_certificates: string[]
}

export interface LifecycleCreateResponse {
  schema: "needle.lifecycle-create/1"
  created: boolean
  change_id: string
  lifecycle_id: string
  phase: LifecyclePhase
  status: LifecycleStatus
  generation: number
  state_digest: string
  source_snapshot: string
  action_plan_definition_digest: string
}

export interface LifecycleUsage {
  worker_turns: number
  output_tokens: number
  cost_microusd: number
}

export interface LifecycleExploreReuseAuthority {
  capability_class: string
  capability_definition_digest: string
  evidence: string
  decision: string
}

export interface LifecycleExploreReuseCompletion {
  authority: LifecycleExploreReuseAuthority
  action_request: string
  origin_request: string
  artifact: string
  validation_certificate: string
  selected_plan: string
  sufficiency_certificate: string
  repository_id: string
  source_snapshot: string
  resolution_definition_digest: string
}

export type LifecycleExploreReuseOutcome =
  | {
      kind: "resolver_authorized"
      authority: LifecycleExploreReuseAuthority
    }
  | {
      kind: "consumed"
      completion: LifecycleExploreReuseCompletion
    }

export interface LifecycleSummary {
  lifecycle_id: string
  change_id: string
  source_snapshot: string
  phase: LifecyclePhase
  status: LifecycleStatus
  state_digest: string
  generation: number
  usage: LifecycleUsage
  terminal_outcome: string | null
  terminal_reason: { code: string; detail_digest: string } | null
  created_unix_ms: number
  updated_unix_ms: number
}

export interface LifecycleDetail extends LifecycleSummary {
  worker_depth_limit: number
  profiles: Array<{
    phase: LifecyclePhase
    profile_id: string
    revision: number
    definition_digest: string
  }>
  test_plans: Array<{ plan_digest: string; certificate_digest: string }>
  budget: LifecycleBudget
  artifacts: {
    exploration: Array<{
      kind: string
      artifact_id: string
      source_snapshot: string
    }>
    patch: { patch_id: string; revision: number } | null
    tests: Array<{
      plan_digest: string
      certificate_digest: string
      available: boolean
      executed: boolean
      passed: boolean
      evidence_id: string | null
      action_evidence_artifact: string | null
      failure_code: string | null
    }>
    review: unknown | null
    verification: unknown | null
  }
  explore_reuse: LifecycleExploreReuseCompletion | null
  repair_reserved: boolean
  repair_consumed: boolean
  approval: unknown | null
  apply_id: string | null
  cleanup: unknown | null
  recovery: unknown | null
}

export interface LifecycleStepResponse {
  schema: "needle.lifecycle-step/1"
  change_id: string
  disposition: string
  phase: LifecyclePhase
  status: LifecycleStatus
  generation: number
  state_digest: string
  invocation_id: string | null
  adapter_usage: LifecycleUsage
  observation: {
    observation_digest: string
    resolution: string
    planned_action_count: number
    authority: "shadow"
    adapter_invocation_required: boolean
  } | null
  observation_persistence: string | null
  reuse: LifecycleExploreReuseOutcome | null
}

export interface LifecycleApplyResponse {
  schema: "needle.lifecycle-apply/1"
  operation_id: string
  change_id: string
  phase: "apply"
  status: LifecycleStatus
  state_digest: string
  artifact_id: string
  validation_certificate_id: string
  idempotent_replay: boolean
  receipt: {
    schema: string
    id: string
    operation_id: string
    change_id: string
    patch_id: string
    expected_state_digest: string
    source_before: string
    source_after: string
    applied_files_digest: string
    applied_unix_ms: number
  }
}

export interface LifecycleAdapterRecoveryRecord {
  recovery_digest: string
  source: "web_user"
  recovered_unix_ms: number
}

export interface LifecycleAdapterInvocation {
  invocation_id: string
  lifecycle_id: string
  expected_state_digest: string
  phase: LifecyclePhase
  status: "in_progress" | "completed" | "aborted"
  request_digest: string
  adapter_definition_digest: string
  started_unix_ms: number
  completed_unix_ms: number | null
  recovery: LifecycleAdapterRecoveryRecord | null
}

export interface LifecycleAdapterInvocationResponse {
  schema: "needle.lifecycle-adapter-invocation/1"
  change_id: string
  invocation: LifecycleAdapterInvocation | null
}

export interface LifecycleAdapterRecoveryResponse {
  schema: "needle.lifecycle-adapter-recovery/1"
  created: boolean
  change_id: string
  lifecycle: LifecycleSummary
  invocation: LifecycleAdapterInvocation
}

export interface NeedStep {
  id: string
  ordinal: number
  turn_id: string
  need_id: string
  coordination: "wait-response" | "continue-working"
  relation:
    | "repeat"
    | "residual"
    | "extension"
    | "overlap"
    | "independent"
    | "incompatible"
  state:
    | "requested"
    | "queued"
    | "resolving"
    | "resolved"
    | "delivered"
    | "native_fallback"
    | "failed"
    | "cancelled"
  required: string[]
  satisfied: string[]
  missing: string[]
  artifacts: string[]
  proof: string | null
  delivery:
    "turn_start" | "turn_steer" | "already_satisfied" | "native_fallback" | null
  worker_avoided: boolean
  main_discovery_tainted: boolean
}

export interface NeedStepEnvelope {
  session_id: string
  step: NeedStep
  request: NeedStepRequest | null
  main_turn_observations: Array<{
    turn_id: string
    status: string
    delivery: string | null
    usage_json: string
    tools_json: string
    main_discovery_tainted: boolean
  }>
  cost_microcredits: number | null
}

export interface NeedStepRequest {
  need_step_id: string
  session_id: string
  request_digest: string
  raw_message: string
  semantic_interrupt: unknown | null
  need_ir: unknown | null
  transport: string | null
  request_format: string | null
  created_unix_ms: number
}

export interface SemanticFacet {
  key: string
  value: string
}

export interface SemanticObligation {
  id: string
  predicate: "implementation-location" | "runtime-flow" | "focused-tests"
  subject: string
  facets: SemanticFacet[]
}

export interface SemanticNeed {
  id: string
  required: SemanticObligation[]
  preferred: SemanticObligation[]
  residual: { reason: string; mandatory: boolean } | null
  world: {
    repository_lineage: string
    source_selector: string
    platform: string
    features: string
  }
  format_revision: number
}

export interface SemanticSubject {
  id: string
  kind: string
  canonical_name: string
  repository_lineage: string
}

export interface CapabilityClass {
  id: string
  predicate: string
  reuse_unit?: "artifact" | "claim"
  exact_subject_only: boolean
  positive_only: boolean
  single_world_only: boolean
  composition: boolean
  mode: "disabled" | "shadow" | "advisory" | "authoritative"
  definition_digest: string
}

export interface PredicateContract {
  predicate: string
  allowed_subject_kinds: string[]
  allowed_facets: string[]
  world_dimensions: string[]
  definition_digest: string
}

export interface RouteContractDefinition {
  route: string
  required: Array<{ predicate: string; facets: SemanticFacet[] }>
  preferred: Array<{ predicate: string; facets: SemanticFacet[] }>
  definition_digest: string
}

export interface SelectedProofPlan {
  id: string
  need: string
  artifact_ids: string[]
  claim_ids?: string[]
  claim_validation_certificate_ids?: string[]
  claim_set_certificate_ids?: string[]
  covered_mask: number
  missing_mask: number
  decision_reason: string
  economics: {
    expected_fresh_microusd: number | null
    expected_selected_microusd: number | null
    proof_overhead_micros: number
    expected_net_microusd: number | null
  }
}

export interface SufficiencyProof {
  id: string
  need: string
  obligations: string[]
  artifacts: string[]
  validation_certificates: string[]
  world_digest: string
  engine_definition: string
}

export interface ProofAccountingRecord {
  need_id: string
  plan_id: string | null
  parse_micros: number
  lookup_micros: number
  validation_micros: number
  planning_micros: number
  projection_micros: number
  allocation_count: number | null
  allocated_bytes: number | null
  stale_candidates: number
  created_unix_ms: number
}

export interface WorkerProfile {
  platform: string
  model: string
  reasoning: string
  service_tier: string | null
  definition_digest: string
}

export type RoleProfileRole =
  | "explorer"
  | "implementer"
  | "test_runner"
  | "reviewer"
  | "verifier"
  | "auditor"
export type RoleProfileReasoning = "low" | "medium" | "high" | "xhigh"
export type RoleProfileServiceTier = "default" | "priority"
export type RoleProfileHost = "codex" | "antigravity"

export interface RoleProfileBudget {
  max_turns: number
  max_output_tokens: number
  max_cost_microusd: number
}

export interface RoleProfileDefinitionInput {
  profile_id: string
  role: RoleProfileRole
  host: RoleProfileHost
  model: string
  reasoning: RoleProfileReasoning
  service_tier: RoleProfileServiceTier
  timeout_seconds: number
  budget: RoleProfileBudget
  prompt_profile_digest: string
  output_contract_digest: string
  tool_policy: "read_only" | "isolated_write"
  command_policy: "denied" | "read_only" | "certified_tests"
  filesystem_policy: "read_only_checkout" | "disposable_checkout"
  network_policy: "denied"
  test_policy: "disabled" | "certified"
  repair_policy: "none" | "once"
  fallback_policy: "disabled" | "native"
  concurrency: number
  route_assignments: string[]
}

export interface RoleProfileDefinition extends RoleProfileDefinitionInput {
  definition_digest: string
}

export interface EffectiveWorkerAllowancesV1 {
  schema: "needle.worker-allowances/1"
  host: RoleProfileHost
  filesystem_read_checkout: boolean
  filesystem_write: "denied" | "disposable_checkout"
  command_policy: "denied" | "read_only" | "certified_tests"
  network: boolean
  mcp: boolean
  subagents: boolean
  external_effects: boolean
  human_approval_required: boolean
  role_profile_definition_digest: string
  allowance_digest: string
}

export type RoleProfileState = "draft" | "active" | "inactive"

export interface RoleProfilePreflightSummary {
  passed: boolean
  failures: string[]
  worker_profile_digest: string | null
  allowance_digest: string | null
}

export interface RoleProfileSummary {
  profile_id: string
  role: RoleProfileRole
  host: RoleProfileHost
  latest_revision: number
  latest_definition_digest: string
  active_revision: number | null
  active_definition_digest: string | null
  state: RoleProfileState
  state_digest: string
  updated_unix_ms: number
  allowance_digest: string
}

export interface RoleProfileRevisionSummary {
  revision: number
  definition_digest: string
  role: RoleProfileRole
  host: RoleProfileHost
  model: string
  reasoning: RoleProfileReasoning
  service_tier: RoleProfileServiceTier
  state: RoleProfileState
  created_unix_ms: number
  activated_unix_ms: number | null
}

export interface RoleProfileDetail {
  profile_id: string
  revision: number
  state: RoleProfileState
  definition: RoleProfileDefinition
  definition_digest: string
  worker_profile: WorkerProfile | null
  worker_profile_digest: string | null
  allowances: EffectiveWorkerAllowancesV1 | null
  allowance_digest: string | null
  preflight: RoleProfilePreflightSummary
  created_unix_ms: number
  activated_unix_ms: number | null
  state_digest: string
  latest_revision: number
  latest_definition_digest: string
  active_revision: number | null
  active_definition_digest: string | null
  updated_unix_ms: number
}

export interface RoleProfileAuditSummary {
  audit_id: number
  profile_id: string
  revision: number
  definition_digest: string
  operation: "create" | "revise" | "activate" | "deactivate"
  prior_state: RoleProfileState | null
  resulting_state: RoleProfileState
  prior_state_digest: string | null
  resulting_state_digest: string
  prior_active_revision: number | null
  prior_active_digest: string | null
  resulting_active_revision: number | null
  resulting_active_digest: string | null
  created_unix_ms: number
}

export interface RoleProfileListResponse {
  schema: string
  items: RoleProfileSummary[]
  limit: number
}

export interface RoleProfileDetailResponse {
  schema: string
  profile: RoleProfileDetail
}

export interface RoleProfileRevisionsResponse {
  schema: string
  profile_id: string
  items: RoleProfileRevisionSummary[]
  limit: number
  total: number
}

export interface RoleProfileAuditResponse {
  schema: string
  profile_id: string
  items: RoleProfileAuditSummary[]
  limit: number
}

export interface RoleProfilePreflightResponse {
  schema: string
  profile_id?: string
  operation: "create" | "revise" | "activate" | "invalid"
  passed: boolean
  failures: string[]
  if_match?: string
  definition: RoleProfileDefinition | null
  definition_digest: string | null
  worker_profile: WorkerProfile | null
  worker_profile_digest: string | null
  allowances: EffectiveWorkerAllowancesV1 | null
  allowance_digest: string | null
}

export interface RoleProfileMutationResponse {
  schema: string
  operation: "create" | "revise" | "activate" | "deactivate"
  profile: RoleProfileDetail
  state_digest: string
}

export class RoleProfileApiError extends Error {
  readonly status: number
  readonly code: string
  readonly body: unknown

  constructor(status: number, code: string, message: string, body?: unknown) {
    super(message)
    this.name = "RoleProfileApiError"
    this.status = status
    this.code = code
    this.body = body
  }
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin" })
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`)
  }
  return response.json() as Promise<T>
}

async function roleProfileJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...init,
  })
  if (response.ok) return (await response.json()) as T
  const body = (await response.json().catch(() => null)) as {
    code?: string
    message?: string
    error?: string
  } | null
  throw new RoleProfileApiError(
    response.status,
    body?.code ?? "request_failed",
    body?.message ??
      body?.error ??
      `Role-profile request failed with ${response.status}`,
    body
  )
}

function csrfToken() {
  return (
    document
      .querySelector<HTMLMetaElement>('meta[name="needle-csrf"]')
      ?.getAttribute("content") ?? ""
  )
}

function roleProfileHeaders(digest?: string) {
  return {
    "content-type": "application/json",
    "x-csrf-token": csrfToken(),
    ...(digest ? { "if-match": `"${digest}"` } : {}),
  }
}

function invalidateRoleProfileQueries(
  queryClient: ReturnType<typeof useQueryClient>
) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: ["role-profiles"] }),
    queryClient.invalidateQueries({ queryKey: ["role-profile"] }),
    queryClient.invalidateQueries({ queryKey: ["control-plane"] }),
  ])
}

function refreshAfterRoleProfileConflict(
  queryClient: ReturnType<typeof useQueryClient>,
  error: unknown
) {
  if (
    error instanceof RoleProfileApiError &&
    (error.status === 409 || error.status === 412)
  ) {
    return Promise.all([
      invalidateRoleProfileQueries(queryClient),
      queryClient.refetchQueries({ queryKey: ["role-profile"] }),
    ]).then(() => undefined)
  }
  return Promise.resolve()
}

export function useRoleProfiles() {
  return useQuery({
    queryKey: ["role-profiles"],
    queryFn: () =>
      roleProfileJson<RoleProfileListResponse>("/api/v1/role-profiles"),
  })
}

export function useRoleProfile(
  profileId: string | undefined,
  revision?: number
) {
  const query = revision == null ? "" : `?revision=${revision}`
  return useQuery({
    queryKey: ["role-profile", profileId, revision ?? "latest"],
    queryFn: () =>
      roleProfileJson<RoleProfileDetailResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId ?? "")}${query}`
      ),
    enabled: Boolean(profileId),
  })
}

export function useRoleProfileRevisions(profileId: string | undefined) {
  return useQuery({
    queryKey: ["role-profile", profileId, "revisions"],
    queryFn: () =>
      roleProfileJson<RoleProfileRevisionsResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId ?? "")}/revisions`
      ),
    enabled: Boolean(profileId),
  })
}

export function useRoleProfileAudit(profileId: string | undefined) {
  return useQuery({
    queryKey: ["role-profile", profileId, "audit"],
    queryFn: () =>
      roleProfileJson<RoleProfileAuditResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId ?? "")}/audit`
      ),
    enabled: Boolean(profileId),
  })
}

export function useRoleProfilePreflight() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      profileId,
      input,
    }: {
      profileId: string
      input: RoleProfileDefinitionInput
    }) =>
      roleProfileJson<RoleProfilePreflightResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId)}/preflight`,
        {
          method: "POST",
          headers: roleProfileHeaders(),
          body: JSON.stringify(input),
        }
      ),
    onError: (error) => refreshAfterRoleProfileConflict(queryClient, error),
  })
}

export function useRoleProfileDraft() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      profileId,
      input,
      stateDigest,
    }: {
      profileId: string
      input: RoleProfileDefinitionInput
      stateDigest: string
    }) =>
      roleProfileJson<RoleProfileMutationResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId)}/draft`,
        {
          method: "POST",
          headers: roleProfileHeaders(stateDigest),
          body: JSON.stringify(input),
        }
      ),
    onSuccess: (_, variables) =>
      Promise.all([
        invalidateRoleProfileQueries(queryClient),
        queryClient.invalidateQueries({
          queryKey: ["role-profile", variables.profileId],
        }),
      ]),
    onError: (error) => refreshAfterRoleProfileConflict(queryClient, error),
  })
}

export function useRoleProfileActivate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      profileId,
      revision,
      definitionDigest,
      stateDigest,
    }: {
      profileId: string
      revision: number
      definitionDigest: string
      stateDigest: string
    }) =>
      roleProfileJson<RoleProfileMutationResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId)}/activate`,
        {
          method: "POST",
          headers: roleProfileHeaders(stateDigest),
          body: JSON.stringify({
            revision,
            definition_digest: definitionDigest,
            confirm: true,
          }),
        }
      ),
    onSuccess: (_, variables) =>
      Promise.all([
        invalidateRoleProfileQueries(queryClient),
        queryClient.invalidateQueries({
          queryKey: ["role-profile", variables.profileId],
        }),
      ]),
    onError: (error) => refreshAfterRoleProfileConflict(queryClient, error),
  })
}

export function useRoleProfileDeactivate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      profileId,
      activeDefinitionDigest,
      stateDigest,
    }: {
      profileId: string
      activeDefinitionDigest: string
      stateDigest: string
    }) =>
      roleProfileJson<RoleProfileMutationResponse>(
        `/api/v1/role-profiles/${encodeURIComponent(profileId)}/deactivate`,
        {
          method: "POST",
          headers: roleProfileHeaders(stateDigest),
          body: JSON.stringify({
            active_definition_digest: activeDefinitionDigest,
            confirm: true,
          }),
        }
      ),
    onSuccess: (_, variables) =>
      Promise.all([
        invalidateRoleProfileQueries(queryClient),
        queryClient.invalidateQueries({
          queryKey: ["role-profile", variables.profileId],
        }),
      ]),
    onError: (error) => refreshAfterRoleProfileConflict(queryClient, error),
  })
}

export function useControlPlane() {
  return useQuery({
    queryKey: ["control-plane"],
    queryFn: () => getJson<ControlPlane>("/api/v1/control-plane"),
  })
}

export function useActivationToggle() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (enabled: boolean) => {
      const current = queryClient.getQueryData<ControlPlane>(["control-plane"])
      const response = await fetch("/api/v1/activation", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrfToken(),
        },
        body: JSON.stringify({
          enabled,
          expected_state_digest:
            current?.activation.repository?.state_digest ?? null,
        }),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Activation request failed with ${response.status}`
        )
      }
      return response.json() as Promise<ActivationStatus>
    },
    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: ["control-plane"] }),
  })
}

export function useApprovals() {
  return useQuery({
    queryKey: ["approvals"],
    queryFn: () =>
      getJson<ApprovalRequest[]>("/api/v1/approvals?status=pending"),
    refetchInterval: 1000,
  })
}

export function useApprovalEvents() {
  const queryClient = useQueryClient()
  useEffect(() => {
    const events = new EventSource("/api/v1/approvals/events")
    const refresh = () => {
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["approvals"] }),
        queryClient.invalidateQueries({ queryKey: ["control-plane"] }),
      ])
    }
    events.addEventListener("approval-change", refresh)
    return () => {
      events.removeEventListener("approval-change", refresh)
      events.close()
    }
  }, [queryClient])
}

export function useApprovalDecision() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      request,
      decision,
    }: {
      request: ApprovalRequest
      decision: ApprovalDecision
    }) => {
      const response = await fetch(
        `/api/v1/approvals/${encodeURIComponent(request.id)}/decision`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({
            decision,
            payload_digest: request.payload_digest,
          }),
        }
      )
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Decision failed with ${response.status}`
        )
      }
      return response.json() as Promise<ApprovalRequest>
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["approvals"] }),
        queryClient.invalidateQueries({ queryKey: ["control-plane"] }),
      ])
    },
  })
}

export function useRouteState() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      route,
      enabled,
    }: {
      route: RouteDefinition
      enabled: boolean
    }) => {
      const response = await fetch(
        `/api/v1/routes/${encodeURIComponent(route.id)}/state`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "if-match": `"${route.definition_digest}"`,
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({ enabled }),
        }
      )
      if (!response.ok) {
        throw new Error(`Route update failed with ${response.status}`)
      }
      return response.json() as Promise<RouteDefinition>
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["control-plane"] })
    },
  })
}

export function useSettingsUpdate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      settings,
      digest,
    }: {
      settings: SettingsConfig
      digest: string
    }) => {
      const response = await fetch("/api/v1/settings", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "if-match": `"${digest}"`,
          "x-csrf-token": csrfToken(),
        },
        body: JSON.stringify(settings),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Settings update failed with ${response.status}`
        )
      }
      return response.json()
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["control-plane"] })
    },
  })
}

export function useApprovalAutomationUpdate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      policy,
      digest,
    }: {
      policy: ApprovalAutomationPolicy
      digest: string
    }) => {
      const response = await fetch("/api/v1/approval-automation", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "if-match": `"${digest}"`,
          "x-csrf-token": csrfToken(),
        },
        body: JSON.stringify(policy),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Approval automation update failed with ${response.status}`
        )
      }
      return response.json()
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["control-plane"] })
    },
  })
}

export function useModelPolicyUpdate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      policy,
      digest,
    }: {
      policy: ModelPolicyInput
      digest: string
    }) => {
      const response = await fetch("/api/v1/model-policy", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "if-match": `"${digest}"`,
          "x-csrf-token": csrfToken(),
        },
        body: JSON.stringify(policy),
      })
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Model policy update failed with ${response.status}`
        )
      }
      return response.json()
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["control-plane"] })
    },
  })
}

export function useCapabilityModeUpdate() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      capability,
      mode,
      evidenceDigest,
    }: {
      capability: CapabilityClass
      mode: CapabilityClass["mode"]
      evidenceDigest: string | null
    }) => {
      const response = await fetch(
        `/api/v1/capabilities/${encodeURIComponent(capability.id)}/mode`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "if-match": `"${capability.definition_digest}"`,
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({
            mode,
            evidence_digest: evidenceDigest,
            confirm: true,
          }),
        }
      )
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(
          body?.error ?? `Capability update failed with ${response.status}`
        )
      }
      return response.json() as Promise<CapabilityClass>
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["control-plane"] })
    },
  })
}

export function useProofReplay() {
  return useMutation({
    mutationFn: async (proofId: string) => {
      const response = await fetch(
        `/api/v1/proofs/${encodeURIComponent(proofId)}/replay`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": csrfToken(),
          },
          body: "{}",
        }
      )
      if (!response.ok) {
        throw new Error(`Proof replay failed with ${response.status}`)
      }
      return response.json() as Promise<{
        proof_id: string
        structural_valid: boolean
        fresh: boolean
        contradiction_free: boolean
        replay_valid: boolean
        model_invoked: false
      }>
    },
  })
}

async function lifecycleJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin", ...init })
  if (response.ok) return response.json() as Promise<T>
  const body = (await response.json().catch(() => null)) as {
    code?: string
    message?: string
  } | null
  throw new Error(
    body?.message ??
      body?.code ??
      `Lifecycle request failed with ${response.status}`
  )
}

export function useLifecycleStartPreflight() {
  return useQuery({
    queryKey: ["lifecycles", "preflight"],
    queryFn: () =>
      lifecycleJson<LifecycleStartPreflight>("/api/v1/lifecycles/preflight"),
  })
}

export function useCreateLifecycle() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: LifecycleCreateInput) =>
      lifecycleJson<LifecycleCreateResponse>("/api/v1/lifecycles", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrfToken(),
        },
        body: JSON.stringify(input),
      }),
    onSuccess: async (created) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["lifecycles", "list"] }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "detail", created.change_id],
        }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "preflight"],
        }),
      ])
    },
  })
}

export function useLifecycles() {
  return useQuery({
    queryKey: ["lifecycles", "list"],
    queryFn: () =>
      lifecycleJson<{
        schema: "needle.lifecycle-list/1"
        items: LifecycleSummary[]
        limit: number
      }>("/api/v1/lifecycles"),
  })
}

export function useLifecycle(changeId: string | undefined) {
  return useQuery({
    queryKey: ["lifecycles", "detail", changeId],
    queryFn: () =>
      lifecycleJson<{
        schema: "needle.lifecycle-detail/1"
        lifecycle: LifecycleDetail
      }>(`/api/v1/lifecycles/${encodeURIComponent(changeId ?? "")}`),
    enabled: Boolean(changeId),
  })
}

export function useLifecycleAdapterInvocation(changeId: string | undefined) {
  return useQuery({
    queryKey: ["lifecycles", "adapter-invocation", changeId],
    queryFn: () =>
      lifecycleJson<LifecycleAdapterInvocationResponse>(
        `/api/v1/lifecycles/${encodeURIComponent(changeId ?? "")}/adapter-invocation`
      ),
    enabled: Boolean(changeId),
  })
}

export function useStepLifecycle() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      changeId,
      expectedStateDigest,
    }: {
      changeId: string
      expectedStateDigest: string
    }) =>
      lifecycleJson<LifecycleStepResponse>(
        `/api/v1/lifecycles/${encodeURIComponent(changeId)}/step`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({ expected_state_digest: expectedStateDigest }),
        }
      ),
    onSuccess: async (_, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["lifecycles", "list"] }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "detail", variables.changeId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "adapter-invocation", variables.changeId],
        }),
      ])
    },
    onError: async (_, variables) => {
      await queryClient.invalidateQueries({
        queryKey: ["lifecycles", "adapter-invocation", variables.changeId],
      })
    },
  })
}

export function useApplyLifecycle() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      changeId,
      expectedStateDigest,
    }: {
      changeId: string
      expectedStateDigest: string
    }) =>
      lifecycleJson<LifecycleApplyResponse>(
        `/api/v1/lifecycles/${encodeURIComponent(changeId)}/apply`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({
            expected_state_digest: expectedStateDigest,
            confirm: true,
          }),
        }
      ),
    onSuccess: async (_, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["lifecycles", "list"] }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "detail", variables.changeId],
        }),
        queryClient.invalidateQueries({ queryKey: ["changes"] }),
      ])
    },
  })
}

export function useRecoverLifecycleAdapterInvocation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      changeId,
      invocationId,
      expectedStateDigest,
    }: {
      changeId: string
      invocationId: string
      expectedStateDigest: string
    }) =>
      lifecycleJson<LifecycleAdapterRecoveryResponse>(
        `/api/v1/lifecycles/${encodeURIComponent(changeId)}/adapter-invocation/recover`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({
            invocation_id: invocationId,
            expected_state_digest: expectedStateDigest,
            confirm_provider_stopped: true,
          }),
        }
      ),
    onSuccess: async (_, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["lifecycles", "list"] }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "detail", variables.changeId],
        }),
        queryClient.invalidateQueries({
          queryKey: ["lifecycles", "adapter-invocation", variables.changeId],
        }),
      ])
    },
  })
}

export function useChanges() {
  return useQuery({
    queryKey: ["changes"],
    queryFn: () => getJson<ChangeListItem[]>("/api/v1/changes"),
  })
}

export function useChange(changeId: string | undefined) {
  return useQuery({
    queryKey: ["changes", changeId],
    queryFn: () =>
      getJson<ChangeDetail>(
        `/api/v1/changes/${encodeURIComponent(changeId ?? "")}`
      ),
    enabled: Boolean(changeId),
  })
}

export function useChangeDiff(changeId: string | undefined) {
  return useQuery({
    queryKey: ["changes", changeId, "diff"],
    queryFn: async () => {
      const response = await fetch(
        `/api/v1/changes/${encodeURIComponent(changeId ?? "")}/diff`,
        { credentials: "same-origin" }
      )
      if (!response.ok) {
        throw new Error(`Diff request failed with ${response.status}`)
      }
      return response.text()
    },
    enabled: Boolean(changeId),
  })
}

export function useApplyChange() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      changeId,
      digest,
    }: {
      changeId: string
      digest: string
    }) => {
      const response = await fetch(
        `/api/v1/changes/${encodeURIComponent(changeId)}/apply`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "content-type": "application/json",
            "if-match": `"${digest}"`,
            "x-csrf-token": csrfToken(),
          },
          body: JSON.stringify({ confirm: true }),
        }
      )
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(body?.error ?? `Apply failed with ${response.status}`)
      }
      return response.json() as Promise<ChangeApplyRecord>
    },
    onSuccess: async (_, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["changes"] }),
        queryClient.invalidateQueries({
          queryKey: ["changes", variables.changeId],
        }),
        queryClient.invalidateQueries({ queryKey: ["control-plane"] }),
      ])
    },
  })
}
