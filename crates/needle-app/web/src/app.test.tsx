import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { vi } from "vitest"

import App from "@/App"
import { TooltipProvider } from "@/components/ui/tooltip"

const controlPlane = {
  schema: "needle.control-plane/1",
  activation: {
    enabled: false,
    effective_scope: null,
    role_profile_id: null,
    global: null,
    repository: null,
  },
  integrations: {
    desktop_skill: {
      installed: false,
      managed: false,
      ready: false,
      error: null,
    },
  },
  runtime: {
    status: "healthy",
    transport: "codex-app-server",
    sandbox: "read-only",
    approval_policy: "on-request",
    storage: "sqlite",
    external_telemetry: false,
  },
  phases: [],
  routes: [
    {
      id: "locate.implementation",
      enabled: true,
      priority: 100,
      preset_id: "locate.implementation",
      definition_digest: "b3:route",
    },
  ],
  plans: [],
  settings: null,
  cache: [],
  worker_runs: 0,
  pending_approvals: 0,
  route_promotions: [],
  changes: [],
  semantic: {
    action_contracts: {
      schema: "needle.action-contract-catalog/3",
      status: "shadow_only",
      bounded: { limit: 6 },
      items: [
        {
          id: "needle.location.resolve",
          coverage: {
            kind: "semantic_predicate",
            predicate: "implementation-location",
            definition_digest: "b3:coverage",
          },
          artifact_kind: "code-location",
          output_contract: {
            id: "needle.semantic.code-location",
            revision: 2,
            schema: "needle.semantic-artifact-result/1",
            definition_digest: "b3:output",
          },
          validator_definition_digest: "b3:validator",
          effect_class: "pure-evidence",
          reuse_modes: ["exact", "project", "assemble"],
          default_dispatch_policy: {
            completion: "reuse-allowed",
            evidence: "standard",
            prior_artifacts: "contract-defined",
            persistence: "persistent",
          },
          initial_mode: "shadow",
          definition_digests: {
            semantic: "b3:semantic",
            validation: "b3:validation",
            operational: "b3:operational",
            complete: "b3:complete",
          },
        },
        {
          id: "needle.architecture.describe",
          coverage: {
            kind: "partitioned",
            declared_policy_authority_digest: "b3:architecture-partitions",
            scheme: {
              id: "needle.architecture.package",
              kind: { kind: "contract_defined" },
              key_scope: "manifest_local",
              key_schema: "needle.opaque.architecture-package.v1",
              maximum_key_bytes: 32,
              definition_digest: "b3:architecture-scheme",
            },
            policy: {
              id: "needle.architecture.partition-policy",
              manifest_validator:
                "needle.validator.architecture-brief-manifest.v1",
              maximum_partitions: 64,
              maximum_manifest_bytes: 65536,
              overlap_policy: "validator_defined",
              closure_policy: "closed_required",
              definition_digest: "b3:architecture-policy",
            },
            adapter_definition_digest: "b3:architecture-adapter",
            fixed_mode: "shadow",
          },
          artifact_kind: "architecture-brief",
          output_contract: {
            id: "needle.repository.architecture-brief",
            revision: 1,
            schema: "needle.architecture-brief/1",
            definition_digest: "b3:architecture-output",
          },
          validator_definition_digest: "b3:architecture-validator",
          effect_class: "derived-analysis",
          reuse_modes: ["exact", "project", "assemble"],
          default_dispatch_policy: {
            completion: "reuse-allowed",
            evidence: "standard",
            prior_artifacts: "contract-defined",
            persistence: "persistent",
          },
          initial_mode: "shadow",
          definition_digests: {
            semantic: "b3:architecture-semantic",
            validation: "b3:architecture-validation",
            operational: "b3:architecture-operational",
            complete: "b3:architecture-complete",
          },
        },
        {
          id: "needle.change.impact",
          coverage: {
            kind: "partitioned",
            declared_policy_authority_digest: "b3:change-impact-partitions",
            scheme: {
              id: "needle.change-impact.component",
              kind: { kind: "contract_defined" },
              key_scope: "manifest_local",
              key_schema: "needle.opaque.change-impact-component.v1",
              maximum_key_bytes: 32,
              definition_digest: "b3:change-impact-scheme",
            },
            policy: {
              id: "needle.change-impact.partition-policy",
              manifest_validator: "needle.validator.change-impact-manifest.v1",
              maximum_partitions: 64,
              maximum_manifest_bytes: 65536,
              overlap_policy: "validator_defined",
              closure_policy: "closed_required",
              definition_digest: "b3:change-impact-policy",
            },
            adapter_definition_digest: "b3:change-impact-adapter",
            fixed_mode: "shadow",
          },
          artifact_kind: "change-impact",
          output_contract: {
            id: "needle.analysis.change-impact",
            revision: 1,
            schema: "needle.change-impact/1",
            definition_digest: "b3:change-impact-output",
          },
          validator_definition_digest: "b3:change-impact-validator",
          effect_class: "derived-analysis",
          reuse_modes: ["exact", "project", "assemble"],
          default_dispatch_policy: {
            completion: "reuse-allowed",
            evidence: "standard",
            prior_artifacts: "contract-defined",
            persistence: "persistent",
          },
          initial_mode: "shadow",
          definition_digests: {
            semantic: "b3:change-impact-semantic",
            validation: "b3:change-impact-validation",
            operational: "b3:change-impact-operational",
            complete: "b3:change-impact-complete",
          },
        },
      ],
    },
    refresh_economics: {
      schema: "needle.refresh-economic-inspection/1",
      status: "shadow_audit_only",
      bounded: { limit: 20, maximum: 500 },
      items: [
        {
          assessment: {
            definition_digest: "b3:refresh-economic-assessment",
            action_contract: "needle.tests.inventory",
            expected_net_microusd: "600",
            decision: { selection: "refresh" },
            evidence: { basis: "benchmark_derived" },
          },
          selected_refresh_attempt: null,
          recorded_unix_ms: 1,
        },
      ],
    },
    selected_plans: [],
    metrics: {
      worker_avoided: 0,
      proof_overhead_micros: 0,
      stale_candidates: 0,
      active_contradictions: 0,
    },
  },
  cost_observations: [],
}

class EventSourceStub {
  addEventListener() {}
  removeEventListener() {}
  close() {}
}

test("overview distinguishes proof metrics and persisted shadow economics", async () => {
  let activationBody: unknown
  vi.stubGlobal("EventSource", EventSourceStub)
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith("/api/v1/activation")) {
        activationBody = JSON.parse(String(init?.body))
        return new Response(JSON.stringify(controlPlane.activation), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      }
      const body = url.includes("/approvals") ? [] : controlPlane
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    })
  )
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </QueryClientProvider>
  )

  expect(await screen.findByRole("heading", { name: "Overview" })).toBeVisible()
  expect(screen.getByRole("button", { name: "Enable Needle" })).toBeEnabled()
  expect(screen.getByText("Disabled")).toBeVisible()
  expect(
    screen.getByRole("heading", { name: "Action contracts — Shadow" })
  ).toBeVisible()
  expect(screen.getByText("needle.location.resolve")).toBeVisible()
  expect(
    screen.getByText("implementation-location → code-location · pure-evidence")
  ).toBeVisible()
  expect(screen.getByText("needle.architecture.describe")).toBeVisible()
  expect(
    screen.getByText("partitioned → architecture-brief · derived-analysis")
  ).toBeVisible()
  expect(screen.getByText("needle.change.impact")).toBeVisible()
  expect(
    screen.getByText("partitioned → change-impact · derived-analysis")
  ).toBeVisible()
  expect(
    screen.getByRole("heading", { name: "Root proof decisions — legacy audit" })
  ).toBeVisible()
  expect(
    screen.getByRole("heading", { name: "Refresh economics — Shadow" })
  ).toBeVisible()
  expect(screen.getByText("needle.tests.inventory")).toBeVisible()
  expect(screen.getByText("600 µUSD")).toBeVisible()
  expect(screen.getByText("benchmark derived")).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Enable Needle" }))
  await waitFor(() =>
    expect(activationBody).toEqual({
      enabled: true,
      expected_state_digest: null,
    })
  )
  expect(screen.getAllByText("Recorded plans")).toHaveLength(8)
  expect(screen.getByText("0 candidates")).toBeVisible()
  expect(screen.getByText("0 active")).toBeVisible()
  expect(screen.queryByText(/\$\d/)).not.toBeInTheDocument()
})

test("overview exposes enabled activation when the Desktop projection is not ready", async () => {
  window.history.pushState({}, "", "/overview")
  vi.stubGlobal("EventSource", EventSourceStub)
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            ...controlPlane,
            activation: { ...controlPlane.activation, enabled: true },
            integrations: {
              desktop_skill: {
                installed: null,
                managed: null,
                ready: false,
                error: "managed Codex Desktop skill status is unavailable",
              },
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
    )
  )
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })

  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </QueryClientProvider>
  )

  expect(await screen.findByText("Desktop not ready")).toBeVisible()
  expect(
    screen.getByText("managed Codex Desktop skill status is unavailable")
  ).toBeVisible()
  expect(screen.getByRole("button", { name: "Disable Needle" })).toBeEnabled()
})

test("overview exposes pending Desktop cleanup after deactivation", async () => {
  window.history.pushState({}, "", "/overview")
  vi.stubGlobal("EventSource", EventSourceStub)
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            ...controlPlane,
            integrations: {
              desktop_skill: {
                installed: true,
                managed: true,
                ready: true,
                error: null,
              },
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        )
    )
  )
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })

  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </QueryClientProvider>
  )

  expect(await screen.findByText("Desktop cleanup pending")).toBeVisible()
  expect(
    screen.getByText(/managed Desktop skill remains installed/)
  ).toBeVisible()
  expect(screen.getByRole("button", { name: "Enable Needle" })).toBeEnabled()
})

test("changes page lists isolated patches without exposing their full diff", async () => {
  window.history.pushState({}, "", "/changes")
  vi.stubGlobal("EventSource", EventSourceStub)
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      const body = url.endsWith("/api/v1/changes")
        ? [
            {
              change_id: "chg_0123456789abcdef01234567",
              state: "verified",
              patch_id: `b3:${"1".repeat(64)}`,
              revision: 1,
              summary: "Update the fixture",
              changed_files: [{ path: "fixture.txt", operation: "update" }],
              change_digest: `b3:${"2".repeat(64)}`,
              created_unix_ms: 1,
            },
          ]
        : url.includes("/approvals")
          ? []
          : controlPlane
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    })
  )
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </QueryClientProvider>
  )

  expect(await screen.findByRole("heading", { name: "Changes" })).toBeVisible()
  expect(await screen.findByText("chg_0123456789abcdef01234567")).toBeVisible()
  expect(screen.getByText("Update the fixture")).toBeVisible()
  expect(screen.queryByText("Filesystem-derived diff")).not.toBeInTheDocument()
  window.history.pushState({}, "", "/")
})
