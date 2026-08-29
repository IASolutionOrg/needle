import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { MemoryRouter, Route, Routes } from "react-router"
import { vi } from "vitest"

import LifecyclesPage from "@/pages/lifecycles-page"

const digest = (value: string) => `b3:${value.repeat(64)}`

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function preflight(overrides: Record<string, unknown> = {}) {
  return {
    schema: "needle.lifecycle-start-preflight/1",
    repository_id: digest("1"),
    source_snapshot: digest("2"),
    watcher_uncertain: false,
    eligible: true,
    blockers: [],
    profiles: [
      ["explorer.default", "explorer", "3"],
      ["implementer.default", "implementer", "4"],
      ["test.default", "test_runner", "5"],
      ["reviewer.default", "reviewer", "6"],
      ["verifier.default", "verifier", "7"],
    ].map(([profile_id, role, value]) => ({
      profile_id,
      role,
      revision: 1,
      definition_digest: digest(value),
    })),
    needs: [
      {
        need_id: digest("8"),
        route: "tests.relevant",
        required_predicates: ["focused-tests"],
        need_definition_digest: digest("9"),
        action_plan_definition_digest: digest("a"),
      },
    ],
    test_plans: [
      {
        artifact_id: digest("b"),
        plan_digest: digest("c"),
        certificate_digest: digest("d"),
        issued_unix_ms: 1_700_000_000_000,
      },
    ],
    max_selected_test_plans: 8,
    default_budget: {
      max_worker_turns: 10,
      max_output_tokens: 10_000,
      max_cost_microusd: 100_000,
      max_concurrent_workers: 1,
    },
    ...overrides,
  }
}

function detail(changeId: string) {
  return {
    schema: "needle.lifecycle-detail/1",
    lifecycle: {
      lifecycle_id: digest("e"),
      change_id: changeId,
      source_snapshot: digest("2"),
      phase: "explore",
      status: "active",
      state_digest: digest("f"),
      generation: 0,
      worker_depth_limit: 1,
      profiles: [],
      test_plans: [
        { plan_digest: digest("c"), certificate_digest: digest("d") },
      ],
      budget: {
        max_worker_turns: 10,
        max_output_tokens: 10_000,
        max_cost_microusd: 100_000,
        max_concurrent_workers: 1,
      },
      usage: { worker_turns: 0, output_tokens: 0, cost_microusd: 0 },
      artifacts: {
        exploration: [],
        patch: null,
        tests: [],
        review: null,
        verification: null,
      },
      explore_reuse: null,
      repair_reserved: false,
      repair_consumed: false,
      terminal_outcome: null,
      terminal_reason: null,
      approval: null,
      apply_id: null,
      cleanup: null,
      recovery: null,
      created_unix_ms: 1_700_000_000_000,
      updated_unix_ms: 1_700_000_000_000,
    },
  }
}

function renderPage(initialEntry = "/lifecycles") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/lifecycles" element={<LifecyclesPage />} />
          <Route path="/lifecycles/:id" element={<LifecyclesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

test("lifecycle start displays preflight blockers and never exposes TestPlan commands", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/preflight")) {
        return response(
          preflight({
            eligible: false,
            blockers: ["missing_explorer_profile"],
            profiles: [],
          })
        )
      }
      return response({
        schema: "needle.lifecycle-list/1",
        items: [],
        limit: 50,
      })
    })
  )
  renderPage()

  expect(await screen.findByText("missing explorer profile")).toBeVisible()
  expect(
    screen.getByRole("button", { name: "Create lifecycle" })
  ).toBeDisabled()
  expect(screen.queryByText(/cargo test/i)).toBeNull()
  expect(screen.queryByLabelText(/command/i)).toBeNull()
})

test("lifecycle creation freezes the selected preflight inputs before Explore is run", async () => {
  const changeId = "chg_1234567890abcdef12345678"
  let createBody: Record<string, unknown> | undefined
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith("/preflight")) return response(preflight())
      if (url.endsWith(`/lifecycles/${changeId}`))
        return response(detail(changeId))
      if (url.endsWith("/lifecycles") && init?.method === "POST") {
        createBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return response(
          {
            schema: "needle.lifecycle-create/1",
            created: true,
            change_id: changeId,
            lifecycle_id: digest("e"),
            phase: "explore",
            status: "active",
            generation: 0,
            state_digest: digest("f"),
            source_snapshot: digest("2"),
            action_plan_definition_digest: digest("a"),
          },
          201
        )
      }
      return response({
        schema: "needle.lifecycle-list/1",
        items: [],
        limit: 50,
      })
    }
  )
  vi.stubGlobal("fetch", fetchMock)
  renderPage()

  await screen.findByText("Certified TestPlans")
  fireEvent.click(screen.getByRole("checkbox"))
  fireEvent.change(screen.getByLabelText("Task"), {
    target: { value: "Implement the approved lifecycle slice." },
  })
  fireEvent.change(screen.getByLabelText("Acceptance criteria"), {
    target: { value: "The selected lifecycle is durable." },
  })
  fireEvent.change(screen.getByLabelText("Allowed path 1"), {
    target: { value: "src/lifecycle.rs" },
  })
  fireEvent.click(screen.getByRole("button", { name: "Create lifecycle" }))

  await waitFor(() => expect(createBody).toBeDefined())
  expect(createBody?.operation_id).toMatch(/^[0-9a-f]{64}$/)
  expect(createBody).toMatchObject({
    expected_source_snapshot: digest("2"),
    need_id: digest("8"),
    change: {
      task: "Implement the approved lifecycle slice.",
      acceptance_criteria: ["The selected lifecycle is durable."],
      allowed_paths: [{ path: "src/lifecycle.rs", scope: "exact" }],
    },
    profiles: {
      explore: {
        profile_id: "explorer.default",
        definition_digest: digest("3"),
      },
      implement: {
        profile_id: "implementer.default",
        definition_digest: digest("4"),
      },
      test: { profile_id: "test.default", definition_digest: digest("5") },
      review: {
        profile_id: "reviewer.default",
        definition_digest: digest("6"),
      },
      verify: {
        profile_id: "verifier.default",
        definition_digest: digest("7"),
      },
    },
    test_plan_certificates: [digest("d")],
  })
  expect(
    await screen.findByRole("button", { name: "Run Explore" })
  ).toBeEnabled()
  expect(screen.getByText("Exact reuse authority-gated")).toBeVisible()
  expect(screen.getByText("Fresh fallback")).toBeVisible()
})

test("the next action phase remains runnable after durable Explore reuse", async () => {
  const changeId = "chg_13579abcdef02468abcdef12"
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith("/adapter-invocation")) {
        return response({
          schema: "needle.lifecycle-adapter-invocation/1",
          change_id: changeId,
          invocation: null,
        })
      }
      if (url.endsWith(`/lifecycles/${changeId}`)) {
        return response({
          ...detail(changeId),
          lifecycle: {
            ...detail(changeId).lifecycle,
            phase: "implement",
            generation: 1,
            explore_reuse: {
              authority: {
                capability_class: digest("1"),
                capability_definition_digest: digest("2"),
                evidence: digest("3"),
                decision: digest("4"),
              },
              action_request: digest("5"),
              origin_request: digest("5"),
              artifact: digest("6"),
              validation_certificate: digest("7"),
              selected_plan: digest("8"),
              sufficiency_certificate: digest("9"),
              repository_id: digest("a"),
              source_snapshot: digest("2"),
              resolution_definition_digest: digest("b"),
            },
          },
        })
      }
      return response({
        schema: "needle.lifecycle-list/1",
        items: [],
        limit: 50,
      })
    })
  )

  renderPage(`/lifecycles/${changeId}`)

  expect(await screen.findByText("Explore artifact reused")).toBeVisible()
  expect(screen.getByText("Action-native adapter")).toBeVisible()
  expect(screen.getByRole("button", { name: "Run Implement" })).toBeEnabled()
})

test("Apply requires an explicit state-bound confirmation", async () => {
  const changeId = "chg_2468abcdef13579abcdef012"
  let applyBody: Record<string, unknown> | undefined
  const awaiting = {
    ...detail(changeId),
    lifecycle: {
      ...detail(changeId).lifecycle,
      phase: "apply",
      status: "awaiting_approval",
      generation: 5,
      artifacts: {
        ...detail(changeId).lifecycle.artifacts,
        patch: { patch_id: digest("1"), revision: 1 },
        verification: { verification_id: digest("2") },
      },
    },
  }
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith("/apply")) {
        applyBody = JSON.parse(String(init?.body)) as Record<string, unknown>
        return response({
          schema: "needle.lifecycle-apply/1",
          operation_id: digest("3"),
          change_id: changeId,
          phase: "apply",
          status: "completed",
          state_digest: digest("4"),
          artifact_id: digest("5"),
          validation_certificate_id: digest("6"),
          idempotent_replay: false,
          receipt: {
            schema: "needle.apply-receipt/1",
            id: digest("7"),
            operation_id: digest("3"),
            change_id: changeId,
            patch_id: digest("1"),
            expected_state_digest: digest("f"),
            source_before: digest("2"),
            source_after: digest("8"),
            applied_files_digest: digest("9"),
            applied_unix_ms: 1_700_000_001_000,
          },
        })
      }
      if (url.endsWith("/adapter-invocation")) {
        return response({
          schema: "needle.lifecycle-adapter-invocation/1",
          change_id: changeId,
          invocation: null,
        })
      }
      if (url.endsWith(`/lifecycles/${changeId}`)) return response(awaiting)
      return response({
        schema: "needle.lifecycle-list/1",
        items: [],
        limit: 50,
      })
    })
  )
  renderPage(`/lifecycles/${changeId}`)

  fireEvent.click(
    await screen.findByRole("button", { name: "Approve and Apply" })
  )
  expect(applyBody).toBeUndefined()
  expect(screen.getByText(/writes the verified patch/i)).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Confirm Apply" }))

  await waitFor(() => expect(applyBody).toBeDefined())
  expect(applyBody).toEqual({
    expected_state_digest: digest("f"),
    confirm: true,
  })
  expect(await screen.findByText("Apply completed")).toBeVisible()
})

test("abandoned invocation recovery requires an explicit destructive confirmation", async () => {
  const changeId = "chg_abcdef1234567890abcdef12"
  const invocationId = digest("1")
  let recoveryBody: Record<string, unknown> | undefined
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith("/adapter-invocation/recover")) {
        recoveryBody = JSON.parse(String(init?.body)) as Record<string, unknown>
        return response(
          {
            schema: "needle.lifecycle-adapter-recovery/1",
            created: true,
            change_id: changeId,
            lifecycle: {
              ...detail(changeId).lifecycle,
              status: "failed",
              generation: 1,
              terminal_outcome: "failed",
            },
            invocation: {
              invocation_id: invocationId,
              lifecycle_id: digest("e"),
              expected_state_digest: digest("f"),
              phase: "explore",
              status: "aborted",
              request_digest: digest("2"),
              adapter_definition_digest: digest("3"),
              started_unix_ms: 1_700_000_000_000,
              completed_unix_ms: null,
              recovery: {
                recovery_digest: digest("4"),
                source: "web_user",
                recovered_unix_ms: 1_700_000_001_000,
              },
            },
          },
          201
        )
      }
      if (url.endsWith("/adapter-invocation")) {
        return response({
          schema: "needle.lifecycle-adapter-invocation/1",
          change_id: changeId,
          invocation: {
            invocation_id: invocationId,
            lifecycle_id: digest("e"),
            expected_state_digest: digest("f"),
            phase: "explore",
            status: "in_progress",
            request_digest: digest("2"),
            adapter_definition_digest: digest("3"),
            started_unix_ms: 1_700_000_000_000,
            completed_unix_ms: null,
            recovery: null,
          },
        })
      }
      if (url.endsWith(`/lifecycles/${changeId}`)) {
        return response(detail(changeId))
      }
      return response({
        schema: "needle.lifecycle-list/1",
        items: [],
        limit: 50,
      })
    }
  )
  vi.stubGlobal("fetch", fetchMock)
  renderPage(`/lifecycles/${changeId}`)

  expect(
    await screen.findByText(/durable claim has no terminal outcome/i)
  ).toBeVisible()
  expect(screen.getByRole("button", { name: "Run Explore" })).toBeDisabled()
  fireEvent.click(
    screen.getByRole("button", { name: "Abort abandoned invocation" })
  )
  expect(recoveryBody).toBeUndefined()
  expect(screen.getByText(/This does not retry Codex/i)).toBeVisible()
  fireEvent.click(
    screen.getByRole("button", {
      name: /Provider stopped.*abort lifecycle/i,
    })
  )

  await waitFor(() => expect(recoveryBody).toBeDefined())
  expect(recoveryBody).toEqual({
    invocation_id: invocationId,
    expected_state_digest: digest("f"),
    confirm_provider_stopped: true,
  })
})
