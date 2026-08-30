import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { vi } from "vitest"

import ApprovalInboxPage from "@/pages/approval-inbox-page"

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ApprovalInboxPage />
    </QueryClientProvider>,
  )
}

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  })
}

test("approval inbox exposes the safe default AI policy and persists a digest-bound update", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url === "/api/v1/approvals?status=pending") return jsonResponse([])
    if (url === "/api/v1/control-plane") {
      return jsonResponse({
        approval_automation: {
          schema: "needle.approval-automation-policy/1",
          mode: "disabled",
          evaluator_host: "codex",
          model: "gpt-5.6-luna",
          reasoning: "low",
          timeout_seconds: 30,
        },
        approval_automation_digest: `b3:${"a".repeat(64)}`,
      })
    }
    if (url === "/api/v1/approval-automation" && init?.method === "POST") {
      return jsonResponse({ status: "updated" })
    }
    return jsonResponse({ error: "unexpected request" }, 404)
  })
  vi.stubGlobal("fetch", fetchMock)

  renderPage()

  expect(await screen.findByText("AI approval reviewer")).toBeVisible()
  expect(screen.getByLabelText("Mode")).toHaveValue("disabled")
  expect(screen.getByLabelText("Model")).toHaveValue("gpt-5.6-luna")
  expect(screen.getByLabelText("Reasoning")).toHaveValue("low")

  fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "decide" } })
  fireEvent.click(screen.getByRole("button", { name: "Save AI policy" }))

  await waitFor(() => {
    const update = fetchMock.mock.calls.find(([input, init]) =>
      String(input) === "/api/v1/approval-automation" && init?.method === "POST"
    )
    expect(update).toBeDefined()
    expect(update?.[1]?.headers).toMatchObject({
      "if-match": `"b3:${"a".repeat(64)}"`,
    })
    expect(JSON.parse(String(update?.[1]?.body))).toMatchObject({
      mode: "decide",
      model: "gpt-5.6-luna",
      reasoning: "low",
    })
  })
})
