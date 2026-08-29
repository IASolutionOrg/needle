import { useMemo, useState } from "react"
import { RefreshCw, ShieldCheck } from "lucide-react"
import { useNavigate } from "react-router"

import {
  type LifecycleCreateInput,
  type LifecycleProfileSelection,
  type LifecycleStartPreflight,
  type LifecycleStartProfile,
  useCreateLifecycle,
} from "@/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

type ProfileSlot = "explore" | "implement" | "test" | "review" | "verify"
type AllowedScope = "exact" | "subtree"

const PROFILE_SLOTS: Array<{
  slot: ProfileSlot
  role: LifecycleStartProfile["role"]
  label: string
}> = [
  { slot: "explore", role: "explorer", label: "Explore" },
  { slot: "implement", role: "implementer", label: "Implement" },
  { slot: "test", role: "test_runner", label: "Test" },
  { slot: "review", role: "reviewer", label: "Review" },
  { slot: "verify", role: "verifier", label: "Verify" },
]

function operationId() {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    ""
  )
}

function profileKey(profile: LifecycleStartProfile) {
  return `${profile.profile_id}\u0000${profile.definition_digest}`
}

function lines(value: string) {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean)
}

function blockerLabel(blocker: string) {
  return blocker.replaceAll("_", " ")
}

function initialProfileKeys(preflight: LifecycleStartPreflight) {
  const selected = {} as Record<ProfileSlot, string>
  for (const { slot, role } of PROFILE_SLOTS) {
    const candidates = preflight.profiles.filter(
      (profile) => profile.role === role
    )
    selected[slot] = candidates.length === 1 ? profileKey(candidates[0]) : ""
  }
  return selected
}

export function LifecycleStartForm({
  preflight,
  refreshing,
  onRefresh,
}: {
  preflight: LifecycleStartPreflight
  refreshing: boolean
  onRefresh: () => void
}) {
  const navigate = useNavigate()
  const create = useCreateLifecycle()
  const [requestOperationId] = useState(operationId)
  const [needId, setNeedId] = useState(preflight.needs[0]?.need_id ?? "")
  const [profileKeys, setProfileKeys] = useState<Record<ProfileSlot, string>>(
    () => initialProfileKeys(preflight)
  )
  const [selectedCertificates, setSelectedCertificates] = useState<string[]>([])
  const [task, setTask] = useState("")
  const [criteria, setCriteria] = useState("")
  const [constraints, setConstraints] = useState("")
  const [allowedPaths, setAllowedPaths] = useState<
    Array<{ path: string; scope: AllowedScope }>
  >([{ path: "", scope: "exact" }])
  const [budget, setBudget] = useState(() => ({
    max_worker_turns: preflight.default_budget.max_worker_turns,
    max_output_tokens: preflight.default_budget.max_output_tokens,
    max_cost_microusd: preflight.default_budget.max_cost_microusd,
  }))

  const profiles = useMemo(() => {
    const selected = {} as Record<
      ProfileSlot,
      LifecycleProfileSelection | undefined
    >
    for (const { slot } of PROFILE_SLOTS) {
      const profile = preflight.profiles.find(
        (candidate) => profileKey(candidate) === profileKeys[slot]
      )
      selected[slot] = profile
        ? {
            profile_id: profile.profile_id,
            definition_digest: profile.definition_digest,
          }
        : undefined
    }
    return selected
  }, [preflight.profiles, profileKeys])

  const criteriaItems = lines(criteria)
  const constraintItems = lines(constraints)
  const validPaths = allowedPaths.filter(({ path }) => path.trim().length > 0)
  const canCreate =
    preflight.eligible &&
    needId.length > 0 &&
    task.trim().length > 0 &&
    criteriaItems.length > 0 &&
    validPaths.length > 0 &&
    selectedCertificates.length > 0 &&
    PROFILE_SLOTS.every(({ slot }) => profiles[slot]) &&
    !create.isPending

  function submit() {
    if (!canCreate) return
    const selectedProfiles = profiles as Record<
      ProfileSlot,
      LifecycleProfileSelection
    >
    const input: LifecycleCreateInput = {
      operation_id: requestOperationId,
      expected_source_snapshot: preflight.source_snapshot,
      need_id: needId,
      change: {
        task: task.trim(),
        acceptance_criteria: criteriaItems,
        allowed_paths: validPaths.map(({ path, scope }) => ({
          path: path.trim(),
          scope,
        })),
        artifact_ids: [],
        claim_ids: [],
        constraints: constraintItems,
      },
      profiles: {
        explore: selectedProfiles.explore,
        implement: selectedProfiles.implement,
        test: selectedProfiles.test,
        review: selectedProfiles.review,
        verify: selectedProfiles.verify,
      },
      budget,
      test_plan_certificates: selectedCertificates,
    }
    create.mutate(input, {
      onSuccess: (result) => navigate(`/lifecycles/${result.change_id}`),
    })
  }

  return (
    <section className="min-w-0 border bg-panel">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b p-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">Start a lifecycle</h2>
            <Badge variant={preflight.eligible ? "outline" : "destructive"}>
              {preflight.eligible ? "Ready" : "Blocked"}
            </Badge>
            <Badge variant="outline">Shadow planning</Badge>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Freeze a validated Need, active role profiles, certified TestPlans,
            and a bounded budget. Creation does not execute a worker.
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          disabled={refreshing}
          onClick={onRefresh}
        >
          <RefreshCw /> {refreshing ? "Refreshing..." : "Refresh preflight"}
        </Button>
      </div>

      <div className="grid gap-5 p-4">
        {preflight.watcher_uncertain ? (
          <p
            role="status"
            className="border-warning/40 bg-warning/5 border p-3 text-sm"
          >
            Repository watcher health is uncertain. The create request still
            performs an exact source snapshot check.
          </p>
        ) : null}
        {preflight.blockers.length > 0 ? (
          <div
            role="alert"
            className="border border-destructive/40 p-3 text-sm text-destructive"
          >
            <p className="font-medium">Preflight blockers</p>
            <ul className="mt-2 list-disc pl-5">
              {preflight.blockers.map((blocker) => (
                <li key={blocker}>{blockerLabel(blocker)}</li>
              ))}
            </ul>
          </div>
        ) : null}

        <div className="grid gap-4 lg:grid-cols-2">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Validated Need</span>
            <select
              aria-label="Validated Need"
              className="h-9 border bg-background px-2"
              value={needId}
              onChange={(event) => setNeedId(event.target.value)}
            >
              <option value="">Select a Need</option>
              {preflight.needs.map((need) => (
                <option key={need.need_id} value={need.need_id}>
                  {need.route} · {need.required_predicates.join(", ")}
                </option>
              ))}
            </select>
          </label>
          <div className="grid gap-1 text-sm">
            <span className="font-medium">Source snapshot</span>
            <code className="min-w-0 truncate border bg-muted/30 p-2 text-xs">
              {preflight.source_snapshot}
            </code>
          </div>
        </div>

        <div>
          <h3 className="text-sm font-medium">Active role profiles</h3>
          <div className="mt-2 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            {PROFILE_SLOTS.map(({ slot, role, label }) => {
              const candidates = preflight.profiles.filter(
                (profile) => profile.role === role
              )
              return (
                <label key={slot} className="grid gap-1 text-sm">
                  <span>{label}</span>
                  <select
                    aria-label={`${label} profile`}
                    className="h-9 min-w-0 border bg-background px-2"
                    value={profileKeys[slot]}
                    onChange={(event) =>
                      setProfileKeys((current) => ({
                        ...current,
                        [slot]: event.target.value,
                      }))
                    }
                  >
                    <option value="">Select</option>
                    {candidates.map((profile) => (
                      <option
                        key={profileKey(profile)}
                        value={profileKey(profile)}
                      >
                        {profile.profile_id} · r{profile.revision}
                      </option>
                    ))}
                  </select>
                </label>
              )
            })}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-medium">Certified TestPlans</h3>
            <span className="text-xs text-muted-foreground">
              {selectedCertificates.length}/{preflight.max_selected_test_plans}{" "}
              selected
            </span>
          </div>
          <div className="mt-2 grid gap-2 md:grid-cols-2">
            {preflight.test_plans.map((plan) => {
              const checked = selectedCertificates.includes(
                plan.certificate_digest
              )
              const atLimit =
                !checked &&
                selectedCertificates.length >= preflight.max_selected_test_plans
              return (
                <label
                  key={plan.certificate_digest}
                  className="flex gap-3 border p-3 text-sm"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={atLimit}
                    onChange={() =>
                      setSelectedCertificates((current) =>
                        checked
                          ? current.filter(
                              (item) => item !== plan.certificate_digest
                            )
                          : [...current, plan.certificate_digest]
                      )
                    }
                  />
                  <span className="min-w-0">
                    <span className="block truncate font-mono text-xs">
                      {plan.plan_digest}
                    </span>
                    <span className="mt-1 block text-xs text-muted-foreground">
                      Current-source certificate ·{" "}
                      {new Date(plan.issued_unix_ms).toLocaleString()}
                    </span>
                  </span>
                </label>
              )
            })}
          </div>
        </div>

        <label className="grid gap-1 text-sm">
          <span className="font-medium">Task</span>
          <textarea
            aria-label="Task"
            className="min-h-20 border bg-background p-2"
            maxLength={8192}
            value={task}
            onChange={(event) => setTask(event.target.value)}
          />
        </label>
        <div className="grid gap-4 lg:grid-cols-2">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">
              Acceptance criteria · one per line
            </span>
            <textarea
              aria-label="Acceptance criteria"
              className="min-h-28 border bg-background p-2"
              value={criteria}
              onChange={(event) => setCriteria(event.target.value)}
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">
              Constraints · optional, one per line
            </span>
            <textarea
              aria-label="Constraints"
              className="min-h-28 border bg-background p-2"
              value={constraints}
              onChange={(event) => setConstraints(event.target.value)}
            />
          </label>
        </div>

        <div>
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-sm font-medium">Allowed paths</h3>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={allowedPaths.length >= 16}
              onClick={() =>
                setAllowedPaths((current) => [
                  ...current,
                  { path: "", scope: "exact" },
                ])
              }
            >
              Add path
            </Button>
          </div>
          <div className="mt-2 grid gap-2">
            {allowedPaths.map((allowed, index) => (
              <div
                key={index}
                className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_8rem_auto]"
              >
                <Input
                  aria-label={`Allowed path ${index + 1}`}
                  placeholder="src/module.rs"
                  value={allowed.path}
                  onChange={(event) =>
                    setAllowedPaths((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? { ...item, path: event.target.value }
                          : item
                      )
                    )
                  }
                />
                <select
                  aria-label={`Allowed path ${index + 1} scope`}
                  className="h-8 border bg-background px-2 text-sm"
                  value={allowed.scope}
                  onChange={(event) =>
                    setAllowedPaths((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? {
                              ...item,
                              scope: event.target.value as AllowedScope,
                            }
                          : item
                      )
                    )
                  }
                >
                  <option value="exact">Exact</option>
                  <option value="subtree">Subtree</option>
                </select>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={allowedPaths.length === 1}
                  onClick={() =>
                    setAllowedPaths((current) =>
                      current.filter((_, itemIndex) => itemIndex !== index)
                    )
                  }
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-medium">Lifecycle budget</h3>
          <div className="mt-2 grid gap-3 sm:grid-cols-3">
            {[
              ["Worker turns", "max_worker_turns"],
              ["Output tokens", "max_output_tokens"],
              ["Cost (micro-USD)", "max_cost_microusd"],
            ].map(([label, field]) => (
              <label key={field} className="grid gap-1 text-sm">
                <span>{label}</span>
                <Input
                  aria-label={label}
                  type="number"
                  min={1}
                  value={budget[field as keyof typeof budget]}
                  onChange={(event) =>
                    setBudget((current) => ({
                      ...current,
                      [field]: Math.max(1, Number(event.target.value) || 1),
                    }))
                  }
                />
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Worker depth and concurrency are fixed to one for this lifecycle
            contract.
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck /> Exact source CAS and frozen profile/TestPlan digests
            are revalidated on create.
          </p>
          <Button type="button" disabled={!canCreate} onClick={submit}>
            {create.isPending ? "Creating..." : "Create lifecycle"}
          </Button>
        </div>
        {create.error ? (
          <p role="alert" className="text-sm text-destructive">
            {create.error.message}
          </p>
        ) : null}
      </div>
    </section>
  )
}
