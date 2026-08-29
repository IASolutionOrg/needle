import {
  AlertTriangle,
  ArrowLeft,
  Play,
  ShieldCheck,
  Workflow,
} from "lucide-react"
import { Link, useParams } from "react-router"

import {
  type LifecycleDetail,
  type LifecycleAdapterInvocation,
  type LifecycleSummary,
  useApplyLifecycle,
  useLifecycle,
  useLifecycleAdapterInvocation,
  useLifecycles,
  useLifecycleStartPreflight,
  useRecoverLifecycleAdapterInvocation,
  useStepLifecycle,
} from "@/api"
import { LifecycleStartForm } from "@/components/lifecycle-start-form"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function Header({ detail = false }: { detail?: boolean }) {
  return (
    <div className="mb-6 flex w-full min-w-0 flex-wrap items-start justify-between gap-4">
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <Workflow className="mt-1 text-primary" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">
              Lifecycles
            </h1>
            <Badge variant="outline">Phase 9</Badge>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Frozen, bounded development workflows with explicit operator
            transitions.
          </p>
        </div>
      </div>
      {detail ? (
        <Button asChild variant="outline">
          <Link to="/lifecycles">
            <ArrowLeft /> Back to lifecycles
          </Link>
        </Button>
      ) : null}
    </div>
  )
}

export default function LifecyclesPage() {
  const { id } = useParams()
  return id ? <LifecycleDetailPage changeId={id} /> : <LifecycleListPage />
}

function LifecycleListPage() {
  const preflight = useLifecycleStartPreflight()
  const lifecycles = useLifecycles()

  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6 p-4 md:p-6">
      <Header />
      {preflight.data ? (
        <LifecycleStartForm
          key={[
            preflight.data.source_snapshot,
            ...preflight.data.needs.map((need) => need.need_definition_digest),
            ...preflight.data.profiles.map(
              (profile) => profile.definition_digest
            ),
            ...preflight.data.test_plans.map((plan) => plan.certificate_digest),
          ].join(":")}
          preflight={preflight.data}
          refreshing={preflight.isFetching}
          onRefresh={() => void preflight.refetch()}
        />
      ) : preflight.error ? (
        <p
          role="alert"
          className="border border-destructive/40 p-4 text-sm text-destructive"
        >
          Unable to load lifecycle preflight: {preflight.error.message}
        </p>
      ) : (
        <p className="border bg-panel p-4 text-sm text-muted-foreground">
          Loading lifecycle preflight...
        </p>
      )}

      <section className="border bg-panel">
        <div className="border-b px-4 py-3">
          <h2 className="text-sm font-semibold">Recorded lifecycles</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            The list is bounded and rebuilt from the durable lifecycle event
            log.
          </p>
        </div>
        {lifecycles.error ? (
          <p role="alert" className="p-4 text-sm text-destructive">
            {lifecycles.error.message}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Change</TableHead>
                <TableHead>Phase</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Generation</TableHead>
                <TableHead>Usage</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(lifecycles.data?.items ?? []).map((lifecycle) => (
                <LifecycleRow key={lifecycle.change_id} lifecycle={lifecycle} />
              ))}
            </TableBody>
          </Table>
        )}
        {!lifecycles.isLoading && lifecycles.data?.items.length === 0 ? (
          <p className="p-8 text-center text-sm text-muted-foreground">
            No lifecycle has been created yet.
          </p>
        ) : null}
      </section>
    </div>
  )
}

function LifecycleRow({ lifecycle }: { lifecycle: LifecycleSummary }) {
  return (
    <TableRow>
      <TableCell className="max-w-64 truncate font-mono text-xs">
        <Link
          className="text-primary hover:underline"
          to={`/lifecycles/${lifecycle.change_id}`}
        >
          {lifecycle.change_id}
        </Link>
      </TableCell>
      <TableCell>{lifecycle.phase}</TableCell>
      <TableCell>
        <Badge variant="outline">{lifecycle.status}</Badge>
      </TableCell>
      <TableCell>{lifecycle.generation}</TableCell>
      <TableCell className="font-mono text-xs">
        {lifecycle.usage.worker_turns} turns · {lifecycle.usage.output_tokens}{" "}
        tokens
      </TableCell>
      <TableCell>
        {new Date(lifecycle.updated_unix_ms).toLocaleString()}
      </TableCell>
    </TableRow>
  )
}

function LifecycleDetailPage({ changeId }: { changeId: string }) {
  const detail = useLifecycle(changeId)
  const adapterInvocation = useLifecycleAdapterInvocation(changeId)
  const step = useStepLifecycle()
  const apply = useApplyLifecycle()
  const recovery = useRecoverLifecycleAdapterInvocation()
  const lifecycle = detail.data?.lifecycle
  const invocation = adapterInvocation.data?.invocation
  const runnable =
    lifecycle &&
    lifecycle.phase !== "apply" &&
    (lifecycle.status === "active" || lifecycle.status === "repair_reserved")
  const phaseLabel = lifecycle
    ? lifecycle.status === "repair_reserved"
      ? "Repair"
      : lifecycle.phase[0].toUpperCase() + lifecycle.phase.slice(1)
    : "phase"

  return (
    <div className="grid gap-5 p-4 md:p-6">
      <Header detail />
      {detail.error ? (
        <p
          role="alert"
          className="border border-destructive/40 p-4 text-sm text-destructive"
        >
          {detail.error.message}
        </p>
      ) : lifecycle ? (
        <>
          <LifecycleIdentity lifecycle={lifecycle} />

          <section className="border bg-panel p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-semibold">
                    {phaseLabel} transition
                  </h2>
                  {lifecycle.phase === "explore" ? (
                    <>
                      <Badge variant="outline">
                        {lifecycle.explore_reuse
                          ? "Validated artifact reused"
                          : "Exact reuse authority-gated"}
                      </Badge>
                      <Badge variant="outline">Fresh fallback</Badge>
                    </>
                  ) : (
                    <>
                      <Badge variant="outline">Action-native adapter</Badge>
                      {lifecycle.explore_reuse ? (
                        <Badge variant="outline">Explore artifact reused</Badge>
                      ) : null}
                    </>
                  )}
                </div>
                <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
                  {lifecycle.phase === "explore"
                    ? "Run Explore is a separate, state-bound operation. Needle may skip the adapter only for one exact, current, validated read-only artifact backed by both resolver and lifecycle authority. Every other result runs the fresh adapter."
                    : lifecycle.status === "repair_reserved"
                      ? "Resume the bounded repair loop from the exact persisted lifecycle state. The kernel returns to Implement without applying changes to the active worktree."
                      : `Run ${phaseLabel} invokes the immutable action plan bound to this lifecycle state. The server and kernel own phase selection and the CAS transition.`}
                </p>
              </div>
              <Button
                type="button"
                disabled={
                  !runnable ||
                  invocation?.status === "in_progress" ||
                  step.isPending
                }
                onClick={() =>
                  step.mutate({
                    changeId: lifecycle.change_id,
                    expectedStateDigest: lifecycle.state_digest,
                  })
                }
              >
                <Play />
                {step.isPending
                  ? `Running ${phaseLabel}...`
                  : `Run ${phaseLabel}`}
              </Button>
            </div>
            {step.data ? (
              <div role="status" className="mt-3 space-y-1 text-sm">
                <p>
                  Transition result: {step.data.disposition}; phase{" "}
                  {step.data.phase}, generation {step.data.generation}.
                </p>
                {lifecycle.phase === "explore" &&
                step.data.reuse?.kind === "consumed" ? (
                  <p>
                    Needle reused the validated artifact with zero adapter
                    invocation and zero worker usage.
                  </p>
                ) : lifecycle.phase === "explore" &&
                  step.data.reuse?.kind === "resolver_authorized" ? (
                  <p>
                    Resolver authority was accepted, but lifecycle consumption
                    is not approved; the fresh adapter was invoked.
                  </p>
                ) : null}
              </div>
            ) : null}
            {step.error ? (
              <p role="alert" className="mt-3 text-sm text-destructive">
                {step.error.message}
              </p>
            ) : null}
          </section>

          {lifecycle.status === "awaiting_approval" ? (
            <section className="border border-amber-500/50 bg-amber-500/5 p-4">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="size-4 text-amber-600" />
                    <h2 className="text-sm font-semibold">Apply approval</h2>
                    <Badge variant="outline">Parent-owned effect</Badge>
                  </div>
                  <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
                    Test, Review, and Verify are complete. Applying is the only
                    step that can modify the active worktree and requires this
                    explicit confirmation. Needle rechecks the source snapshot
                    and exact lifecycle state before writing.
                  </p>
                  <p className="mt-2 truncate font-mono text-xs text-muted-foreground">
                    expected state {lifecycle.state_digest}
                  </p>
                </div>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      type="button"
                      variant="destructive"
                      disabled={apply.isPending}
                    >
                      <ShieldCheck />
                      {apply.isPending ? "Applying..." : "Approve and Apply"}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Apply this verified patch?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        This writes the verified patch to the active worktree.
                        The approval is bound to the current source snapshot,
                        patch, verification, and lifecycle state. A stale
                        binding is rejected.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() =>
                          apply.mutate({
                            changeId: lifecycle.change_id,
                            expectedStateDigest: lifecycle.state_digest,
                          })
                        }
                      >
                        Confirm Apply
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
              {apply.error ? (
                <p role="alert" className="mt-3 text-sm text-destructive">
                  {apply.error.message}
                </p>
              ) : null}
            </section>
          ) : null}

          {apply.data ? (
            <section role="status" className="border bg-panel p-4 text-sm">
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-emerald-600" />
                <h2 className="font-semibold">Apply completed</h2>
                {apply.data.idempotent_replay ? (
                  <Badge variant="outline">Idempotent replay</Badge>
                ) : null}
              </div>
              <p className="mt-2 text-muted-foreground">
                Receipt {apply.data.receipt.id}; source snapshot advanced to{" "}
                {apply.data.receipt.source_after}.
              </p>
            </section>
          ) : null}

          {adapterInvocation.error ? (
            <p
              role="alert"
              className="border border-destructive/40 p-4 text-sm text-destructive"
            >
              Unable to inspect the adapter invocation:{" "}
              {adapterInvocation.error.message}
            </p>
          ) : invocation ? (
            <AdapterInvocationPanel
              invocation={invocation}
              recovering={recovery.isPending}
              error={recovery.error?.message}
              onRecover={() =>
                recovery.mutate({
                  changeId,
                  invocationId: invocation.invocation_id,
                  expectedStateDigest: invocation.expected_state_digest,
                })
              }
            />
          ) : null}

          <section className="grid gap-4 lg:grid-cols-2">
            <div className="border bg-panel p-4">
              <h2 className="text-sm font-semibold">Frozen role profiles</h2>
              <dl className="mt-3 grid gap-3">
                {lifecycle.profiles.map((profile) => (
                  <div
                    key={profile.phase}
                    className="grid gap-1 border-b pb-2 last:border-0"
                  >
                    <dt className="text-xs text-muted-foreground uppercase">
                      {profile.phase}
                    </dt>
                    <dd className="text-sm">
                      {profile.profile_id} · revision {profile.revision}
                    </dd>
                    <dd className="truncate font-mono text-xs text-muted-foreground">
                      {profile.definition_digest}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="border bg-panel p-4">
              <h2 className="text-sm font-semibold">Certified TestPlans</h2>
              <div className="mt-3 grid gap-3">
                {lifecycle.test_plans.map((plan) => (
                  <div
                    key={plan.plan_digest}
                    className="border-b pb-2 last:border-0"
                  >
                    <p className="truncate font-mono text-xs">
                      {plan.plan_digest}
                    </p>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">
                      certificate {plan.certificate_digest}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="border bg-panel p-4">
            <h2 className="text-sm font-semibold">Artifacts and budget</h2>
            <div className="mt-3 grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <Metric
                label="Exploration artifacts"
                value={lifecycle.artifacts.exploration.length}
              />
              <Metric
                label="Worker turns"
                value={`${lifecycle.usage.worker_turns}/${lifecycle.budget.max_worker_turns}`}
              />
              <Metric
                label="Output tokens"
                value={`${lifecycle.usage.output_tokens}/${lifecycle.budget.max_output_tokens}`}
              />
              <Metric
                label="Cost (micro-USD)"
                value={`${lifecycle.usage.cost_microusd}/${lifecycle.budget.max_cost_microusd}`}
              />
            </div>
          </section>
        </>
      ) : (
        <p className="text-sm text-muted-foreground">Loading lifecycle...</p>
      )}
    </div>
  )
}

function AdapterInvocationPanel({
  invocation,
  recovering,
  error,
  onRecover,
}: {
  invocation: LifecycleAdapterInvocation
  recovering: boolean
  error?: string
  onRecover: () => void
}) {
  const blocked = invocation.status === "in_progress"
  return (
    <section
      className={
        blocked
          ? "border border-amber-500/50 bg-amber-500/5 p-4"
          : "border bg-panel p-4"
      }
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {blocked ? (
              <AlertTriangle className="size-4 text-amber-600" />
            ) : null}
            <h2 className="text-sm font-semibold">Fresh adapter invocation</h2>
            <Badge variant="outline">{invocation.status}</Badge>
          </div>
          <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
            {blocked
              ? "The durable claim has no terminal outcome. Recovery is allowed only after confirming that the provider process is no longer running."
              : invocation.status === "aborted"
                ? "This invocation was explicitly aborted. Its lifecycle is terminal; create a new lifecycle to retry."
                : "The durable adapter invocation has a completed outcome."}
          </p>
          <p className="mt-2 truncate font-mono text-xs text-muted-foreground">
            {invocation.invocation_id}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Started {new Date(invocation.started_unix_ms).toLocaleString()}
          </p>
        </div>
        {blocked ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button type="button" variant="destructive" disabled={recovering}>
                <AlertTriangle />
                {recovering ? "Aborting..." : "Abort abandoned invocation"}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  Confirm the provider has stopped
                </AlertDialogTitle>
                <AlertDialogDescription>
                  This does not retry Codex. It permanently marks this
                  invocation aborted and fails the current lifecycle. Create a
                  new lifecycle if you want to run Explore again.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Keep blocked</AlertDialogCancel>
                <AlertDialogAction variant="destructive" onClick={onRecover}>
                  Provider stopped — abort lifecycle
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : null}
      </div>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </section>
  )
}

function LifecycleIdentity({ lifecycle }: { lifecycle: LifecycleDetail }) {
  return (
    <section className="border bg-panel p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-mono text-sm">{lifecycle.change_id}</p>
          <p className="mt-2 truncate font-mono text-xs text-muted-foreground">
            lifecycle {lifecycle.lifecycle_id}
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant="outline">{lifecycle.phase}</Badge>
          <Badge variant="outline">{lifecycle.status}</Badge>
          <Badge variant="outline">generation {lifecycle.generation}</Badge>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 text-sm lg:grid-cols-2">
        <div>
          <dt className="text-xs text-muted-foreground">Source snapshot</dt>
          <dd className="truncate font-mono text-xs">
            {lifecycle.source_snapshot}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">
            Current state digest
          </dt>
          <dd className="truncate font-mono text-xs">
            {lifecycle.state_digest}
          </dd>
        </div>
      </dl>
    </section>
  )
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="border p-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="mt-1 font-mono">{value}</p>
    </div>
  )
}
