import {
  Activity,
  Box,
  Database,
  Inbox,
  LockKeyhole,
  Network,
  Server,
} from "lucide-react"
import type { ReactNode } from "react"
import { Link } from "react-router"

import { useActivationToggle, useControlPlane } from "@/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const legacyRootResolutions = [
  "Exact Hit",
  "Coverage Hit",
  "Composite Hit",
  "Partial Hit",
  "Miss",
  "Stale",
  "Ambiguous",
  "Contradicted",
  "Rejected",
  "Bypass",
]

function Panel({
  title,
  children,
  className = "",
}: {
  title: string
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`min-w-0 border bg-panel ${className}`}>
      <div className="border-b px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>
      {children}
    </section>
  )
}

export default function OverviewPage() {
  const control = useControlPlane()
  const activation = useActivationToggle()
  const routes = control.data?.routes ?? []
  const semantic = control.data?.semantic
  const actionContracts = semantic?.action_contracts?.items ?? []
  const partitionManifests = semantic?.partition_manifests?.items ?? []
  const refreshEconomicAssessments = semantic?.refresh_economics?.items ?? []
  const proofPlans = semantic?.selected_plans ?? []
  const proofMetrics = semantic?.metrics
  const desktopSkill = control.data?.integrations.desktop_skill
  const desktopIntegrationNotReady =
    control.data?.activation.enabled === true && desktopSkill?.ready !== true
  const desktopCleanupPending =
    control.data?.activation.enabled === false &&
    desktopSkill?.installed === true &&
    desktopSkill.managed === true

  return (
    <div className="grid min-h-[calc(100svh-3.75rem)] grid-cols-1 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <div className="min-w-0 p-4 md:p-6">
        <h1 className="mb-5 text-2xl font-semibold tracking-tight">Overview</h1>

        <section
          aria-labelledby="needle-activation-title"
          className="mb-5 flex flex-col gap-4 border bg-panel p-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div>
            <div className="flex items-center gap-2">
              <h2
                id="needle-activation-title"
                className="text-sm font-semibold"
              >
                Codex companion
              </h2>
              <Badge
                variant={
                  control.data?.activation.enabled ? "default" : "outline"
                }
              >
                {control.data?.activation.enabled ? "Enabled" : "Disabled"}
              </Badge>
              {desktopIntegrationNotReady ? (
                <Badge variant="outline">Desktop not ready</Badge>
              ) : null}
              {desktopCleanupPending ? (
                <Badge variant="outline">Desktop cleanup pending</Badge>
              ) : null}
            </div>
            <p className="mt-1 text-sm text-muted-foreground">
              When enabled, Codex can request repository context from Needle
              automatically.
            </p>
            {activation.error ? (
              <p role="alert" className="mt-2 text-sm text-destructive">
                {activation.error.message}
              </p>
            ) : null}
            {desktopIntegrationNotReady ? (
              <p role="status" className="mt-2 text-sm text-muted-foreground">
                {desktopSkill?.error ??
                  "The managed Codex Desktop skill is missing or outdated. Run `needle enable` to reconcile it."}
              </p>
            ) : null}
            {desktopCleanupPending ? (
              <p role="status" className="mt-2 text-sm text-muted-foreground">
                Activation is disabled, but the managed Desktop skill remains
                installed. Run `needle disable` to retry cleanup.
              </p>
            ) : null}
          </div>
          <Button
            type="button"
            variant={control.data?.activation.enabled ? "outline" : "default"}
            disabled={!control.data || activation.isPending}
            onClick={() => activation.mutate(!control.data?.activation.enabled)}
          >
            {activation.isPending
              ? "Updating..."
              : control.data?.activation.enabled
                ? "Disable Needle"
                : "Enable Needle"}
          </Button>
        </section>

        <section className="mb-5 grid border bg-panel sm:grid-cols-2 xl:grid-cols-4">
          {[
            [Database, "SQLite ready"],
            [Server, "App Server compatible"],
            [LockKeyhole, "Sandbox read-only"],
            [Network, "Approval bridge ready"],
          ].map(([Icon, label], index) => (
            <div
              key={String(label)}
              className={`flex h-16 items-center gap-3 px-4 ${
                index > 0 ? "border-t sm:border-t-0 sm:border-l" : ""
              }`}
            >
              <Icon className="text-primary" />
              <span className="text-sm">{String(label)}</span>
            </div>
          ))}
        </section>

        <section className="mb-5 grid border bg-panel sm:grid-cols-2 xl:grid-cols-4">
          {[
            ["Legacy v0.3 entries", control.data?.cache.length ?? 0],
            ["Proof candidates", proofPlans.length],
            ["Workers avoided", proofMetrics?.worker_avoided ?? 0],
            [
              "Proof overhead",
              `${proofMetrics?.proof_overhead_micros ?? 0} µs`,
            ],
          ].map(([label, value], index) => (
            <div
              key={String(label)}
              className={`px-4 py-3 ${
                index > 0 ? "border-t sm:border-t-0 sm:border-l" : ""
              }`}
            >
              <div className="text-xs text-muted-foreground">
                {String(label)}
              </div>
              <div className="mt-1 font-mono text-lg">{String(value)}</div>
            </div>
          ))}
        </section>

        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Action contracts — Shadow" className="lg:col-span-2">
            {actionContracts.length > 0 ? (
              <div className="divide-y">
                {actionContracts.map((action) => (
                  <div
                    key={action.id}
                    className="grid gap-3 px-4 py-3 text-[13px] md:grid-cols-[minmax(0,1fr)_auto] md:items-center"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono break-all text-link">
                          {action.id}
                        </span>
                        <Badge variant="outline">Shadow</Badge>
                      </div>
                      <div className="mt-1 text-muted-foreground">
                        {action.coverage.kind === "semantic_predicate"
                          ? action.coverage.predicate
                          : "partitioned"}{" "}
                        → {action.artifact_kind} · {action.effect_class}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1.5 md:justify-end">
                      {action.reuse_modes.map((mode) => (
                        <span
                          key={mode}
                          className="border px-2 py-1 font-mono text-xs"
                        >
                          {mode}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Empty className="min-h-36 rounded-none border-0">
                <EmptyHeader>
                  <Box />
                  <EmptyTitle>No action contracts exposed</EmptyTitle>
                  <EmptyDescription>
                    This runtime predates the bounded Shadow action catalog
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </Panel>

          <Panel title="Partition manifests — Shadow" className="lg:col-span-2">
            <p className="border-b px-4 py-2.5 text-xs text-muted-foreground">
              Server-certified audit records. They are not consumed by the
              resolver.
            </p>
            {partitionManifests.length > 0 ? (
              <div className="divide-y">
                {partitionManifests.map((manifest) => (
                  <div
                    key={manifest.manifest}
                    className="grid gap-2 px-4 py-3 text-[13px] md:grid-cols-[minmax(0,1fr)_auto] md:items-center"
                  >
                    <div className="min-w-0">
                      <div className="font-mono break-all text-link">
                        {manifest.manifest}
                      </div>
                      <div className="mt-1 text-muted-foreground">
                        {manifest.action_contract} · {manifest.scheme}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 md:justify-end">
                      <Badge variant="outline">Shadow</Badge>
                      <span className="font-mono text-xs text-muted-foreground">
                        {manifest.entry_count} partitions
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Empty className="min-h-36 rounded-none border-0">
                <EmptyHeader>
                  <Box />
                  <EmptyTitle>No partition manifests recorded</EmptyTitle>
                  <EmptyDescription>
                    Certified Shadow publications will appear here after
                    validation
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </Panel>

          <Panel title="Root proof decisions — legacy audit">
            <p className="border-b px-4 py-2.5 text-xs text-muted-foreground">
              Historical resolver outcomes retained separately from per-action
              Shadow resolution.
            </p>
            <div className="divide-y">
              {legacyRootResolutions.map((resolution) => (
                <div
                  key={resolution}
                  className="grid grid-cols-[1fr_auto_auto] items-center gap-4 px-4 py-2.5 text-[13px]"
                >
                  <span>{resolution}</span>
                  <span className="font-mono text-muted-foreground">
                    {
                      proofPlans.filter((plan) =>
                        plan.decision_reason.includes(
                          resolution.replaceAll(" ", "")
                        )
                      ).length
                    }
                  </span>
                  <span className="text-muted-foreground">
                    {resolution === "Stale"
                      ? `${proofMetrics?.stale_candidates ?? 0} candidates`
                      : resolution === "Contradicted"
                        ? `${proofMetrics?.active_contradictions ?? 0} active`
                        : "Recorded plans"}
                  </span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Refresh economics — Shadow">
            <p className="border-b px-4 py-2.5 text-xs text-muted-foreground">
              Immutable local assessments. They do not authorize refresh or
              promote a capability.
            </p>
            {refreshEconomicAssessments.length > 0 ? (
              <div className="divide-y">
                {refreshEconomicAssessments.map(({ assessment }) => {
                  const decision = assessment.decision
                  const fallbackReason =
                    decision.selection === "full_compute"
                      ? decision.reason.replaceAll("_", " ")
                      : null
                  return (
                    <div
                      key={assessment.definition_digest}
                      className="px-4 py-3 text-[13px]"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono break-all text-link">
                          {assessment.action_contract}
                        </span>
                        <Badge variant="outline">
                          {decision.selection === "refresh"
                            ? "Refresh"
                            : "Full compute"}
                        </Badge>
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <div className="text-muted-foreground">
                            Expected net
                          </div>
                          <div className="mt-0.5 font-mono">
                            {assessment.expected_net_microusd === null
                              ? "Unknown"
                              : `${assessment.expected_net_microusd} µUSD`}
                          </div>
                        </div>
                        <div>
                          <div className="text-muted-foreground">Evidence</div>
                          <div className="mt-0.5 font-mono">
                            {assessment.evidence?.basis.replaceAll("_", " ") ??
                              "Missing"}
                          </div>
                        </div>
                      </div>
                      {fallbackReason ? (
                        <div className="mt-2 text-xs text-muted-foreground">
                          Fallback: {fallbackReason}
                        </div>
                      ) : null}
                    </div>
                  )
                })}
              </div>
            ) : (
              <Empty className="min-h-44 rounded-none border-0">
                <EmptyHeader>
                  <Box />
                  <EmptyTitle>No refresh economics recorded</EmptyTitle>
                  <EmptyDescription>
                    Shadow assessments will appear after an evaluated refresh
                    candidate
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            )}
          </Panel>

          <Panel title="Route health" className="lg:col-span-2">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Route</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Quality</TableHead>
                  <TableHead>p95</TableHead>
                  <TableHead>Error rate</TableHead>
                  <TableHead>Last run</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {routes.map((route) => (
                  <TableRow key={route.id}>
                    <TableCell className="font-mono text-link">
                      {route.id}
                    </TableCell>
                    <TableCell>Not promoted</TableCell>
                    <TableCell>—</TableCell>
                    <TableCell>—</TableCell>
                    <TableCell>—</TableCell>
                    <TableCell>—</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Panel>

          <Panel title="Recent runs" className="lg:col-span-2">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Route</TableHead>
                  <TableHead>Resolution</TableHead>
                  <TableHead>Workers</TableHead>
                  <TableHead>Quality</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Cost</TableHead>
                </TableRow>
              </TableHeader>
            </Table>
            <Empty className="min-h-44 rounded-none border-0">
              <EmptyHeader>
                <Inbox />
                <EmptyTitle>No runs recorded</EmptyTitle>
              </EmptyHeader>
            </Empty>
          </Panel>
        </div>
      </div>

      <aside className="border-t bg-sidebar p-4 xl:border-t-0 xl:border-l">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Approvals</h2>
          <Link className="text-xs text-link hover:underline" to="/approvals">
            Review
          </Link>
        </div>
        <Empty className="min-h-52 rounded-none border-0">
          <EmptyHeader>
            <Inbox />
            <EmptyTitle>No pending approvals</EmptyTitle>
          </EmptyHeader>
        </Empty>
        <div className="mt-4 border-t pt-4">
          <h2 className="mb-4 text-sm font-semibold">Runtime events</h2>
          <div className="flex items-center gap-3 text-xs">
            <Activity className="text-success" />
            <span>Runtime started</span>
          </div>
        </div>
      </aside>
    </div>
  )
}
