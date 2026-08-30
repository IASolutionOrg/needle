# Configuration

Needle stores profile configuration in the same local SQLite database used for
routes, artifacts, proofs, approvals, runs, and changes.

## Data directory

Precedence:

1. `--data-dir <directory>`;
2. `NEEDLE_DATA_DIR`;
3. `%LOCALAPPDATA%\Needle` on Windows;
4. `$XDG_DATA_HOME/needle`;
5. `$HOME/.local/share/needle`.

The database is `<data-dir>/needle.sqlite3`. Use an explicit directory for
tests, experiments, or parallel profiles.

## Initialization

```text
needle init \
  --codex <codex-launcher> \
  --worker-model <model> \
  --worker-reasoning <low|medium|high|xhigh> \
  [--worker-timeout-seconds <seconds>] \
  [--evidence-failure-policy <discard_invalid_fact|repair_once>] \
  [--trust-test-execution] \
  [--data-dir <directory>]
```

Persistent runtime settings are:

- resolved user-installed Codex launcher;
- worker model and reasoning;
- worker timeout;
- evidence failure policy;
- trusted test execution;
- multi-need policy.

Credentials are neither imported nor exported.

## Current agent-host scope

Production worker execution and orchestration currently use Codex App Server
from the user's existing Codex installation. Needle uses the host's
authentication and does not install a private Codex copy.

Phase 10-A/B adds the first second-host foundation for Antigravity. A role-profile
draft may select `host=antigravity`, and the control plane preserves that host in
the canonical definition identity. Activation remains fail-closed until Gate A8
passes. The Shadow adapter invokes the user's official `agy` headless CLI,
requires its structured NDJSON, schema, usage, timeout, and sandbox surface, and
runs inside a disposable checkout. It never invokes the Antigravity IDE binary
or its private language-server executable. `needle doctor` reports the IDE and
CLI separately. The resolver has an explicit immutable-profile dispatcher for
standalone Explore, but Antigravity profiles cannot yet become active, so this
path remains unreachable in ordinary production sessions until Gate A8.

Antigravity execution is bound to one exact disposable checkout in three independent places: the
child process starts with that checkout as its current directory, the adapter passes
`--add-dir <checkout>`, and the trusted prompt names the checkout and requires repository-relative
outputs. Needle does not require a global `read_file(...)` permission rule and does not classify
Antigravity's native tool names. Host-native tools remain opaque implementation details; the kernel
only reasons about the canonical filesystem, command, network, MCP, subagent, and external-effect
allowances described below. Unsafe `read_file(*)`, always-proceed, and
`--dangerously-skip-permissions` configurations remain unsupported.

The two earlier live attempts are retained as failed-closed evidence, but their original diagnosis
was too strong: transcript review showed that native directory tools requested paths outside the
isolated checkout, so their denial did not prove an incompatibility between an in-checkout read and
Antigravity's permission system. The corrected binding has now completed one provider-backed Explore
smoke successfully: it returned a bounded `src/lib.rs` artifact in one turn, preserved the active
checkout, and cleaned the disposable checkout. Gate A8 remains open for the other action, lifecycle,
accounting, and cross-host quality criteria; the smoke alone does not enable production routing.

No non-Codex profile is production-routable yet. Cross-host fallback remains
disabled, and a separately approved provider-backed validation is required
before Antigravity activation. See the [product roadmap](ROADMAP.md).

## Canonical agent role profiles

Named role profiles are persisted in the local SQLite database as
canonical, immutable definition revisions. The supported roles are
`explorer`, `implementer`, `test_runner`, `reviewer`, `verifier`, and `auditor`;
the authorable hosts are `codex` and `antigravity`, while only `codex` may be
activated until Gate A8 passes. Definitions are stored separately from runtime
settings and `ModelPolicy`, and are not automatically selected or activated.

The safe policy vocabulary is deliberately closed:

- tools: `read_only` or `isolated_write`;
- commands: `denied`, `read_only`, or `certified_tests`;
- filesystem: `read_only_checkout` or `disposable_checkout`;
- network: `denied` only;
- tests: `disabled` or `certified`;
- repair: `none` or `once`;
- fallback: `disabled` or `native`.

`isolated_write` is limited to `implementer` in a `disposable_checkout`.
Every other role is read-only. `certified_tests` is paired with `certified`
tests and is limited to `test_runner` or `verifier`. Concurrency is exactly
one. Timeout is 1--3600 seconds; budgets are 1--8 turns, 1--2000 output
tokens, and 1--1,000,000,000 micro-USD. Route assignments are canonicalized
by sort-and-deduplicate and are bounded by the hard per-task limit of eight.
Models are 1--128 ASCII `[A-Za-z0-9._-]` tokens; credential-like prefixes,
paths, credentials, and network settings are rejected.

Each revision stores its complete canonical JSON and definition digest. State
changes use a generation-bound state digest (draft, active, or inactive) and
are applied transactionally. Historical revisions remain readable; activating
an exact historical revision does not rewrite its definition. `Default` tier
projects to the existing `WorkerProfile` representation with `None`, while
`Priority` projects to `Some("priority")`; that compatibility digest is
distinct from the role-profile definition/revision digest. Projection is
explicit and does not read or modify `ModelPolicy`.

Role-profile definitions and revisions remain local SQLite state. New
production sessions bind an explicitly selected active revision; the binding
stores only profile ID, revision, and definition digest. Historical sessions
reload that exact revision even after a later activation. Legacy rows remain
unknown and cannot be reused for profile-dependent cache or worker execution.
The local HTTP/editor exposes bounded, authenticated routes for
list/detail/history, audit, request-time preflight, draft CAS, and explicit
activation/deactivation. Preflight is recomputed at request time and is never
persisted. These endpoints do not launch workers, bind sessions, execute a
lifecycle, or configure a non-Codex host. Role profiles never carry
credentials, host paths, raw transcripts, or network access.

The product hook selects a profile with `NEEDLE_ROLE_PROFILE_ID`. If that
variable is missing or invalid, the hook remains fail-open but records no
session row, so the runtime cannot silently attribute the session to a current
active revision. MCP uses the required `--role-profile <id>` selector.

## Effective worker allowances and approval automation

Every immutable role-profile revision projects to a canonical
`EffectiveWorkerAllowancesV1`. The projection records the selected host and the effective
filesystem-read, filesystem-write, command, network, MCP, subagent, and external-effect boundaries.
Its digest is independent from, and bound alongside, the role-profile definition digest. The local
Role Profiles page displays both digests and the complete effective allowances before activation;
the confirmation is invalidated if either digest changes.

The Approval Inbox is host-neutral. A pending request records the host, worker role, immutable
profile binding, allowance projection, operation kind, bounded operation payload, and a v2 payload
digest. Human decisions use compare-and-swap against that exact request, so a changed command,
checkout scope, host, profile, allowance set, or operation cannot inherit an older approval.

The dashboard also exposes a local AI reviewer policy with three modes:

- `disabled` (default): every AI-eligible request waits for the user;
- `advisory`: the evaluator records `allow`/`disallow` advice, but the user still decides;
- `decide`: valid evaluator output applies the approval decision automatically.

The default evaluator configuration is the user's Codex host with model `gpt-5.6-luna`, reasoning
`low`, and a 30-second timeout. Changing the policy is digest-bound and local. AI eligibility is a
hard safety predicate, not a command-name allowlist: it is limited to direct, read-only command
requests inside the exact checkout, under an immutable allowance set that denies writes, network,
MCP, subagents, and external effects. Apply and every other side effect are never AI-eligible.

The evaluator receives only a canonical bounded JSON description, never the repository path or
contents. It runs in a fresh empty read-only workspace and its final text must parse as the bare JSON
integer `0` or `1`; an App Server Structured Output schema is deliberately omitted because that API
requires an object at the schema root.
Any timeout, malformed output, tool activity, file observation, nested approval, policy mismatch, or
persistence failure falls back to the human inbox. A provider-backed Luna/low smoke has returned `1`
for the safe `git status` case and `0` for an ambiguous `unknown-tool delete-all` case, both without
tool activity or checkout mutation. The feature remains disabled by default as a deliberate safety
default; these two bounded cases validate the binary evaluator contract, not the broader Gate A8.

## Export and import

```text
needle config export --data-dir .needle-data
needle config export --output needle.toml --data-dir .needle-data
needle config import needle.toml --data-dir .needle-data
```

The TOML snapshot contains a format revision, runtime settings, presets,
routes, and optional model policy. Import rejects unsupported revisions,
invalid values, and definition-digest mismatches.

## Routes

```text
needle route list --data-dir .needle-data
needle route show locate.implementation --data-dir .needle-data
needle route enable locate.implementation --data-dir .needle-data
needle route disable tests.relevant --data-dir .needle-data
```

Each route binds an ID, enabled state, priority, matcher, preset, plan, and
immutable definition digest. State can change; definitions remain digest
addressed.

## Model policies

`FixedOrder` contains explicit worker profiles, one optional repair in the same
thread, and native fallback. Profiles are attempted in configured order.

`CheapestValidatedFirst` accepts only route/profile combinations with recorded
promotion evidence. Recommendations never change policy automatically.

Model policy is edited through the Models page or digest-bound HTTP API.

## Multi-need policy

Default settings:

```toml
[settings.multi_need_policy]
multi_need_enabled = true
continue_working_enabled = true
max_needs_per_task = 3
max_workers_per_task = 3
pending_main_tools = "allow_and_taint"
resolver_concurrency = 1
```

Need and worker limits have an internal hard cap of eight. Resolution
concurrency is one. Main tools used while a continue-working resolution is
pending taint the zero-discovery claim but do not fail the task.

## Capability promotion

Semantic capability modes are `Shadow`, `Advisory`, and `Authoritative`.

Authoritative reuse additionally requires:

- exact canonical repository-scoped subject;
- supported predicate facets and compatible world;
- fresh validation and sufficiency certificates;
- no mandatory residual or contradiction;
- compatible observed fresh and reuse costs;
- positive net reuse value.

Promotion requires the current definition digest, confirmation, and evidence
digest. It is audited in SQLite. Route/profile promotion and semantic
capability promotion are separate decisions.

## Optimistic concurrency

Settings, route state, model policy, capability authority, and apply use:

```text
If-Match: "<current-digest>"
```

- missing digest → `428 Precondition Required`;
- stale digest → `412 Precondition Failed`;
- valid digest → update plus new state/digest.

## Session immutability

A session freezes its prompt profile, transport definition, semantic
definition, route set, main model, repository, and multi-need policy. Later
configuration updates affect future sessions only. A digest mismatch causes
bypass or rejection; it never silently reinterprets historical input.

## Cache operations

```text
needle cache list --data-dir .needle-data
needle cache show <identity-digest> --data-dir .needle-data
needle cache latest-run --data-dir .needle-data
needle cache invalidate <identity-digest> --data-dir .needle-data
needle cache invalidate --all --data-dir .needle-data
```

Invalidation is local and does not change source files or remote state.

## See also

- [Developer setup](DEVELOPER_SETUP.md)
- [Artifacts and cache](ARTIFACTS_AND_CACHE.md)
- [Runtime and web control plane](RUNTIME_AND_WEB_CONTROL_PLANE.md)
