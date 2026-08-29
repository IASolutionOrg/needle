use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const MANAGED_MARKER: &str =
    "<!-- Managed by Needle. Run `needle enable` to refresh this skill. -->";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SkillInstallation {
    pub path: PathBuf,
    pub installed: bool,
    pub managed: bool,
    pub current: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SkillRemoval {
    pub path: PathBuf,
    pub removed: bool,
    pub unmanaged_preserved: bool,
}

pub(crate) fn inspect() -> Result<SkillInstallation, String> {
    let root = personal_skills_root()?;
    let executable = current_executable()?;
    inspect_at(&root, &executable)
}

pub(crate) fn ensure_installed() -> Result<SkillInstallation, String> {
    let root = personal_skills_root()?;
    let executable = current_executable()?;
    ensure_installed_at(&root, &executable)
}

pub(crate) fn remove_managed() -> Result<SkillRemoval, String> {
    let root = personal_skills_root()?;
    let executable = current_executable()?;
    remove_managed_at(&root, &executable)
}

fn personal_skills_root() -> Result<PathBuf, String> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(|home| PathBuf::from(home).join(".agents").join("skills"))
        .ok_or_else(|| "the personal Codex skills directory is unavailable".to_owned())
}

fn current_executable() -> Result<PathBuf, String> {
    env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("cannot resolve the Needle executable: {error}"))
}

fn inspect_at(root: &Path, executable: &Path) -> Result<SkillInstallation, String> {
    let path = root.join("needle").join("SKILL.md");
    if !path.is_file() {
        return Ok(SkillInstallation {
            path,
            installed: false,
            managed: false,
            current: false,
            changed: false,
        });
    }
    let existing = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let managed = existing.contains(MANAGED_MARKER);
    let current = managed && existing == render_skill(executable);
    Ok(SkillInstallation { path, installed: true, managed, current, changed: false })
}

fn ensure_installed_at(root: &Path, executable: &Path) -> Result<SkillInstallation, String> {
    let mut status = inspect_at(root, executable)?;
    if status.installed && !status.managed {
        return Err(format!(
            "{} already exists and is not managed by Needle; move or rename it before enabling the Codex Desktop integration",
            status.path.display()
        ));
    }
    if status.current {
        return Ok(status);
    }
    let parent = status
        .path
        .parent()
        .ok_or_else(|| "the Needle skill path has no parent directory".to_owned())?;
    if parent.exists() && !status.installed {
        let mut entries = fs::read_dir(parent)
            .map_err(|error| format!("cannot inspect {}: {error}", parent.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "{} already exists and contains files not managed by Needle",
                parent.display()
            ));
        }
    }
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    fs::write(&status.path, render_skill(executable))
        .map_err(|error| format!("cannot write {}: {error}", status.path.display()))?;
    status.installed = true;
    status.managed = true;
    status.current = true;
    status.changed = true;
    Ok(status)
}

fn remove_managed_at(root: &Path, executable: &Path) -> Result<SkillRemoval, String> {
    let status = inspect_at(root, executable)?;
    if !status.installed {
        return Ok(SkillRemoval { path: status.path, removed: false, unmanaged_preserved: false });
    }
    if !status.managed {
        return Ok(SkillRemoval { path: status.path, removed: false, unmanaged_preserved: true });
    }

    fs::remove_file(&status.path)
        .map_err(|error| format!("cannot remove {}: {error}", status.path.display()))?;
    if let Some(parent) = status.path.parent() {
        let empty = fs::read_dir(parent)
            .map_err(|error| format!("cannot inspect {}: {error}", parent.display()))?
            .next()
            .is_none();
        if empty {
            fs::remove_dir(parent)
                .map_err(|error| format!("cannot remove empty {}: {error}", parent.display()))?;
        }
    }
    Ok(SkillRemoval { path: status.path, removed: true, unmanaged_preserved: false })
}

fn render_skill(executable: &Path) -> String {
    let executable = executable.display();
    format!(
        r#"---
name: needle
description: In Codex Desktop, use Needle for repository resolution, standalone typed patch/test/review/verify/apply actions, or a complete bounded change lifecycle with explicit Apply approval.
---

# Needle repository execution

{MANAGED_MARKER}

Use this skill only in Codex Desktop. Codex CLI uses Needle lifecycle hooks instead and must not also invoke this skill. Use Needle for bounded repository resolution, one typed action, or a complete change lifecycle. Do not invoke it for general questions, trivial file reads, or work outside a Git repository.

Choose `execution.kind` explicitly from the user's requested operation. Never infer it from keywords such as "implement", "review", or "test":

- `resolve`: resolve one Need without starting or modifying a change.
- `action`: execute exactly one typed action contract. A standalone Review or Verify stays standalone and never creates a lifecycle halfway through.
- `lifecycle`: start or resume the complete `Explore -> Implement -> Test -> Review -> Verify` flow. A lifecycle always starts at Explore and stops at `AwaitingApproval`; it never applies a patch automatically.

Construct one closed `needle.need-execution/1` JSON envelope and pass it on stdin to:

`{executable} run --request-stdin --repository <absolute-repository-path>`

The envelope has exactly these top-level fields: `schema`, `operation_id`, `need`, and `execution`. Use `schema: "needle.need-execution/1"`. Generate a fresh non-zero `b3:` digest for a new invocation; reuse the exact same `operation_id` only to resume that same invocation. Never reuse it for changed semantic input.

Build `need` as canonical NeedIR revision 1 with exactly: `route_hint`, `subjects`, `required`, `preferred`, `semantic_constraints`, `world`, `input_artifacts`, `projection`, `body`, and `format_revision`. Keep repeated fields deterministically ordered. For repository exploration use exactly one route and its predicate:

- `locate.implementation` with `implementation-location`;
- `trace.state-flow` with `runtime-flow`;
- `tests.relevant` with `focused-tests`.

Use stable subject kinds `symbol`, `cli-option`, `configuration-key`, `test`, `file`, `module`, or `behavior`. The canonical name must identify the source subject, not repeat the full prompt.

For `resolve`, set `execution` to `{{"kind":"resolve"}}`.

For `lifecycle`, set `execution` to `{{"kind":"lifecycle","lifecycle":{{"change":{{"task":...,"acceptance_criteria":[...],"allowed_paths":[{{"path":...,"scope":"exact|subtree"}}],"artifact_ids":[],"claim_ids":[],"constraints":[]}}}}}}`. `acceptance_criteria` and `allowed_paths` are mandatory. Use only repository-relative forward-slash paths and the narrowest write scope authorized by the user. Never widen allowed paths to the repository root. An optional `budget_override` may only reduce active limits.

Do not preselect, guess, or execute a test command for a lifecycle. When Test has no bound plan, the Needle parent resolves `needle.tests.plan` through the configured provider, certifies the returned direct command against the exact source, binds it durably, and then executes only that certified plan in isolation. Ecosystem discovery belongs to the provider; the Needle kernel remains language-neutral.

For `action`, set `execution` to `{{"kind":"action","action":{{"contract":<contract>,"input":<typed-input>}}}}`. The typed input `kind` must match the contract exactly:

- `needle.patch.propose` -> `patch_propose` with `change`; add both `prior_patch` and `repair_verification` only for Repair.
- `needle.tests.execute` -> `tests_execute` with `change_id`, `requirements_digest`, exact `patch`, and certified `test_plan_artifact`.
- `needle.review.diff` -> `review_diff` with `change_id`, `requirements_digest`, exact `patch`, and optional `prior_review_artifacts`.
- `needle.patch.verify` -> `patch_verify` with `change_id`, `requirements_digest`, exact `patch`, and at least one certified `test_evidence_artifacts` entry.
- `needle.patch.apply` -> `patch_apply` with the exact binding returned by an `AwaitingApproval` lifecycle or prior actions. Set `confirm: true` only after the user explicitly approves Apply in the current conversation.

Artifact references are closed objects: patch references contain `artifact` and `patch`; verification references contain `artifact` and `verification`. Copy typed identifiers and digests verbatim from Needle output. Never fabricate, guess, or substitute legacy IDs.

Quote every argument for the active shell. Set the shell execution timeout to at least 360 seconds and wait until the Needle process exits; a first uncached exploration can take more than one minute. If the shell tool yields a running process or cell, keep waiting for that same process instead of starting another invocation. Needle writes progress to stderr and emits the bounded context on stdout only after resolution completes.

Treat the versioned JSON stdout as the only machine-readable result. Do not reconstruct lifecycle state from prose. At `AwaitingApproval`, show the user the result and ask whether to Apply; if approved, issue a separate `needle.patch.apply` action using the exact returned binding and a fresh operation ID. If Needle reports disabled, unavailable, inconclusive, or unsuccessful, report the actionable state and continue natively only when safe.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        env::temp_dir().join(format!("needle-skill-{name}-{nonce}"))
    }

    #[test]
    fn installation_is_idempotent_and_tracks_the_executable() {
        let root = temporary_root("idempotent");
        let first_executable = root.join(if cfg!(windows) { "needle.exe" } else { "needle" });
        let second_executable =
            root.join("new").join(if cfg!(windows) { "needle.exe" } else { "needle" });

        let first = ensure_installed_at(&root, &first_executable).unwrap();
        let unchanged = ensure_installed_at(&root, &first_executable).unwrap();
        let updated = ensure_installed_at(&root, &second_executable).unwrap();

        assert!(first.changed);
        assert!(!unchanged.changed);
        assert!(updated.changed);
        let contents = fs::read_to_string(updated.path).unwrap();
        assert!(contents.contains(MANAGED_MARKER));
        assert!(contents.contains(&second_executable.display().to_string()));
        assert!(contents.contains("run --request-stdin"));
        assert!(contents.contains("Never infer it from keywords"));
        assert!(contents.contains("A lifecycle always starts at Explore"));
        assert!(contents.contains("standalone and never creates a lifecycle"));
        assert!(contents.contains("needle.patch.apply"));
        assert!(contents.contains("explicitly approves Apply"));
        assert!(contents.contains("Never widen allowed paths"));
        assert!(contents.contains("Do not preselect, guess, or execute a test command"));
        assert!(contents.contains("kernel remains language-neutral"));
        assert!(contents.contains("timeout to at least 360 seconds"));
        assert!(contents.contains("keep waiting for that same process"));
        assert!(!contents.contains("@@need"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installation_refuses_to_overwrite_an_unmanaged_skill() {
        let root = temporary_root("collision");
        let skill = root.join("needle");
        fs::create_dir_all(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), "---\nname: needle\n---\nUser content.\n").unwrap();

        let error = ensure_installed_at(&root, Path::new("needle")).unwrap_err();
        assert!(error.contains("not managed by Needle"));
        assert!(fs::read_to_string(skill.join("SKILL.md")).unwrap().contains("User content"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_skill_removal_is_safe_and_idempotent() {
        let root = temporary_root("remove-managed");
        let executable = root.join(if cfg!(windows) { "needle.exe" } else { "needle" });
        let installation = ensure_installed_at(&root, &executable).unwrap();

        let removed = remove_managed_at(&root, &executable).unwrap();
        let repeated = remove_managed_at(&root, &executable).unwrap();

        assert!(removed.removed);
        assert!(!removed.unmanaged_preserved);
        assert!(!installation.path.exists());
        assert!(!repeated.removed);
        assert!(!repeated.unmanaged_preserved);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removal_preserves_unmanaged_skills_and_sibling_files() {
        let root = temporary_root("remove-preserves-user-content");
        let executable = root.join(if cfg!(windows) { "needle.exe" } else { "needle" });
        let skill = root.join("needle");
        fs::create_dir_all(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), "---\nname: needle\n---\nUser content.\n").unwrap();

        let unmanaged = remove_managed_at(&root, &executable).unwrap();
        assert!(!unmanaged.removed);
        assert!(unmanaged.unmanaged_preserved);
        assert!(skill.join("SKILL.md").is_file());

        fs::remove_file(skill.join("SKILL.md")).unwrap();
        ensure_installed_at(&root, &executable).unwrap();
        fs::write(skill.join("notes.txt"), "preserve me").unwrap();
        let managed = remove_managed_at(&root, &executable).unwrap();
        assert!(managed.removed);
        assert!(!skill.join("SKILL.md").exists());
        assert_eq!(fs::read_to_string(skill.join("notes.txt")).unwrap(), "preserve me");
        fs::remove_dir_all(root).unwrap();
    }
}
