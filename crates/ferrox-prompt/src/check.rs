//! The gate `ci.yml` runs on the library's shape — touches, gates, placeholders, graph — never a judgement of prose.

use std::path::Path;

use crate::markdown::{Diagnostic, Library, Prompt, Touch};

/// Parser findings plus filesystem and roadmap-wide ones; `verify_paths` is false for an outside library, and the report says what was skipped.
pub fn run(library: &Library, root: &Path, verify_paths: bool) -> Vec<Diagnostic> {
    let mut findings = library.diagnostics.clone();
    if !verify_paths {
        findings.push(Diagnostic::warning(
            0,
            format!(
                "this library is outside {}, so **Touches:** and the workflows its gates name \
                 were not checked",
                root.display()
            ),
        ));
    }
    for prompt in &library.prompts {
        if verify_paths {
            check_touches(prompt, root, &mut findings);
        }
        check_gates(prompt, root, verify_paths, &mut findings);
        check_placeholders(prompt, &mut findings);
    }
    check_roadmap(library, &mut findings);
    findings.sort_by_key(|finding| (finding.line, finding.severity));
    findings
}

/// Paths this prompt claims, against what is actually there.
fn check_touches(prompt: &Prompt, root: &Path, findings: &mut Vec<Diagnostic>) {
    for touch in &prompt.touches {
        let path = touch.path();
        let full = root.join(path);
        match touch {
            Touch::Existing(_) if !full.exists() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `{path}` does not exist, so this slice points at a file \
                     nothing will edit",
                    prompt.id
                ),
            )),
            Touch::Created(_) if full.exists() => findings.push(Diagnostic::error(
                prompt.line,
                format!(
                    "P{}: **Touches:** `+{path}` already exists, so this slice claims to create a \
                     file that is there — mark the prompt done, or file it against the real path",
                    prompt.id
                ),
            )),
            _ => {}
        }
    }
}

/// Gates against the repository they name.
fn check_gates(prompt: &Prompt, root: &Path, verify_paths: bool, findings: &mut Vec<Diagnostic>) {
    let workflows = root.join(".github/workflows");
    for gate in &prompt.gates {
        let trimmed = gate.trim();
        if looks_like_a_command(trimmed) && !trimmed.starts_with('`') {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: the gate `{trimmed}` is a command written as plain text; wrap it in \
                     backticks so it reads as one",
                    prompt.id
                ),
            ));
        }
        if !verify_paths {
            continue;
        }
        for token in trimmed.split(|character: char| character.is_whitespace() || character == ',')
        {
            let name = token.trim_matches('`');
            // Case-insensitive: `CI.yml` and `ci.yml` are one workflow to the author, two strings to a byte compare.
            let extension = Path::new(name)
                .extension()
                .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let names_a_workflow =
                matches!(extension.as_str(), "yml" | "yaml") && !name.contains('/');
            if names_a_workflow && !workflows.join(name).is_file() {
                findings.push(Diagnostic::error(
                    prompt.line,
                    format!(
                        "P{}: the gate names `{name}`, which is not in .github/workflows/; a gate \
                         that names a job which does not exist is a promise, not a check",
                        prompt.id
                    ),
                ));
            }
        }
    }
}

/// Whether a gate opens like a shell command.
fn looks_like_a_command(gate: &str) -> bool {
    const OPENERS: &[&str] = &[
        "cargo ", "./", "bash ", "sh ", "git ", "gh ", "make ", "npm ",
    ];
    OPENERS.iter().any(|opener| gate.starts_with(opener))
}

/// Defaults that are empty, which render as a hole that looks like a value.
fn check_placeholders(prompt: &Prompt, findings: &mut Vec<Diagnostic>) {
    for placeholder in &prompt.placeholders {
        if placeholder.default.as_deref() == Some("") {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{}: `{{{} =}}` has an empty default; give it a value or drop the `=` so it \
                     reads as required",
                    prompt.id, placeholder.name
                ),
            ));
        }
    }
}

/// Checks about the roadmap as a whole.
fn check_roadmap(library: &Library, findings: &mut Vec<Diagnostic>) {
    let open: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open())
        .collect();
    if open.is_empty() {
        findings.push(Diagnostic::warning(
            0,
            "no prompt is `todo` or `blocked`: the roadmap has nothing to offer, so `next` will \
             only ever say so",
        ));
    }

    // Files more than one available prompt claims. See `contention`.
    for prompt in library
        .prompts
        .iter()
        .filter(|prompt| is_available(library, prompt))
    {
        for clash in contention(library, prompt) {
            findings.push(Diagnostic::warning(
                prompt.line,
                format!(
                    "P{} and {} are both open now and both claim `{}`; they are one slice, or two \
                     that must be taken in order",
                    prompt.id,
                    clash
                        .also
                        .iter()
                        .map(|id| format!("P{id}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    clash.path
                ),
            ));
        }
    }
}

/// Started or ready now: only two *available* slices claiming one file is a real ordering decision.
pub fn is_available(library: &Library, prompt: &Prompt) -> bool {
    prompt.status == crate::markdown::Status::Doing
        || crate::advisor::readiness(library, prompt) == crate::advisor::Readiness::Ready
}

/// A file this prompt shares with another available prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contention {
    /// The path, as both prompts write it.
    pub path: String,
    /// The other prompts that are available and claim it.
    pub also: Vec<u32>,
}

/// Files `prompt` shares with a prompt the advisor could also be asked for.
pub fn contention(library: &Library, prompt: &Prompt) -> Vec<Contention> {
    let mut found: Vec<Contention> = Vec::new();
    for path in prompt.existing_paths() {
        let also: Vec<u32> = library
            .prompts
            .iter()
            .filter(|other| other.id != prompt.id)
            .filter(|other| is_available(library, other))
            .filter(|other| other.existing_paths().any(|claimed| claimed == path))
            .map(|other| other.id)
            .collect();
        if !also.is_empty() {
            found.push(Contention {
                path: path.to_owned(),
                also,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    const GOOD: &str = "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test`; CI: `ci.yml`
**Touches:** Cargo.toml

```text
body
```
";

    #[test]
    fn the_live_library_passes_its_own_gate() {
        let library = crate::load_library(None, Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("the library is next to this crate");
        let root = crate::workspace_root(Path::new(env!("CARGO_MANIFEST_DIR")));
        let findings = run(&library, &root, true);
        let errors: Vec<&Diagnostic> = findings
            .iter()
            .filter(|finding| finding.severity == crate::markdown::Severity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "prompts.md fails its own gate: {errors:#?}"
        );
    }

    #[test]
    fn a_touch_at_a_missing_file_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "crates/gone.rs"));
        let findings = run(&library, Path::new("/nonexistent-root"), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("does not exist")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_touch_at_an_existing_file_is_fine_against_the_real_root() {
        let library = load(GOOD);
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(findings
            .iter()
            .all(|finding| !finding.message.contains("does not exist")));
    }

    #[test]
    fn a_created_file_that_already_exists_is_an_error() {
        let library = load(&GOOD.replace("Cargo.toml", "+Cargo.toml"));
        let root = crate::manifest_root();
        let findings = run(&library, &root, true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("already exists")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_gate_naming_a_missing_workflow_is_an_error() {
        let library = load(&GOOD.replace("CI: `ci.yml`", "CI: `no-such.yml`"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("not in .github/workflows")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_command_gate_without_backticks_is_a_warning() {
        let library = load(&GOOD.replace("`cargo test`", "cargo test"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("wrap it in")),
            "{findings:#?}"
        );
    }

    #[test]
    fn two_open_prompts_claiming_one_file_are_reported() {
        let text = format!(
            "{GOOD}\n## P2 · Two\n\n**When to use:** now\n**Status:** todo\n**Leverage:** 1\n\
             **Effort:** small\n**Gates:** `cargo test`\n**Touches:** Cargo.toml\n\n```text\nb\n```\n"
        );
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("both claim")),
            "{findings:#?}"
        );
    }

    #[test]
    fn an_empty_default_is_a_warning() {
        let library = load(&GOOD.replace("```text\nbody", "```text\nbody {a=}"));
        let findings = run(&library, &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("empty default")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_finished_roadmap_says_so() {
        let text = GOOD.replace("**Status:** todo", "**Status:** done");
        let findings = run(&load(&text), &crate::manifest_root(), true);
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("nothing to offer")),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_library_outside_the_repository_says_which_checks_were_skipped() {
        let findings = run(&load(GOOD), &crate::manifest_root(), false);
        let note = findings
            .iter()
            .find(|finding| finding.message.contains("were not checked"))
            .unwrap_or_else(|| panic!("a skipped check must be said out loud: {findings:#?}"));
        assert!(note.message.contains("**Touches:**"));
    }
}
