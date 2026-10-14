//! Assembly order is fixed: shared protocol, prompt protocol, body, add-ons, worktree, gates verbatim; an unfilled required input goes at the top loudly or is not rendered.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::markdown::{is_placeholder_name, Addon, Library, Prompt};
use crate::worktree::{Place, Worktree};

/// What to include beyond the prompt itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Print the acceptance gates: a prompt with no acceptance section is a request, not a slice.
    pub gates: bool,
    /// The header and footer describe the tool, not the work, so they frame the request only when asked.
    pub provenance: bool,
    /// Render a prompt with unfilled required inputs, the gap stated at the top; `next` refuses instead.
    pub allow_unfilled: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            gates: true,
            provenance: false,
            allow_unfilled: false,
        }
    }
}

/// A rendered prompt and what went into it.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The text.
    pub text: String,
    /// Required inputs with no value, in library order; empty means the prompt is complete.
    pub missing: Vec<String>,
    /// The values that were substituted, so a caller can report what it filled.
    pub supplied: BTreeMap<String, String>,
    /// The add-ons that were resolved, in the order given.
    pub addons: Vec<Addon>,
    /// The worktree the slice runs in, when the caller named one: where to make it, or where it already is.
    pub worktree: Option<Worktree>,
}

/// Render `prompt`; a malformed library is `check`'s find, not something to re-detect here.
pub fn render(
    library: &Library,
    prompt: &Prompt,
    values: &BTreeMap<String, String>,
    addons: &[Addon],
    worktree: Option<&Worktree>,
    options: Options,
) -> Rendered {
    let missing: Vec<String> = prompt
        .required_inputs()
        .filter(|name| !values.contains_key(*name))
        .map(str::to_owned)
        .collect();

    let mut parts: Vec<String> = Vec::new();
    if options.provenance {
        parts.push(header(library, prompt));
    }
    if !missing.is_empty() && options.allow_unfilled {
        parts.push(unfilled_block(prompt, &missing));
    }
    if !library.shared_protocol.is_empty() {
        parts.push(library.shared_protocol.clone());
    }
    if !prompt.protocol.is_empty() {
        parts.push(prompt.protocol.clone());
    }
    parts.push(substitute(&prompt.body, values));

    let mut resolved = Vec::new();
    for addon in addons {
        resolved.push(addon.clone());
        parts.push(format!(
            "**Add-on — {}:** {}",
            addon.title,
            substitute(&addon.body, values)
        ));
    }

    if let Some(worktree) = worktree {
        parts.push(worktree_block(worktree));
    }

    if options.gates {
        parts.push(acceptance_block(prompt));
    }

    let mut text = parts.join("\n\n---\n\n");
    let footer = footer(library, prompt, options.provenance);
    if !footer.is_empty() {
        text.push_str("\n\n");
        text.push_str(&footer);
    }

    let supplied = prompt
        .placeholders
        .iter()
        .filter_map(|placeholder| {
            values
                .get(&placeholder.name)
                .map(|value| (placeholder.name.clone(), value.clone()))
        })
        .collect();

    Rendered {
        text,
        missing,
        supplied,
        addons: resolved,
        worktree: worktree.cloned(),
    }
}

/// The first block: which slice this is, and what the roadmap says about it.
fn header(library: &Library, prompt: &Prompt) -> String {
    let opens = prompt.blocks(library).count();
    let mut line = format!(
        "# P{} · {}\n\nstatus {} · leverage {} · effort {}",
        prompt.id,
        prompt.title,
        prompt.status.as_str(),
        prompt.leverage,
        prompt.effort.as_str()
    );
    if !prompt.depends_on.is_empty() {
        let _ = write!(
            line,
            " · depends on {}",
            prompt
                .depends_on
                .iter()
                .map(|id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if opens > 0 {
        let _ = write!(line, " · opens {opens} slice(s)");
    }
    line
}

/// The block that states an unfilled input instead of leaving a hole.
fn unfilled_block(prompt: &Prompt, missing: &[String]) -> String {
    let mut block = String::from(
        "## Inputs required before this slice can start\n\n\
         These were not supplied. Do not invent a value for any of them: each is a \
         decision this tool refused to make on your behalf.",
    );
    for name in missing {
        let _ = write!(block, "\n- `{name}` — re-run with `--set {name}=<value>`.");
    }
    let _ = write!(
        block,
        "\n\nFull command: `{}`",
        suggested_command(prompt, missing, &[])
    );
    block
}

/// Where the slice runs: the script makes the worktree when there is none, and an existing one is updated to `main` before the first edit.
fn worktree_block(worktree: &Worktree) -> String {
    let mut line = String::new();
    match worktree.place {
        Place::Absent => {
            let _ = write!(
                line,
                "There is no worktree for this slice yet. Create it with \
                 `./scripts/new-worktree.sh {name}` and work only there — that script \
                 and never a hand-made `git worktree add`, because it is what points the \
                 build at the shared `target-dir`, writes `.cargo/config.toml` with the \
                 hardware-crypto cfgs CI builds with, and links the `upstream/` checkouts \
                 the references are read from. It makes `{path}` on branch `{name}`; open \
                 the pull request from that branch.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Linked => {
            let _ = write!(
                line,
                "Worktree `{name}` already exists at `{path}` — do this slice there, not in \
                 the checkout this prompt came from. Update it to match `main` before the \
                 first edit (`git fetch origin main && git rebase origin/main`): `main` moves \
                 under a worktree, and a slice built on a stale base measures the wrong code. \
                 If it holds unmerged work, read it and carry on rather than starting over.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Current => {
            let _ = write!(
                line,
                "This slice's worktree `{name}` is the very checkout this prompt was read \
                 from (`{path}`): update it to match `main` first (`git fetch origin main && \
                 git rebase origin/main`), then do the work here.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
        Place::Occupied => {
            let _ = write!(
                line,
                "`{path}` exists but is not a worktree, so `./scripts/new-worktree.sh {name}` \
                 refuses it. Move that directory aside and create `{name}` with the script — \
                 the same one, for the same reasons — then work there.",
                name = worktree.name,
                path = worktree.path.display(),
            );
        }
    }
    format!("## Worktree\n\n- {line}")
}

/// The gates, verbatim, under a heading that says what they are for.
fn acceptance_block(prompt: &Prompt) -> String {
    let mut block = String::from(
        "## Acceptance\n\n\
         These checks come from the library, and this slice is not done until every one of \
         them is green. Run them; do not report the result of a command you did not run.",
    );
    for gate in &prompt.gates {
        let _ = write!(block, "\n- {gate}");
    }
    block
}

/// A comment naming the slice, the file and the tag of the text it came from.
fn footer(library: &Library, prompt: &Prompt, with_provenance: bool) -> String {
    if !with_provenance {
        return String::new();
    }
    format!(
        "<!-- ferrox-prompt · P{} · {} · library tag {} (fnv1a-64, not a checksum) -->",
        prompt.id,
        library.path.display(),
        library.tag()
    )
}

/// `{name}` and `{name=default}` substitute; `{{`/`}}` escape one brace, lone braces are prose, and an unfilled placeholder stays as written.
pub fn substitute(text: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '}' {
            if chars.peek() == Some(&'}') {
                chars.next();
                out.push('}');
            } else {
                out.push('}');
            }
            continue;
        }
        if character != '{' {
            out.push(character);
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            out.push('{');
            continue;
        }
        let mut body = String::new();
        let mut closed = false;
        for inner in chars.by_ref() {
            if inner == '}' {
                closed = true;
                break;
            }
            body.push(inner);
        }
        // No closing brace: the `{` was prose, so emit what was read and stop scanning for placeholders.
        if !closed {
            out.push('{');
            out.push_str(&body);
            continue;
        }
        // An unfilled placeholder stays exactly as written, so the gap is visible in the output, not in a footnote.
        if let Some(value) = resolved(&body, values) {
            out.push_str(&value);
        } else {
            out.push('{');
            out.push_str(&body);
            out.push('}');
        }
    }
    out
}

/// The text for one placeholder body, or `None` to leave the placeholder alone.
fn resolved(body: &str, values: &BTreeMap<String, String>) -> Option<String> {
    let (name, default) = match body.split_once('=') {
        Some((name, default)) => (name.trim(), Some(default)),
        None => (body.trim(), None),
    };
    if !is_placeholder_name(name) {
        return None;
    }
    match values.get(name) {
        Some(value) => Some(value.clone()),
        // An empty default reads as no default so the placeholder stays visible; `check` reports it separately.
        None => default
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    }
}

/// The add-ons `requests` names, slug-exact then unique substring; ambiguity is an error, never a guess.
pub fn resolve_addons(prompt: &Prompt, requests: &[String]) -> Result<Vec<Addon>, String> {
    let mut flat: Vec<&str> = requests
        .iter()
        .flat_map(|request| request.split(','))
        .map(str::trim)
        .filter(|request| !request.is_empty())
        .collect();
    if flat.len() == 1 && flat[0].eq_ignore_ascii_case("all") {
        return Ok(prompt.addons.clone());
    }
    flat.dedup();
    let mut resolved_addons = Vec::new();
    for request in flat {
        if let Some(addon) = prompt.addon(&request.to_ascii_lowercase()) {
            resolved_addons.push(addon.clone());
            continue;
        }
        let needle = request.to_ascii_lowercase();
        let matches: Vec<&Addon> = prompt
            .addons
            .iter()
            .filter(|addon| {
                addon.slug.contains(&needle) || addon.title.to_ascii_lowercase().contains(&needle)
            })
            .collect();
        match matches.as_slice() {
            [only] => resolved_addons.push((*only).clone()),
            [] => {
                let available = prompt
                    .addons
                    .iter()
                    .map(|addon| addon.slug.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "P{} has no add-on matching `{request}`; it has {}",
                    prompt.id,
                    if available.is_empty() {
                        "none".to_owned()
                    } else {
                        available
                    }
                ));
            }
            many => {
                let choices = many
                    .iter()
                    .map(|addon| addon.slug.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "`{request}` matches {choices}; pass the whole slug, or `list` to see them"
                ));
            }
        }
    }
    Ok(resolved_addons)
}

/// The command line that would render `prompt` with `missing` filled: one paste, not a dialog about four keys.
pub fn suggested_command(prompt: &Prompt, missing: &[String], addons: &[String]) -> String {
    let mut command = format!("ferrox-prompt render P{}", prompt.id);
    for name in missing {
        let _ = write!(command, " --set {name}=<value>");
    }
    for name in prompt
        .placeholders
        .iter()
        .filter(|placeholder| !missing.contains(&placeholder.name))
        .map(|placeholder| &placeholder.name)
    {
        let _ = write!(command, " --set {name}=<value>");
    }
    if !addons.is_empty() {
        let _ = write!(command, " --addon {}", addons.join(","));
    }
    command
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::markdown::{Effort, Status};

    fn worktree(place: Place) -> Worktree {
        Worktree {
            name: "p1-one".to_owned(),
            path: PathBuf::from("/tmp/ferrox-p1-one"),
            place,
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn library() -> Library {
        Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
prove it or do not say it
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 4
**Effort:** small
**Gates:** `cargo test --workspace`

```text
run with {len=40} and {scope}
```

**Add-on — Local first:** author here

## P2 · Two

**When to use:** second
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test`
**Depends on:** P1
**Touches:** README.md

```text
with {target=core}
```

**Add-on — Miri limits:** name the limits
**Add-on — Isa matrix:** one runner per ISA
",
        )
    }

    #[test]
    fn the_sections_come_out_in_the_documented_order() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let addons = resolve_addons(prompt, &["local-first".to_owned()]).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &addons,
            Some(&worktree(Place::Absent)),
            Options {
                provenance: true,
                ..Options::default()
            },
        );
        let protocol = rendered.text.find("prove it or do not say it").unwrap();
        let body = rendered.text.find("run with 40").unwrap();
        let addon = rendered.text.find("**Add-on — Local first:**").unwrap();
        let worktree = rendered.text.find("## Worktree").unwrap();
        let gates = rendered.text.find("## Acceptance").unwrap();
        let footer = rendered.text.find("<!-- ferrox-prompt").unwrap();
        assert!(protocol < body, "protocol before body");
        assert!(body < addon, "body before add-ons");
        assert!(addon < worktree, "add-ons before the worktree");
        assert!(worktree < gates, "worktree before acceptance");
        assert!(gates < footer, "acceptance before the footer");
    }

    #[test]
    fn an_absent_worktree_is_created_with_the_script_it_names() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&worktree(Place::Absent)),
            Options::default(),
        );
        assert!(
            rendered.text.contains("./scripts/new-worktree.sh p1-one"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("/tmp/ferrox-p1-one"),
            "{}",
            rendered.text
        );
        assert!(
            rendered
                .text
                .contains("never a hand-made `git worktree add`"),
            "the script is named as the only way one is made"
        );
    }

    #[test]
    fn an_existing_worktree_is_used_and_put_onto_main() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        for place in [Place::Linked, Place::Current] {
            let rendered = render(
                &library,
                prompt,
                &values(&[]),
                &[],
                Some(&worktree(place)),
                Options::default(),
            );
            assert!(
                rendered.text.contains("git rebase origin/main"),
                "{place:?} renders without the update"
            );
            assert!(
                rendered.text.contains("p1-one"),
                "{place:?} renders without naming the worktree"
            );
            assert!(
                !rendered.text.contains("./scripts/new-worktree.sh p1-one"),
                "{place:?} tells the reader to make one that exists"
            );
        }
    }

    #[test]
    fn a_directory_in_the_way_is_named_rather_than_worked_around() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            Some(&worktree(Place::Occupied)),
            Options::default(),
        );
        assert!(
            rendered.text.contains("is not a worktree"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("/tmp/ferrox-p1-one"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn a_render_without_a_worktree_says_nothing_about_one() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options::default(),
        );
        assert!(!rendered.text.contains("## Worktree"), "{}", rendered.text);
    }

    #[test]
    fn the_default_output_is_the_request_and_nothing_that_frames_it() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options::default(),
        );
        assert!(!rendered.text.contains("# P1 · One"), "{}", rendered.text);
        assert!(!rendered.text.contains("library tag "));
    }

    #[test]
    fn a_supplied_value_beats_the_default() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[("len", "200")]),
            &[],
            None,
            Options::default(),
        );
        assert!(rendered.text.contains("run with 200"));
        assert!(!rendered.text.contains("run with 40"));
        assert_eq!(rendered.missing, vec!["scope"]);
    }

    #[test]
    fn a_missing_input_is_reported_not_guessed() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options::default(),
        );
        assert_eq!(rendered.missing, vec!["scope"]);
        assert!(
            rendered.text.contains("{scope}"),
            "the placeholder stays visible"
        );
        assert!(
            !rendered.text.contains("Inputs required"),
            "unless asked for"
        );
    }

    #[test]
    fn an_unfilled_prompt_states_the_gap_before_everything() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let options = Options {
            allow_unfilled: true,
            ..Options::default()
        };
        let rendered = render(&library, prompt, &values(&[]), &[], None, options);
        let gap = rendered.text.find("## Inputs required").unwrap();
        let protocol = rendered.text.find("prove it or do not say it").unwrap();
        assert!(gap < protocol, "the gap is the first thing read");
        assert!(rendered
            .text
            .contains("ferrox-prompt render P1 --set scope=<value> --set len=<value>"));
    }

    #[test]
    fn braces_can_be_escaped() {
        let values = values(&[("a", "1")]);
        assert_eq!(substitute("{{a}} and {a}", &values), "{a} and 1");
        assert_eq!(substitute("a { b", &values), "a { b");
        assert_eq!(substitute("{} {a b}", &values), "{} {a b}");
        // Unfilled stays as written; a supplied value wins over an empty default.
        assert_eq!(substitute("{b=}", &values), "{b=}");
        assert_eq!(substitute("{a=}", &values), "1");
    }

    #[test]
    fn addons_resolve_exactly_then_by_unique_substring() {
        let library = library();
        let prompt = library.prompt(2).unwrap();
        assert_eq!(prompt.addon("isa-matrix").unwrap().slug, "isa-matrix");
        assert_eq!(resolve_addons(prompt, &["miri".into()]).unwrap().len(), 1);
        assert_eq!(resolve_addons(prompt, &["all".into()]).unwrap().len(), 2);
        assert_eq!(
            resolve_addons(prompt, &["miri,isa".into()]).unwrap().len(),
            2
        );
        let missing = resolve_addons(prompt, &["nope".into()]).unwrap_err();
        assert!(missing.contains("isa-matrix"), "{missing}");
        assert!(missing.contains("no add-on matching `nope`"), "{missing}");
    }

    #[test]
    fn an_ambiguous_addon_is_an_error_rather_than_a_guess() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`

```text
body
```

**Add-on — Isa matrix:** one
**Add-on — Isa baseline:** two
",
        );
        let prompt = library.prompt(1).unwrap();
        let error = resolve_addons(prompt, &["isa".into()]).unwrap_err();
        assert!(
            error.contains("isa-matrix") && error.contains("isa-baseline"),
            "{error}"
        );
    }

    #[test]
    fn the_header_states_the_graph_position() {
        let library = library();
        let prompt = library.prompt(2).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options {
                provenance: true,
                ..Options::default()
            },
        );
        assert!(rendered.text.contains("# P2 · Two"), "{}", rendered.text);
        assert!(rendered.text.contains("depends on P1"));
        assert!(rendered
            .text
            .contains("status todo · leverage 4 · effort large"));
    }

    #[test]
    fn the_footer_names_the_tag_and_says_it_is_not_a_checksum() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options {
                provenance: true,
                ..Options::default()
            },
        );
        assert!(rendered.text.contains("library tag "));
        assert!(rendered.text.contains("not a checksum"));
        let quiet = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options::default(),
        );
        assert!(!quiet.text.contains("ferrox-prompt ·"));
    }

    #[test]
    fn gates_can_be_left_out() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let rendered = render(
            &library,
            prompt,
            &values(&[]),
            &[],
            None,
            Options {
                gates: false,
                ..Options::default()
            },
        );
        assert!(!rendered.text.contains("## Acceptance"));
        assert!(rendered.text.contains("run with 40"));
    }

    #[test]
    fn a_prompt_with_no_addons_says_so() {
        let library = Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`

```text
body
```
",
        );
        let prompt = library.prompt(1).unwrap();
        assert_eq!(prompt.status, Status::Todo);
        assert_eq!(prompt.effort, Effort::Small);
        let error = resolve_addons(prompt, &["any".into()]).unwrap_err();
        assert!(error.contains("has none"), "{error}");
    }
}
