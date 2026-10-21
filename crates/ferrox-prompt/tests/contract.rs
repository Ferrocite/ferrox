//! Contract locks on the live `prompts.md`, read off disk — never `include_str!` — so a breaking edit fails in the same commit that made it.

use std::collections::BTreeMap;
use std::path::Path;

use ferrox_prompt::advisor::{self, Ledger};
use ferrox_prompt::check;
use ferrox_prompt::expand::{self, ProjectState};
use ferrox_prompt::markdown::{Severity, Status, Targets};
use ferrox_prompt::render::{self, Options};
use ferrox_prompt::{load_library, manifest_root};

fn library() -> ferrox_prompt::Library {
    load_library(None, Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("prompts.md sits next to this crate")
}

#[test]
fn the_live_library_parses_without_a_single_error() {
    let library = library();
    assert!(
        !library.has_errors(),
        "prompts.md has errors:\n{:#?}",
        library.errors().collect::<Vec<_>>()
    );
    assert!(
        library.prompts.len() > 1,
        "a roadmap of one prompt is not a roadmap"
    );
}

#[test]
fn the_live_library_passes_its_own_gate() {
    let library = library();
    let findings = check::run(&library, &manifest_root(), true);
    let errors: Vec<String> = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .map(|finding| format!("line {}: {}", finding.line, finding.message))
        .collect();
    assert!(
        errors.is_empty(),
        "prompts.md fails its own check:\n{}",
        errors.join("\n")
    );
}

#[test]
fn the_library_is_numbered_without_gaps() {
    // Ids are how `**Depends on:**` refers to a prompt, so a gap means one was deleted without asking the graph.
    let library = library();
    let ids: Vec<u32> = library.prompts.iter().map(|prompt| prompt.id).collect();
    assert_eq!(
        ids,
        (1..=ids.len() as u32).collect::<Vec<_>>(),
        "prompt ids should be 1..=n with no gaps; got {ids:?}"
    );
}

#[test]
fn every_prompt_says_when_to_use_it_and_names_a_gate() {
    for prompt in &library().prompts {
        assert!(
            prompt.when_to_use.len() > 20,
            "P{} ({}) has no usable **When to use:** — a prompt nobody can place is a prompt \\
             nobody starts",
            prompt.id,
            prompt.title
        );
        assert!(
            !prompt.gates.is_empty(),
            "P{} ({}) has no gates, so nothing can tell whether it is finished",
            prompt.id,
            prompt.title
        );
        assert!(
            prompt.body.len() > 80,
            "P{} ({}) has almost no body; the section may have lost its fenced block",
            prompt.id,
            prompt.title
        );
        assert!(
            (1..=5).contains(&prompt.leverage),
            "P{} has leverage {}",
            prompt.id,
            prompt.leverage
        );
    }
}

#[test]
fn every_prompt_renders_end_to_end_and_renders_the_same_twice() {
    let library = library();
    for prompt in &library.prompts {
        // Required inputs get a plausible value, what the tool asks the person for; defaults cover the rest.
        let values: BTreeMap<String, String> = prompt
            .required_inputs()
            .map(|name| (name.to_owned(), "supplied-by-the-test".to_owned()))
            .collect();
        let rendered = render::render(&library, prompt, &values, &[], None, Options::default());
        let again = render::render(&library, prompt, &values, &[], None, Options::default());

        assert!(
            rendered.missing.is_empty(),
            "P{} is missing {:?}",
            prompt.id,
            rendered.missing
        );
        assert_eq!(
            rendered.text, again.text,
            "P{} renders differently each time",
            prompt.id
        );
        assert!(
            rendered.text.contains(&library.shared_protocol),
            "P{} does not carry the shared protocol",
            prompt.id
        );
        // The header is opt-in, so slice identity is checked where it is printed, not in the default handover.
        let headed = render::render(
            &library,
            prompt,
            &values,
            &[],
            None,
            Options {
                provenance: true,
                ..Options::default()
            },
        );
        assert!(
            headed
                .text
                .contains(&format!("# P{} · {}", prompt.id, prompt.title)),
            "P{} does not name itself in the header",
            prompt.id
        );
        for gate in &prompt.gates {
            assert!(
                rendered.text.contains(gate.as_str()),
                "P{} dropped the gate {gate}",
                prompt.id
            );
        }
        for placeholder in &prompt.placeholders {
            let leftover = format!("{{{}}}", placeholder.name);
            assert!(
                !rendered.text.contains(&leftover),
                "P{} rendered with {leftover} still in it",
                prompt.id
            );
        }
    }
}

#[test]
fn every_add_on_resolves_and_renders() {
    let library = library();
    let mut seen_any = false;
    for prompt in &library.prompts {
        let mut slugs: Vec<&str> = Vec::new();
        for addon in &prompt.addons {
            seen_any = true;
            assert!(
                !addon.slug.is_empty(),
                "P{} has an add-on with no typeable name",
                prompt.id
            );
            assert!(
                !slugs.contains(&addon.slug.as_str()),
                "P{} has two add-ons called {}",
                prompt.id,
                addon.slug
            );
            slugs.push(&addon.slug);

            let resolved = render::resolve_addons(prompt, std::slice::from_ref(&addon.slug))
                .unwrap_or_else(|error| panic!("P{}: {error}", prompt.id));
            assert_eq!(resolved.len(), 1);
            let rendered = render::render(
                &library,
                prompt,
                &BTreeMap::new(),
                &resolved,
                None,
                Options::default(),
            );
            assert!(
                rendered.text.contains(&addon.body),
                "P{}: the add-on {addon_slug} rendered without its text",
                prompt.id,
                addon_slug = addon.slug
            );
        }
        // `all` means every add-on, and must not silently include none.
        let all =
            render::resolve_addons(prompt, &["all".to_owned()]).expect("`all` always resolves");
        assert_eq!(all.len(), prompt.addons.len(), "P{}", prompt.id);
    }
    assert!(
        seen_any,
        "the library has no add-ons, so none of this is exercised"
    );
}

#[test]
fn every_dependency_names_a_prompt_that_exists_and_done_waits_on_nothing_open() {
    let library = library();
    for prompt in &library.prompts {
        for dependency in &prompt.depends_on {
            assert!(
                library.prompt(*dependency).is_some(),
                "P{} waits on P{dependency}, which is not in the library",
                prompt.id
            );
            assert_ne!(
                *dependency, prompt.id,
                "P{} waits on itself, so it can never become ready",
                prompt.id
            );
        }
        if !prompt.status.is_open() {
            for dependency in &prompt.depends_on {
                let target = library
                    .prompt(*dependency)
                    .expect("a dependency that exists, checked above");
                assert!(
                    !target.status.is_open(),
                    "P{} is done but waits on P{dependency}, which is not done",
                    prompt.id
                );
            }
        }
    }
}

#[test]
fn the_advisor_always_has_a_justified_answer() {
    let library = library();
    let root = manifest_root();
    // A fresh, unwritten ledger, so the answer does not depend on this machine's history.
    let empty = Ledger::load(root.join(".ferrox/does-not-exist.log"));
    assert_eq!(empty.entries, []);

    let (handable, skipped) = advisor::handable(&library, None, &[], &BTreeMap::new(), false);
    let ranked = advisor::ranked(&library, None);
    assert_eq!(
        handable.len() + skipped.len(),
        ranked.len(),
        "every ready slice must be either handable or skipped for a named reason"
    );
    if handable.is_empty() {
        assert!(
            !ranked.is_empty()
                || library
                    .prompts
                    .iter()
                    .all(|prompt| prompt.status == Status::Done),
            "nothing to offer with nothing ready is only allowed when the roadmap is finished"
        );
        return;
    }

    let top = handable[0];
    let best_id = library.prompts[ranked[0]].id;
    let best = library
        .prompt(best_id)
        .expect("a ranked index is a prompt index");
    assert_eq!(
        top.leverage, best.leverage,
        "the top handable slice should not be lower leverage than the best ready one, unless the \\
         best one is waiting on a decision — which is {skipped:?}"
    );
    // Rank order is leverage then the smaller slice, so the comparison key is effort reversed.
    let key = |prompt: &ferrox_prompt::markdown::Prompt| {
        (prompt.leverage, std::cmp::Reverse(prompt.effort))
    };
    for later in &handable[1..] {
        assert!(
            key(later) <= key(top),
            "{} ranks below {} but was offered first",
            later.title,
            top.title
        );
    }
    // And the pick is reproducible.
    let (again, _) = advisor::handable(&library, None, &[], &BTreeMap::new(), false);
    assert_eq!(again[0].id, top.id);
}

#[test]
fn a_prompt_with_a_required_input_is_only_offered_when_it_is_filled() {
    let library = library();
    let (_, skipped) = advisor::handable(&library, None, &[], &BTreeMap::new(), false);
    for slice in &skipped {
        let prompt = library
            .prompt(slice.id)
            .expect("a skipped id is a prompt id");
        assert!(
            !slice.missing.is_empty(),
            "P{} was skipped for no stated reason",
            slice.id
        );
        for name in &slice.missing {
            assert!(
                prompt.required_inputs().any(|required| required == name),
                "P{} was skipped for {name}, which it does not actually require",
                prompt.id
            );
        }
        let supplied: BTreeMap<String, String> = slice
            .missing
            .iter()
            .map(|name| (name.clone(), "a-value".to_owned()))
            .collect();
        let rendered = render::render(&library, prompt, &supplied, &[], None, Options::default());
        assert!(rendered.missing.is_empty(), "P{}", prompt.id);
    }
}

#[test]
fn every_body_says_something_the_project_can_act_on() {
    // A sanity floor, not a content check: a prompt that dropped the standing contract lost rules even if its own text is fine.
    let library = library();
    for line in library.shared_protocol.lines() {
        assert!(
            line.ends_with(['.', ':', '`']) || line.is_empty(),
            "unexpected line in the shared protocol: {line}"
        );
    }
}

#[test]
fn a_row_is_picked_by_key_by_number_or_by_name_and_fills_the_template() {
    let library = library();
    let state = ProjectState::load(&manifest_root());
    assert!(state.has_matrix(), "the live matrix must be readable");

    // Every row is reachable by its own key, and the key is what the ledger and the JSON name it by.
    for row in &state.methods {
        let picked = expand::select_row(&state, &row.key())
            .unwrap_or_else(|reason| panic!("row {} is not reachable: {reason}", row.key()));
        assert_eq!(picked.key(), row.key());
        assert_eq!(picked.method, row.method);
    }

    // A whole method name names one row, and a part of one names what it can.
    let open = state
        .methods
        .iter()
        .find(|row| !row.implemented)
        .expect("the matrix has an open row");
    let by_name = expand::select_row(&state, &open.method)
        .unwrap_or_else(|reason| panic!("row {} is not reachable by name: {reason}", open.key()));
    assert_eq!(by_name.key(), open.key());

    // A template that draws the row's class renders it with every blank filled from that row.
    let template = library
        .prompts
        .iter()
        .find(|prompt| prompt.targets == Targets::Open)
        .expect("a template draws open rows");
    let values = expand::fill(template, open, &state.pins);
    let rendered = render::render(&library, template, &values, &[], None, Options::default());
    assert!(rendered.missing.is_empty(), "P{} left a hole", template.id);
    assert!(
        rendered.text.contains(&open.method),
        "P{} did not name the row's method",
        template.id
    );
    assert!(
        rendered.text.contains(&open.index.to_string()),
        "P{} did not name the row's number",
        template.id
    );
}

#[test]
fn every_matrix_template_draws_a_row_of_its_own_class() {
    let library = library();
    let state = ProjectState::load(&manifest_root());
    assert!(state.has_matrix());
    for prompt in &library.prompts {
        if !prompt.targets.is_matrix() {
            continue;
        }
        for row in &state.methods {
            assert_eq!(
                expand::row_fits(row, prompt.targets),
                match prompt.targets {
                    Targets::Open => !row.implemented,
                    Targets::Implemented => row.implemented,
                    _ => true,
                },
                "P{} and row {} disagree about the class",
                prompt.id,
                row.key()
            );
        }
        // And the template has a row to draw at all, from the live matrix.
        let candidates = state.candidates(prompt.targets);
        assert!(
            !candidates.is_empty(),
            "P{} draws a class the matrix has no row for",
            prompt.id
        );
    }
}
