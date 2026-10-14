//! `ferrox-prompt` — the command line: exit 1 is a library not telling the truth, exit 2 a mistake at the keyboard.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ferrox_prompt::advisor::{self, Ledger, Readiness};
use ferrox_prompt::check;
use ferrox_prompt::expand::{self, ProjectState};
use ferrox_prompt::json::Value;
use ferrox_prompt::markdown::{
    Addon, Diagnostic, Effort, Library, Prompt, Severity, Status, Targets, Touch,
};
use ferrox_prompt::render::{self, Options, Rendered};
use ferrox_prompt::worktree::Worktree;
use ferrox_prompt::{clipboard, load_library, workspace_root};

const USAGE: &str = "\
ferrox-prompt — render the slice to work on next, from a Markdown library

USAGE
    ferrox-prompt <command> [options]

COMMANDS
    check                  read the library and report everything wrong with it
    list                   roadmap progress: templates, matrix rows left, what is next
    next                   the slice to work on, its blanks filled from the matrix
    render <id>            that slice's prompt, with add-ons and gates
    show <id>              that slice's metadata, then its full prompt
    set-status <id> <status>  record progress: todo, doing, done or blocked

OPTIONS
    --library <path>       read this Markdown instead of prompts.md
    --set KEY=VALUE        fill a placeholder; repeatable, wins over a default
    --addon <slug|all>     append an add-on; repeatable or comma-separated
    --print                print instead of copying to the clipboard
    --json                 machine-readable output (list, next, render, show)
    --status <status>      list only these: todo, doing, done, blocked
    --effort <effort>      restrict to small, medium or large
    --id <id>              ask for a specific slice from `next`
    --rotate               draw at random among ready slices, weighted by the library
    --seed <n>             make that draw reproducible
    --memory <n>           how many recent slices to keep out of the draw (default 3)
    --no-ledger            do not record the handout in .ferrox/slices.log
    --allow-unfilled       render even when a required input has no value
    --strict               `check` treats warnings as errors
    --version, --help

EXAMPLES
    ferrox-prompt next
    ferrox-prompt next --rotate --seed 4
    ferrox-prompt render 5 --addon isa-matrix
    ferrox-prompt set-status 5 doing
    ferrox-prompt list --status todo
    ferrox-prompt check --library /tmp/draft-prompts.md

A prompt with a required input is never rendered with a hole in it: the tool
prints the command that would fill it instead. Every handout is recorded in
.ferrox/slices.log so the next few calls do not offer the same slice twice.
Every handout also names the worktree the slice runs in and what to do about it:
created with `scripts/new-worktree.sh` when there is none, used and brought onto
`main` when that script has made one for this task already.
";

/// What to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// The gate `ci.yml` runs.
    Check,
    /// The roadmap.
    List,
    /// The advisor.
    Next,
    /// One prompt.
    Render,
    /// One prompt's metadata.
    Show,
    /// Record a prompt's status: the only field progress edits.
    SetStatus,
    /// Usage.
    Help,
    /// Version.
    Version,
}

/// Where the answer goes; one setting, not two booleans, because `--print --json` is one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    /// The clipboard, the default: the next thing to happen to a prompt is a paste.
    Copy,
    /// Standard output.
    Print,
    /// Standard output, as JSON.
    Json,
}

impl Output {
    /// Whether the text goes to standard output rather than the clipboard.
    fn is_stdout(self) -> bool {
        matches!(self, Self::Print | Self::Json)
    }
}

/// How `next` chooses, when it is not asked for a slice by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Draw {
    /// The highest leverage, then the smaller slice.
    Ranked,
    /// At random among ready slices, weighted by the library.
    Rotate,
}

/// Everything the command line said.
#[derive(Debug)]
struct Args {
    command: Command,
    /// A prompt id, for `render` and `show`.
    id: Option<u32>,
    library: Option<PathBuf>,
    output: Output,
    draw: Draw,
    /// Whether a handout is recorded in the ledger.
    record: bool,
    /// Whether a prompt with unfilled inputs may be rendered anyway.
    allow_unfilled: bool,
    /// Whether `check` counts warnings as errors.
    strict: bool,
    status: Option<Status>,
    effort: Option<Effort>,
    /// `--id <id>` on `next`: a deliberate choice instead of a ranked one.
    forced: Option<u32>,
    /// The value `set-status` writes.
    set_to: Option<Status>,
    seed: u64,
    memory: usize,
    values: BTreeMap<String, String>,
    addons: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            command: Command::Help,
            id: None,
            library: None,
            output: Output::Copy,
            draw: Draw::Ranked,
            record: true,
            allow_unfilled: false,
            strict: false,
            status: None,
            effort: None,
            forced: None,
            set_to: None,
            seed: 1,
            memory: 3,
            values: BTreeMap::new(),
            addons: Vec::new(),
        }
    }
}

fn main() -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&arguments) {
        Ok(args) => args,
        Err(message) => {
            // Print the parse error alone; the whole usage block on every typo would bury it.
            eprintln!("{message}");
            eprintln!("run `ferrox-prompt --help` for the commands");
            return ExitCode::from(2);
        }
    };
    match args.command {
        Command::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("ferrox-prompt {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Check => run_check(&args, &cwd),
        command => {
            let library = match load_library(args.library.as_deref(), &cwd) {
                Ok(library) => library,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            // Parse errors block every verb: a malformed section renders a prompt that looks complete.
            if library.has_errors() {
                eprintln!(
                    "{}: {} error(s) must be fixed first",
                    library.path.display(),
                    library.errors().count()
                );
                for finding in library.errors() {
                    eprintln!("  {}: {finding}", library.path.display());
                }
                return ExitCode::from(1);
            }
            for finding in library
                .diagnostics
                .iter()
                .filter(|finding| finding.severity == Severity::Warning)
            {
                eprintln!("warning: {}: {finding}", library.path.display());
            }
            let root = workspace_root(&cwd);
            match command {
                Command::List => run_list(&args, &library, &root),
                Command::Next => run_next(&args, &library, &root),
                Command::Render => run_render(&args, &library, &root),
                Command::Show => run_show(&args, &library, &root),
                Command::SetStatus => run_set_status(&args, &library),
                Command::Check | Command::Help | Command::Version => ExitCode::SUCCESS,
            }
        }
    }
}

/// Read the command line, written out rather than a crate: this crate's zero dependencies are a decision.
fn parse(arguments: &[String]) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut positional: Vec<String> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].clone();
        index += 1;
        // Both `--flag=value` and `--flag value` parse; the long way is not a reason to be unhelpful.
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) if flag.starts_with('-') => {
                (flag.to_owned(), Some(value.to_owned()))
            }
            _ => (argument.clone(), None),
        };
        let borrowed = inline.as_deref();
        let text = |at: &mut usize| take_value(arguments, at, borrowed, &flag);
        match flag.as_str() {
            verb @ ("check" | "list" | "ls" | "next" | "render" | "show" | "set-status") => {
                parsed.command = verb_of(verb);
            }
            "help" | "-h" | "--help" => parsed.command = Command::Help,
            "version" | "-V" | "--version" => parsed.command = Command::Version,
            "--library" | "-L" => parsed.library = Some(PathBuf::from(text(&mut index)?)),
            "--prompt" | "-p" => {
                if parsed.id.is_some() {
                    return Err("prompt id given twice".to_owned());
                }
                parsed.id = Some(parse_id(&text(&mut index)?)?);
            }
            "--id" => parsed.forced = Some(parse_id(&text(&mut index)?)?),
            "--set" => assign(&mut parsed.values, &text(&mut index)?)?,
            "--addon" => parsed.addons.push(text(&mut index)?),
            "--print" => parsed.output = Output::Print,
            // JSON wins over `--print` rather than fighting it: both mean stdout.
            "--json" => parsed.output = Output::Json,
            "--rotate" => parsed.draw = Draw::Rotate,
            "--no-ledger" => parsed.record = false,
            "--allow-unfilled" => parsed.allow_unfilled = true,
            "--strict" => parsed.strict = true,
            "--seed" => {
                parsed.seed = text(&mut index)?
                    .parse()
                    .map_err(|_| "--seed needs a whole number".to_owned())?;
            }
            "--memory" => {
                parsed.memory = text(&mut index)?
                    .parse()
                    .map_err(|_| "--memory needs a whole number".to_owned())?;
            }
            "--status" => {
                let status = text(&mut index)?;
                parsed.status = Some(Status::parse(&status).ok_or_else(|| {
                    format!("`{status}` is not a status: {}", Status::NAMES.join(", "))
                })?);
            }
            "--effort" => {
                let effort = text(&mut index)?;
                parsed.effort = Some(Effort::parse(&effort).ok_or_else(|| {
                    format!("`{effort}` is not an effort: {}", Effort::NAMES.join(", "))
                })?);
            }
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            _ => positional.push(argument),
        }
    }
    if parsed.command == Command::SetStatus {
        parse_set_status(&mut parsed, &positional)?;
        return Ok(parsed);
    }
    if let Some(id) = positional.pop() {
        if parsed.id.is_some() {
            return Err(format!("prompt id given twice: {id}"));
        }
        if !matches!(parsed.command, Command::Render | Command::Show) {
            return Err(format!(
                "`{id}` is not a command this tool has; try `list`, `next`, `render <id>`, `show <id>` \
                 or `check`"
            ));
        }
        parsed.id = Some(parse_id(&id)?);
    }
    if !positional.is_empty() {
        return Err(format!("unexpected arguments: {}", positional.join(", ")));
    }
    if matches!(parsed.command, Command::Render | Command::Show) && parsed.id.is_none() {
        let name = if parsed.command == Command::Render {
            "render"
        } else {
            "show"
        };
        return Err(format!(
            "{name} needs a prompt id, as in `ferrox-prompt {name} 2`"
        ));
    }
    Ok(parsed)
}

/// `set-status <id> <status>`, positional in that order; split out of `parse` for the line-count lint.
fn parse_set_status(parsed: &mut Args, positional: &[String]) -> Result<(), String> {
    if positional.len() != 2 {
        return Err(
            "`set-status` needs a prompt id and a status, as in `ferrox-prompt set-status 5 doing`"
                .to_owned(),
        );
    }
    parsed.id = Some(parse_id(&positional[0])?);
    parsed.set_to = Some(Status::parse(&positional[1]).ok_or_else(|| {
        format!(
            "`{}` is not a status: {}",
            positional[1],
            Status::NAMES.join(", ")
        )
    })?);
    Ok(())
}

/// The command a verb names, spelled out so a non-verb flag is a compile error, not a quiet no-op.
fn verb_of(word: &str) -> Command {
    match word {
        "check" => Command::Check,
        "list" | "ls" => Command::List,
        "next" => Command::Next,
        "render" => Command::Render,
        "show" => Command::Show,
        "set-status" => Command::SetStatus,
        _ => Command::Help,
    }
}

/// One `--set KEY=VALUE`: only the first `=` separates, so a value may contain `=`.
fn assign(values: &mut BTreeMap<String, String>, assignment: &str) -> Result<(), String> {
    let Some((name, value)) = assignment.split_once('=') else {
        return Err(format!("`{assignment}` is not KEY=VALUE"));
    };
    if name.trim().is_empty() {
        return Err(format!("`{assignment}` has no key"));
    }
    values.insert(name.trim().to_owned(), value.to_owned());
    Ok(())
}

/// The value for a flag: what followed `=`, or the next argument.
fn take_value(
    arguments: &[String],
    index: &mut usize,
    inline: Option<&str>,
    flag: &str,
) -> Result<String, String> {
    if let Some(value) = inline {
        return Ok(value.to_owned());
    }
    let value = arguments
        .get(*index)
        .ok_or_else(|| format!("{flag} needs a value"))?
        .clone();
    *index += 1;
    Ok(value)
}

/// `2`, `P2`, `p2` — all the same id.
fn parse_id(text: &str) -> Result<u32, String> {
    text.trim()
        .trim_start_matches(['P', 'p'])
        .parse()
        .map_err(|_| format!("`{text}` is not a prompt id; write it as P<n>"))
}

/// `check`, and the CI step that runs it.
fn run_check(args: &Args, cwd: &Path) -> ExitCode {
    let library = match load_library(args.library.as_deref(), cwd) {
        Ok(library) => library,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let root = workspace_root(cwd);
    // A library outside this repo has nothing local to check **Touches:** against; the canonicalised path decides.
    let inside = match args.library.as_deref() {
        None => true,
        Some(given) => {
            let given = std::fs::canonicalize(given).unwrap_or_else(|_| given.to_path_buf());
            let canonical_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
            given.starts_with(canonical_root)
        }
    };
    let findings = check::run(&library, &root, inside);
    let (errors, warnings): (Vec<&Diagnostic>, Vec<&Diagnostic>) = findings
        .iter()
        .partition(|finding| finding.severity == Severity::Error);
    for finding in &errors {
        println!(
            "{}:{}: {} [error]",
            library.path.display(),
            finding.line,
            finding.message
        );
    }
    for finding in &warnings {
        println!(
            "{}:{}: {} [warning]",
            library.path.display(),
            finding.line,
            finding.message
        );
    }
    println!(
        "{}: {} prompt(s), {} error(s), {} warning(s)",
        library.path.display(),
        library.prompts.len(),
        errors.len(),
        warnings.len()
    );
    let strict_failures = args.strict && !warnings.is_empty();
    if strict_failures {
        println!("--strict: warnings count as errors");
    }
    if errors.is_empty() && !strict_failures {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `list`: totals, served count and the status summary; per-prompt lines only when `--status`/`--effort` narrowed.
fn run_list(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let ledger = Ledger::load(Ledger::path_for(root));
    let selected: Vec<&Prompt> = library
        .prompts
        .iter()
        .filter(|prompt| args.status.is_none_or(|wanted| prompt.status == wanted))
        // `--effort` filters list and ranking alike: one flag must not mean two things.
        .filter(|prompt| args.effort.is_none_or(|wanted| prompt.effort == wanted))
        .collect();

    if args.output == Output::Json {
        println!(
            "{}",
            Value::object([
                ("library", Value::text(library.path.display().to_string())),
                ("tag", Value::text(library.tag())),
                ("ready", ready_json(library, args.effort)),
                (
                    "prompts",
                    Value::List(
                        selected
                            .iter()
                            .map(|prompt| prompt_json(prompt, &ledger))
                            .collect()
                    )
                ),
            ])
            .to_pretty()
        );
        return ExitCode::SUCCESS;
    }

    let state = ProjectState::load(root);
    if state.has_matrix() {
        println!(
            "matrix: {} open · {} implemented · {} rows served here",
            state.candidates(Targets::Open).len(),
            state.candidates(Targets::Implemented).len(),
            ledger
                .entries
                .iter()
                .filter(|entry| entry.target.is_some())
                .count(),
        );
    }
    if args.status.is_some() || args.effort.is_some() {
        for prompt in &selected {
            println!(
                "P{} · {:<7} · lev {} · {:<6} · {}",
                prompt.id,
                prompt.status.as_str(),
                prompt.leverage,
                prompt.effort.as_str(),
                prompt.title,
            );
        }
    }
    summarise(library, args.effort);
    ExitCode::SUCCESS
}

/// The state-filled placeholder values a template renders with.
type Values = BTreeMap<String, String>;

/// A slice the advisor may hand over: the prompt plus, for a matrix template, the row key and its values.
type Offer<'p> = (&'p Prompt, Option<(String, Values)>);

/// A matrix template stays offered only while its class has an unserved row, so `next` moves on when it empties.
fn build_offers<'p>(
    handable: &[&'p Prompt],
    state: &ProjectState,
    ledger: &Ledger,
) -> Vec<Offer<'p>> {
    handable
        .iter()
        .filter_map(|prompt| {
            if prompt.targets.is_matrix() {
                target_for(prompt, state, ledger).map(|pair| (*prompt, Some(pair)))
            } else {
                Some((*prompt, None))
            }
        })
        .collect()
}

/// Top-ranked offer, or a weighted draw under `--rotate`; the clone frees the borrow from the slice.
fn choose_offer<'p>(offers: &[Offer<'p>], rotate: bool, seed: u64) -> Offer<'p> {
    if !rotate {
        let (prompt, target) = &offers[0];
        return (*prompt, target.clone());
    }
    let refs: Vec<&Prompt> = offers.iter().map(|(prompt, _)| *prompt).collect();
    // A draw fails only when every weight is zero, which prompts.md forbids; the fallback is belt-and-braces.
    match advisor::rotate_among(&refs, seed) {
        Ok(prompt) => {
            let (candidate, target) = offers
                .iter()
                .find(|(p, _)| p.id == prompt.id)
                .expect("a rotated prompt is one of the offers");
            (*candidate, target.clone())
        }
        Err(_) => (offers[0].0, offers[0].1.clone()),
    }
}

/// Fold `--set` over the state-filled row; `{references}` falls back to the core pins even for a `none` class.
fn merge_values(
    requested: &Values,
    target: Option<&(String, Values)>,
    state: &ProjectState,
) -> Values {
    let mut values = requested.clone();
    if let Some((_, fill)) = target {
        for (name, value) in fill {
            values.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    if !values.contains_key("references") {
        let references = state.references();
        if !references.is_empty() {
            values.insert("references".to_owned(), references);
        }
    }
    values
}

/// The worktree this slice runs in: named from the matrix row it draws, or from its title when it draws none, so one task keeps one worktree.
fn slice_worktree(prompt: &Prompt, values: &Values, root: &Path) -> Worktree {
    let label = values
        .get("method")
        .map_or_else(|| prompt.title.as_str(), String::as_str);
    Worktree::plan(prompt.id, label, root)
}

/// The `--json` shape for a `next` handout, so an agent drives the loop without parsing prose.
fn next_json(
    library: &Library,
    prompt: &Prompt,
    args: &Args,
    suppressed: &[u32],
    target_key: Option<&String>,
    ledger: &Ledger,
    rendered: &render::Rendered,
) -> String {
    Value::object([
        ("library", Value::text(library.path.display().to_string())),
        ("tag", Value::text(library.tag())),
        (
            "selection",
            selection_json(library, prompt, args, suppressed, &[]),
        ),
        (
            "target",
            target_key.map_or(Value::Null, |key| Value::text(key.to_owned())),
        ),
        ("slice", prompt_json(prompt, ledger)),
        ("worktree", worktree_json(rendered.worktree.as_ref())),
        ("prompt", Value::text(rendered.text.clone())),
    ])
    .to_pretty()
}

/// The worktree a handout names, so an agent creates it or reuses it without parsing prose.
fn worktree_json(worktree: Option<&Worktree>) -> Value {
    let Some(worktree) = worktree else {
        return Value::Null;
    };
    Value::object([
        ("name", Value::text(worktree.name.clone())),
        ("path", Value::text(worktree.path.display().to_string())),
        ("state", Value::text(worktree.state())),
    ])
}

/// `next`: fills a matrix template from its first unserved row, so repeat runs walk the matrix; `--set` still wins.
fn run_next(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let ledger = Ledger::load(Ledger::path_for(root));
    let suppressed = ledger.recent_ids(args.memory);
    let state = ProjectState::load(root);

    // Matrix-filled names are not holes: FILLABLE counts as supplied when the matrix was readable.
    let mut supplied = args.values.clone();
    if state.has_matrix() {
        for name in expand::FILLABLE {
            supplied.entry((*name).to_owned()).or_default();
        }
    }

    // Resolve the (template, row) pair: `forced` names one on purpose, else walk the handable set for a live target.
    let offer: Option<Offer> = if let Some(id) = args.forced {
        let Some(prompt) = library.prompt(id) else {
            eprintln!("{}", unknown_prompt(library, id));
            return ExitCode::from(2);
        };
        Some((prompt, target_for(prompt, &state, &ledger)))
    } else {
        let (handable, skipped) = advisor::handable(
            library,
            args.effort,
            &suppressed,
            &supplied,
            args.allow_unfilled,
        );
        let offers = build_offers(&handable, &state, &ledger);
        if offers.is_empty() {
            eprintln!(
                "{}",
                nothing_to_hand_over(library, args.effort, &suppressed, &skipped)
            );
            return ExitCode::from(1);
        }
        let chosen = choose_offer(&offers, args.draw == Draw::Rotate, args.seed);
        Some(chosen)
    };
    let Some((prompt, target)) = offer else {
        // Unreachable — both branches return early; the let-else only satisfies the borrow checker.
        return ExitCode::from(1);
    };

    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    // `--set` wins over the state-filled value, so an explicit row beats the first unserved candidate.
    let values = merge_values(&args.values, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, &values, root);
    let options = Options {
        allow_unfilled: args.allow_unfilled,
        ..Options::default()
    };
    let rendered = render::render(library, prompt, &values, &addons, Some(&worktree), options);

    let target_key = target.as_ref().map(|(key, _)| key.clone());
    if args.output == Output::Json {
        let json = next_json(
            library,
            prompt,
            args,
            &suppressed,
            target_key.as_ref(),
            &ledger,
            &rendered,
        );
        // A `--json` handout is recorded too, so a JSON-driven agent still walks the matrix.
        record(
            ledger,
            prompt.id,
            &how_asked(args),
            target_key.as_deref(),
            args.record,
        );
        println!("{json}");
        return ExitCode::SUCCESS;
    }

    report_next(library, prompt, &ledger, &suppressed, &[], args, &addons);
    if let Some((key, _)) = &target {
        if let Some(row) = state.methods.iter().find(|row| row.key() == *key) {
            println!(
                "targeting row {key} — {} (state: {})",
                row.method, row.state
            );
        }
    }
    if let Some(worktree) = &rendered.worktree {
        println!("worktree    {}", worktree.brief());
    }
    deliver(&rendered, library, prompt.id, args.output.is_stdout());
    record(
        ledger,
        prompt.id,
        &how_asked(args),
        target_key.as_deref(),
        args.record,
    );
    ExitCode::SUCCESS
}

/// The first matrix row this template may draw that `served` has not, or `None` when its class is exhausted.
fn target_for(
    prompt: &Prompt,
    state: &ProjectState,
    ledger: &Ledger,
) -> Option<(String, BTreeMap<String, String>)> {
    if !expand::is_fillable(prompt, state) {
        return None;
    }
    expand::next_target(prompt, state, &ledger.targets_for(prompt.id))
}

/// `render <id>`: a matrix template filled from its first unserved row, like `next`, not a page of holes.
fn run_render(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let id = args.id.expect("parse requires an id for render");
    let Some(prompt) = library.prompt(id) else {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    };
    let ledger = Ledger::load(Ledger::path_for(root));
    let state = ProjectState::load(root);
    let target = target_for(prompt, &state, &ledger);
    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    let values = merge_values(&args.values, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, &values, root);
    let options = Options {
        allow_unfilled: args.allow_unfilled,
        ..Options::default()
    };
    let rendered = render::render(library, prompt, &values, &addons, Some(&worktree), options);
    if !rendered.missing.is_empty() && !args.allow_unfilled {
        eprintln!(
            "P{id} needs a value for {}",
            rendered
                .missing
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        eprintln!(
            "{}",
            render::suggested_command(prompt, &rendered.missing, &args.addons)
        );
        return ExitCode::from(2);
    }
    let target_key = target.as_ref().map(|(key, _)| key.clone());
    if args.output == Output::Json {
        let json = Value::object([
            ("tag", Value::text(library.tag())),
            (
                "target",
                target_key
                    .as_deref()
                    .map_or(Value::Null, |key| Value::text(key.to_owned())),
            ),
            ("slice", prompt_json(prompt, &ledger)),
            ("worktree", worktree_json(rendered.worktree.as_ref())),
            ("prompt", Value::text(rendered.text.clone())),
        ])
        .to_pretty();
        // Recorded like a `next` handout, so a by-id JSON render still advances the template's served rows.
        record(
            ledger,
            prompt.id,
            &how_asked(args),
            target_key.as_deref(),
            args.record,
        );
        println!("{json}");
        return ExitCode::SUCCESS;
    }
    deliver(&rendered, library, prompt.id, args.output.is_stdout());
    record(
        ledger,
        prompt.id,
        &how_asked(args),
        target_key.as_deref(),
        args.record,
    );
    ExitCode::SUCCESS
}

/// `show <id>`: metadata, then the same rendered prompt `render <id>` delivers, so one command reads a slice.
fn run_show(args: &Args, library: &Library, root: &Path) -> ExitCode {
    let id = args.id.expect("parse requires an id for show");
    let Some(prompt) = library.prompt(id) else {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    };
    let ledger = Ledger::load(Ledger::path_for(root));
    let state = ProjectState::load(root);
    let target = target_for(prompt, &state, &ledger);
    let addons = match render::resolve_addons(prompt, &args.addons) {
        Ok(addons) => addons,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    let values = merge_values(&args.values, target.as_ref(), &state);
    let worktree = slice_worktree(prompt, &values, root);
    let rendered = render::render(
        library,
        prompt,
        &values,
        &addons,
        Some(&worktree),
        Options {
            allow_unfilled: true,
            ..Options::default()
        },
    );
    let target_key = target.as_ref().map(|(key, _)| key.clone());
    if args.output == Output::Json {
        println!(
            "{}",
            Value::object([
                ("tag", Value::text(library.tag())),
                ("slice", prompt_json(prompt, &ledger)),
                ("selection", selection_json(library, prompt, args, &[], &[])),
                (
                    "target",
                    target_key
                        .as_deref()
                        .map_or(Value::Null, |key| Value::text(key.to_owned())),
                ),
                ("prompt", Value::text(rendered.text.clone())),
            ])
            .to_pretty()
        );
        return ExitCode::SUCCESS;
    }
    println!("P{} · {}", prompt.id, prompt.title);
    println!("  status        {}", prompt.status.as_str());
    println!("  readiness     {}", describe_readiness(library, prompt));
    println!("  leverage      {}", prompt.leverage);
    println!("  effort        {}", prompt.effort.as_str());
    println!("  when to use   {}", prompt.when_to_use);
    println!(
        "  depends on    {}",
        join_or(prompt.depends_on.iter().map(|id| {
            let state = library
                .prompt(*id)
                .map_or("missing", |found| found.status.as_str());
            format!("P{id} ({state})")
        }))
    );
    println!(
        "  opens         {}",
        join_or(prompt.blocks(library).map(|other| format!("P{}", other.id)))
    );
    if !prompt.touches.is_empty() {
        println!("  touches       {}", describe_touches(prompt, root));
    }
    let overlaps = overlaps(library, prompt);
    if !overlaps.is_empty() {
        println!("  overlaps      {}", overlaps.join(", "));
    }
    println!("  random weight {}", prompt.random_weight);
    println!("  last drawn    {}", describe_history(&ledger, prompt.id));
    println!("  gates         {}", prompt.gates.join("; "));
    println!(
        "  add-ons       {}",
        join_or(prompt.addons.iter().map(|addon| addon.slug.clone()))
    );
    if let Some(key) = &target_key {
        if let Some(row) = state.methods.iter().find(|row| row.key() == *key) {
            println!(
                "  targeting     {key} — {} (state: {})",
                row.method, row.state
            );
        }
    }
    if let Some(worktree) = &rendered.worktree {
        println!("  worktree      {} — {}", worktree.name, worktree.brief());
    }
    println!();
    println!("--- prompt ---");
    println!();
    println!("{}", rendered.text);
    ExitCode::SUCCESS
}

/// Record progress by rewriting exactly the prompt's `**Status:**` line: reflowing Markdown would fight the contributor's edits.
fn run_set_status(args: &Args, library: &Library) -> ExitCode {
    let id = args.id.expect("parse requires an id for set-status");
    let to = args.set_to.expect("parse requires a status for set-status");
    let Some(prompt) = library.prompt(id) else {
        eprintln!("{}", unknown_prompt(library, id));
        return ExitCode::from(2);
    };
    if prompt.status == to {
        println!("P{id} is already {}", to.as_str());
        return ExitCode::SUCCESS;
    }
    match set_status_text(&library.source, id, to) {
        Ok(updated) => {
            if let Err(error) = std::fs::write(&library.path, updated) {
                eprintln!("could not write {}: {error}", library.path.display());
                return ExitCode::from(1);
            }
            if args.output == Output::Json {
                println!(
                    "{}",
                    Value::object([
                        ("id", Value::text(id.to_string())),
                        ("from", Value::text(prompt.status.as_str())),
                        ("to", Value::text(to.as_str())),
                    ])
                    .to_pretty()
                );
            } else {
                println!("P{id}: {} -> {}", prompt.status.as_str(), to.as_str());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

/// Byte-identical everywhere else; fenced blocks are skipped, so a body quoting `**Status:**` is prose, not the field.
fn set_status_text(source: &str, id: u32, status: Status) -> Result<String, String> {
    let mut out = Vec::new();
    let mut current: Option<u32> = None;
    let mut in_block = false;
    let mut replaced = false;
    for line in source.lines() {
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
        } else if !in_block {
            if let Some(body) = line.strip_prefix("## ") {
                current = section_id(body.trim_end());
            } else if current == Some(id)
                && !replaced
                && line.trim_start().starts_with("**Status:**")
            {
                out.push(format!("**Status:** {}", status.as_str()));
                replaced = true;
                continue;
            }
        }
        out.push(line.to_owned());
    }
    if !replaced {
        return Err(format!("P{id} has no **Status:** line to rewrite"));
    }
    let mut text = out.join("\n");
    if source.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

/// `(id)` from a `P<n> · <title>` heading; the separator is permissive, same as the parser.
fn section_id(heading: &str) -> Option<u32> {
    let rest = heading
        .strip_prefix('P')
        .or_else(|| heading.strip_prefix('p'))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Why this slice was or was not offered.
fn describe_readiness(library: &Library, prompt: &Prompt) -> String {
    match advisor::readiness(library, prompt) {
        Readiness::Ready => "ready".to_owned(),
        Readiness::Deferred => "deferred — started or held by a person".to_owned(),
        Readiness::Finished => "done".to_owned(),
        Readiness::WaitingOn(ids) => format!(
            "waiting on {}",
            join_or(ids.iter().map(|id| format!("P{id}")))
        ),
    }
}

fn join_or(values: impl Iterator<Item = String>) -> String {
    let joined: Vec<String> = values.collect();
    if joined.is_empty() {
        "nothing".to_owned()
    } else {
        joined.join(", ")
    }
}

/// When the slice was last handed out, or that it never was.
fn describe_history(ledger: &Ledger, id: u32) -> String {
    match ledger.history(id) {
        Some((at, times)) => format!("{at} ({times} time(s))"),
        None => "never".to_owned(),
    }
}

/// Three empty-ready causes with three fixes — ledger withholding, unfilled inputs, nothing open — reported separately, and two can hold at once.
fn nothing_to_hand_over(
    library: &Library,
    effort: Option<Effort>,
    suppressed: &[u32],
    skipped: &[advisor::Skipped],
) -> String {
    let withheld: Vec<u32> = advisor::ranked(library, effort)
        .iter()
        .map(|&index| library.prompts[index].id)
        .filter(|id| suppressed.contains(id))
        .collect();
    let mut message = String::from("nothing to hand over:");
    if !withheld.is_empty() {
        let _ = writeln!(
            message,
            "\n  withheld by the ledger: {} — the last {} handed out; --rotate draws differently \
             and --memory 0 forgets",
            join_or(withheld.iter().map(|id| format!("P{id}"))),
            withheld.len()
        );
    }
    if !skipped.is_empty() {
        message.push_str("\n  waiting on a decision this tool will not make:");
        for slice in skipped {
            let missing = slice.missing.clone();
            let prompt = library
                .prompt(slice.id)
                .expect("a skipped id is a prompt id");
            let _ = writeln!(
                message,
                "\n    P{} needs {} — {}",
                slice.id,
                join_or(missing.iter().map(|name| format!("`{name}`"))),
                render::suggested_command(prompt, &missing, &[])
            );
        }
    }
    if withheld.is_empty() && skipped.is_empty() {
        return advisor::next_index(library, effort, &[]).unwrap_err();
    }
    message
}

/// The reasoning, printed above the prompt so it is read before it is obeyed.
fn report_next(
    library: &Library,
    prompt: &Prompt,
    ledger: &Ledger,
    suppressed: &[u32],
    skipped: &[advisor::Skipped],
    args: &Args,
    addons: &[Addon],
) {
    let ready = advisor::ranked(library, args.effort);
    let place = ready
        .iter()
        .position(|&index| library.prompts[index].id == prompt.id);
    println!("NEXT SLICE  P{} · {}", prompt.id, prompt.title);
    println!(
        "WHY NOW     leverage {}, effort {} — {}",
        prompt.leverage,
        prompt.effort.as_str(),
        match place {
            Some(0) => format!("first of {} ready, by leverage then by effort", ready.len()),
            Some(at) => format!("{} of {} ready", at + 1, ready.len()),
            None => "asked for by id, so the ranking does not apply".to_owned(),
        }
    );
    println!(
        "OPENS       {}",
        join_or(prompt.blocks(library).map(|other| format!("P{}", other.id)))
    );
    println!(
        "WAITING ON  {}",
        join_or(
            prompt
                .depends_on
                .iter()
                .filter(|id| {
                    library
                        .prompt(**id)
                        .is_some_and(|dependency| dependency.status != Status::Done)
                })
                .map(|id| format!("P{id}"))
        )
    );
    let overlaps = overlaps(library, prompt);
    if !overlaps.is_empty() {
        println!("OVERLAPS    {}", overlaps.join(", "));
    }
    if args.draw == Draw::Rotate {
        println!(
            "DRAW        --rotate with seed {} — random among ready slices, weighted by the library",
            args.seed
        );
    }
    println!(
        "SUPPRESSED  {}",
        if suppressed.is_empty() {
            "nothing; the ledger is empty or --memory is 0".to_owned()
        } else {
            suppressed
                .iter()
                .map(|id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if !skipped.is_empty() {
        println!(
            "LEFT OUT    {} — ready, but waiting on a decision: {}",
            skipped
                .iter()
                .map(|slice| format!("P{}", slice.id))
                .collect::<Vec<_>>()
                .join(", "),
            skipped
                .iter()
                .flat_map(|slice| {
                    slice
                        .missing
                        .iter()
                        .map(|name| format!("{name} for P{}", slice.id))
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("LAST DRAWN  {}", describe_history(ledger, prompt.id));
    println!(
        "ADD-ONS     {}",
        join_or(addons.iter().map(|addon| addon.slug.clone()))
    );
    println!("ACCEPTANCE  {}", prompt.gates.join("  ·  "));
    println!();
    println!("---");
    println!();
}

/// Counts, and what is waiting on what.
fn summarise(library: &Library, effort: Option<Effort>) {
    let ready = advisor::ranked(library, effort);
    let mut counts = [0usize; 4];
    for prompt in &library.prompts {
        counts[match prompt.status {
            Status::Todo => 0,
            Status::Doing => 1,
            Status::Blocked => 2,
            Status::Done => 3,
        }] += 1;
    }
    let zero_weight = library
        .prompts
        .iter()
        .filter(|prompt| prompt.is_open() && prompt.random_weight == 0)
        .count();
    println!();
    println!(
        "todo {} · doing {} · blocked {} · done {} · ready {}{}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        ready.len(),
        if zero_weight == 0 {
            String::new()
        } else {
            format!(" · {zero_weight} kept out of rotation by weight 0")
        }
    );
    let waiting: Vec<String> = library
        .prompts
        .iter()
        .filter_map(|prompt| match advisor::readiness(library, prompt) {
            Readiness::WaitingOn(ids) => Some(format!(
                "P{} on {}",
                prompt.id,
                ids.iter()
                    .map(|id| format!("P{id}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ => None,
        })
        .collect();
    if !waiting.is_empty() {
        println!("waiting     {}", waiting.join(" · "));
    }
    let ready_ids: Vec<String> = ready
        .iter()
        .map(|&index| format!("P{}", library.prompts[index].id))
        .collect();
    if !ready_ids.is_empty() {
        println!("ready       {} in this order", ready_ids.join(" → "));
    }
}

/// Hand the text over: the clipboard, or the terminal when asked or unable to.
fn deliver(rendered: &Rendered, library: &Library, id: u32, print: bool) {
    if print {
        println!("{}", rendered.text);
        return;
    }
    match clipboard::copy(&rendered.text) {
        Ok(()) => {
            let note = if rendered.missing.is_empty() {
                String::new()
            } else {
                format!(" with {} input(s) unfilled", rendered.missing.len())
            };
            let chars = rendered.text.chars().count();
            println!(
                "P{id} copied ({chars} chars{note}) from {}",
                library.path.display()
            );
        }
        Err(reason) => {
            eprintln!("clipboard unavailable ({reason}); printing instead:");
            println!("{}", rendered.text);
        }
    }
}

/// Record the handout; an unwritable ledger is a warning, not a failure — the prompt was handed over.
fn record(mut ledger: Ledger, id: u32, how: &str, target: Option<&str>, enabled: bool) {
    if !enabled {
        return;
    }
    if let Err(error) = ledger.record(id, how, target) {
        eprintln!(
            "warning: could not write {}: {error}",
            ledger.path.display()
        );
    }
}

/// How this handout was asked for, for the ledger.
fn how_asked(args: &Args) -> String {
    match args.command {
        Command::Next if args.draw == Draw::Rotate => "next --rotate".to_owned(),
        Command::Next => "next".to_owned(),
        Command::Render => "render".to_owned(),
        _ => "show".to_owned(),
    }
}

/// Files another prompt the advisor could pick right now claims — same availability rule as `check`, so the line means "both in play".
fn overlaps(library: &Library, prompt: &Prompt) -> Vec<String> {
    check::contention(library, prompt)
        .iter()
        .map(|clash| {
            let others: Vec<String> = clash.also.iter().map(|id| format!("P{id}")).collect();
            format!("{} (also {})", clash.path, others.join(", "))
        })
        .collect()
}

/// Paths, marked with whether they are there.
fn describe_touches(prompt: &Prompt, root: &Path) -> String {
    prompt
        .touches
        .iter()
        .map(|touch| {
            let present = root.join(touch.path()).exists();
            match touch {
                Touch::Existing(_) => format!(
                    "{}{}",
                    touch.path(),
                    if present { "" } else { " (missing)" }
                ),
                Touch::Created(_) => format!(
                    "+{}{}",
                    touch.path(),
                    if present { " (already there)" } else { "" }
                ),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The choices, for when there is no choice to make.
fn unknown_prompt(library: &Library, id: u32) -> String {
    let available: Vec<String> = library
        .prompts
        .iter()
        .map(|prompt| format!("P{}", prompt.id))
        .collect();
    format!(
        "no P{id} in {}; it has {}",
        library.path.display(),
        available.join(", ")
    )
}

/// Ready ids, for `--json`.
fn ready_json(library: &Library, effort: Option<Effort>) -> Value {
    Value::List(
        advisor::ranked(library, effort)
            .iter()
            .map(|&index| Value::Number(i64::from(library.prompts[index].id)))
            .collect(),
    )
}

/// Everything about one prompt that another tool might want.
fn prompt_json(prompt: &Prompt, ledger: &Ledger) -> Value {
    Value::object([
        ("id", Value::Number(i64::from(prompt.id))),
        ("title", Value::text(prompt.title.clone())),
        ("status", Value::text(prompt.status.as_str())),
        ("leverage", Value::Number(i64::from(prompt.leverage))),
        ("effort", Value::text(prompt.effort.as_str())),
        ("when_to_use", Value::text(prompt.when_to_use.clone())),
        (
            "gates",
            Value::List(
                prompt
                    .gates
                    .iter()
                    .map(|gate| Value::text(gate.clone()))
                    .collect(),
            ),
        ),
        (
            "depends_on",
            Value::List(
                prompt
                    .depends_on
                    .iter()
                    .map(|&id| Value::Number(i64::from(id)))
                    .collect(),
            ),
        ),
        (
            "touches",
            Value::List(
                prompt
                    .touches
                    .iter()
                    .map(|touch| Value::text(touch.path()))
                    .collect(),
            ),
        ),
        (
            "random_weight",
            Value::Number(i64::from(prompt.random_weight)),
        ),
        (
            "placeholders",
            Value::List(
                prompt
                    .placeholders
                    .iter()
                    .map(|placeholder| {
                        Value::object([
                            ("name", Value::text(placeholder.name.clone())),
                            (
                                "default",
                                match &placeholder.default {
                                    Some(default) => Value::text(default.clone()),
                                    None => Value::Null,
                                },
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "addons",
            Value::List(
                prompt
                    .addons
                    .iter()
                    .map(|addon| {
                        Value::object([
                            ("slug", Value::text(addon.slug.clone())),
                            ("title", Value::text(addon.title.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "last_drawn",
            match ledger.history(prompt.id) {
                Some((at, _)) => Value::text(at),
                None => Value::Null,
            },
        ),
    ])
}

/// Why this slice was chosen, for `--json`.
fn selection_json(
    library: &Library,
    prompt: &Prompt,
    args: &Args,
    suppressed: &[u32],
    skipped: &[advisor::Skipped],
) -> Value {
    let ready = advisor::ranked(library, args.effort);
    let rank = ready
        .iter()
        .position(|&index| library.prompts[index].id == prompt.id)
        .map_or(0, |at| at + 1);
    let count = |value: usize| Value::Number(i64::try_from(value).unwrap_or(i64::MAX));
    Value::object([
        (
            "reason",
            Value::text(match (args.forced, args.draw) {
                (Some(id), _) if id == prompt.id => "asked for by id",
                _ if args.draw == Draw::Rotate => {
                    "rotated among ready slices, weighted by the library"
                }
                _ => "highest leverage, then the smaller slice",
            }),
        ),
        ("rank", count(rank)),
        ("ready_count", count(ready.len())),
        (
            "seed",
            if args.draw == Draw::Rotate {
                Value::Number(i64::try_from(args.seed).unwrap_or(i64::MAX))
            } else {
                Value::Null
            },
        ),
        (
            "suppressed",
            Value::List(
                suppressed
                    .iter()
                    .map(|&id| Value::Number(i64::from(id)))
                    .collect(),
            ),
        ),
        (
            "left_out",
            Value::List(
                skipped
                    .iter()
                    .map(|slice| {
                        Value::object([
                            ("id", Value::Number(i64::from(slice.id))),
                            (
                                "missing",
                                Value::List(
                                    slice
                                        .missing
                                        .iter()
                                        .map(|name| Value::text(name.clone()))
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "opens",
            Value::List(
                prompt
                    .blocks(library)
                    .map(|other| Value::Number(i64::from(other.id)))
                    .collect(),
            ),
        ),
        (
            "readiness",
            Value::text(match advisor::readiness(library, prompt) {
                Readiness::Ready => "ready",
                Readiness::Deferred => "deferred",
                Readiness::Finished => "done",
                Readiness::WaitingOn(_) => "waiting",
            }),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(arguments: &[&str]) -> Args {
        let owned: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect();
        parse(&owned).unwrap_or_else(|error| panic!("`{arguments:?}` should parse: {error}"))
    }

    #[test]
    fn a_bare_invocation_asks_for_help() {
        assert_eq!(parse_args(&[]).command, Command::Help);
    }

    #[test]
    fn verbs_and_ids_parse_in_both_spellings() {
        assert_eq!(parse_args(&["next"]).command, Command::Next);
        assert_eq!(parse_args(&["render", "P2"]).id, Some(2));
        assert_eq!(parse_args(&["render", "7"]).id, Some(7));
        assert_eq!(parse_args(&["render", "--prompt", "p9"]).id, Some(9));
        assert_eq!(parse_args(&["show", "3"]).command, Command::Show);
        assert_eq!(parse_args(&["ls"]).command, Command::List);
    }

    #[test]
    fn equals_and_space_forms_are_the_same() {
        let spaced = parse_args(&["render", "P2", "--set", "len=40", "--seed", "7"]);
        let equals = parse_args(&["render", "P2", "--set", "len=40", "--seed=7"]);
        assert_eq!(spaced.values, equals.values);
        assert_eq!(spaced.seed, equals.seed);
    }

    #[test]
    fn every_id_in_the_usage_examples_is_parseable() {
        // Only EXAMPLES lines start with the tool name *and* a verb; the description line is prose.
        let examples: Vec<Vec<String>> = USAGE
            .lines()
            .filter(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some("ferrox-prompt")
                    && words.next().is_some_and(|word| {
                        ["check", "list", "next", "render", "show", "set-status"].contains(&word)
                    })
            })
            .map(|line| line.split_whitespace().skip(1).map(str::to_owned).collect())
            .collect();
        assert!(!examples.is_empty(), "the usage block should have examples");
        for example in &examples {
            assert!(
                parse(example).is_ok(),
                "the usage example `{example:?}` does not parse"
            );
        }
    }

    #[test]
    fn bad_input_is_rejected_with_a_reason() {
        let owned =
            |words: &[&str]| -> Vec<String> { words.iter().map(|w| (*w).to_owned()).collect() };
        assert!(parse(&owned(&["render", "two"])).is_err());
        assert!(parse(&owned(&["render"])).is_err());
        assert!(parse(&owned(&["nope"])).is_err());
        assert!(parse(&owned(&["next", "--set", "nope"])).is_err());
        assert!(parse(&owned(&["list", "--status", "finished"])).is_err());
        assert!(parse(&owned(&["list", "--effort", "enormous"])).is_err());
        assert!(parse(&owned(&["next", "--seed", "soon"])).is_err());
        assert!(parse(&owned(&["next", "--rotate", "extra"])).is_err());
        assert!(parse(&owned(&["render", "2", "3"])).is_err());
        assert!(parse(&owned(&["render", "2", "--prompt", "3"])).is_err());
        assert!(parse(&owned(&["list", "--memory"])).is_err());
    }

    #[test]
    fn repeatables_accumulate_and_the_last_set_wins() {
        let args = parse_args(&[
            "render", "P2", "--set", "a=1", "--set", "b=2", "--addon", "x,y", "--addon", "z",
            "--set", "a=3",
        ]);
        assert_eq!(args.values["a"], "3");
        assert_eq!(args.values["b"], "2");
        assert_eq!(args.addons, vec!["x,y", "z"]);
    }

    #[test]
    fn a_set_value_may_contain_equals() {
        let args = parse_args(&["render", "P2", "--set", "cmd=cargo test --all-features"]);
        assert_eq!(args.values["cmd"], "cargo test --all-features");
    }

    #[test]
    fn set_wins_over_a_default_because_the_map_is_read_first() {
        let mut values = BTreeMap::new();
        values.insert("len".to_owned(), "40".to_owned());
        values.insert("len".to_owned(), "200".to_owned());
        assert_eq!(render::substitute("{len=40}", &values), "200");
    }

    #[test]
    fn the_handout_is_recorded_as_it_was_asked_for() {
        assert_eq!(how_asked(&parse_args(&["next"])), "next");
        assert_eq!(
            how_asked(&parse_args(&["next", "--rotate"])),
            "next --rotate"
        );
        assert_eq!(how_asked(&parse_args(&["render", "2"])), "render");
    }

    #[test]
    fn set_status_needs_an_id_and_a_status() {
        let args = parse_args(&["set-status", "P5", "doing"]);
        assert_eq!(args.command, Command::SetStatus);
        assert_eq!(args.id, Some(5));
        assert_eq!(args.set_to, Some(Status::Doing));
        assert!(parse(&["set-status".to_owned()]).is_err());
        assert!(parse(&["set-status".to_owned(), "5".to_owned()]).is_err());
        assert!(parse(&["set-status".to_owned(), "5".to_owned(), "x".to_owned()]).is_err());
    }

    #[test]
    fn set_status_rewrites_one_line_and_nothing_else() {
        let source = "## Shared protocol\n\n```text\n**Status:** not a field here\n```\n\n## P2 · Second\n\n**Status:** todo\n**Leverage:** 5\n";
        let updated = set_status_text(source, 2, Status::Done).expect("the field is there");
        assert_eq!(
            updated,
            "## Shared protocol\n\n```text\n**Status:** not a field here\n```\n\n## P2 · Second\n\n**Status:** done\n**Leverage:** 5\n"
        );
        assert!(set_status_text(source, 9, Status::Done).is_err());
    }
}
