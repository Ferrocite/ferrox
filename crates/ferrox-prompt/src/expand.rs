//! Fills a template from the first matrix row of its class the ledger has not served it, and only the `FILLABLE` names — never an invented value.

use std::collections::BTreeMap;
use std::path::Path;

use crate::markdown::{Prompt, Targets};
use crate::state::{self, MethodRow, Pin};

/// Public so `check` reports a typo'd matrix placeholder like `{methd}` instead of silently rendering the hole.
pub const FILLABLE: &[&str] = &[
    "method",
    "index",
    "section",
    "page",
    "state",
    "target",
    "references",
];

/// The state the advisor reads to fill templates: the matrix and the pins.
#[derive(Debug, Default, Clone)]
pub struct ProjectState {
    /// Every method row in `README.md`'s matrix, in document order.
    pub methods: Vec<MethodRow>,
    /// Every pin in `upstream/pins.toml`.
    pub pins: Vec<Pin>,
}

impl ProjectState {
    /// Read `README.md` and `upstream/pins.toml` from the workspace root.
    pub fn load(root: &Path) -> Self {
        Self {
            methods: state::read_methods(root),
            pins: state::read_pins(root),
        }
    }

    /// Whether the matrix was readable; an empty read means fall back to hand-supplied values, not offer a hole-filled prompt.
    pub fn has_matrix(&self) -> bool {
        !self.methods.is_empty()
    }

    /// Rows a class may draw; `open` stably sorts half-shipped (real page) rows first — finishing a wired half is the cheapest parity win.
    pub fn candidates(&self, targets: Targets) -> Vec<&MethodRow> {
        let mut rows: Vec<&MethodRow> = match targets {
            Targets::Open => self.methods.iter().filter(|row| !row.implemented).collect(),
            Targets::Implemented => self.methods.iter().filter(|row| row.implemented).collect(),
            Targets::All => self.methods.iter().collect(),
            Targets::None => Vec::new(),
        };
        if targets == Targets::Open {
            rows.sort_by_key(|row| !row.real_page);
        }
        rows
    }

    /// Pin names a template with no row compares against: the `always` set, the pins that ride every slice.
    pub fn references(&self) -> String {
        state::references_for(&self.pins, "")
    }
}

/// Values from one row plus pins, limited to the [`FILLABLE`] names the template actually declares.
pub fn fill(prompt: &Prompt, row: &MethodRow, pins: &[Pin]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for placeholder in &prompt.placeholders {
        let value = match placeholder.name.as_str() {
            "method" => row.method.clone(),
            "index" => row.index.to_string(),
            "section" => row.section.to_string(),
            "page" => row.page.clone(),
            "state" => row.state.clone(),
            "target" => row.key(),
            "references" => state::references_for(pins, &row.text),
            _ => continue,
        };
        values.insert(placeholder.name.clone(), value);
    }
    values
}

/// The first candidate row the ledger has not served to this template, with its values; `None` is the advisor's cue to offer the next template.
pub fn next_target<'a>(
    prompt: &Prompt,
    state: &'a ProjectState,
    served: &[String],
) -> Option<(&'a MethodRow, BTreeMap<String, String>)> {
    if prompt.targets == Targets::None {
        return None;
    }
    let row = state
        .candidates(prompt.targets)
        .into_iter()
        .find(|row| !served.contains(&row.key()))?;
    Some((row, fill(prompt, row, &state.pins)))
}

/// The rows a selector names: its key (`A13`), its index (`13`), or part of a method name.
pub fn matching_rows<'a>(state: &'a ProjectState, selector: &str) -> Vec<&'a MethodRow> {
    let text = selector.trim();
    if text.is_empty() {
        return Vec::new();
    }
    // A key first: `A13`.
    if let Some((section, index)) = key_parts(text) {
        let keyed: Vec<&MethodRow> = state
            .methods
            .iter()
            .filter(|row| row.section.eq_ignore_ascii_case(&section) && row.index == index)
            .collect();
        if !keyed.is_empty() {
            return keyed;
        }
    }
    // Then the number on its own: `13`.
    if let Ok(index) = text.parse::<u32>() {
        let numbered: Vec<&MethodRow> = state
            .methods
            .iter()
            .filter(|row| row.index == index)
            .collect();
        if !numbered.is_empty() {
            return numbered;
        }
    }
    // Then the method name, whole before part: `VLESS TCP none` is one row, not every row that starts with it.
    let lower = text.to_ascii_lowercase();
    let exact: Vec<&MethodRow> = state
        .methods
        .iter()
        .filter(|row| row.method.to_ascii_lowercase() == lower)
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    state
        .methods
        .iter()
        .filter(|row| row.method.to_ascii_lowercase().contains(&lower))
        .collect()
}

/// The one row a selector names, or why it names none or several.
pub fn select_row<'a>(state: &'a ProjectState, selector: &str) -> Result<&'a MethodRow, String> {
    let matches = matching_rows(state, selector);
    match matches.as_slice() {
        [only] => Ok(only),
        [] => Err(format!(
            "no matrix row matches `{}`; the matrix has {} rows — `ferrox-prompt rows` lists them",
            selector.trim(),
            state.methods.len()
        )),
        many => Err(format!(
            "`{}` matches {} rows: {}; name one by its key, as in `--row {}`",
            selector.trim(),
            many.len(),
            describe_rows(many),
            many[0].key()
        )),
    }
}

/// Whether a template drawing `targets` may draw this row: an open row is not work for a shipped-row template.
pub fn row_fits(row: &MethodRow, targets: Targets) -> bool {
    match targets {
        Targets::Open => !row.implemented,
        Targets::Implemented => row.implemented,
        Targets::All => true,
        Targets::None => false,
    }
}

/// `A13` — a table letter and a row number.
fn key_parts(text: &str) -> Option<(char, u32)> {
    let mut chars = text.chars();
    let section = chars.next()?.to_ascii_uppercase();
    if !section.is_ascii_alphabetic() {
        return None;
    }
    Some((section, chars.as_str().parse().ok()?))
}

/// The candidates on one line, so an ambiguous selector is answerable without a second command.
fn describe_rows(rows: &[&MethodRow]) -> String {
    const LIMIT: usize = 6;
    let named: Vec<String> = rows
        .iter()
        .take(LIMIT)
        .map(|row| format!("{} {}", row.key(), row.method))
        .collect();
    if rows.len() <= LIMIT {
        named.join(", ")
    } else {
        format!("{} (+{} more)", named.join(", "), rows.len() - LIMIT)
    }
}

/// Whether `prompt` fills from this state untold: it draws from the matrix and still has an unserved target.
pub fn is_fillable(prompt: &Prompt, state: &ProjectState) -> bool {
    prompt.targets != Targets::None && state.has_matrix()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;

    const LIBRARY: &str = "\
## Shared protocol

```text
p
```

## P1 · Close a method

**When to use:** an open row
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Targets:** open
**Gates:** `cargo test --workspace`

```text
implement {method} (row {index} of table {section}); compare against {references}
```

## P2 · Optimise a method

**When to use:** a shipped row
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Targets:** implemented
**Gates:** `cargo test --workspace`

```text
make {method} faster and leaner; page {page}
```

## P3 · Not matrix-driven

**When to use:** a pins chore
**Status:** todo
**Leverage:** 2
**Effort:** small
**Gates:** `cargo test --workspace`

```text
update the pins, nothing per-method here
```
";

    fn library() -> Library {
        Library::parse(Path::new("prompts.md"), LIBRARY)
    }

    fn state() -> ProjectState {
        ProjectState {
            methods: vec![
                MethodRow {
                    section: 'A',
                    index: 3,
                    method: "VLESS TCP none".to_owned(),
                    state: "implemented".to_owned(),
                    implemented: true,
                    page: "docs/function/vless.md".to_owned(),
                    real_page: true,
                    text: "| 3 | VLESS TCP none, private/loopback only | implemented |".to_owned(),
                },
                MethodRow {
                    section: 'A',
                    index: 13,
                    method: "VLESS over QUIC".to_owned(),
                    state: "client only".to_owned(),
                    implemented: false,
                    page: "docs/function/carrier-quic.md".to_owned(),
                    real_page: true,
                    text:
                        "| 13 | VLESS over QUIC | vless-quic | client only | quiche with ALPN h3 |"
                            .to_owned(),
                },
                MethodRow {
                    section: 'C',
                    index: 45,
                    method: "WireGuard".to_owned(),
                    state: "planned".to_owned(),
                    implemented: false,
                    page: "docs/function/wireguard.md".to_owned(),
                    real_page: false,
                    text: "| 45 | WireGuard (UDP) | planned | amneziawg-go, sing-box |".to_owned(),
                },
            ],
            pins: vec![
                Pin {
                    name: "xray-core".to_owned(),
                    repo: "r".to_owned(),
                    test_enabled: false,
                    always: true,
                    topics: Vec::new(),
                },
                Pin {
                    name: "sing-box".to_owned(),
                    repo: "r".to_owned(),
                    test_enabled: false,
                    always: true,
                    topics: Vec::new(),
                },
                Pin {
                    name: "quiche".to_owned(),
                    repo: "r".to_owned(),
                    test_enabled: false,
                    always: false,
                    topics: vec!["quic".to_owned(), "h3".to_owned()],
                },
                Pin {
                    name: "amneziawg-go".to_owned(),
                    repo: "r".to_owned(),
                    test_enabled: false,
                    always: false,
                    topics: vec!["wireguard".to_owned()],
                },
            ],
        }
    }

    #[test]
    fn an_open_template_fills_the_first_open_row() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let made = state();
        let (row, values) = next_target(prompt, &made, &[]).expect("an open row exists");
        assert_eq!(row.key(), "A13");
        assert_eq!(values["method"], "VLESS over QUIC");
        assert_eq!(values["section"], "A");
        assert_eq!(values["references"], "xray-core, sing-box, quiche");
    }

    #[test]
    fn references_follow_the_row_not_the_whole_pin_file() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let wg = state().methods[2].clone();
        let values = fill(prompt, &wg, &state().pins);
        // The WireGuard row names amneziawg-go, not quiche.
        assert_eq!(values["references"], "xray-core, sing-box, amneziawg-go");
        // A template with no row gets the core set.
        assert_eq!(state().references(), "xray-core, sing-box");
    }

    #[test]
    fn a_half_shipped_open_row_beats_an_earlier_greenfield_one() {
        // A greenfield row earlier in the matrix must not beat a half-shipped row: the missing half of a row already on the wire is the cheaper parity win.
        let mut made = state();
        made.methods.push(MethodRow {
            section: 'A',
            index: 2,
            method: "A greenfield row".to_owned(),
            state: "planned".to_owned(),
            implemented: false,
            page: "docs/function/a-greenfield-row.md".to_owned(),
            real_page: false,
            text: "| 2 | A greenfield row | planned |".to_owned(),
        });
        let open = made.candidates(Targets::Open);
        let keys: Vec<String> = open.iter().map(|row| row.key()).collect();
        assert_eq!(keys, ["A13", "C45", "A2"]);
    }

    #[test]
    fn a_served_target_advances_to_the_next_row_of_the_same_class() {
        let library = library();
        let prompt = library.prompt(1).unwrap();
        let made = state();
        let (row, _) = next_target(prompt, &made, &["A13".to_owned()]).expect("still open rows");
        assert_eq!(row.key(), "C45");
        // And once both open rows are served there is nothing left for this class.
        assert!(next_target(prompt, &made, &["A13".to_owned(), "C45".to_owned()]).is_none());
    }

    #[test]
    fn a_target_class_only_draws_its_own_rows() {
        let library = library();
        let optimise = library.prompt(2).unwrap();
        let made = state();
        let (row, _) = next_target(optimise, &made, &[]).expect("an implemented row exists");
        assert_eq!(row.key(), "A3");
    }

    #[test]
    fn a_none_template_draws_nothing_from_the_matrix() {
        let library = library();
        let pins = library.prompt(3).unwrap();
        assert!(next_target(pins, &state(), &[]).is_none());
        assert!(!is_fillable(pins, &state()));
    }

    #[test]
    fn fill_declares_only_names_the_body_uses() {
        let library = library();
        let prompt = library.prompt(2).unwrap();
        let row = &state().methods[0];
        let values = fill(prompt, row, &state().pins);
        assert!(values.contains_key("method"));
        assert!(values.contains_key("page"));
        // P2's body never names {index}, so it is not in the map.
        assert!(!values.contains_key("index"));
    }

    #[test]
    fn an_empty_matrix_makes_nothing_fillable() {
        let empty = ProjectState::default();
        let library = library();
        assert!(!is_fillable(library.prompt(1).unwrap(), &empty));
    }

    #[test]
    fn a_row_is_picked_by_key_by_index_or_by_name() {
        let state = state();
        assert_eq!(select_row(&state, "A13").unwrap().key(), "A13");
        // The letter is case-insensitive, and the index alone names the row too.
        assert_eq!(select_row(&state, "a13").unwrap().key(), "A13");
        assert_eq!(select_row(&state, "13").unwrap().key(), "A13");
        assert_eq!(select_row(&state, "45").unwrap().key(), "C45");
        // A name is matched on the method, whole or in part.
        assert_eq!(select_row(&state, "vless over quic").unwrap().key(), "A13");
        assert_eq!(select_row(&state, "wireguard").unwrap().key(), "C45");
    }

    #[test]
    fn a_selector_that_names_nothing_says_how_many_rows_there_are() {
        let error = select_row(&state(), "no-such-method").unwrap_err();
        assert!(error.contains("no matrix row matches"), "{error}");
        assert!(error.contains("3 rows"), "{error}");
        assert!(error.contains("rows"), "{error}");
    }

    #[test]
    fn a_whole_method_name_beats_a_row_that_starts_with_it() {
        let mut made = state();
        made.methods.push(MethodRow {
            section: 'B',
            index: 7,
            method: "VLESS over QUIC, second spelling".to_owned(),
            state: "planned".to_owned(),
            implemented: false,
            page: "docs/function/vless-over-quic.md".to_owned(),
            real_page: false,
            text: "| 7 | VLESS over QUIC, second spelling | planned |".to_owned(),
        });
        // The whole name is one row, even though the other row starts with it.
        assert_eq!(select_row(&made, "VLESS over QUIC").unwrap().key(), "A13");
        assert_eq!(select_row(&made, "vless over quic").unwrap().key(), "A13");
        // A part of a name matches what it can, and says so when it matches more than one.
        let error = select_row(&made, "over quic").unwrap_err();
        assert!(error.contains("matches 2 rows"), "{error}");
        assert!(error.contains("A13"), "{error}");
        assert!(error.contains("B7"), "{error}");
        // The key is the way out, so the message names one.
        assert!(error.contains("--row A13"), "{error}");
    }

    #[test]
    fn a_row_fits_only_the_class_that_wants_it() {
        let state = state();
        let open = select_row(&state, "A13").unwrap();
        let shipped = select_row(&state, "A3").unwrap();
        assert!(row_fits(open, Targets::Open));
        assert!(!row_fits(open, Targets::Implemented));
        assert!(row_fits(open, Targets::All));
        assert!(row_fits(shipped, Targets::Implemented));
        assert!(!row_fits(shipped, Targets::Open));
        // A fixed slice draws no row at all.
        assert!(!row_fits(open, Targets::None));
    }
}
