//! Reads README's matrix and `upstream/pins.toml` as project state: a row is open unless its state cell — and only it — asserts implemented.

use std::path::Path;

/// One row of the README connection-method matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRow {
    /// The table letter, `A` through `O`.
    pub section: char,
    /// The `#` cell, the row's stable number across the whole matrix.
    pub index: u32,
    /// The method name as written, minus Markdown emphasis and links.
    pub method: String,
    /// The state cell, the verdict text that decides open versus done.
    pub state: String,
    /// Whether the state cell marks the method implemented.
    pub implemented: bool,
    /// The doc page path if the row links one, else a suggested page for the slug.
    pub page: String,
    /// Whether `page` is the row's own link (live surface to finish) or only the slug's suggestion (greenfield).
    pub real_page: bool,
    /// The row's raw Markdown line, every column — the surface a reference's name or topic is matched against.
    pub text: String,
}

impl MethodRow {
    /// The ledger key: table letter plus row number, unique across the matrix.
    pub fn key(&self) -> String {
        format!("{}{}", self.section, self.index)
    }
}

/// One pinned reference in `upstream/pins.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The `[sources.<name>]` key.
    pub name: String,
    /// The repository URL.
    pub repo: String,
    /// Whether a suite from this pin runs against a Ferrox binary in CI.
    pub test_enabled: bool,
    /// A core reference: listed for every row, because comparing it is nearly always worth the read.
    pub always: bool,
    /// Lowercased keywords that make this pin relevant to a row mentioning them.
    pub topics: Vec<String>,
}

impl Pin {
    /// Whether this pin belongs in `{references}` for one row; `row` must already be lowercased.
    pub fn relevant_to(&self, row: &str) -> bool {
        self.always
            || row.contains(&self.name.to_ascii_lowercase())
            || self.topics.iter().any(|topic| row.contains(topic))
    }
}

/// A free function so a test asks the reader's question against a made-up cell, without fabricating a row.
pub fn is_implemented(state: &str) -> bool {
    let lower = state.to_ascii_lowercase();
    let negated = lower.contains("planned")
        || lower.contains("not carried")
        || lower.contains("not parsed")
        || lower.contains("not implemented")
        || lower.contains("refused");
    if lower.contains("implemented") && !negated {
        return true;
    }
    if lower.contains("in tree") && !negated {
        return true;
    }
    // `both roles` with no negation reads as shipped even without the word "implemented", as in two prose table-A rows.
    lower.contains("both roles") && !negated
}

/// Strip the Markdown a method name is wrapped in: links become their text, emphasis and ticks drop.
fn clean_cell(cell: &str) -> String {
    let mut out = String::with_capacity(cell.len());
    let mut chars = cell.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '[' => {
                // Collect up to `]`, then skip an optional `(...)` link target.
                let mut text = String::new();
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                    text.push(inner);
                }
                if chars.peek() == Some(&'(') {
                    for inner in chars.by_ref() {
                        if inner == ')' {
                            break;
                        }
                    }
                }
                out.push_str(&text);
            }
            '*' | '`' => {}
            other => out.push(other),
        }
    }
    out.trim().to_owned()
}

/// Split a Markdown table row into cells, dropping the empties the outer pipes create.
fn cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

/// Whether a header line names a column exactly `state` or `binary`.
fn state_column(header: &[String]) -> Option<usize> {
    header
        .iter()
        .position(|name| name.eq_ignore_ascii_case("state") || name.eq_ignore_ascii_case("binary"))
}

/// Lowercase hyphenated slug for a suggested page path; runs of non-alphanumerics collapse to one dash.
fn slugify_method(method: &str) -> String {
    let mut slug = String::with_capacity(method.len());
    let mut pending_dash = false;
    for character in method.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(character.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "method".to_owned()
    } else {
        slug
    }
}

/// Read the matrix; empty when README cannot be read, and only numeric rows under a `### <Letter>` heading count.
pub fn read_methods(root: &Path) -> Vec<MethodRow> {
    let Ok(text) = std::fs::read_to_string(root.join(crate::README_RELATIVE)) else {
        return Vec::new();
    };
    methods_from_text(&text)
}

/// The matrix reader split out of the file read, so it can be tested on a fixture.
pub fn methods_from_text(text: &str) -> Vec<MethodRow> {
    let mut rows = Vec::new();
    let mut section: Option<char> = None;
    // Recomputed per header so table A's `binary` and the rest's `state` are both honoured.
    let mut state_col = 2usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("### ") {
            // `### A — proxy protocols` — the letter is the first token.
            section = rest.trim().chars().next().filter(char::is_ascii_uppercase);
            continue;
        }
        if trimmed.starts_with("| # |") || trimmed.starts_with("|#|") {
            if let Some(col) = state_column(&cells(trimmed)) {
                state_col = col;
            }
            continue;
        }
        // A separator row (`| --- | --- |`) or any non-table line: nothing to do.
        let Some(letter) = section else { continue };
        if !trimmed.starts_with('|') || trimmed.contains("---") {
            continue;
        }
        let row = cells(trimmed);
        let Some(first) = row.first() else { continue };
        let Ok(index) = first.parse::<u32>() else {
            continue;
        };
        let Some(name) = row.get(1) else { continue };
        // A row shorter than its state column is malformed; skip rather than read a neighbouring cell as the verdict.
        if row.len() <= state_col {
            continue;
        }
        let state = clean_cell(&row[state_col]);
        let (page, real_page) = match row.get(4) {
            // Table A's `page` column links the real path; other tables suggest one from the slug.
            Some(cell) if state_col == 3 && cell.contains("docs/function/") => (
                cell.chars()
                    .skip_while(|c| *c != '(')
                    .skip(1)
                    .take_while(|c| *c != ')')
                    .collect::<String>(),
                true,
            ),
            _ => (
                format!("docs/function/{}.md", slugify_method(&clean_cell(name))),
                false,
            ),
        };
        let method = clean_cell(name);
        if method.is_empty() {
            continue;
        }
        rows.push(MethodRow {
            section: letter,
            index,
            method,
            implemented: is_implemented(&state),
            state,
            page,
            real_page,
            text: trimmed.to_owned(),
        });
    }
    rows
}

/// A deliberately small scan, not a TOML parser — this crate has no dependencies by design — bounded at the next `[sources.` header.
pub fn read_pins(root: &Path) -> Vec<Pin> {
    let Ok(text) = std::fs::read_to_string(root.join(crate::PINS_RELATIVE)) else {
        return Vec::new();
    };
    pins_from_text(&text)
}

/// The pin reader split out of the file read, so it can be tested on a fixture.
pub fn pins_from_text(text: &str) -> Vec<Pin> {
    let mut pins = Vec::new();
    let mut current: Option<Pin> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("[sources.") {
            if let Some(pin) = current.take() {
                pins.push(pin);
            }
            current = Some(Pin {
                name: name.trim_end_matches(']').to_owned(),
                repo: String::new(),
                test_enabled: false,
                always: false,
                topics: Vec::new(),
            });
            continue;
        }
        let Some(pin) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("repo") {
            if let Some(value) = value.trim_start().strip_prefix('=') {
                pin.repo = unquote(value.trim());
            }
        } else if let Some(value) = trimmed.strip_prefix("test_enabled") {
            if let Some(value) = value.trim_start().strip_prefix('=') {
                pin.test_enabled = value.trim() == "true";
            }
        } else if let Some(value) = trimmed.strip_prefix("always") {
            if let Some(value) = value.trim_start().strip_prefix('=') {
                pin.always = value.trim() == "true";
            }
        } else if let Some(value) = trimmed.strip_prefix("topics") {
            if let Some(value) = value.trim_start().strip_prefix('=') {
                pin.topics = unquote(value.trim())
                    .split(',')
                    .map(|topic| topic.trim().to_ascii_lowercase())
                    .filter(|topic| !topic.is_empty())
                    .collect();
            }
        }
    }
    if let Some(pin) = current.take() {
        pins.push(pin);
    }
    pins
}

/// A TOML scalar string or boolean, with its quotes removed.
fn unquote(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_owned()
}

/// Comma-separated pin names: the honest "best implementation of everything" list a prompt compares against.
pub fn reference_names(pins: &[Pin]) -> String {
    let names: Vec<&str> = pins.iter().map(|pin| pin.name.as_str()).collect();
    names.join(", ")
}

/// The pins one row should be compared against: the `always` set plus every pin the row's own text names or topics; all pins when a row matches nothing, so the blank is never empty.
pub fn references_for(pins: &[Pin], row: &str) -> String {
    let lower = row.to_ascii_lowercase();
    let matched: Vec<&str> = pins
        .iter()
        .filter(|pin| pin.relevant_to(&lower))
        .map(|pin| pin.name.as_str())
        .collect();
    if matched.is_empty() {
        return reference_names(pins);
    }
    matched.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATRIX: &str = "\
### A — proxy protocols

| # | method | link | binary | page | notes |
| --- | --- | --- | --- | --- | --- |
| 1 | VLESS TCP REALITY | `vless-x` | **server only** | [vless](docs/function/vless.md) | notes |
| 3 | VLESS TCP none | `vless-tcp-none` | implemented | [vless](docs/function/vless.md) | both roles |
| 16 | ed httpUpgrade | — | parsed, **not carried** | [x](docs/function/carrier-httpupgrade.md) | note |

### C — VPN

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 45 | WireGuard (UDP) | planned | Xray-core, sing-box |
| 76 | Foxy lane | in tree, proven | configer |
";

    fn find(rows: &[MethodRow], index: u32) -> MethodRow {
        rows.iter()
            .find(|row| row.index == index)
            .cloned()
            .unwrap_or_else(|| panic!("row {index} missing: {rows:?}"))
    }

    #[test]
    fn a_row_without_implemented_in_its_state_cell_is_open() {
        let rows = methods_from_text(MATRIX);
        // `server only` and `not carried` stay open despite prose beside them: the verdict lives in the state cell alone.
        assert!(!find(&rows, 1).implemented);
        assert!(!find(&rows, 16).implemented);
        assert!(!find(&rows, 45).implemented);
    }

    #[test]
    fn an_implemented_row_is_closed_and_both_roles_counts_as_shipped() {
        let rows = methods_from_text(MATRIX);
        assert!(find(&rows, 3).implemented);
        assert!(find(&rows, 76).implemented);
    }

    #[test]
    fn the_state_column_is_found_per_table() {
        let rows = methods_from_text(MATRIX);
        // Table A reads its verdict from `binary`; table C from `state`.
        assert_eq!(find(&rows, 1).section, 'A');
        assert_eq!(find(&rows, 1).state, "server only");
        assert_eq!(find(&rows, 45).section, 'C');
        assert_eq!(find(&rows, 45).state, "planned");
    }

    #[test]
    fn method_names_are_cleaned_and_pages_derived() {
        let rows = methods_from_text(MATRIX);
        assert_eq!(find(&rows, 1).method, "VLESS TCP REALITY");
        // Table A's page column is the real path; table C suggests one.
        assert_eq!(find(&rows, 1).page, "docs/function/vless.md");
        assert_eq!(find(&rows, 45).page, "docs/function/wireguard-udp.md");
    }

    #[test]
    fn the_live_matrix_reads_and_has_open_rows() {
        let rows = methods_from_text(include_str!("../../../README.md"));
        assert!(rows.len() > 80, "the matrix should have ~130 rows");
        // Some rows done, some not: a reader finding only one class has mis-parsed a column.
        assert!(rows.iter().any(|row| row.implemented));
        assert!(rows.iter().any(|row| !row.implemented));
        // G and H are prose lists with no `| # |` matrix, so they contribute no rows by design.
        for letter in [
            'A', 'B', 'C', 'D', 'E', 'F', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        ] {
            assert!(
                rows.iter().any(|row| row.section == letter),
                "section {letter} not read"
            );
        }
        assert!(!rows
            .iter()
            .any(|row| row.section == 'G' || row.section == 'H'));
    }

    #[test]
    fn pins_are_read_by_name_repo_and_enablement() {
        let pins = pins_from_text(
            "[sources.xray-core]\nrepo = \"https://github.com/X/Y\"\nrev = \"abc\"\ntest_enabled  = false\nalways        = true\n\n[sources.zeronet]\nrepo = \"https://github.com/zeghostwriter/ZeroNet\"\ntest_enabled  = true\n",
        );
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0].name, "xray-core");
        assert!(!pins[0].test_enabled);
        assert!(pins[0].always);
        assert_eq!(pins[1].repo, "https://github.com/zeghostwriter/ZeroNet");
        assert!(pins[1].test_enabled);
        assert_eq!(reference_names(&pins), "xray-core, zeronet");
    }

    #[test]
    fn a_references_list_draws_the_core_set_plus_what_the_row_names() {
        let pins = pins_from_text(
            "[sources.sing-box]\nalways        = true\n\n[sources.quiche]\ntopics        = \"quic, h3, masque\"\n\n[sources.zeptun]\ntopics        = \"tun2socks\"\n",
        );
        let quic_row = "| 13 | VLESS over QUIC | client only | quiche with ALPN `h3` |";
        assert_eq!(references_for(&pins, quic_row), "sing-box, quiche");
        assert_eq!(
            references_for(&pins, "| 58 | tun2socks engine |"),
            "sing-box, zeptun"
        );
        // A row that matches nothing falls back to the full list rather than a blank.
        let no_core = pins_from_text("[sources.quiche]\ntopics        = \"quic\"\n\n[sources.zeptun]\ntopics        = \"tun2socks\"\n");
        assert_eq!(references_for(&no_core, "no topic here"), "quiche, zeptun");
        // The no-row fallback is the core set.
        assert_eq!(references_for(&pins, ""), "sing-box");
    }

    #[test]
    fn the_live_pins_resolve() {
        let pins = pins_from_text(include_str!("../../../upstream/pins.toml"));
        assert!(pins.len() >= 13, "expected at least the thirteen pins");
        assert!(pins.iter().any(|pin| pin.name == "xray-core-rust"));
        // The always set is the four same-format cores, and nothing else claims it.
        let always: Vec<&str> = pins
            .iter()
            .filter(|pin| pin.always)
            .map(|pin| pin.name.as_str())
            .collect();
        assert_eq!(
            always,
            ["xray-core", "sing-box", "xray-core-rust", "zeronet"]
        );
    }

    #[test]
    fn a_quic_matrix_row_draws_quiche_and_not_the_unrelated_pins() {
        let pins = pins_from_text(include_str!("../../../upstream/pins.toml"));
        let rows = methods_from_text(include_str!("../../../README.md"));
        let quic = rows
            .iter()
            .find(|row| row.method == "VLESS over QUIC")
            .expect("row A13 is in the matrix");
        let refs = references_for(&pins, &quic.text).to_ascii_lowercase();
        assert!(refs.contains("quiche"), "{refs}");
        assert!(refs.contains("xray-core"), "core set always rides: {refs}");
        for unrelated in ["zeptun", "slipstream", "mqvpn", "amnezia-client"] {
            assert!(
                !refs.contains(unrelated),
                "{unrelated} rode into a QUIC row: {refs}"
            );
        }
        let tun = rows
            .iter()
            .find(|row| row.method.starts_with("tun2socks"))
            .expect("row 59 is in the matrix");
        let tun_refs = references_for(&pins, &tun.text).to_ascii_lowercase();
        assert!(tun_refs.contains("zeptun"), "{tun_refs}");
        assert!(
            !tun_refs.contains("quiche"),
            "quiche rode into a tun row: {tun_refs}"
        );
    }

    #[test]
    fn slugs_are_hyphenated_and_never_empty() {
        assert_eq!(slugify_method("WireGuard (UDP)"), "wireguard-udp");
        assert_eq!(slugify_method("VLESS over ws"), "vless-over-ws");
        assert_eq!(slugify_method("!!!"), "method");
    }

    #[test]
    fn is_implemented_follows_the_stated_rule() {
        assert!(is_implemented("implemented"));
        assert!(is_implemented("implemented, both roles"));
        assert!(is_implemented("in tree, every carrier socket-proven"));
        assert!(is_implemented("**both roles, raw + ws**"));
        assert!(!is_implemented("planned"));
        assert!(!is_implemented("refused"));
        assert!(!is_implemented("**server only**"));
        assert!(!is_implemented("parsed, **not carried**"));
    }
}
