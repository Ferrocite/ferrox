//! Ready = `todo` with every dependency done, ranked by leverage then smaller effort; `--rotate` draws only from that ready set, and every draw is ledged.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::markdown::{Effort, Library, Prompt, Status};

/// Whether the advisor may offer a prompt, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Open, and every dependency is done.
    Ready,
    /// Open, waiting on these prompts to be `done`.
    WaitingOn(Vec<u32>),
    /// Open, but a human owns it: a half-finished slice must finish before a new one starts, yet `list` still shows it.
    Deferred,
    /// `done`.
    Finished,
}

/// Why a prompt is or is not ready.
pub fn readiness(library: &Library, prompt: &Prompt) -> Readiness {
    if prompt.status == Status::Done {
        return Readiness::Finished;
    }
    if prompt.status != Status::Todo {
        return Readiness::Deferred;
    }
    let waiting: Vec<u32> = prompt
        .depends_on
        .iter()
        .copied()
        .filter(|id| {
            library
                .prompt(*id)
                .is_none_or(|dependency| dependency.status != Status::Done)
        })
        .collect();
    if waiting.is_empty() {
        Readiness::Ready
    } else {
        Readiness::WaitingOn(waiting)
    }
}

/// Ready prompt indices, best first.
pub fn ranked(library: &Library, effort: Option<Effort>) -> Vec<usize> {
    let mut ready: Vec<usize> = library
        .prompts
        .iter()
        .enumerate()
        .filter(|(_, prompt)| readiness(library, prompt) == Readiness::Ready)
        .filter(|(_, prompt)| effort.is_none_or(|wanted| prompt.effort == wanted))
        .map(|(index, _)| index)
        .collect();
    ready.sort_by_key(|&index| {
        let prompt = &library.prompts[index];
        (Reverse(prompt.leverage), prompt.effort, prompt.id)
    });
    ready
}

/// The best ready prompt skipping `exclude`; `Err` names what was skipped, so an empty answer is explainable.
pub fn next_index(
    library: &Library,
    effort: Option<Effort>,
    exclude: &[u32],
) -> Result<usize, String> {
    let ready = ranked(library, effort);
    if ready.is_empty() {
        return Err(match effort {
            Some(wanted) => format!(
                "no prompt is ready at {} effort; the roadmap has {} open prompt(s) but none \
                 are unblocked",
                wanted.as_str(),
                library
                    .prompts
                    .iter()
                    .filter(|prompt| prompt.is_open())
                    .count()
            ),
            None => "no prompt is ready: every open one is waiting on a dependency".to_owned(),
        });
    }
    let available: Vec<usize> = ready
        .iter()
        .copied()
        .filter(|&index| !exclude.contains(&library.prompts[index].id))
        .collect();
    match available.first() {
        Some(&index) => Ok(index),
        None => Err(format!(
            "every ready slice is one of the last {} handed out ({}); pass --rotate for a \
             different draw, or --id P<n> for that one on purpose",
            exclude.len(),
            exclude
                .iter()
                .map(|id| format!("P{id}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// A ready prompt the advisor left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The prompt.
    pub id: u32,
    /// The inputs it needs and nobody supplied.
    pub missing: Vec<String>,
}

/// Ready prompts with every required input supplied; one with a hole is skipped, not handed over, unless `allow_unfilled`.
pub fn handable<'a>(
    library: &'a Library,
    effort: Option<Effort>,
    exclude: &[u32],
    supplied: &BTreeMap<String, String>,
    allow_unfilled: bool,
) -> (Vec<&'a Prompt>, Vec<Skipped>) {
    let mut ready = Vec::new();
    let mut skipped = Vec::new();
    for index in ranked(library, effort) {
        let prompt = &library.prompts[index];
        if exclude.contains(&prompt.id) {
            continue;
        }
        if !allow_unfilled {
            let missing: Vec<String> = prompt
                .required_inputs()
                .filter(|name| !supplied.contains_key(*name))
                .map(str::to_owned)
                .collect();
            if !missing.is_empty() {
                skipped.push(Skipped {
                    id: prompt.id,
                    missing,
                });
                continue;
            }
        }
        ready.push(prompt);
    }
    (ready, skipped)
}

/// A prompt drawn from `candidates` at random by `**Random weight:**`, deterministic in `seed` so a draw reproduces.
pub fn rotate_among<'a>(candidates: &[&'a Prompt], seed: u64) -> Result<&'a Prompt, String> {
    let total: u64 = candidates
        .iter()
        .map(|prompt| u64::from(prompt.random_weight))
        .sum();
    if total == 0 {
        return Err(
            "every candidate carries `**Random weight:** 0`; raise one above 0 or the draw \
                    is decided before it starts"
                .to_owned(),
        );
    }
    let mut draw = split_mix(seed) % total;
    for prompt in candidates {
        let weight = u64::from(prompt.random_weight);
        if prompt.random_weight == 0 {
            continue;
        }
        if draw < weight {
            return Ok(prompt);
        }
        draw -= weight;
    }
    Err("the weighted draw ran past its total; that is a bug in the weights".to_owned())
}

/// A weighted random ready prompt skipping `exclude`, deterministic in `seed`, which is reported with the result.
pub fn rotate_index(
    library: &Library,
    effort: Option<Effort>,
    exclude: &[u32],
    seed: u64,
) -> Result<usize, String> {
    let candidates: Vec<usize> = ranked(library, effort)
        .into_iter()
        .filter(|&index| {
            let prompt = &library.prompts[index];
            prompt.random_weight > 0 && !exclude.contains(&prompt.id)
        })
        .collect();
    if candidates.is_empty() {
        return Err(
            "nothing to rotate between: every ready slice is either excluded or has \
                    `**Random weight:** 0`"
                .to_owned(),
        );
    }
    let total: u64 = candidates
        .iter()
        .map(|&index| u64::from(library.prompts[index].random_weight))
        .sum();
    let mut draw = split_mix(seed) % total;
    for &index in &candidates {
        let weight = u64::from(library.prompts[index].random_weight);
        if draw < weight {
            return Ok(index);
        }
        draw -= weight;
    }
    // Unreachable while the weights sum to the total; kept so an out-of-range index can never be silent.
    Ok(candidates[0])
}

/// `SplitMix64`'s finalizer: a seed mixed so consecutive seeds do not produce adjacent draws, which a plain multiply does.
fn split_mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// One recorded handout: when, which slice, how it was asked for, and the matrix row it was served against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// UTC, second resolution.
    pub at: String,
    /// The prompt that was handed out.
    pub id: u32,
    /// `next`, `render`, `next --rotate`.
    pub how: String,
    /// The matrix target key (`A13`) this handout pointed at; `None` for a hand-written slice.
    pub target: Option<String>,
}

/// The log of what has been handed out on this machine.
#[derive(Debug, Default)]
pub struct Ledger {
    /// Where it is written.
    pub path: PathBuf,
    /// Everything it could read.
    pub entries: Vec<Entry>,
    /// Non-entry lines, counted so a truncated or hand-edited log is visible rather than silently shortening suppression.
    pub skipped: usize,
}

impl Ledger {
    /// Where the ledger lives, given the workspace root.
    pub fn path_for(root: &Path) -> PathBuf {
        root.join(crate::LEDGER_RELATIVE)
    }

    /// Read a ledger; a missing file is an empty one, not an error — the first run has no history.
    pub fn load(path: PathBuf) -> Self {
        let mut ledger = Self {
            path,
            ..Self::default()
        };
        let Ok(text) = std::fs::read_to_string(&ledger.path) else {
            return ledger;
        };
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(at), Some(id), Some(how)) = (fields.next(), fields.next(), fields.next())
            else {
                if !line.trim().is_empty() {
                    ledger.skipped += 1;
                }
                continue;
            };
            // Only the `t=`-prefixed fourth field is the matrix target; `--rotate` inside `how` is not.
            let target = fields.find_map(|field| field.strip_prefix("t=").map(str::to_owned));
            match id.trim_start_matches(['P', 'p']).parse::<u32>() {
                Ok(id) => ledger.entries.push(Entry {
                    at: at.to_owned(),
                    id,
                    how: how.to_owned(),
                    target,
                }),
                Err(_) => ledger.skipped += 1,
            }
        }
        ledger
    }

    /// Append one handout; a ledger that cannot be written is worth a warning, not a lost prompt.
    pub fn record(&mut self, id: u32, how: &str, target: Option<&str>) -> std::io::Result<()> {
        let entry = Entry {
            at: now_utc(),
            id,
            how: how.to_owned(),
            target: target.map(str::to_owned),
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = match &entry.target {
            Some(key) => format!("{} P{} {} t={key}\n", entry.at, entry.id, entry.how),
            None => format!("{} P{} {}\n", entry.at, entry.id, entry.how),
        };
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?
            .write_all(line.as_bytes())?;
        self.entries.push(entry);
        Ok(())
    }

    /// Keys already served to this template, oldest first, so `next` advances to the next unclaimed row instead of repeating.
    pub fn targets_for(&self, id: u32) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.id == id)
            .filter_map(|entry| entry.target.clone())
            .collect()
    }

    /// The most recent `window` distinct prompt ids, newest first.
    pub fn recent_ids(&self, window: usize) -> Vec<u32> {
        let mut seen: Vec<u32> = Vec::new();
        for entry in self.entries.iter().rev() {
            if seen.len() >= window {
                break;
            }
            if !seen.contains(&entry.id) {
                seen.push(entry.id);
            }
        }
        seen
    }

    /// When a prompt was last handed out, and how often in total.
    pub fn history(&self, id: u32) -> Option<(String, usize)> {
        let last = self
            .entries
            .iter()
            .rev()
            .find(|entry| entry.id == id)
            .map(|entry| entry.at.clone())?;
        let times = self.entries.iter().filter(|entry| entry.id == id).count();
        Some((last, times))
    }
}

/// UTC now as `YYYY-MM-DDTHH:MM:SSZ` — four lines of arithmetic here rather than a dependency, this crate having none.
pub fn now_utc() -> String {
    // Saturating seconds: a wrapped timestamp in a ledger is worse than a clamped one.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant's `civil_from_days`: exact over the whole `i64` day range, no lookup table.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::markdown::Library;

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    /// P1 done; P2, P3, P4 ready; P5 waiting on P3; P6 deferred.
    fn library() -> Library {
        Library::parse(
            Path::new("prompts.md"),
            "\
## Shared protocol

```text
p
```

## P1 · Done

**When to use:** past
**Status:** done
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`

```text
b
```

## P2 · Big leverage

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```

## P3 · Small leverage

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test`
**Random weight:** 3

```text
b
```

## P4 · Waiter

**When to use:** now
**Status:** todo
**Leverage:** 4
**Effort:** small
**Gates:** `cargo test`
**Depends on:** P3
**Random weight:** 1

```text
b
```

## P5 · Started

**When to use:** now
**Status:** doing
**Leverage:** 5
**Effort:** small
**Gates:** `cargo test`
**Random weight:** 9

```text
b
```
",
        )
    }

    fn ids(library: &Library, indices: &[usize]) -> Vec<u32> {
        indices
            .iter()
            .map(|&index| library.prompts[index].id)
            .collect()
    }

    #[test]
    fn readiness_follows_status_and_dependencies() {
        let library = library();
        let by_id = |id: u32| readiness(&library, library.prompt(id).unwrap());
        assert_eq!(by_id(1), Readiness::Finished);
        assert_eq!(by_id(2), Readiness::Ready);
        assert_eq!(by_id(3), Readiness::Ready);
        assert_eq!(by_id(4), Readiness::WaitingOn(vec![3]));
        assert_eq!(by_id(5), Readiness::Deferred);
    }

    #[test]
    fn ranking_is_leverage_then_the_smaller_slice_then_the_id() {
        let library = library();
        // P2 (5) beats P3 (3); P4 is blocked and P5 is `doing`, so neither is ranked however much leverage it claims.
        assert_eq!(ids(&library, &ranked(&library, None)), vec![2, 3]);
    }

    #[test]
    fn an_effort_filter_is_honoured_before_ranking() {
        let library = library();
        assert_eq!(
            ids(&library, &ranked(&library, Some(Effort::Small))),
            vec![3]
        );
        assert_eq!(ranked(&library, Some(Effort::Medium)), []);
    }

    #[test]
    fn the_next_index_skips_what_was_already_handed_out() {
        let library = library();
        assert_eq!(next_index(&library, None, &[]).unwrap(), 1);
        assert_eq!(next_index(&library, None, &[2]).unwrap(), 2);
        let error = next_index(&library, None, &[2, 3]).unwrap_err();
        assert!(error.contains("P2, P3"), "{error}");
        assert!(error.contains("--rotate"), "{error}");
    }

    #[test]
    fn rotation_is_deterministic_for_a_seed_and_respects_weights() {
        let library = library();
        // P2 has weight 0, so rotation never draws it even though it tops the ranking.
        for seed in 0..40 {
            let index = rotate_index(&library, None, &[], seed).unwrap();
            assert_eq!(library.prompts[index].id, 3);
        }
        assert_eq!(
            rotate_index(&library, None, &[], 7).unwrap(),
            rotate_index(&library, None, &[], 7).unwrap()
        );
    }

    #[test]
    fn a_prompt_missing_an_input_is_left_out_rather_than_handed_over() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Needs a decision

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Gates:** `cargo test`

```text
run it with {scope}
```

## P2 · Ready

**When to use:** now
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test`

```text
run it
```
",
        );
        let (ready, skipped) = handable(&library, None, &[], &BTreeMap::new(), false);
        assert_eq!(
            ready.iter().map(|prompt| prompt.id).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            skipped,
            vec![Skipped {
                id: 1,
                missing: vec!["scope".to_owned()]
            }]
        );
        // With the value supplied it becomes the top pick again.
        let supplied = BTreeMap::from([("scope".to_owned(), "crates/**".to_owned())]);
        let (ready, skipped) = handable(&library, None, &[], &supplied, false);
        assert_eq!(
            ready.iter().map(|prompt| prompt.id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(skipped, []);
        // And with `--allow-unfilled` it was never skipped at all.
        let (ready, skipped) = handable(&library, None, &[], &BTreeMap::new(), true);
        assert_eq!(ready.len(), 2);
        assert_eq!(skipped, []);
    }

    #[test]
    fn a_rotation_only_draws_from_what_is_handable() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Zero weight

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```

## P2 · Drawn

**When to use:** now
**Status:** todo
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`
**Random weight:** 3

```text
b
```
",
        );
        let (ready, _) = handable(&library, None, &[], &BTreeMap::new(), false);
        for seed in 0..30 {
            assert_eq!(rotate_among(&ready, seed).unwrap().id, 2);
        }
        let none = [library.prompt(1).unwrap()];
        assert!(rotate_among(&none, 1).unwrap_err().contains("weight"));
    }

    #[test]
    fn a_rotation_with_nothing_left_says_what_to_do() {
        let library = load(
            "\
## Shared protocol

```text
p
```

## P1 · Only

**When to use:** now
**Status:** todo
**Leverage:** 5
**Effort:** small
**Gates:** `cargo test`
**Random weight:** 0

```text
b
```
",
        );
        let error = rotate_index(&library, None, &[], 1).unwrap_err();
        assert!(error.contains("Random weight"), "{error}");
    }

    #[test]
    fn the_ledger_remembers_and_suppresses() {
        let mut path = std::env::temp_dir();
        path.push(format!("ferrox-ledger-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries, []);
        ledger.record(2, "next", None).unwrap();
        ledger.record(3, "next", Some("A13")).unwrap();
        ledger.record(2, "render", None).unwrap();
        assert_eq!(ledger.recent_ids(2), vec![2, 3]);
        assert_eq!(ledger.targets_for(3), vec!["A13"]);
        assert_eq!(ledger.targets_for(2), Vec::<String>::new());
        let (at, times) = ledger.history(2).unwrap();
        assert_eq!(times, 2);
        assert_eq!(at.len(), 20, "{at}");
        assert_eq!(ledger.history(9), None);
        let reread = Ledger::load(path.clone());
        assert_eq!(reread.entries.len(), 3);
        assert_eq!(reread.skipped, 0);
        assert_eq!(reread.targets_for(3), vec!["A13"]);
        drop(ledger);
        drop(reread);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_corrupt_ledger_line_is_counted_not_obeyed() {
        let mut path = std::env::temp_dir();
        path.push(format!("ferrox-ledger-bad-{}.log", std::process::id()));
        std::fs::write(
            &path,
            "2026-10-02T00:00:00Z P2 next\nnonsense\n\n2026-10-02T00:00:01Z Pthree render\n",
        )
        .unwrap();
        let ledger = Ledger::load(path.clone());
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.skipped, 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dates_are_exact_at_the_edges() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(20_728), (2026, 10, 2));
        // A leap day, and the day after it.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }

    #[test]
    fn the_clock_is_shaped_like_an_iso_timestamp() {
        let now = now_utc();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[10..11], "T");
    }
}
