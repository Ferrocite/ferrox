//! One worktree per slice, made only by `scripts/new-worktree.sh`: the tool names the slice's worktree and says whether it exists yet.

use std::path::{Path, PathBuf};

/// The directory `scripts/new-worktree.sh` makes for a slice: a sibling of the checkout it runs from, this prefix on the branch name.
pub const DIR_PREFIX: &str = "ferrox-";

/// The longest label a slice name takes from its row, so a branch, a directory and a `git log --oneline` stay readable.
const LABEL_LIMIT: usize = 40;

/// What the filesystem says about the path a slice's worktree would use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// Nothing there: the script makes it.
    Absent,
    /// The script made it already, elsewhere than this checkout.
    Linked,
    /// This checkout is the slice's worktree.
    Current,
    /// A directory of that name exists and is not a worktree, so the script refuses to overwrite it.
    Occupied,
}

/// The worktree a slice runs in: what it is called, where it sits, and whether it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worktree {
    /// The branch name, the directory suffix and the pull-request head, as in `p2-shadowsocks-tcp-udp`.
    pub name: String,
    /// The path `scripts/new-worktree.sh` would use for it.
    pub path: PathBuf,
    /// What is at that path right now.
    pub place: Place,
}

impl Worktree {
    /// The worktree for the slice `P{id}` drawing `label` now draws — named from the label so the same task keeps the same worktree, located without creating anything.
    #[must_use]
    pub fn plan(id: u32, label: &str, root: &Path) -> Self {
        Self::named(name(id, label), root)
    }

    /// A worktree whose branch name is already decided, as `bugfix-661` is for an issue template.
    #[must_use]
    pub fn named(name: impl Into<String>, root: &Path) -> Self {
        let name = name.into();
        let path = path_for(&name, root);
        Self {
            place: probe(&path, root),
            name,
            path,
        }
    }

    /// One word for `--json`.
    #[must_use]
    pub fn state(&self) -> &'static str {
        match self.place {
            Place::Absent => "absent",
            Place::Linked => "linked",
            Place::Current => "current",
            Place::Occupied => "occupied",
        }
    }

    /// The terminal's one-line verdict: what to do with the worktree, not why.
    #[must_use]
    pub fn brief(&self) -> String {
        match self.place {
            Place::Absent => format!("create it: ./scripts/new-worktree.sh {}", self.name),
            Place::Linked => format!("{} — use it, onto main first", self.path.display()),
            Place::Current => "this checkout — onto main first".to_owned(),
            Place::Occupied => format!("{} is not a worktree; move it aside", self.path.display()),
        }
    }
}

/// `p2-shadowsocks-tcp-udp`: the template id, so no two classes share a name, and the row's method as a path-safe slug.
#[must_use]
pub fn name(id: u32, label: &str) -> String {
    let slug = kebab(label);
    if slug.is_empty() {
        format!("p{id}")
    } else {
        format!("p{id}-{slug}")
    }
}

/// The label as a slug: alphanumeric runs joined by one hyphen, cut at a word boundary past [`LABEL_LIMIT`].
fn kebab(label: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(label.len());
    let mut pending = false;
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            if pending && !out.is_empty() {
                out.push(b'-');
            }
            pending = false;
            out.push(byte.to_ascii_lowercase());
        } else {
            pending = true;
        }
    }
    if out.len() > LABEL_LIMIT {
        let cut = out[..LABEL_LIMIT]
            .iter()
            .rposition(|byte| *byte == b'-')
            .unwrap_or(LABEL_LIMIT);
        out.truncate(cut);
    }
    out.iter().copied().map(char::from).collect()
}

/// Where the script would put it: beside this checkout, under [`DIR_PREFIX`].
fn path_for(name: &str, root: &Path) -> PathBuf {
    root.parent()
        .unwrap_or(root)
        .join(format!("{DIR_PREFIX}{name}"))
}

/// A linked worktree carries a `.git` *file*; a directory written by hand carries one of its own, or none.
fn probe(path: &Path, root: &Path) -> Place {
    if path == root {
        return Place::Current;
    }
    if !path.exists() {
        return Place::Absent;
    }
    if path.join(".git").is_file() {
        Place::Linked
    } else {
        Place::Occupied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own under the system temp dir, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            path.push(format!("ferrox-prompt-worktree-{tag}-{stamp}"));
            std::fs::create_dir_all(&path).expect("scratch");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn the_name_is_the_template_and_the_row_in_path_order() {
        assert_eq!(name(2, "Shadowsocks TCP/UDP"), "p2-shadowsocks-tcp-udp");
        assert_eq!(
            name(17, "REALITY Vision handshake"),
            "p17-reality-vision-handshake"
        );
        assert_eq!(
            name(9, "///"),
            "p9",
            "a label with no slug falls back to the id"
        );
    }

    #[test]
    fn a_long_label_is_cut_at_a_word_boundary() {
        let long = name(3, "VLESS over XHTTP with Multi-Upload Mode Selected Case");
        assert_eq!(long, "p3-vless-over-xhttp-with-multi-upload-mode", "{long}");
        assert!(!long.ends_with('-'), "{long}");
        assert!(
            long["p3-".len()..].len() <= LABEL_LIMIT,
            "the slug alone is what the limit bounds"
        );
    }

    #[test]
    fn the_same_slice_always_gets_the_same_name() {
        assert_eq!(name(7, "VMess TCP (AEAD)"), name(7, "VMess TCP (AEAD)"));
    }

    #[test]
    fn an_explicit_branch_name_is_not_prefixed_or_slugified() {
        let scratch = Scratch::new("named");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let plan = Worktree::named("bugfix-661", &root);
        assert_eq!(plan.name, "bugfix-661");
        assert_eq!(plan.place, Place::Absent);
        assert_eq!(plan.path, scratch.0.join(format!("{DIR_PREFIX}bugfix-661")));
        assert!(plan
            .brief()
            .contains("./scripts/new-worktree.sh bugfix-661"));
    }

    #[test]
    fn an_absent_slice_names_the_worktree_the_script_would_make() {
        let scratch = Scratch::new("absent");
        let root = scratch.0.join("ferrox");
        std::fs::create_dir_all(&root).expect("checkout");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", &root);
        assert_eq!(plan.name, "p2-shadowsocks-tcp-udp");
        assert_eq!(plan.place, Place::Absent);
        assert_eq!(plan.state(), "absent");
        assert!(plan.brief().contains("./scripts/new-worktree.sh"));
        assert_eq!(
            plan.path,
            scratch
                .0
                .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"))
        );
    }

    #[test]
    fn a_worktree_the_script_made_is_found_and_used() {
        let scratch = Scratch::new("linked");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(&other).expect("worktree");
        std::fs::write(other.join(".git"), "gitdir: somewhere\n").expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", &root);
        assert_eq!(plan.place, Place::Linked);
        assert_eq!(plan.path, other);
        assert!(plan.brief().contains("use it"), "{}", plan.brief());
    }

    #[test]
    fn running_from_the_slices_own_worktree_says_so() {
        let scratch = Scratch::new("current");
        let root = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::write(root.join(".git"), "gitdir: somewhere\n").expect(".git file");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", &root);
        assert_eq!(plan.place, Place::Current);
    }

    #[test]
    fn a_directory_that_is_not_a_worktree_is_not_claimed() {
        let scratch = Scratch::new("occupied");
        let root = scratch.0.join("ferrox");
        let other = scratch
            .0
            .join(format!("{DIR_PREFIX}p2-shadowsocks-tcp-udp"));
        std::fs::create_dir_all(&root).expect("checkout");
        std::fs::create_dir_all(other.join("src")).expect("a hand-made directory");
        let plan = Worktree::plan(2, "Shadowsocks TCP/UDP", &root);
        assert_eq!(plan.place, Place::Occupied);
        assert!(plan.brief().contains("not a worktree"));
    }
}
