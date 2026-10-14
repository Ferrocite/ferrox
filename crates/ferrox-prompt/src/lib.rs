//! Chooses the next slice — ready means `todo` with every dependency `done`, ranked by leverage then smaller effort — and never invents a placeholder value.

#![deny(missing_debug_implementations)]

pub mod advisor;
pub mod check;
pub mod clipboard;
pub mod expand;
pub mod json;
pub mod markdown;
pub mod render;
pub mod state;
pub mod worktree;

use std::path::{Path, PathBuf};

pub use markdown::{Addon, Diagnostic, Effort, Library, Prompt, Severity, Status, Targets};

/// The library's path relative to the root, searched upwards so the tool runs from anywhere inside the repository.
pub const LIBRARY_RELATIVE: &str = "crates/ferrox-prompt/prompts.md";

/// The slice ledger, relative to the root: runtime state, never committed, since one machine's handout log is wrong for every other.
pub const LEDGER_RELATIVE: &str = ".ferrox/slices.log";

/// The matrix, a second source of truth beside `prompts.md`: templates give the work's shape, the matrix says which row is due now.
pub const README_RELATIVE: &str = "README.md";

/// The pinned references: `{references}` is filled from here, never hand-written into a prompt.
pub const PINS_RELATIVE: &str = "upstream/pins.toml";

/// The workspace root, found by walking up for [`LIBRARY_RELATIVE`]; the manifest fallback lets a released binary name where it looked.
pub fn workspace_root(start: &Path) -> PathBuf {
    let mut cursor = Some(start);
    while let Some(dir) = cursor {
        if dir.join(LIBRARY_RELATIVE).is_file() {
            return dir.to_path_buf();
        }
        cursor = dir.parent();
    }
    manifest_root()
}

/// Two levels up from the compile-time `CARGO_MANIFEST_DIR`, so a binary built here still knows where its library is.
pub fn manifest_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or(manifest.clone(), Path::to_path_buf)
}

/// FNV-1a tag naming the exact library text: a tag, not a checksum — nothing about correctness depends on it.
pub fn library_tag(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A library that could not be read at all: no prompts, so nothing to report a line number against.
#[derive(Debug)]
pub struct Unreadable {
    /// The path that was tried.
    pub path: PathBuf,
    /// What the filesystem said.
    pub message: String,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot read prompt library {}: {}",
            self.path.display(),
            self.message
        )
    }
}

impl std::error::Error for Unreadable {}

/// Read and parse the library; `--library` wins over the search, and the recorded path stays root-relative so a diagnostic opens.
pub fn load_library(explicit: Option<&Path>, cwd: &Path) -> Result<Library, Unreadable> {
    let root = workspace_root(cwd);
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => root.join(LIBRARY_RELATIVE),
    };
    let text = std::fs::read_to_string(&path).map_err(|source| Unreadable {
        path: path.clone(),
        message: source.to_string(),
    })?;
    let display = path
        .strip_prefix(&root)
        .map_or_else(|_| path.clone(), Path::to_path_buf);
    Ok(Library::parse(&display, &text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_stable_and_input_sensitive() {
        assert_eq!(library_tag("ferrox"), library_tag("ferrox"));
        assert_ne!(library_tag("ferrox"), library_tag("dovetai"));
        // A trailing newline changes the tag on purpose: it names the file, not its gist.
        assert_ne!(library_tag("ferrox\n"), library_tag("ferrox"));
        assert_eq!(library_tag("").len(), 16);
    }

    #[test]
    fn the_manifest_root_is_the_workspace_root() {
        let root = manifest_root();
        assert!(
            root.join(LIBRARY_RELATIVE).is_file(),
            "manifest root {} does not hold the library",
            root.display()
        );
        assert!(root.join("Cargo.toml").is_file());
    }

    #[test]
    fn the_root_is_found_from_a_subdirectory() {
        let root = manifest_root();
        let deep = root.join("crates/ferrox-core/src");
        assert_eq!(workspace_root(&deep), root);
        // Outside the repository entirely, fall back to the compiled-in root rather than returning nothing.
        assert_eq!(workspace_root(Path::new("/")), manifest_root());
    }
}
