//! Which base image a run boots — a built-in flavor, or an imported one.
//!
//! This is the resolution boundary the import design asks for: a closed type at
//! the CLI and MCP edge, and plain `(slug, digest)` strings everywhere the
//! choice is *persisted*. [`stage::BaseId`](crate::stage::BaseId),
//! `StageMeta::base` and `SnapshotKey::base` were already strings, so nothing
//! stored has to change and no stage has to be migrated — a
//! `RootfsFlavor::Imported` variant would have rippled through every match on
//! the enum instead.
//!
//! An imported base is spelled `oci:<name>`. The prefix is not decoration: a
//! bare name would collide with the flavor slugs the moment somebody imported
//! an image called `base-alpine`, and "which one did it boot?" is not a
//! question an operator should have to ask about the root filesystem.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use super::import::{self, OciProvenance};
use super::rootfs::{self, RootfsFlavor};
use crate::paths;

/// How an imported base is spelled on `--base` and recorded in a stage.
pub const IMPORTED_PREFIX: &str = "oci:";

/// The base image a run boots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseRef {
    /// One of the flavors isopod builds itself.
    Builtin(RootfsFlavor),
    /// An image imported with `isopod image import`, by its name.
    Imported(String),
}

impl BaseRef {
    /// Parse a `--base` value, or the slug a stage recorded.
    ///
    /// # Errors
    /// An unknown name, or an `oci:` name that could not address a file.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(name) = s.strip_prefix(IMPORTED_PREFIX) {
            // Validated by the same rules the import applied, so a recorded
            // slug cannot become a path the import would never have produced.
            import::imported_image_path(Path::new("/"), name)
                .with_context(|| format!("'{s}' does not name an imported image"))?;
            return Ok(Self::Imported(name.to_string()));
        }
        RootfsFlavor::from_slug(s).map(Self::Builtin).map_err(|e| {
            anyhow::anyhow!(
                "{e}. An imported image is spelled `{IMPORTED_PREFIX}<name>` \
                 (see `isopod image ls`)"
            )
        })
    }

    /// The string form: the flavor slug, or `oci:<name>`.
    ///
    /// This is what a stage records and what the snapshot key holds, so it has
    /// to round-trip through [`parse`](Self::parse) exactly.
    #[must_use]
    pub fn slug(&self) -> String {
        match self {
            Self::Builtin(f) => f.slug().to_string(),
            Self::Imported(name) => format!("{IMPORTED_PREFIX}{name}"),
        }
    }

    /// `true` for a base a stage overlay chain can boot as its read-only root.
    /// Every imported base is one; only two of the built-in flavors are.
    #[must_use]
    pub fn is_squashfs_base(&self) -> bool {
        match self {
            Self::Builtin(f) => f.is_squashfs_base(),
            Self::Imported(_) => true,
        }
    }

    /// Resolve to the on-disk image, checking it is present and not stale.
    pub fn image_path_in(&self, images: &Path) -> Result<PathBuf> {
        match self {
            Self::Builtin(f) => rootfs::base_image_path_in(images, *f),
            Self::Imported(name) => {
                let path = import::imported_image_path(images, name)?;
                if !path.exists() {
                    bail!(
                        "imported base '{}' is not at {}; import it first: \
                         `isopod image import <reference> --name {name}`",
                        self.slug(),
                        path.display()
                    );
                }
                // The same pre-boot freshness check a built-in base gets. It
                // matters more here: an imported base is stamped with the agent
                // hash it was built against, and every agent rebuild
                // invalidates every imported base.
                rootfs::check_image_proto(&path)?;
                Ok(path)
            }
        }
    }

    /// [`image_path_in`](Self::image_path_in) against the real images directory.
    pub fn image_path(&self) -> Result<PathBuf> {
        self.image_path_in(&paths::images_dir()?)
    }

    /// The image's content id, for the warm-pool snapshot key.
    pub fn content_id(&self) -> Result<String> {
        match self {
            Self::Builtin(f) => rootfs::base_content_id(*f),
            Self::Imported(name) => {
                let path = import::imported_image_path(&paths::images_dir()?, name)?;
                Ok(rootfs::read_image_meta(&path)?
                    .map(|m| m.sha256)
                    .unwrap_or_else(|| "unstamped".to_string()))
            }
        }
    }

    /// The image config an imported base carries, if any.
    ///
    /// `None` for a built-in flavor, which has no config to carry, and `None`
    /// for an imported image whose sidecar predates the field.
    pub fn provenance_in(&self, images: &Path) -> Result<Option<OciProvenance>> {
        match self {
            Self::Builtin(_) => Ok(None),
            Self::Imported(name) => {
                let path = import::imported_image_path(images, name)?;
                import::read_provenance(&path)
            }
        }
    }
}

impl std::fmt::Display for BaseRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.slug())
    }
}

/// The defaults an imported image's config contributes to a run.
///
/// Defaults, never behaviour: the run always wins. `Entrypoint`, `Cmd` and
/// `User` are deliberately absent — the first two are recorded and never
/// executed, and the agent execs as root regardless of the third.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunDefaults {
    /// `KEY=VALUE` pairs from the image, applied **under** the run's own env.
    pub env: Vec<(String, String)>,
    /// The image's `WorkingDir`, used only when the run names no cwd.
    pub cwd: Option<String>,
}

impl RunDefaults {
    /// Derive the defaults from an image config.
    ///
    /// An entry without `=` is skipped rather than guessed at: the image
    /// config's `Env` is a free-form array of strings, and half a variable is
    /// not something to invent the other half of.
    #[must_use]
    pub fn from_provenance(p: &OciProvenance) -> Self {
        let env = p
            .env
            .iter()
            .filter_map(|kv| kv.split_once('='))
            .filter(|(k, _)| !k.is_empty())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            env,
            // A `WorkingDir` of "" or "/" is what an image says when it means
            // "no opinion"; the agent's own default is a better answer than a
            // root directory nothing is in.
            cwd: p
                .working_dir
                .as_deref()
                .filter(|d| !d.is_empty() && *d != "/")
                .map(str::to_string),
        }
    }

    /// Merge these defaults **under** a run's own choices.
    ///
    /// Without this a `python:3.12` base does not find `python` on `PATH`: the
    /// interpreter is installed where the image's own `PATH` says, and a run
    /// that sets no `PATH` would get the agent's baseline instead.
    ///
    /// The run wins on every key it names, and `cwd` is all-or-nothing rather
    /// than merged, because half a path is not a path.
    pub fn apply(&self, env: &mut Vec<(String, String)>, cwd: &mut Option<String>) {
        if cwd.is_none() {
            cwd.clone_from(&self.cwd);
        }
        if self.env.is_empty() {
            return;
        }
        let named: std::collections::HashSet<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        let mut under: Vec<(String, String)> = self
            .env
            .iter()
            .filter(|(k, _)| !named.contains(k.as_str()))
            .cloned()
            .collect();
        // The image's variables first, so a reader of the resulting list sees
        // the run's own additions last — the order the precedence implies.
        under.append(env);
        *env = under;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(env: &[&str], wd: Option<&str>) -> OciProvenance {
        OciProvenance {
            source_ref: "x".into(),
            platform: "linux/amd64".into(),
            manifest_digest: "sha256:aa".into(),
            config_digest: "sha256:bb".into(),
            layer_digests: vec![],
            env: env.iter().map(|s| (*s).to_string()).collect(),
            working_dir: wd.map(str::to_string),
            entrypoint: vec![],
            cmd: vec![],
            user: None,
            replaced_init: false,
            setuid_paths: vec![],
        }
    }

    #[test]
    fn a_base_ref_round_trips_through_its_slug() {
        for s in ["base-sqfs", "base-alpine", "dev-agent", "dev-busybox"] {
            let b = BaseRef::parse(s).expect("known flavor");
            assert_eq!(b.slug(), s);
            assert_eq!(BaseRef::parse(&b.slug()).expect("round trip"), b);
        }
        let b = BaseRef::parse("oci:alpine-3.20").expect("imported");
        assert_eq!(b, BaseRef::Imported("alpine-3.20".into()));
        assert_eq!(b.slug(), "oci:alpine-3.20");
        assert_eq!(BaseRef::parse(&b.slug()).expect("round trip"), b);
    }

    #[test]
    fn an_imported_name_that_could_address_a_file_is_refused() {
        for bad in [
            "oci:../escape",
            "oci:a/b",
            "oci:",
            "oci:.hidden",
            "oci:has space",
        ] {
            assert!(BaseRef::parse(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn an_unknown_base_says_how_an_imported_one_is_spelled() {
        // The failure an operator actually hits: they imported `alpine-3.20`
        // and then typed it without the prefix.
        let err = BaseRef::parse("alpine-3.20").expect_err("not a flavor");
        let msg = err.to_string();
        assert!(msg.contains("oci:"), "{msg}");
    }

    #[test]
    fn every_imported_base_is_a_squashfs_base() {
        assert!(BaseRef::parse("oci:x").unwrap().is_squashfs_base());
        assert!(BaseRef::parse("base-alpine").unwrap().is_squashfs_base());
        // The two ext4 dev flavors are not, and that must not change.
        assert!(!BaseRef::parse("dev-agent").unwrap().is_squashfs_base());
        assert!(!BaseRef::parse("dev-busybox").unwrap().is_squashfs_base());
    }

    #[test]
    fn the_run_wins_every_key_the_image_also_names() {
        let d = RunDefaults::from_provenance(&provenance(
            &["PATH=/img/bin", "LANG=C.UTF-8"],
            Some("/srv"),
        ));
        let mut env = vec![("PATH".to_string(), "/run/bin".to_string())];
        let mut cwd = None;
        d.apply(&mut env, &mut cwd);

        // PATH is the run's; LANG comes from the image; the image's is first.
        assert_eq!(
            env,
            vec![
                ("LANG".to_string(), "C.UTF-8".to_string()),
                ("PATH".to_string(), "/run/bin".to_string()),
            ]
        );
        assert_eq!(cwd.as_deref(), Some("/srv"));
    }

    #[test]
    fn a_run_that_names_a_cwd_keeps_it() {
        let d = RunDefaults::from_provenance(&provenance(&[], Some("/srv")));
        let mut env = vec![];
        let mut cwd = Some("/elsewhere".to_string());
        d.apply(&mut env, &mut cwd);
        assert_eq!(cwd.as_deref(), Some("/elsewhere"));
    }

    #[test]
    fn a_working_dir_of_root_or_empty_is_no_opinion() {
        for wd in [Some("/"), Some(""), None] {
            let d = RunDefaults::from_provenance(&provenance(&[], wd));
            assert_eq!(d.cwd, None, "{wd:?} should not override the agent default");
        }
        // Neighbour: a real path still comes through.
        let d = RunDefaults::from_provenance(&provenance(&[], Some("/app")));
        assert_eq!(d.cwd.as_deref(), Some("/app"));
    }

    #[test]
    fn a_malformed_env_entry_is_skipped_rather_than_guessed() {
        let d = RunDefaults::from_provenance(&provenance(
            &["GOOD=1", "NOEQUALS", "=novalue", "EMPTY="],
            None,
        ));
        assert_eq!(
            d.env,
            vec![
                ("GOOD".to_string(), "1".to_string()),
                ("EMPTY".to_string(), String::new()),
            ],
            "an entry with no '=' and one with no name are both dropped; \
             an empty VALUE is legitimate"
        );
    }

    #[test]
    fn a_builtin_base_contributes_no_defaults() {
        let images = Path::new("/nonexistent");
        let b = BaseRef::parse("base-alpine").unwrap();
        assert_eq!(b.provenance_in(images).expect("no error"), None);
    }
}
