//! Turning an archive-supplied name into something that can be acted on.
//!
//! Nothing else in the crate ever sees a raw tar name. Everything downstream
//! receives a [`Plan`], whose paths are already known to be root-relative, free
//! of `..`, and spelled in a way a refusal message can safely quote.

use crate::{Limits, Refusal};

/// What one entry name asks the extractor to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Write the entry at these components (non-empty, no `.`/`..`).
    Write(Vec<String>),
    /// Delete `parent/target`, per the `.wh.<name>` convention.
    Whiteout { parent: Vec<String>, target: String },
    /// Hide everything the lower layers put in `parent`, per `.wh..wh..opq`.
    Opaque { parent: Vec<String> },
    /// The archive root itself (`.`, `./`, `/`). Nothing to do.
    Root,
}

/// The whiteout prefix, and the opaque marker, from the OCI Image Layer
/// specification (`.wh.` / `.wh..wh..opq`).
const WH: &str = ".wh.";
const OPQ: &str = ".wh..wh..opq";

/// Normalise and confine one entry name.
///
/// The checks run in the order a reader would want them reported: a name that
/// is both over-long and absolute is refused for its length, because that is
/// the property the caller can act on without reading the rest.
///
/// # Errors
/// One of the name-shaped [`Refusal`]s. Every one of them is total: this crate
/// never sanitises a name and carries on, because "we fixed your path for you"
/// is how a traversal becomes a write to a path nobody audited.
pub fn plan(raw: &[u8], limits: &Limits) -> Result<Plan, Refusal> {
    if raw.len() > limits.max_path_len {
        return Err(Refusal::LimitExceeded {
            limit: "max_path_len",
            cap: limits.max_path_len as u64,
            raise: "Limits::max_path_len",
        });
    }
    let name = match std::str::from_utf8(raw) {
        Ok(s) => s,
        // Not a fidelity judgement: every path this crate reports, compares and
        // hands to the pack step is a `String`, so a name that cannot be one
        // would be reported as something other than what was written.
        Err(_) => return Err(Refusal::NonUtf8Name { raw: raw.to_vec() }),
    };
    // A newline or a carriage return in a name lets an archive forge lines in
    // any log or report that quotes it; NUL truncates the name at the syscall
    // boundary, so what is checked and what is created differ.
    if name.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(Refusal::ControlCharInName {
            entry: name.escape_debug().to_string(),
        });
    }
    if name.starts_with('/') {
        return Err(Refusal::AbsolutePath {
            entry: name.to_string(),
        });
    }

    let mut components: Vec<String> = Vec::new();
    for part in name.split('/') {
        match part {
            "" | "." => {}
            // Every `..` is refused, not just the ones that leave the root.
            // `a/../b` and `b` name the same file, so normalising would be
            // safe — but then the extractor's idea of the path and the
            // archive's differ, and every later comparison (whiteouts, opaque
            // pruning, the duplicate check) is made against the wrong one.
            // Real layers never contain `..`; verified against the tars of
            // alpine, debian, ubuntu, python and node.
            ".." => {
                return Err(Refusal::PathEscapesRoot {
                    entry: name.to_string(),
                })
            }
            other => components.push(other.to_string()),
        }
    }
    if components.is_empty() {
        return Ok(Plan::Root);
    }
    if components.len() > limits.max_path_depth {
        return Err(Refusal::LimitExceeded {
            limit: "max_path_depth",
            cap: limits.max_path_depth as u64,
            raise: "Limits::max_path_depth",
        });
    }

    // A whiteout marker is an instruction, never a file, so it can never be a
    // directory that something else lives under. Accepting `.wh.foo/bar` would
    // create a real `.wh.foo` directory on the way to `bar`, and a later layer's
    // genuine `.wh.foo` whiteout would then be indistinguishable from it.
    if let Some(bad) = components[..components.len() - 1]
        .iter()
        .find(|c| c.starts_with(WH))
    {
        return Err(Refusal::Malformed {
            entry: name.to_string(),
            detail: format!(
                "{bad:?} is a whiteout marker used as a directory. Markers delete \
                 things; they are never created, so nothing can live beneath one."
            ),
        });
    }

    let last = components.last().expect("checked non-empty");
    if last == OPQ {
        components.pop();
        return Ok(Plan::Opaque { parent: components });
    }
    if let Some(target) = last.strip_prefix(WH) {
        if target.is_empty() {
            // "A `.wh.` file, without a basename to delete, is invalid and
            // implementations SHOULD return an error." — OCI Image Layer spec.
            return Err(Refusal::Malformed {
                entry: name.to_string(),
                detail: "a `.wh.` marker with no basename names nothing to delete".into(),
            });
        }
        // A whiteout target is the one place a name reaches the delete walk
        // without having been through the component loop above, so `.` and `..`
        // have to be refused here as well. `.wh...` asks the extractor to unlink
        // `..` from the marker's own directory — which, applied at the top of
        // the tree, is the *parent of the staging root*: the caller's
        // destination directory, and everything else in it.
        if target == ".." {
            return Err(Refusal::PathEscapesRoot {
                entry: name.to_string(),
            });
        }
        if target == "." {
            return Err(Refusal::Malformed {
                entry: name.to_string(),
                detail: "a `.wh.` marker whose basename is `.` names its own directory, \
                         not anything in it"
                    .into(),
            });
        }
        let target = target.to_string();
        components.pop();
        return Ok(Plan::Whiteout {
            parent: components,
            target,
        });
    }
    Ok(Plan::Write(components))
}

/// Join components the way every message, report entry and bookkeeping key in
/// this crate spells a path: root-relative, `/`-separated, no leading slash.
#[must_use]
pub fn join(components: &[String]) -> String {
    components.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    fn p(s: &str) -> Result<Plan, Refusal> {
        plan(s.as_bytes(), &lim())
    }

    #[test]
    fn ordinary_names_normalise_to_components() {
        assert_eq!(
            p("./usr/bin/env").unwrap(),
            Plan::Write(vec!["usr".into(), "bin".into(), "env".into()])
        );
        assert_eq!(
            p("etc//passwd").unwrap(),
            Plan::Write(vec!["etc".into(), "passwd".into()])
        );
        // A trailing separator is how tar spells a directory; it must not
        // produce an empty final component, or every directory would be
        // classified by the wrong basename.
        assert_eq!(
            p("var/log/").unwrap(),
            Plan::Write(vec!["var".into(), "log".into()])
        );
        for root in [".", "./", "/", "", "././"] {
            assert!(matches!(
                p(root),
                Ok(Plan::Root) | Err(Refusal::AbsolutePath { .. })
            ));
        }
    }

    #[test]
    fn every_spelling_of_leaving_the_root_is_refused() {
        // The traversal row of the fixture matrix, plus the neighbours it
        // misses: a `..` that lands back inside the root is refused too,
        // because a normalised path the archive did not spell is a path no
        // later comparison agrees about.
        for entry in [
            "../../../.ssh/authorized_keys",
            "foo/../../etc/passwd",
            "./a/./../../b",
            "..",
            "../",
            "a/../b",
            "a/b/../../../c",
        ] {
            assert!(
                matches!(p(entry), Err(Refusal::PathEscapesRoot { .. })),
                "{entry} was not refused: {:?}",
                p(entry)
            );
        }
        for entry in ["/etc/passwd", "//etc/passwd", "/"] {
            assert!(
                matches!(p(entry), Err(Refusal::AbsolutePath { .. })),
                "{entry} was not refused as absolute"
            );
        }
    }

    #[test]
    fn control_characters_and_non_utf8_are_refused() {
        for entry in ["a\nb", "a\rb", "a\u{7f}b", "\u{1}"] {
            assert!(
                matches!(p(entry), Err(Refusal::ControlCharInName { .. })),
                "{} was not refused",
                entry.escape_debug()
            );
        }
        // NUL cannot reach here through a ustar header, but a PAX `path=`
        // record carries arbitrary bytes.
        assert!(matches!(
            plan(b"a\0b", &lim()),
            Err(Refusal::ControlCharInName { .. })
        ));
        assert!(matches!(
            plan(&[0xff, 0xfe], &lim()),
            Err(Refusal::NonUtf8Name { .. })
        ));
    }

    #[test]
    fn whiteout_markers_are_classified_not_written() {
        assert_eq!(
            p("d/.wh.secret").unwrap(),
            Plan::Whiteout {
                parent: vec!["d".into()],
                target: "secret".into()
            }
        );
        assert_eq!(
            p(".wh.top").unwrap(),
            Plan::Whiteout {
                parent: vec![],
                target: "top".into()
            }
        );
        assert_eq!(
            p("d/.wh..wh..opq").unwrap(),
            Plan::Opaque {
                parent: vec!["d".into()]
            }
        );
        assert_eq!(p(".wh..wh..opq").unwrap(), Plan::Opaque { parent: vec![] });
        // The neighbours: a marker with nothing to delete, and a marker used as
        // a directory. Both are instructions that name no file, so neither may
        // fall through to the write path.
        assert!(matches!(p(".wh."), Err(Refusal::Malformed { .. })));
        assert!(matches!(p("d/.wh."), Err(Refusal::Malformed { .. })));
        assert!(matches!(p(".wh.foo/bar"), Err(Refusal::Malformed { .. })));
        assert!(matches!(
            p(".wh..wh..opq/x"),
            Err(Refusal::Malformed { .. })
        ));
        // `.wh..wh.aufs` and friends are aufs bookkeeping the spec does not
        // name; treating them as ordinary whiteouts deletes `.wh.aufs`, which
        // no image contains. Harmless, and better than materialising them.
        assert_eq!(
            p(".wh..wh.aufs").unwrap(),
            Plan::Whiteout {
                parent: vec![],
                target: ".wh.aufs".into()
            }
        );
    }

    #[test]
    fn the_length_and_depth_caps_name_themselves() {
        let long = "a".repeat(Limits::default().max_path_len + 1);
        match plan(long.as_bytes(), &lim()) {
            Err(Refusal::LimitExceeded { limit, cap, raise }) => {
                assert_eq!(limit, "max_path_len");
                assert_eq!(cap, Limits::default().max_path_len as u64);
                assert!(raise.contains("max_path_len"));
            }
            other => panic!("expected a limit refusal, got {other:?}"),
        }
        // Depth bounds the recursion in the subtree delete and the opaque
        // prune, so it has to be checked before anything acts on the path.
        let deep = vec!["a"; Limits::default().max_path_depth + 1].join("/");
        assert!(matches!(
            plan(deep.as_bytes(), &lim()),
            Err(Refusal::LimitExceeded {
                limit: "max_path_depth",
                ..
            })
        ));
    }
}
