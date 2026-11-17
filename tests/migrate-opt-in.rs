//! Regression tests for issue #4418: migration (and checksum) support must be fully opt-in.
//!
//! The bug lived in the manifests (`Cargo.toml` activating `sqlx-core/migrate` unconditionally,
//! `sqlx-macros-core` activating `migrate` on the driver crates unconditionally), which is not
//! observable from within this crate because Cargo features are additive.
//!
//! These tests therefore drive `cargo tree` against synthetic downstream crates so we can
//! assert on the *resolved* dependency graph:
//!
//! * a bare `sqlx = { default-features = false, features = ["runtime-tokio"] }` dependency
//!   must not pull in `sha2`/`crc` (the crates behind the migration checksums),
//! * enabling the public `migrate` feature must bring them back,
//! * enabling `macros` with a database driver must not leak migration support into the
//!   runtime dependency graph through the macro crate's dependency edges.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a synthetic downstream crate depending on this version of `sqlx`
/// with the given features enabled, and return the path to its manifest.
fn downstream_project(features: &[&str]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sqlx-4418-{}", features.join("-")));
    fs::create_dir_all(&dir).expect("failed to create temp dir");

    let features_list = features
        .iter()
        .map(|feature| format!("{feature:?}"))
        .collect::<Vec<_>>()
        .join(", ");

    let manifest = format!(
        r#"
[workspace]

[package]
name = "downstream"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
sqlx = {{ path = {:?}, default-features = false, features = [{features_list}] }}
"#,
        env!("CARGO_MANIFEST_DIR")
    );

    let manifest_path = dir.join("Cargo.toml");
    fs::write(&manifest_path, manifest).expect("failed to write manifest");

    // Cargo requires at least one target to exist.
    fs::create_dir_all(dir.join("src")).expect("failed to create src dir");
    fs::write(dir.join("src/lib.rs"), "").expect("failed to write lib.rs");

    manifest_path
}

/// Run `cargo tree --invert <package>` for the given manifest, returning the tree of
/// reverse dependencies rooted at the given package, or `None` if the package is not
/// part of the resolved dependency graph.
///
/// Note: the package may still appear in `Cargo.lock` as a locked-but-unactivated
/// optional dependency, in which case `cargo tree` succeeds but prints nothing.
fn reverse_dependencies(manifest_path: &Path, package: &str) -> Option<String> {
    let output = Command::new(env!("CARGO"))
        .arg("tree")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest_path)
        .arg("--invert")
        .arg(package)
        // `cargo tree` doesn't accept `--target-dir`; use the env var instead so the
        // synthetic crate doesn't clobber this workspace's `target` directory.
        .env(
            "CARGO_TARGET_DIR",
            manifest_path.parent().unwrap().join("target"),
        )
        .output()
        .expect("failed to spawn `cargo tree`");

    let stdout = String::from_utf8(output.stdout).expect("`cargo tree` output was not UTF-8");

    // The inverted tree always starts with the queried package if it's in the graph.
    if stdout.contains(&format!("{package} v")) {
        return Some(stdout);
    }

    if output.status.success() {
        // Present in the lockfile but not activated by the selected features.
        return None;
    }

    // `cargo tree --invert` also errors outright if the package isn't in the lockfile at all.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("did not match any packages") {
        return None;
    }

    panic!("`cargo tree --invert {package}` failed unexpectedly:\n{stdout}{stderr}",);
}

fn assert_not_in_graph(manifest_path: &Path, package: &str, enabled: &str) {
    let reverse = reverse_dependencies(manifest_path, package);
    assert!(
        reverse.is_none(),
        "with only `{enabled}` enabled, `sqlx` must not pull in `{package}`:\n{}",
        reverse.unwrap_or_default(),
    );
}

fn assert_in_graph(manifest_path: &Path, package: &str, enabled: &str) {
    let reverse = reverse_dependencies(manifest_path, package);
    assert!(
        reverse.is_some(),
        "with `{enabled}` enabled, `sqlx` must pull in `{package}`",
    );
}

#[test]
fn migration_support_is_opt_in() {
    let manifest_path = downstream_project(&["runtime-tokio"]);

    // `sha2` (migration checksums) and `crc` (migrations table names) must not be
    // compiled into a downstream crate that doesn't ask for migration support.
    assert_not_in_graph(&manifest_path, "sha2", "runtime-tokio");
    assert_not_in_graph(&manifest_path, "crc", "runtime-tokio");
}

#[test]
fn migrate_feature_activates_migration_support() {
    let manifest_path = downstream_project(&["runtime-tokio", "migrate"]);

    assert_in_graph(&manifest_path, "sha2", "migrate");
    assert_in_graph(&manifest_path, "crc", "migrate");
}

#[test]
fn macro_dependency_edges_do_not_activate_migration_support() {
    let manifest_path = downstream_project(&["runtime-tokio", "macros", "sqlite"]);

    // The macro crates are allowed to depend on `sha2` at build time (they hash offline
    // query metadata), but it must not be reachable from the runtime crates, and the
    // migration checksum crate `crc` must not be in the graph at all.
    assert_not_in_graph(&manifest_path, "crc", "macros, sqlite");

    if let Some(reverse) = reverse_dependencies(&manifest_path, "sha2") {
        assert!(
            !reverse.contains("sqlx-core"),
            "enabling `macros` must not activate `sqlx-core/migrate`:\n{reverse}",
        );
    }
}
