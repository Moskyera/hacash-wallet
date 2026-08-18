//! THE PROVIDER-SIDE SEAM MAY NOT ESCAPE ITS FEATURE.
//!
//! `AgentWalletManager::provider_side_registry_channel_init`
//! (`crates/agent-wallet-core/src/service/hvm_registry.rs`) is a test-only
//! seam. It exists because a registry `init` asserts `check_signature(left)`
//! **and** `check_signature(g_hub)`, so no channel whose left party is an
//! Agent Wallet can exist on any chain unless that wallet co-signs the
//! provider's opening transaction — and nothing shipped does that. The seam
//! is that one co-signature made callable from outside the crate, so a proof
//! that drives the Tauri command can have a real channel to walk out of.
//!
//! It reads the wallet's blockchain secret. That is the whole reason this file
//! exists.
//!
//! # Five guards, and why one is not enough
//!
//! There are three separate ways this seam can end up in a shipped build, and
//! a guard for one of them is blind to the other two.
//!
//! Three of the guards below were rewritten after review drove a working
//! escape through each of them with the whole file green. What each one was
//! blind to is recorded at the assertion that now catches it, because the
//! failure mode this project keeps hitting is not an absent guard — it is a
//! guard everybody believes is enforcing a boundary it is not enforcing.
//!
//! 1. **The `#[cfg]` is removed or loosened.** Caught by
//!    [`without_the_feature`], which is compiled *only when the feature is
//!    off* and declares a decoy trait method of the same name. Rust resolves
//!    an inherent method before a trait method, so if the real nine-argument
//!    seam is linked into a featureless build the decoy call stops compiling
//!    (`E0061`). This guard is a build failure, not an assertion, which is why
//!    it cannot be satisfied by editing prose.
//!
//! 2. **The feature becomes reachable from a shipped one** — added to
//!    `default`, or pulled in by `agent-wallet-admin`, or enabled on the
//!    dependency line of an app. Guard 1 is *blind* to this: turn the feature
//!    on and guard 1 switches itself off. So
//!    [`the_seam_feature_is_reachable_from_nothing_a_shipped_build_turns_on`]
//!    resolves the feature graph out of **every workspace member**, and
//!    asserts the exact set of `(crate, feature)` pairs that reach it, plus
//!    that no shipped dependency line names a reaching feature. It read five
//!    hand-written manifest paths once; `crates/agent-wallet-runtime` was not
//!    one of them, and one line in it put the seam into the desktop build.
//!
//! 3. **The seam widens** — a second method behind the same gate, a second
//!    builder call, a return type that hands back key material, or a body that
//!    writes the key somewhere while the return type stays honest. Guards 1
//!    and 2 would all stay green.
//!    [`the_gated_block_holds_one_method_that_builds_one_shape_of_transaction`]
//!    names each rule and then pins the whole body exactly, because two of the
//!    three demonstrated escapes were bodies it had no rule for.
//!
//! 4. **The manifests say one thing and cargo resolves another** — a `[patch]`,
//!    a `.cargo/config.toml` passing `--cfg`, a release workflow's own
//!    `--features`. Guard 2 reads TOML; it does not resolve it.
//!    [`cargo_itself_resolves_the_seam_feature_off_in_every_build_that_ships`]
//!    asks cargo, about the default build *and* every configuration a release
//!    really builds with, and proves its own detector on a resolution that
//!    turns the feature on.
//!
//! And one more, because a guard that names a symbol nobody has can pass
//! forever while guarding nothing — this project has shipped three of those:
//! [`with_the_feature`] fails to compile if the seam is renamed or deleted, so
//! the name the other four guards are written against is a name that exists.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The seam. Every guard below is written against this one name, and
/// [`with_the_feature`] is what stops that name from going stale.
const SEAM: &str = "provider_side_registry_channel_init";

/// The feature the seam is confined to. Assembled rather than written so that
/// a repository-wide grep for the feature name does not land in the test that
/// is supposed to be counting its occurrences elsewhere.
fn seam_feature() -> String {
    "on-chain-exit-proof".to_owned()
}

// ---------------------------------------------------------------------------
// GUARD 1: the seam is not linked into a build that did not ask for it.
// ---------------------------------------------------------------------------

/// Compiled only when the feature is **off**.
///
/// The decoy below has the seam's name and takes no arguments. Rust's method
/// resolution prefers an inherent method to a trait method at the same
/// autoref step, so the moment the real seam is present in a featureless build
/// this call resolves to the nine-argument inherent method and the test binary
/// stops compiling.
#[cfg(not(feature = "on-chain-exit-proof"))]
mod without_the_feature {
    use agent_wallet_core::AgentWalletManager;

    /// Nothing but the decoy can produce this value.
    pub struct NoSeamHere;

    trait TheSeamMustNotBeReachable {
        fn provider_side_registry_channel_init(&self) -> NoSeamHere;
    }

    impl TheSeamMustNotBeReachable for AgentWalletManager {
        fn provider_side_registry_channel_init(&self) -> NoSeamHere {
            NoSeamHere
        }
    }

    #[test]
    fn the_provider_side_seam_is_not_linked_into_a_default_build() {
        let root = tempfile::tempdir().expect("a temporary wallet root");
        let manager = AgentWalletManager::open(root.path()).expect("a manager over that root");

        // If this line ever resolves to the real seam, it will not compile:
        // the inherent method takes nine arguments and returns a signed
        // transaction, not `NoSeamHere`.
        let _: NoSeamHere = manager.provider_side_registry_channel_init();
    }
}

/// Compiled only when the feature is **on**, and the reason the guards above
/// are not decorations: they are all written against one spelling of one name,
/// and this is what fails if that spelling stops naming anything.
#[cfg(feature = "on-chain-exit-proof")]
mod with_the_feature {
    use agent_wallet_core::AgentWalletManager;

    #[test]
    fn the_seam_the_other_guards_name_actually_exists() {
        // A rename or a removal is a compile error here, not a silent pass.
        let _seam = AgentWalletManager::provider_side_registry_channel_init;
    }
}

// ---------------------------------------------------------------------------
// Manifests, and the feature graph they really describe.
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The body of a manifest's `[features]` table, comments removed and folded
/// onto one line so that multi-line lists parse the same as single-line ones.
fn features_body(manifest: &str) -> String {
    let mut inside = false;
    let mut body = String::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.contains('"') {
            inside = trimmed == "[features]";
            continue;
        }
        if inside && !trimmed.starts_with('#') {
            body.push_str(trimmed);
            body.push(' ');
        }
    }
    body
}

/// `feature name -> the entries it enables`, exactly as Cargo would read them.
fn features_of(manifest: &str) -> BTreeMap<String, BTreeSet<String>> {
    let body = features_body(manifest);
    let mut out = BTreeMap::new();
    let mut rest = body.as_str();
    while let Some(equals) = rest.find("= [") {
        let name = rest[..equals]
            .split_whitespace()
            .next_back()
            .unwrap_or_default()
            .trim_matches('"')
            .to_owned();
        let after = &rest[equals + 3..];
        let close = after
            .find(']')
            .unwrap_or_else(|| panic!("feature list for {name} never closes"));
        let entries = after[..close]
            .split(',')
            .map(|entry| entry.trim().trim_matches('"').to_owned())
            .filter(|entry| !entry.is_empty())
            .collect();
        out.insert(name, entries);
        rest = &after[close + 1..];
    }
    out
}

/// The `name = "..."` of a manifest's `[package]` table.
fn package_name(manifest: &str) -> String {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("name = ") {
            return rest.trim().trim_matches('"').to_owned();
        }
    }
    panic!("a workspace member manifest declares no package name");
}

/// Every workspace member as `(package name, manifest path)`, taken from the
/// workspace root's own `members` list.
///
/// This used to be five manifest paths written out here, and that is precisely
/// how a guard stops guarding: `crates/agent-wallet-runtime` was not one of
/// the five, it depends on `agent-wallet-core`, and `agent-wallet-admin` pulls
/// it into the desktop build (`crates/wallet-tauri-common/Cargo.toml`, the
/// `dep:agent-wallet-runtime` entry). One line in a manifest this file never
/// opened put the seam's feature into the app people install, with every
/// assertion below still green. The list is the workspace's now, so a crate
/// added tomorrow is covered without anyone remembering to come here.
fn workspace_members() -> Vec<(String, String)> {
    let root = read("Cargo.toml");
    let start = root
        .find("members = [")
        .expect("the workspace root declares its members");
    let after = &root[start + "members = [".len()..];
    let close = after.find(']').expect("the members list closes");
    let members: Vec<String> = after[..close]
        .lines()
        .map(|line| {
            line.trim()
                .trim_end_matches(',')
                .trim_matches('"')
                .to_owned()
        })
        .filter(|entry| !entry.is_empty())
        .collect();
    assert!(
        members.len() >= 12,
        "the workspace member list parsed to {} entries, which is not this workspace; the \
         parser is looking at the wrong thing and every assertion built on it is empty",
        members.len()
    );
    members
        .into_iter()
        .map(|member| {
            let manifest = format!("{member}/Cargo.toml");
            (package_name(&read(&manifest)), manifest)
        })
        .collect()
}

/// The `[features]` table of every workspace member, keyed by package name.
fn feature_graph() -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    let graph: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = workspace_members()
        .into_iter()
        .map(|(name, manifest)| (name, features_of(&read(&manifest))))
        .collect();
    for expected in [
        "agent-wallet-core",
        "wallet-tauri-common",
        "agent-wallet-runtime",
    ] {
        assert!(
            graph.contains_key(expected),
            "the member walk did not reach {expected}, so nothing below says anything about it"
        );
    }
    graph
}

/// Every feature named on a **non-dev** dependency line of a workspace member,
/// as `(member, dependency, feature)`, with comments stripped.
///
/// These are on whenever the depending crate is in the graph at all, so they
/// are invisible to a walk that starts from a feature name — which is the
/// other half of the same hole: `agent-wallet-core = { path = "..", features =
/// ["on-chain-exit-proof"] }` is not a feature of anything and would never
/// appear in the reaching set.
///
/// `[dev-dependencies]` and `[build-dependencies]` are skipped deliberately
/// and not by accident: neither is ever in a shipped build, and a test crate
/// that needs the seam is allowed to ask for it. That is what the feature is
/// for.
fn unconditional_dependency_features() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (member, manifest) in workspace_members() {
        let text = read(&manifest);
        let mut shipped = String::new();
        let mut inside = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // Every shape of dependency table, not just `[dependencies]`:
                // `[target.'cfg(unix)'.dependencies]` and the sub-table form
                // `[dependencies.agent-wallet-core]` both carry a `features`
                // list, and a check that only matched a header *ending* in
                // `dependencies]` would walk straight past the second one.
                // That is the same blind spot this whole function exists to
                // close, one level down.
                let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
                inside = inner.contains("dependencies")
                    && !inner.contains("dev-dependencies")
                    && !inner.contains("build-dependencies");
                continue;
            }
            if !inside || trimmed.starts_with('#') {
                continue;
            }
            shipped.push_str(trimmed);
            shipped.push(' ');
        }
        let mut rest = shipped.as_str();
        while let Some(at) = rest.find("features = [") {
            let before = &rest[..at];
            let dependency = before
                .rsplit_once("= {")
                .map_or(before, |(head, _)| head)
                .split_whitespace()
                .next_back()
                .unwrap_or_default()
                .to_owned();
            let after = &rest[at + "features = [".len()..];
            let close = after.find(']').expect("a dependency features list closes");
            for feature in after[..close].split(',') {
                let feature = feature.trim().trim_matches('"');
                if !feature.is_empty() {
                    out.push((member.clone(), dependency.clone(), feature.to_owned()));
                }
            }
            rest = &after[close + 1..];
        }
    }
    assert!(
        !out.is_empty(),
        "no workspace member names a feature on any dependency line, which this workspace does \
         in several places; the parser found nothing and is guarding nothing"
    );
    out
}

/// The features cargo really resolves for `package` in one build.
///
/// `-e normal` is the graph that becomes a binary: no dev-dependencies, which
/// is where a test crate is entitled to ask for the seam, and no build
/// scripts. `-f "{p} FEATURES={f}"` is what makes this an answer rather than a
/// picture — `-e features` renders manifest feature *edges*, so a feature
/// arriving from anywhere else does not print.
///
/// `None` means the package is not in that graph at all, which is a stronger
/// answer than an empty feature set and is why this is an `Option` rather than
/// an assertion: the mobile app's default build does not contain
/// `agent-wallet-core` in any form.
fn cargo_resolved_features(package: &str, arguments: &[&str]) -> Option<BTreeSet<String>> {
    let cargo = std::env::var("CARGO").expect("cargo runs this test and names itself in CARGO");
    let output = std::process::Command::new(cargo)
        .current_dir(workspace_root())
        .args([
            "tree",
            "--offline",
            "--locked",
            "-e",
            "normal",
            "-f",
            "{p} FEATURES={f}",
        ])
        .args(arguments)
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree {arguments:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let marker = format!("{package} v");
    let mut features = BTreeSet::new();
    let mut found = false;
    for line in text.lines() {
        let Some(at) = line.find(&marker) else {
            continue;
        };
        let Some((_, tail)) = line[at..].split_once("FEATURES=") else {
            continue;
        };
        found = true;
        let list = tail.split_whitespace().next().unwrap_or_default();
        for feature in list.split(',') {
            let feature = feature.trim();
            if !feature.is_empty() {
                features.insert(feature.to_owned());
            }
        }
    }
    found.then_some(features)
}

fn files_under(root: &Path, extension: &str, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            files_under(&path, extension, into);
        } else if path.extension().is_some_and(|found| found == extension) {
            into.push(path);
        }
    }
}

/// Every feature string a release configuration hands to an app build.
///
/// The default build is not what ships: every workflow and script that
/// produces an installable artifact passes `--features` on the tauri build
/// line. Reading them here rather than checking `default` alone is the
/// difference between "the seam is off in a build nobody makes" and "the seam
/// is off in the build people install". These files were named as unaudited by
/// two rounds of review; they are read now.
fn release_build_features() -> BTreeSet<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    files_under(&root.join(".github/workflows"), "yml", &mut files);
    files_under(&root.join("apps"), "ps1", &mut files);
    let mut out = BTreeSet::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines() {
            if !line.contains("tauri") {
                continue;
            }
            let Some((_, tail)) = line.split_once("--features ") else {
                continue;
            };
            for feature in tail
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .split(',')
            {
                let feature = feature.trim();
                if !feature.is_empty() {
                    out.insert(feature.to_owned());
                }
            }
        }
    }
    assert!(
        !out.is_empty(),
        "no release configuration was found to pass `--features` to an app build, so the \
         release-configuration check is empty. Looked in {} files.",
        files.len()
    );
    out
}

/// Does turning on `feature` of `crate_name` end up turning on the seam?
///
/// Follows the same three entry shapes Cargo does: a bare name is a feature of
/// the same crate, `dep/feature` and `dep?/feature` cross to another crate,
/// and `dep:name` only activates an optional dependency.
fn reaches_the_seam(
    graph: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    crate_name: &str,
    feature: &str,
) -> bool {
    let seam = seam_feature();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut stack = vec![(crate_name.to_owned(), feature.to_owned())];
    while let Some((owner, name)) = stack.pop() {
        if owner == "agent-wallet-core" && name == seam {
            return true;
        }
        if !seen.insert((owner.clone(), name.clone())) {
            continue;
        }
        let Some(entries) = graph.get(&owner).and_then(|table| table.get(&name)) else {
            continue;
        };
        for entry in entries {
            if entry.starts_with("dep:") {
                continue;
            }
            match entry.split_once('/') {
                Some((dependency, downstream)) => stack.push((
                    dependency.trim_end_matches('?').to_owned(),
                    downstream.to_owned(),
                )),
                None => stack.push((owner.clone(), entry.clone())),
            }
        }
    }
    false
}

/// GUARD 2. Nothing a shipped build turns on may reach the seam's feature.
///
/// The set is asserted whole rather than as a count: adding a reason for
/// `agent-wallet-admin` — which is exactly what the desktop app enables — to
/// enable the seam has to be a deliberate edit to this list, and cannot be a
/// number that happens to stay the same.
#[test]
fn the_seam_feature_is_reachable_from_nothing_a_shipped_build_turns_on() {
    let graph = feature_graph();
    let seam = seam_feature();

    let mut reaching: BTreeSet<String> = BTreeSet::new();
    for (crate_name, table) in &graph {
        for feature in table.keys() {
            if reaches_the_seam(&graph, crate_name, feature) {
                reaching.insert(format!("{crate_name}::{feature}"));
            }
        }
    }

    let expected = BTreeSet::from([
        format!("agent-wallet-core::{seam}"),
        // The crate that owns the Tauri command, whose own proof drives the
        // seam. Its feature is likewise default-off and reached by nothing.
        format!("wallet-tauri-common::{seam}"),
    ]);
    assert_eq!(
        reaching, expected,
        "a feature that a shipped build can turn on now reaches the provider-side seam. Only \
         the two test-only `{seam}` features may reach it."
    );

    // Said again from the other direction, because the set above would also be
    // satisfied by a manifest that stopped declaring `default` at all.
    for (crate_name, table) in &graph {
        // A crate with no `[features]` table at all has an implicit empty
        // `default` and nothing to say here. A crate that has a table and no
        // `default` in it is the case this catches: the walk below would pass
        // by finding nothing rather than by finding nothing wrong.
        assert!(
            table.is_empty() || table.contains_key("default"),
            "{crate_name} declares features but no longer declares `default`, so the walk below \
             says nothing about its default build"
        );
        assert!(
            !reaches_the_seam(&graph, crate_name, "default"),
            "{crate_name}'s default features now reach the seam"
        );
    }
    for named in ["agent-wallet-core", "wallet-tauri-common"] {
        assert!(
            graph[named].contains_key("default"),
            "{named} stopped declaring a default feature set"
        );
    }

    // The apps enable features on `wallet-tauri-common` at the dependency line
    // itself, which is not a feature of the app and so is not in the set above.
    for app in [
        "apps/desktop/src-tauri/Cargo.toml",
        "apps/mobile/src-tauri/Cargo.toml",
    ] {
        let manifest = read(app);
        assert!(
            !manifest.contains(&seam),
            "{app} names the seam's feature; no app manifest may mention it at all"
        );
        for line in manifest.lines() {
            if !line.contains("wallet-tauri-common = {") {
                continue;
            }
            let Some((_, tail)) = line.split_once("features = [") else {
                continue;
            };
            let (list, _) = tail.split_once(']').expect("a features list closes");
            for entry in list.split(',') {
                let entry = entry.trim().trim_matches('"');
                if entry.is_empty() {
                    continue;
                }
                assert!(
                    !reaches_the_seam(&graph, "wallet-tauri-common", entry),
                    "{app} enables `{entry}` on wallet-tauri-common, and that now reaches the \
                     provider-side seam"
                );
            }
        }
    }

    // And the shape neither check above can see: a features list on a plain
    // dependency line. It is not a feature of anything, so it is in nobody's
    // reaching set, and one such line in a manifest this file did not open put
    // the seam into the desktop build with every assertion above still green.
    // Judged conservatively on purpose — a feature name that reaches the seam
    // in *any* crate may not be named on any shipped dependency line of any
    // member — so it holds without having to resolve which package each line
    // refers to.
    let reaching_names: BTreeSet<String> = reaching
        .iter()
        .filter_map(|pair| pair.split_once("::").map(|(_, name)| name.to_owned()))
        .collect();
    assert!(
        !reaching_names.is_empty(),
        "no feature reaches the seam at all, so the dependency-line check below is empty"
    );
    for (member, dependency, feature) in unconditional_dependency_features() {
        assert!(
            !reaching_names.contains(&feature),
            "{member}'s dependency line for `{dependency}` enables `{feature}`, which reaches \
             the provider-side seam. A dependency line is on whenever that crate is in the \
             graph at all, so this puts the seam into every build containing {member}."
        );
    }
}

/// GUARD 5. Cargo's answer, rather than this file's reading of the manifests.
///
/// Guard 2 parses TOML. Cargo resolves it, and the two can disagree — through
/// a `[patch]`, a `.cargo/config.toml`, a workspace-level default, or simply a
/// manifest shape this file does not model. The previous round wrote that gap
/// down as a known limit and left it open; a limit that is only written down
/// is still a limit. So this asks cargo directly, about the two things anybody
/// ships, resolved with default features.
///
/// The positive control is the point of it. A grep that can only ever find
/// nothing passes forever while meaning nothing — the exact failure this
/// project has now shipped three of — so the same detector is pointed at a
/// resolution that *does* enable the feature and is required to find it there.
#[test]
fn cargo_itself_resolves_the_seam_feature_off_in_every_build_that_ships() {
    let seam = seam_feature();

    // The detector first, so a broken detector fails here rather than handing
    // out a column of silent all-clears below it. `wallet-tauri-common` is the
    // crate whose own test-only feature forwards to the seam's, so this is a
    // resolution that really does turn it on, measured by the same function.
    let control = cargo_resolved_features(
        "agent-wallet-core",
        &["-p", "wallet-tauri-common", "--features", &seam],
    )
    .expect("the control resolution contains agent-wallet-core");
    assert!(
        control.contains(&seam),
        "the detector cannot see `{seam}` even in a resolution that turns it on, so every \
         assertion below says nothing. It saw: {control:#?}"
    );

    let apps = [
        ("desktop", "apps/desktop/src-tauri/Cargo.toml"),
        ("mobile", "apps/mobile/src-tauri/Cargo.toml"),
    ];
    let graph = feature_graph();
    let release = release_build_features();
    let mut release_configurations_checked = 0usize;
    let mut resolutions_actually_containing_the_crate = 0usize;

    for (name, manifest) in apps {
        let app_package = package_name(&read(manifest));
        let declared = &graph[&app_package];

        // The default build, and every configuration a release really builds
        // with — which is not the default one.
        let mut configurations: Vec<Vec<&str>> = vec![vec!["--manifest-path", manifest]];
        for feature in &release {
            if !declared.contains_key(feature) {
                continue;
            }
            release_configurations_checked += 1;
            configurations.push(vec!["--manifest-path", manifest, "--features", feature]);
        }

        for arguments in configurations {
            // `None` is the strongest possible pass: agent-wallet-core is not
            // in that graph at all.
            let Some(resolved) = cargo_resolved_features("agent-wallet-core", &arguments) else {
                continue;
            };
            resolutions_actually_containing_the_crate += 1;
            assert!(
                !resolved.contains(&seam),
                "cargo resolves `{seam}` ON for the {name} app built as {arguments:?} — the \
                 seam is in the binary people install. agent-wallet-core resolved to: \
                 {resolved:#?}"
            );
        }
    }
    assert!(
        release_configurations_checked >= 2,
        "only {release_configurations_checked} release configuration(s) were resolved; the \
         release configurations found ({release:#?}) match no feature either app declares, so \
         this test checked the default build and nothing else"
    );
    assert!(
        resolutions_actually_containing_the_crate >= 2,
        "agent-wallet-core appeared in only {resolutions_actually_containing_the_crate} of the \
         resolutions above, so almost nothing was measured"
    );

    // A cargo config cannot enable a cargo feature, but `[build] rustflags`
    // can pass `--cfg feature="..."`, which is the same thing to the `#[cfg]`
    // on the seam and is invisible to every other check in this file.
    for candidate in [
        ".cargo/config.toml",
        ".cargo/config",
        "apps/desktop/src-tauri/.cargo/config.toml",
        "apps/mobile/src-tauri/.cargo/config.toml",
        "crates/agent-wallet-core/.cargo/config.toml",
    ] {
        let path = workspace_root().join(candidate);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        assert!(
            !text.contains(&seam),
            "{candidate} names `{seam}`. A cargo config can hand `--cfg feature=\"{seam}\"` to \
             rustc, which switches the seam on with every manifest untouched."
        );
    }
}

// ---------------------------------------------------------------------------
// GUARD 3: the seam stays one method that builds one shape of transaction.
// ---------------------------------------------------------------------------

/// Everything in a source file a build actually ships: no comment lines.
///
/// A `contains` cannot tell code from prose, and a guard that can be satisfied
/// by writing a comment about the thing it demands is a guard that will be.
fn without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn source_files(root: &Path, into: &mut Vec<(PathBuf, String)>) {
    for entry in fs::read_dir(root).unwrap_or_else(|e| panic!("read {}: {e}", root.display())) {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            source_files(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("source file is utf-8");
            into.push((path, without_comments(&text)));
        }
    }
}

fn crate_sources() -> Vec<(PathBuf, String)> {
    let mut sources = Vec::new();
    source_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    assert!(
        sources.len() > 20,
        "the source walk found only {} files; it is looking in the wrong place",
        sources.len()
    );
    sources
}

/// The `{ .. }` that follows `header`, brace-matched.
fn block_after(source: &str, header: &str) -> String {
    let start = source
        .find(header)
        .unwrap_or_else(|| panic!("the source does not contain:\n{header}"));
    let open = start + header.len() - 1;
    let mut depth = 0usize;
    for (index, byte) in source.bytes().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[open..=index].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("the block opened by\n{header}\nnever closes");
}

/// GUARD 3. One gate, directly on one `impl`, holding one method, which builds
/// one shape of transaction and returns no key material.
#[test]
fn the_gated_block_holds_one_method_that_builds_one_shape_of_transaction() {
    let seam_feature = seam_feature();
    let gate = format!("#[cfg(feature = \"{seam_feature}\")]");
    let sources = crate_sources();

    // The seam is declared once, in shipped source, in the file this guard is
    // about. A second copy anywhere is a second door.
    let declarations: Vec<String> = sources
        .iter()
        .flat_map(|(path, text)| {
            text.lines()
                .filter(|line| line.contains(&format!("fn {SEAM}")))
                .map(move |line| format!("{}: {}", path.display(), line.trim()))
        })
        .collect();
    assert_eq!(
        declarations.len(),
        1,
        "the provider-side seam must be declared exactly once. Found {}: {declarations:#?}",
        declarations.len()
    );
    assert!(
        declarations[0]
            .replace('\\', "/")
            .contains("agent-wallet-core/src/service/hvm_registry.rs"),
        "the seam moved out of the module whose whole subject is this rule: {declarations:#?}"
    );

    // Exactly two mentions of the feature in shipped source across the crate:
    // the gate on the seam's `impl`, and the gate on the on-chain proof's own
    // test module. A third is a second thing hiding behind a test-only door.
    let mentions: Vec<String> = sources
        .iter()
        .flat_map(|(path, text)| {
            text.lines()
                .filter(|line| line.contains(&format!("feature = \"{seam_feature}\"")))
                .map(move |line| format!("{}: {}", path.display(), line.trim()))
        })
        .collect();
    assert_eq!(
        mentions.len(),
        2,
        "the seam's feature must gate exactly two things in this crate: the seam's `impl`, and \
         the on-chain proof's test module. Found {}: {mentions:#?}",
        mentions.len()
    );
    assert_eq!(
        mentions.iter().filter(|line| line.contains(&gate)).count(),
        1
    );
    assert_eq!(
        mentions
            .iter()
            .filter(
                |line| line.contains(&format!("#[cfg(all(test, feature = \"{seam_feature}\"))]"))
            )
            .count(),
        1
    );

    // The gate sits directly on the `impl` that holds the seam - not on a
    // module three levels up whose other contents nobody re-counts.
    let registry = &sources
        .iter()
        .find(|(path, _)| path.ends_with("hvm_registry.rs"))
        .expect("the registry module")
        .1;
    let header = format!("{gate}\nimpl AgentWalletManager {{");
    let block = block_after(registry, &header);

    assert_eq!(
        block.matches("fn ").count(),
        1,
        "the gated block must hold exactly one function. It now holds {}:\n{block}",
        block.matches("fn ").count()
    );
    assert!(
        block.contains(&format!("pub fn {SEAM}")),
        "the one function behind the gate is no longer the seam:\n{block}"
    );

    // One builder call OF ANY KIND, and it is the channel `init`.
    //
    // This counted `build_hvm_registry_pilot_` and nothing else, and that is a
    // prefix rather than a rule: `l2_fast_pay_hub::hvm_pilot::
    // build_hvm_pilot_exact_funding` is a plain HAC transfer to a caller-named
    // address, returns the identical `HvmPilotSignedTransaction`, skips the
    // canonical-deployment check the init path applies, and does not match
    // that prefix. Added behind this gate it compiled, linked and left every
    // assertion in this file green. So the count is on `build_` now.
    assert_eq!(
        block.matches("build_").count(),
        1,
        "the gated block calls more than one builder. Every one of them is a shape of \
         transaction this wallet's key can be made to sign:\n{block}"
    );
    assert!(
        block.contains("build_hvm_registry_pilot_channel_init("),
        "the gated block no longer builds the registry channel init:\n{block}"
    );

    // The secret is read once, and the only thing it is handed to is the
    // account constructor.
    //
    // The `-> {forbidden}` checks below are about the return type, and a
    // return type cannot see `fs::write(path, secrets.blockchain_secret_hex())`
    // in the body. That leaves the wallet's raw private key in plaintext on
    // disk with the signature, the return type and every other assertion here
    // untouched; it was tried, and it passed.
    assert_eq!(
        block.matches("blockchain_secret_hex").count(),
        1,
        "the gated block reads the blockchain secret more than once. It needs it exactly once, \
         to build the account that signs:\n{block}"
    );
    assert_eq!(
        block.matches("secrets").count(),
        3,
        "the unlocked secrets handle must be bound once, read once and dropped — three \
         mentions. It now has {}:\n{block}",
        block.matches("secrets").count()
    );
    let flat = block.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("WalletAccount::from_secret_hex( secrets.blockchain_secret_hex(), )"),
        "the one read of the blockchain secret is no longer the argument to the account \
         constructor, so the key now goes somewhere else as well:\n{block}"
    );
    assert!(
        flat.contains("drop(secrets);"),
        "the gated block no longer drops the unlocked secrets:\n{block}"
    );

    // The three-way agreement between registry entry, vault and wallet_id that
    // `create_agent_wallet_backup` demands before it will open a vault at all
    // (service/backup.rs). The seam did not have it, which made it a weaker
    // door than the shipped code beside it on the one axis its whole safety
    // argument rests on. Pinned here so it cannot be quietly dropped again.
    assert!(
        block.contains("vault.wallet_id() != wallet_id || vault.address() != entry.address"),
        "the seam stopped checking that the vault it opened belongs to the wallet it was asked \
         about, so a vault file swapped under a wallet directory now signs an `init` under a \
         wallet_id it does not belong to:\n{block}"
    );

    // It is no weaker a gate than the vault's own, and the key it reads does
    // not come back out.
    assert!(
        block.contains("passphrase: &str") && block.contains("vault.unlock(passphrase)"),
        "the seam stopped demanding the passphrase:\n{block}"
    );
    assert_eq!(
        block.matches("-> AgentWalletResult<").count(),
        1,
        "the gated block returns more than one kind of value:\n{block}"
    );
    assert!(
        block.contains(
            "-> AgentWalletResult<l2_fast_pay_hub::hvm_pilot::HvmPilotSignedTransaction>"
        ),
        "the seam's return type changed; it may hand back one signed init and nothing else:\n{block}"
    );
    for forbidden in [
        "secret_hex",
        "secret_key",
        "AgentEncryptedSecrets",
        "WalletAccount>",
        "sign_",
    ] {
        assert!(
            !block.contains(&format!("-> {forbidden}")),
            "the seam now returns `{forbidden}`, which is key material or a signing handle:\n\
             {block}"
        );
    }

    // And finally the whole body, pinned exactly.
    //
    // Every assertion above names one rule, and every one of them was written
    // after somebody found the way around the last one. Two of the three ways
    // around this guard that have been demonstrated were bodies it had no rule
    // for, and there is no reason to think the list of rules is finished. This
    // is the catch-all: twenty lines that should never change, and if they do,
    // changing them is a decision somebody makes here in the open rather than
    // a diff nobody re-reads.
    //
    // If this fires and the change was deliberate: read the new body against
    // the claims in the doc comment above the seam, satisfy yourself that each
    // one still holds, then update the text below. Do not delete this.
    let expected = [
        "{ #[allow(clippy::too_many_arguments)]",
        "pub fn provider_side_registry_channel_init(",
        "&self, wallet_id: &AgentWalletId, passphrase: &str, hub: &sys::Account,",
        "contract_address: &str,",
        "network: &l2_fast_pay_hub::hvm_pilot::HvmLocalPilotNetwork,",
        "parameters: &l2_fast_pay_hub::hvm_registry_pilot::HvmRegistryPilotChannelParameters,",
        "network_fee_zhu: u64, timestamp: u64, gas_max: u8, )",
        "-> AgentWalletResult<l2_fast_pay_hub::hvm_pilot::HvmPilotSignedTransaction> {",
        "let registry = self.storage.load_registry()?;",
        "let entry = registry .wallet(wallet_id)",
        ".ok_or(AgentWalletError::AgentWalletNotFound)?;",
        "let paths = self.storage.paths(wallet_id)?;",
        "let vault = crate::vault::AgentEncryptedVault::load(&paths.vault_path())?;",
        "if vault.wallet_id() != wallet_id || vault.address() != entry.address {",
        "return Err(AgentWalletError::SigningBlocked); }",
        "let secrets = vault.unlock(passphrase)?;",
        "let left = hacash_wallet_core::account::WalletAccount::from_secret_hex(",
        "secrets.blockchain_secret_hex(), )",
        ".map_err(|_| AgentWalletError::SigningBlocked)?;",
        "drop(secrets);",
        "l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_channel_init(",
        "left.inner(), hub, contract_address, network, parameters, network_fee_zhu,",
        "timestamp, gas_max, ) .map_err(|_| AgentWalletError::SigningBlocked) } }",
    ]
    .join(" ");
    assert_eq!(
        flat, expected,
        "the body behind the test-only gate is not the body this guard was written about. \
         Nothing above may be assumed to still mean what it says."
    );
}
