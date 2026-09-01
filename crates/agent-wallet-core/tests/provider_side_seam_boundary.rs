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
//!    "One shape of transaction" was once one string: the block had to mention
//!    `build_hvm_registry_pilot_` exactly once. `build_hvm_pilot_exact_funding`
//!    — a HAC transfer from `left` to any address the caller names — is not
//!    spelled that way, and went through. It is now measured against the whole
//!    set of names the Hub crate uses to yield an `HvmPilotSignedTransaction`,
//!    read out of that crate at test time by [`hub_transaction_builders`]; the
//!    one call is required to be spelled with its crate path, and no file in
//!    this crate may shadow that path. And because that escape worked by
//!    *adding* a builder rather than replacing one, the block is also pinned
//!    to a single branch, a single `return` that only refuses, and a builder
//!    call that is the tail expression. A seam with two exits is a seam that
//!    chooses.
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

/// Every manifest a build of anything in this workspace reads: the members,
/// and the workspace root they all inherit from.
fn manifests_a_build_reads() -> Vec<(String, String)> {
    let mut out = workspace_members();
    out.push(("the workspace root".to_owned(), "Cargo.toml".to_owned()));
    out
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
///
/// The workspace root is walked alongside the members, and it is not one more
/// file remembered. It is the one manifest that is *not* a member and that
/// every member can inherit from: `[workspace.dependencies] agent-wallet-core
/// = { path = "..", features = ["on-chain-exit-proof"] }` plus a member's
/// `agent-wallet-core.workspace = true` puts the seam in that member's build
/// with no member manifest naming the feature anywhere. A previous round of
/// review drove exactly that through here.
fn unconditional_dependency_features() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (member, manifest) in manifests_a_build_reads() {
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
    // A resolution that cannot even be attempted offline is not evidence
    // about features, so it must not read as one. CI passes --offline with a
    // cache built from the features CI actually compiles, and the CONTROL arm
    // of this test deliberately asks for a feature no shipped build turns on,
    // so its dependencies are legitimately absent from that cache and cargo
    // cannot resolve it at all. `None` says "no answer" rather than "feature
    // off", and the caller already treats those differently. The
    // shipped-build arms still have to resolve, because their dependencies
    // are exactly what CI built.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && stderr.contains("--offline was specified") {
        return None;
    }
    assert!(
        output.status.success(),
        "cargo tree {arguments:?} failed:
{stderr}"
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

    // Only the two crates that *declare* the feature may name it at all.
    //
    // This opened two app manifests by name and read one dependency line out
    // of each. A third app is a third manifest, and a workspace with three
    // apps in it is a workspace this list is silently not about — which is
    // hole 1 all over again, one level up. The set is the workspace's now,
    // plus the root every member inherits from.
    // A crate that *declares* a feature of this name is skipped, and skipping
    // it costs nothing: what its declaration enables was already walked by the
    // reaching set above, which is asserted whole. Three crates declare one —
    // agent-wallet-core, wallet-tauri-common and hacash-wallet-core, whose own
    // `on-chain-exit-proof` reaches the Hub crate's pilot tools and not this
    // seam — and they are found rather than named, so a fourth is judged by
    // the same walk instead of being added here.
    let declares_it: BTreeSet<&str> = graph
        .iter()
        .filter(|(_, table)| table.contains_key(&seam))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        declares_it.contains("agent-wallet-core"),
        "agent-wallet-core no longer declares the seam's feature, so the walk above resolved \
         nothing"
    );
    for (member, manifest) in manifests_a_build_reads() {
        if declares_it.contains(member.as_str()) {
            continue;
        }
        assert!(
            !read(&manifest).contains(&seam),
            "{manifest} ({member}) names the seam's feature. Only the two crates that declare \
             it may mention it at all — every other manifest naming it is a way to switch it \
             on from somewhere nobody looks."
        );
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
    // `None` means cargo could not resolve at all, which offline it cannot:
    // this arm asks for a feature no shipped build turns on, so its
    // dependencies are absent from a cache built from what CI compiles. That
    // is a missing answer, not a clean one, so the control is skipped rather
    // than read as a pass - and it says so out loud, because a silently
    // skipped control is exactly the all-clear this test exists to refuse.
    match cargo_resolved_features(
        "agent-wallet-core",
        &["-p", "wallet-tauri-common", "--features", &seam],
    ) {
        Some(control) => assert!(
            control.contains(&seam),
            "the detector cannot see `{seam}` even where it is turned on, so every \
             assertion below says nothing. It saw: {control:#?}"
        ),
        None => println!(
            "  CONTROL SKIPPED: cargo cannot resolve `{seam}` offline, so this run shows \
             the shipped builds have it off without showing the detector could see it on"
        ),
    }

    // Every workspace member, not two app manifests named here.
    //
    // This resolved `apps/desktop/src-tauri/Cargo.toml` and
    // `apps/mobile/src-tauri/Cargo.toml`, written out in an array — inside the
    // guard whose whole justification is that it reads every manifest because
    // the resolver does. A third app added to the workspace, inheriting
    // `features = ["on-chain-exit-proof"]` from the root's
    // `[workspace.dependencies]`, resolved the seam ON for a shipped binary
    // with all four tests green, and neither `>= 2` floor below even
    // degraded, because desktop and mobile still met them. The list is the
    // workspace's now, so an app added tomorrow is resolved without anyone
    // remembering to come here.
    let members = workspace_members();
    let graph = feature_graph();
    let release = release_build_features();
    let mut release_configurations_checked = 0usize;
    let mut resolutions_actually_containing_the_crate = 0usize;

    for (member, _) in &members {
        let declared = &graph[member];

        // The default build, and every configuration a release really builds
        // with — which is not the default one.
        let mut configurations: Vec<Vec<String>> = vec![vec!["-p".to_owned(), member.clone()]];
        for feature in &release {
            if !declared.contains_key(feature) {
                continue;
            }
            release_configurations_checked += 1;
            configurations.push(vec![
                "-p".to_owned(),
                member.clone(),
                "--features".to_owned(),
                feature.clone(),
            ]);
        }

        for arguments in configurations {
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            // `None` is the strongest possible pass: agent-wallet-core is not
            // in that graph at all.
            let Some(resolved) = cargo_resolved_features("agent-wallet-core", &borrowed) else {
                continue;
            };
            resolutions_actually_containing_the_crate += 1;
            assert!(
                !resolved.contains(&seam),
                "cargo resolves `{seam}` ON for {member} built as {arguments:?} — the seam is \
                 in a binary people install. agent-wallet-core resolved to: {resolved:#?}"
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
    //
    // Cargo reads a config from the directory a build is started in and from
    // every directory above it, so that is the set walked here — derived from
    // where the members are rather than from five paths written down, for the
    // same reason as everything else in this file.
    let mut directories: BTreeSet<PathBuf> = BTreeSet::from([workspace_root()]);
    for (_, manifest) in &members {
        let mut directory = workspace_root().join(manifest);
        directory.pop();
        while directory.starts_with(workspace_root()) {
            directories.insert(directory.clone());
            if !directory.pop() {
                break;
            }
        }
    }
    for directory in &directories {
        for name in ["config.toml", "config"] {
            let path = directory.join(".cargo").join(name);
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            assert!(
                !text.contains(&seam),
                "{} names `{seam}`. A cargo config can hand `--cfg feature=\"{seam}\"` to \
                 rustc, which switches the seam on with every manifest untouched.",
                path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// GUARD 3: the seam stays one method that builds one shape of transaction.
// ---------------------------------------------------------------------------

/// Everything in a source file a build actually ships: no comments of any
/// kind.
///
/// A `contains` cannot tell code from prose, and a guard that can be satisfied
/// by writing a comment about the thing it demands is a guard that will be.
///
/// This dropped whole `//` lines and nothing else, which is only half of that
/// sentence and got the other half backwards. `drop(secrets); // the key is
/// gone before the builder runs` and a `/* .. */` naming the other builder
/// both survived into the text every rule below counts, so an ordinary
/// explanatory comment was read as a changed body and as a second builder
/// call. Prose that *names* the dangerous thing is not the dangerous thing,
/// in either direction.
///
/// So comments are removed by a scanner that knows where a comment can and
/// cannot begin. String literals, raw string literals and character literals
/// are copied through untouched, because `"https://"` must not open a line
/// comment and `'"'` — which the Hub crate really contains — must not open a
/// string. Block comments nest, as they do in Rust. Lines left blank by the
/// removal are dropped, which is what the line filter did before, so the text
/// the callers below read has the same shape it always had.
fn without_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let identifier = |index: usize| -> bool {
        index > 0 && (chars[index - 1].is_alphanumeric() || chars[index - 1] == '_')
    };
    let mut out = String::with_capacity(source.len());
    let mut index = 0usize;
    while index < chars.len() {
        // `// ..` to the end of the line.
        if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        // `/* .. */`, which nests.
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            let mut depth = 0usize;
            while index < chars.len() {
                if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
                    depth += 1;
                    index += 2;
                } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                    depth -= 1;
                    index += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[index] == '\n' {
                        out.push('\n');
                    }
                    index += 1;
                }
            }
            continue;
        }
        // A raw string, `r"..."` / `r#".."#` and the byte-string spellings:
        // no escapes inside, so it is closed only by a quote and as many
        // hashes as opened it.
        let raw = (chars[index] == 'r' && !identifier(index))
            || (chars[index] == 'r'
                && index > 0
                && chars[index - 1] == 'b'
                && !identifier(index - 1));
        if raw {
            let mut cursor = index + 1;
            while chars.get(cursor) == Some(&'#') {
                cursor += 1;
            }
            if chars.get(cursor) == Some(&'"') {
                let hashes = cursor - index - 1;
                for character in &chars[index..=cursor] {
                    out.push(*character);
                }
                index = cursor + 1;
                while index < chars.len() {
                    if chars[index] == '"'
                        && chars[index + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|character| **character == '#')
                            .count()
                            == hashes
                    {
                        for character in &chars[index..=index + hashes] {
                            out.push(*character);
                        }
                        index += hashes + 1;
                        break;
                    }
                    out.push(chars[index]);
                    index += 1;
                }
                continue;
            }
        }
        // An ordinary string, with escapes.
        if chars[index] == '"' {
            out.push('"');
            index += 1;
            while index < chars.len() {
                let character = chars[index];
                out.push(character);
                index += 1;
                if character == '\\' {
                    if let Some(escaped) = chars.get(index) {
                        out.push(*escaped);
                        index += 1;
                    }
                } else if character == '"' {
                    break;
                }
            }
            continue;
        }
        // A character literal, told from a lifetime by whether it closes:
        // `'"'` and `'/'` are literals and must not open a string or a
        // comment, and `&'a str` is a lifetime and must not swallow the file.
        if chars[index] == '\'' {
            let close = if chars.get(index + 1) == Some(&'\\') {
                chars[index + 2..]
                    .iter()
                    .take(10)
                    .position(|character| *character == '\'')
                    .map(|at| index + 2 + at)
            } else {
                (chars.get(index + 2) == Some(&'\'')).then_some(index + 2)
            };
            if let Some(close) = close {
                for character in &chars[index..=close] {
                    out.push(*character);
                }
                index = close + 1;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out.lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The same text with every whitespace character removed.
///
/// Whitespace is where a `#[cfg]` hid. `#[cfg(feature="on-chain-exit-proof")]`
/// is the same attribute to rustc as the one written with spaces around the
/// `=`, and a rule that matched the spelling with spaces counted one gate
/// where the compiler saw two.
fn without_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Every `#[..]` attribute in `squeezed` — whitespace already removed — that
/// contains `needle`, paired with the beginning of whatever it is attached to.
///
/// The whole attribute rather than the line it is on, because a `#[cfg]` split
/// across lines is one attribute to the compiler and two lines to a line
/// filter, and the compiler is the one that decides what gets built.
fn attributes_containing(squeezed: &str, needle: &str) -> Vec<(String, String)> {
    let bytes = squeezed.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = squeezed[from..].find(needle) {
        let at = from + found;
        from = at + needle.len();
        let loose = || {
            (
                squeezed[at..].chars().take(90).collect::<String>(),
                String::new(),
            )
        };
        let Some(hash) = squeezed[..at].rfind("#[") else {
            out.push(loose());
            continue;
        };
        let open = hash + 1;
        let mut depth = 0usize;
        let mut close = None;
        for (index, byte) in bytes.iter().enumerate().skip(open) {
            match byte {
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        match close.filter(|close| *close > at) {
            Some(close) => out.push((
                squeezed[hash..=close].to_owned(),
                squeezed[close + 1..].chars().take(60).collect(),
            )),
            None => out.push(loose()),
        }
    }
    out
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

/// Every name the Hub crate uses to hand out an `HvmPilotSignedTransaction`.
///
/// Read out of that crate's source, not written down here, because a written
/// list is exactly what failed. This guard used to assert
/// `block.matches("build_hvm_registry_pilot_").count() == 1` — one prefix —
/// and `l2_fast_pay_hub::hvm_pilot::build_hvm_pilot_exact_funding`
/// (`crates/l2-fast-pay-hub/src/hvm_pilot.rs:1240`) is a plain HAC transfer
/// from `left` to an arbitrary contract address, returns the identical
/// `HvmPilotSignedTransaction`, skips the canonical-deployment check the init
/// path applies at `hvm_registry_pilot.rs:467`, and does not match that
/// prefix. Behind this gate it compiled, linked, and left the whole file
/// green with the feature both on and off.
///
/// So the question the guard asks changed. Not "does the block mention the
/// one string I thought of" but "of every way that crate has of producing
/// signed transaction bytes, which ones does this block call". Adding a
/// builder to the Hub crate adds it to this set on the next run without
/// anybody remembering to come here.
///
/// A `fn` counts if the text between its parameter list and its body names
/// the type: that catches the free builders, the `impl` methods, and the
/// accessors alike. Accessors are deliberately not filtered out — a name that
/// hands out one of these is a name this block may not call, whatever it does
/// internally.
fn hub_transaction_builders() -> BTreeSet<String> {
    let root = workspace_root().join("crates/l2-fast-pay-hub/src");
    let mut files = Vec::new();
    source_files(&root, &mut files);
    assert!(
        files.len() > 20,
        "the Hub source walk found only {} file(s) under {}. An empty or tiny set here would \
         let every builder in the workspace through the check below.",
        files.len(),
        root.display()
    );

    let mut out = BTreeSet::new();
    for (_, text) in &files {
        let bytes = text.as_bytes();
        let mut cursor = 0usize;
        while let Some(offset) = text[cursor..].find("fn ") {
            let at = cursor + offset;
            cursor = at + 3;
            // `fn` the keyword, not the tail of some identifier ending in fn.
            if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
                continue;
            }
            let name: String = text[at + 3..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let Some(open) = text[at..].find('(').map(|index| at + index) else {
                continue;
            };
            let mut depth = 0usize;
            let mut close = None;
            for (index, byte) in bytes.iter().enumerate().skip(open) {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(index);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else {
                continue;
            };
            let tail = &text[close + 1..];
            let end = tail.find(['{', ';']).unwrap_or(tail.len());
            if tail[..end].contains("HvmPilotSignedTransaction") {
                out.insert(name);
            }
        }
    }
    out
}

/// Every function a block actually **calls**, as `(the path spelled at the
/// call site, whether it is a method call on some receiver)`.
///
/// `contains` cannot tell a call from a mention and cannot tell
/// `build_hvm_registry_pilot_channel_init(..)` — whatever that resolves to
/// here — from `l2_fast_pay_hub::hvm_registry_pilot::build_..(..)`, which is
/// the difference between the reviewed builder and a same-named forwarder
/// defined three lines above the gate.
///
/// The second half of the pair is what stops an honest change in another
/// crate from reading as a break in this one. The Hub-builder rule below
/// matched on the **leaf** name, so the day the Hub crate gained an ordinary
/// `HvmPilotSignedTransaction::load`, this block's own
/// `AgentEncryptedVault::load` — a line nobody had touched, in a different
/// crate from the one being edited — became a second builder call and a key
/// -material alarm. A method call and a qualified path are not names the Hub
/// crate can collide with. A bare `build_..(..)` is, and that is the one
/// shape that still has to be judged by name.
fn call_targets(block: &str) -> Vec<(String, bool)> {
    let bytes = block.as_bytes();
    let mut out = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'(' {
            continue;
        }
        let mut start = index;
        while start > 0 {
            let previous = bytes[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b':' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == index {
            continue;
        }
        let mut before = start;
        while before > 0 && bytes[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        let method = before > 0 && bytes[before - 1] == b'.';
        let target = block[start..index].trim_start_matches(':');
        if !target.is_empty() {
            out.push((target.to_owned(), method));
        }
    }
    out
}

/// The calls in `block` that hand back one of the Hub crate's signed
/// transactions: a free function, either written with the Hub crate's own path
/// or written bare with a name only that crate has.
fn hub_builder_calls(block: &str, builders: &BTreeSet<String>) -> Vec<String> {
    call_targets(block)
        .into_iter()
        .filter(|(target, method)| {
            !method
                && (target.contains("l2_fast_pay_hub::")
                    || (!target.contains("::") && builders.contains(target.as_str())))
        })
        .map(|(target, _)| target)
        .collect()
}

/// The index of the `)` that closes the `(` at `open`.
fn matching_paren(text: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (index, byte) in text.bytes().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    panic!("the argument list opened at {open} never closes:\n{text}")
}

/// The body of every `if` in `block`, brace-matched.
///
/// The rule these feed used to be `if ` counted once, which is not the
/// property anybody wanted and made the seam's own documented weakness
/// unfixable — see the assertion that reads them.
fn branch_bodies(block: &str) -> Vec<String> {
    let mut out = Vec::new();
    for at in identifier_offsets(block, "if") {
        let Some(offset) = block[at..].find('{') else {
            continue;
        };
        let open = at + offset;
        let mut depth = 0usize;
        for (index, byte) in block.bytes().enumerate().skip(open) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(block[open + 1..index].trim().to_owned());
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Every declaration of `dependency` in `manifest`, in whatever shape it is
/// written: an inline table, a bare version, a `name.workspace = true` line,
/// or a `[dependencies.name]` sub-table.
///
/// One spelling used to be pinned — `path = "../l2-fast-pay-hub"` — so the
/// ordinary hygiene of moving the Hub to a workspace dependency reported that
/// "the `l2_fast_pay_hub` the seam calls is no longer the workspace's Hub
/// crate", which was the opposite of what had happened.
fn dependency_declarations(manifest: &str, dependency: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut sub_table: Option<String> = None;
    let mut inside_dependencies = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.contains('"') {
            if let Some(collected) = sub_table.take() {
                out.push(collected);
            }
            let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
            inside_dependencies = inner.contains("dependencies")
                && !inner.contains("dev-dependencies")
                && !inner.contains("build-dependencies");
            if inside_dependencies && inner.ends_with(&format!(".{dependency}")) {
                sub_table = Some(String::new());
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(collected) = sub_table.as_mut() {
            collected.push_str(trimmed);
            collected.push(' ');
            continue;
        }
        if inside_dependencies
            && (trimmed.starts_with(&format!("{dependency} "))
                || trimmed.starts_with(&format!("{dependency}="))
                || trimmed.starts_with(&format!("{dependency}.")))
        {
            out.push(trimmed.to_owned());
        }
    }
    if let Some(collected) = sub_table.take() {
        out.push(collected);
    }
    out
}

// ---------------------------------------------------------------------------
// What the body DOES with the key, which is not what it returns.
// ---------------------------------------------------------------------------

/// The two calls that put key material into a binding in this block.
///
/// Written as whole call paths rather than as substrings, so that a different
/// unlock or a different constructor is a failure to find them at all rather
/// than a quiet match on something else.
const SECRETS_COME_FROM: &str = "vault.unlock";
const ACCOUNT_COMES_FROM: &str = "hacash_wallet_core::account::WalletAccount::from_secret_hex";

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_path_byte(byte: u8) -> bool {
    is_identifier_byte(byte) || byte == b':' || byte == b'.'
}

/// Every occurrence of `name` as a whole identifier, by byte offset.
///
/// Whole-identifier, because `secrets` occurs inside no other name here but
/// `left` occurs inside `left_deposit_zhu`, and a check that counted
/// substrings would be counting the wrong things in both directions.
fn identifier_offsets(block: &str, name: &str) -> Vec<usize> {
    let bytes = block.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = block[from..].find(name) {
        let at = from + found;
        let end = at + name.len();
        let opens = at == 0 || !is_identifier_byte(bytes[at - 1]);
        let closes = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if opens && closes {
            out.push(at);
        }
        from = end;
    }
    out
}

/// The `a::b.c` path written immediately before `end`, skipping whitespace.
fn path_before(block: &str, end: usize) -> String {
    let bytes = block.as_bytes();
    let mut stop = end;
    while stop > 0 && bytes[stop - 1].is_ascii_whitespace() {
        stop -= 1;
    }
    let mut start = stop;
    while start > 0 && is_path_byte(bytes[start - 1]) {
        start -= 1;
    }
    block[start..stop].trim_start_matches(['.', ':']).to_owned()
}

/// The `a::b.c` path `text` begins with.
fn path_at(text: &str) -> String {
    text.bytes()
        .take_while(|byte| is_path_byte(*byte))
        .map(char::from)
        .collect()
}

/// The call whose argument list **directly** contains the byte at `at`.
///
/// `None` is the answer that matters. For key material, "handed to nothing"
/// is what a new binding, an assignment and a bare statement all look like —
/// every one of which is the key coming to rest somewhere this function was
/// not asked to put it.
fn receiving_call(block: &str, at: usize) -> Option<String> {
    let bytes = block.as_bytes();
    let mut depth = 0usize;
    let mut index = at;
    while index > 0 {
        index -= 1;
        match bytes[index] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' => {
                if depth == 0 {
                    if bytes[index] != b'(' {
                        return None;
                    }
                    let callee = path_before(block, index);
                    return (!callee.is_empty()).then_some(callee);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// Does `head` end in `keyword` as a word rather than as a tail of a name?
fn ends_with_keyword(head: &str, keyword: &str) -> bool {
    head.ends_with(keyword)
        && (head.len() == keyword.len()
            || !is_identifier_byte(head.as_bytes()[head.len() - keyword.len() - 1]))
}

/// `(name, the path its initializer calls)` for every `let` in `block`.
fn let_bindings(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for at in identifier_offsets(block, "let") {
        let rest = block[at + "let".len()..].trim_start();
        let rest = rest.strip_prefix("mut ").map_or(rest, str::trim_start);
        let name: String = rest
            .bytes()
            .take_while(|byte| is_identifier_byte(*byte))
            .map(char::from)
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        let Some(initializer) = after.strip_prefix('=') else {
            continue;
        };
        out.push((name, path_at(initializer.trim_start())));
    }
    out
}

/// The two bindings that hold key material, and **every use of them in source
/// order rendered as what it is handed to**.
///
/// This is the shape, rather than a list of ways out. A blacklist of
/// `fs::write` / `println!` / `reqwest` is a list somebody walks around with
/// the next API, and one of the two escapes proven against this file performs
/// no I/O whatsoever. What the body is allowed to do with the key is one
/// thing, so the check is on that one thing: each use is described by the call
/// it is an argument to, and the whole list is pinned.
///
/// Note what is *not* hard-coded: not the accessor name, so a second accessor
/// on the same handle is a sixth entry; not the binding names, so a rename is
/// not an escape; and not any API name, so there is nothing to walk around.
fn key_material_flow(block: &str) -> (String, String, Vec<String>) {
    let bindings = let_bindings(block);
    let sole = |initializer: &str| -> String {
        let found: Vec<&String> = bindings
            .iter()
            .filter(|(_, from)| from == initializer)
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            found.len(),
            1,
            "the gated block binds the result of `{initializer}(..)` {} time(s). It must do so \
             exactly once — a second one is a second copy of the key with its own uses, and \
             everything below enumerates the uses of the first. The block binds: {bindings:#?}",
            found.len()
        );
        found[0].clone()
    };
    let secrets = sole(SECRETS_COME_FROM);
    let account = sole(ACCOUNT_COMES_FROM);
    assert_ne!(
        secrets, account,
        "the unlocked secrets and the account built from them are the same binding, so the \
         uses below cannot be told apart"
    );

    let mut uses: Vec<(usize, String)> = Vec::new();
    for name in [&secrets, &account] {
        for at in identifier_offsets(block, name) {
            let head = block[..at].trim_end();
            let head = if ends_with_keyword(head, "mut") {
                head[..head.len() - "mut".len()].trim_end()
            } else {
                head
            };
            if ends_with_keyword(head, "let") {
                let after = block[at + name.len()..].trim_start();
                let initializer = after.strip_prefix('=').unwrap_or(after).trim_start();
                uses.push((at, format!("{name} = {}(..)", path_at(initializer))));
                continue;
            }
            let handed_to = receiving_call(block, at).map_or_else(
                || "NOTHING (a new binding, an assignment or a bare statement)".to_owned(),
                |callee| format!("{callee}(..)"),
            );
            match block[at + name.len()..].strip_prefix('.') {
                Some(rest) => {
                    let accessor: String = rest
                        .bytes()
                        .take_while(|byte| is_identifier_byte(*byte))
                        .map(char::from)
                        .collect();
                    uses.push((at, format!("{name}.{accessor}() -> {handed_to}")));
                }
                None => uses.push((at, format!("{name} -> {handed_to}"))),
            }
        }
    }
    uses.sort_by_key(|(at, _)| *at);
    (
        secrets,
        account,
        uses.into_iter().map(|(_, use_)| use_).collect(),
    )
}

/// GUARD 3. One gate, directly on one `impl`, holding one method, which builds
/// one shape of transaction and returns no key material.
#[test]
fn the_gated_block_holds_one_method_that_builds_one_shape_of_transaction() {
    let seam_feature = seam_feature();
    let gate = format!("#[cfg(feature = \"{seam_feature}\")]");
    let sources = crate_sources();

    // ---- WHAT THE COMPILER COMPILES AND WHAT THIS GUARD READS ARE THE SAME
    // SET OF FILES ----
    //
    // Everything below walks `src/`, which is the module tree rooted at
    // `src/lib.rs` — and is a complete picture of the crate only while nothing
    // splices a file in from outside it. `include!("../../extra.rs")` does
    // exactly that. One line added to a shipped source file, and a whole
    // second `#[cfg(feature = "..")] impl AgentWalletManager` — holding a
    // `pub fn` that unlocked the vault, wrote the raw key to disk and built a
    // transfer to a caller-named address — compiled into this crate and was
    // callable from outside it, from a path this walk had no reason to open.
    // All four tests were green with it in place.
    //
    // `#[path]` is the other spelling of the same thing and is *not* banned,
    // because the crate legitimately uses it to put a `#[cfg(test)]` module's
    // files in a subdirectory. It is required to stay inside `src/`.
    for (path, text) in &sources {
        assert!(
            !text.contains("include!"),
            "{} uses `include!`, which compiles a file into this crate from a path the walk of \
             `src/` need never have opened. Nothing below can see what is in it.",
            path.display()
        );
        for (at, _) in text.match_indices("#[path") {
            let target = text[at..].split('"').nth(1).unwrap_or_default();
            assert!(
                !target.is_empty() && !target.contains(".."),
                "{} declares a module at `{target}`, which leaves `src/`. Every rule below \
                 reads `src/` and would not see what is in it.",
                path.display()
            );
        }
    }
    assert!(
        !workspace_root()
            .join("crates/agent-wallet-core/build.rs")
            .exists()
            && !read("crates/agent-wallet-core/Cargo.toml").contains("build ="),
        "agent-wallet-core has a build script. A build script prints \
         `cargo::rustc-cfg=feature=\"..\"` if it wants to, which switches the seam on with \
         every manifest and every source file below untouched."
    );

    // ---- ONE GATE, AND IT IS SPELLED IN WHATEVER WAY THE COMPILER READS ----
    //
    // This counted *lines* containing `feature = "on-chain-exit-proof"` and
    // required exactly two. `#[cfg(feature="on-chain-exit-proof")]` — the same
    // attribute to rustc, two keystrokes different here — was not counted, so
    // a second `impl AgentWalletManager` behind that spelling, holding a
    // method that wrote the raw key to disk and built a transfer to an
    // arbitrary address, left every test in this file green. Whitespace is
    // removed before anything is compared, and the whole attribute is compared
    // rather than a substring of one line, so a gate split across lines is the
    // same gate here that it is to the compiler.
    //
    // Two forms are allowed and the difference between them is what ships.
    // `#[cfg(feature = "..")]` is the seam's own gate and there may be exactly
    // one of it. `#[cfg(all(test, feature = ".."))]` is a `#[cfg(test)]`
    // module, which no build that ships ever compiles and which guards 1 and 5
    // prove is off independently — so the proof's own test suite is allowed to
    // grow into more than one of them without this file going red at somebody
    // who split a test module in two.
    let test_gate = format!("#[cfg(all(test, feature = \"{seam_feature}\"))]");
    let plain_gate = without_whitespace(&gate);
    let test_gate = without_whitespace(&test_gate);
    let needle = without_whitespace(&format!("feature = \"{seam_feature}\""));
    let mut plain_gates: Vec<(PathBuf, String)> = Vec::new();
    let mut test_gates = 0usize;
    for (path, text) in &sources {
        for (attribute, attached_to) in attributes_containing(&without_whitespace(text), &needle) {
            assert!(
                attribute == plain_gate || attribute == test_gate,
                "{} switches something on with `{attribute}`. The seam's feature may be named \
                 in exactly two forms: the seam's own gate `{plain_gate}`, and a `#[cfg(test)]` \
                 module's `{test_gate}`. Anything else is a third way for this feature to \
                 compile something in. It is attached to: {attached_to}",
                path.display()
            );
            if attribute == plain_gate {
                plain_gates.push((path.clone(), attached_to));
            } else {
                test_gates += 1;
            }
        }
    }
    assert_eq!(
        plain_gates.len(),
        1,
        "the seam's feature gates {} things that are not `#[cfg(test)]` modules. Exactly one \
         may exist, and it is the seam's own `impl`: {plain_gates:#?}",
        plain_gates.len()
    );
    assert!(
        test_gates >= 1,
        "the on-chain proof's test module is no longer gated on the seam's feature, so the \
         detector above found nothing to tell the two forms apart"
    );

    // The gate sits directly on the `impl` that holds the seam — not on a
    // module three levels up whose other contents nobody re-counts.
    assert!(
        plain_gates[0].1.starts_with("implAgentWalletManager{"),
        "the seam's gate is no longer directly on an `impl AgentWalletManager`. It now gates \
         `{}`, and whatever else is inside that is behind the same door.",
        plain_gates[0].1
    );

    // Which file it is in is not the rule and never was. Pinning it to
    // `hvm_registry.rs` meant that moving the seam into its own module — a
    // valid refactor of a 1700-line file, with the feature still named exactly
    // twice — failed here, with a message that offered the reader nothing to
    // do about it except delete the assertion. The rule is that there is one
    // gate, that it is on the `impl`, and that the seam is what is inside it.
    let registry = &sources
        .iter()
        .find(|(path, _)| *path == plain_gates[0].0)
        .expect("the file the one gate is in")
        .1;
    let header = format!("{gate}\nimpl AgentWalletManager {{");
    assert_eq!(
        registry.matches(&header).count(),
        1,
        "the gate and the `impl` it sits on are not written as rustfmt writes them, so the \
         block below cannot be lifted out by matching on them. Write the gate as `{gate}` on \
         the line directly above `impl AgentWalletManager {{`. Found {} occurrence(s) in {}.",
        registry.matches(&header).count(),
        plain_gates[0].0.display()
    );
    let block = block_after(registry, &header);
    let flat = block.split_whitespace().collect::<Vec<_>>().join(" ");

    // The seam is declared once in shipped source, and that one declaration is
    // inside the gate. A second copy anywhere is a second door.
    let declarations: Vec<(String, String)> = sources
        .iter()
        .flat_map(|(path, text)| {
            text.lines()
                .filter(|line| line.contains(&format!("fn {SEAM}")))
                .map(move |line| (path.display().to_string(), line.trim().to_owned()))
        })
        .collect();
    assert_eq!(
        declarations.len(),
        1,
        "the provider-side seam must be declared exactly once. Found {}: {declarations:#?}",
        declarations.len()
    );
    assert!(
        block.contains(&declarations[0].1),
        "the seam is declared outside the gated block, so nothing below is about the code that \
         is actually compiled under this feature: {declarations:#?}"
    );

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

    // ---- ONE SHAPE, MEASURED AGAINST THE WHOLE SET ----
    //
    // `build_` above is still a string. It happens to cover the escape that
    // was demonstrated, and it covers nothing that is named differently. What
    // follows asks the Hub crate what it exports instead of guessing: of every
    // name in that crate that yields an `HvmPilotSignedTransaction`, exactly
    // one may be called from this block.
    let builders = hub_transaction_builders();
    assert!(
        builders.len() >= 12,
        "only {} Hub function(s) were found to yield an HvmPilotSignedTransaction. The \
         extractor has stopped working, and a set this small cannot be the whole surface: \
         {builders:#?}",
        builders.len()
    );
    // The positive control, and the reason this is not another grep that can
    // only ever find nothing. The set must contain the builder the seam is
    // allowed to call AND the one that walked through this guard; if it does
    // not see both, every assertion under it is decoration.
    for control in [
        "build_hvm_registry_pilot_channel_init",
        "build_hvm_pilot_exact_funding",
    ] {
        assert!(
            builders.contains(control),
            "the Hub-builder extractor cannot see `{control}`, so the one-shape check below \
             says nothing. It saw: {builders:#?}"
        );
    }

    // The call detector, proven on both shapes the escape can take — the Hub
    // builder written with its own crate path, and the same builder written
    // bare through a `use` — before its verdict on the real block is believed.
    let control = hub_builder_calls(
        "{ l2_fast_pay_hub::hvm_pilot::build_hvm_pilot_exact_funding(); \
         build_hvm_pilot_exact_funding(); let _ = something.build_hvm_pilot_exact_funding(); }",
        &builders,
    );
    assert_eq!(
        control.len(),
        2,
        "the call detector must see the Hub builder both qualified and bare, and must not \
         count a method call of the same name on some other receiver. It saw: {control:#?}"
    );

    let hub_calls = hub_builder_calls(&block, &builders);
    assert_eq!(
        hub_calls.len(),
        1,
        "the gated block calls {} of the Hub crate's {} transaction-yielding functions. Every \
         one of them is a different shape of transaction this wallet's key can be made to \
         sign, and the seam's whole safety argument is that there is exactly one. It calls: \
         {hub_calls:#?}\n{block}",
        hub_calls.len(),
        builders.len()
    );
    // Spelled with its crate path, because the leaf name is not the function.
    // A `fn build_hvm_registry_pilot_channel_init` declared in this very file
    // that forwards to `build_hvm_pilot_exact_funding` satisfies every check
    // above it: one `build_`, one Hub-builder leaf, one shape by name and
    // another by behaviour.
    assert_eq!(
        hub_calls[0], "l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_channel_init",
        "the seam's builder call is no longer the Hub crate's reviewed one named by its full \
         path. `{}` resolves to whatever is in scope here:\n{block}",
        hub_calls[0]
    );
    // ...and that path means the Hub crate. `mod l2_fast_pay_hub { .. }` in
    // this crate re-points the fully-qualified call above with the gated block
    // byte-for-byte unchanged, so this is checked where it can be seen: across
    // every source file, and on the dependency line that gives the name.
    for (path, text) in &sources {
        for shadow in [
            "mod l2_fast_pay_hub",
            "as l2_fast_pay_hub",
            "extern crate l2_fast_pay_hub",
        ] {
            assert!(
                !text.contains(shadow),
                "{} contains `{shadow}`, which can re-point the crate path the seam's builder \
                 call is written with while that call's text never changes",
                path.display()
            );
        }
    }
    // ...and the dependency that gives the name resolves to the Hub crate in
    // this workspace, however that dependency is spelled.
    //
    // One spelling was pinned — `path = "../l2-fast-pay-hub"` — so moving the
    // Hub to a workspace dependency, which every other dependency in that
    // manifest already is, failed here saying the seam no longer calls the
    // workspace's Hub crate. It was more emphatically the workspace's Hub
    // crate than before. The declaration is resolved now instead of matched.
    let hub = "l2-fast-pay-hub";
    let core_manifest = read("crates/agent-wallet-core/Cargo.toml");
    let mut declared = dependency_declarations(&core_manifest, hub);
    assert_eq!(
        declared.len(),
        1,
        "agent-wallet-core declares `{hub}` {} time(s) among its shipped dependencies: \
         {declared:#?}",
        declared.len()
    );
    let mut base = workspace_root().join("crates/agent-wallet-core");
    if without_whitespace(&declared[0]).contains("workspace=true") {
        // Inherited: the declaration that decides what the name means is the
        // workspace root's.
        base = workspace_root();
        declared = dependency_declarations(&read("Cargo.toml"), hub);
        assert_eq!(
            declared.len(),
            1,
            "agent-wallet-core inherits `{hub}` from the workspace, which declares it {} \
             time(s): {declared:#?}",
            declared.len()
        );
    }
    assert!(
        !declared[0].contains("package"),
        "the Hub dependency is renamed, so `l2_fast_pay_hub` in the seam is some other crate \
         wearing that name: {}",
        declared[0]
    );
    let hub_path = declared[0]
        .split_once("path")
        .and_then(|(_, tail)| tail.split('"').nth(1))
        .unwrap_or_else(|| {
            panic!(
                "the Hub dependency is not a path dependency, so `l2_fast_pay_hub` in the seam \
                 is whatever a registry or a git remote is serving under that name: {}",
                declared[0]
            )
        });
    let resolved = base
        .join(hub_path)
        .canonicalize()
        .unwrap_or_else(|error| panic!("the Hub dependency path `{hub_path}`: {error}"));
    let expected = workspace_root()
        .join("crates/l2-fast-pay-hub")
        .canonicalize()
        .expect("the workspace's Hub crate");
    assert_eq!(
        resolved, expected,
        "the `l2_fast_pay_hub` the seam calls is not the Hub crate in this workspace, so every \
         claim above about what that builder does is about some other code"
    );

    // ---- AND EVERY WAY OUT EARLY IS A REFUSAL ----
    //
    // The demonstrated escape did not replace the builder call; it added a
    // second one in front of it, keyed on `gas_max == 1`. Both calls were
    // there, both compiled, and which shape the wallet signed was chosen by an
    // argument. A seam with two exits is a seam that chooses.
    //
    // The rule that caught it counted `if `, exactly one — and counting
    // branches was never the property. It made the seam's own documented
    // weakness unfixable: the doc comment above the seam says in as many words
    // that the Hub builder checks a fee *floor* and never a ceiling, and the
    // fix for that is a second `if` that refuses. A rule that rejects the
    // security fix its own subject documents is a rule somebody deletes.
    //
    // So the property is stated instead of counted. A branch may only
    // *refuse*: every `if` in the block has a body that is nothing but the
    // refusal, there is at least one, and every `return` is that refusal. No
    // `else`, `match`, `while` or `loop`, because each of those is a way to
    // reach a second value. What comes back out is then whatever the tail
    // expression builds, and nothing else can.
    let refusal = "return Err(AgentWalletError::SigningBlocked);";
    let branches = branch_bodies(&flat);
    assert!(
        !branches.is_empty(),
        "the seam no longer refuses anything. It must at least refuse a vault that does not \
         belong to the wallet it was asked about:\n{block}"
    );
    for body in &branches {
        assert_eq!(
            body, refusal,
            "a branch in the seam does something other than refuse. A branch may only turn the \
             request down — anything else is the seam choosing what to sign:\n{block}"
        );
    }
    for choosing in ["else", "match", "while", "loop"] {
        assert!(
            identifier_offsets(&flat, choosing).is_empty(),
            "the seam now contains `{choosing}`, so it has more than one path through it:\n\
             {block}"
        );
    }
    let returns: Vec<&str> = identifier_offsets(&flat, "return")
        .into_iter()
        .map(|at| &flat[at..])
        .collect();
    assert_eq!(
        returns.len(),
        branches.len(),
        "the seam has {} explicit `return`(s) and {} branch(es). Every early exit must be a \
         branch that refuses; a `return` outside one is a second thing this function can hand \
         back:\n{block}",
        returns.len(),
        branches.len()
    );
    for tail in &returns {
        assert!(
            tail.starts_with(refusal),
            "an early exit of the seam no longer refuses — it now returns a value. The only \
             value this function may produce is the one its tail expression builds:\n{block}"
        );
    }

    // The builder call is the last thing the seam does, so what it builds is
    // what comes back.
    //
    // This pinned the builder's whole argument list inside a rule about tail
    // position, so renaming the `hub` parameter reported "the builder call is
    // no longer the last thing the seam does" — which had not happened, and
    // sent the reader looking for a control-flow change that was not there.
    // The argument list is pinned once, at the bottom of this test, by the one
    // assertion that tells its reader what to do about it.
    let call = format!("{}(", hub_calls[0]);
    let at = flat
        .rfind(&call)
        .unwrap_or_else(|| panic!("the seam no longer calls the reviewed builder:\n{block}"));
    let close = matching_paren(&flat, at + call.len() - 1);
    assert_eq!(
        flat[close + 1..].trim(),
        ".map_err(|_| AgentWalletError::SigningBlocked) } }",
        "the builder call is no longer the last thing the seam does, so it is no longer \
         necessarily what the seam returns:\n{block}"
    );

    // ---- AND THE KEY IS HANDED TO EXACTLY ONE THING ----
    //
    // The `-> {forbidden}` list further down is about the *return type*, and a
    // return type cannot see `fs::write(path, secrets.blockchain_secret_hex())`
    // in the body: that leaves the wallet's raw private key in plaintext on
    // disk with the signature, the return type and every other assertion here
    // untouched. It was tried, and it passed.
    //
    // Counting the accessor closed that one line and nothing more. The key
    // does not stop being the key once it is inside `left`:
    // `WalletAccount::secret_hex` (`crates/wallet-core/src/account.rs:44`) is
    // `pub` and hands the same bytes back, with `secrets` never mentioned a
    // fourth time and the accessor never read twice. `left.secret_hex()` into
    // a `OnceLock` was tried too — no file, no socket, no print, nothing a
    // list of dangerous APIs contains — and the only assertion in this file
    // that caught it was the whole-body pin at the bottom, the one whose own
    // comment tells the next person how to update it.
    //
    // So the shape is pinned instead of the ways out. Every use of the
    // unlocked secrets, and of the account built from them, is enumerated
    // with the call it is an argument to, and the list must be these five
    // things. Any other argument position, any new binding, any second
    // accessor, any bare statement, is a sixth entry — whatever API it is
    // spelled with.
    let (secrets_binding, account_binding, flow) = key_material_flow(&block);

    // The detector first, and pointed at this file's own body rather than at a
    // hand-written sample, so it cannot rot into a check of nothing while the
    // seam moves. Both demonstrated escapes are inserted: the `fs::write`, and
    // the one that performs no I/O at all.
    let leaks = format!(
        "std::fs::write(\"leak.hex\", {secrets_binding}.blockchain_secret_hex()).ok();\n        \
         drop({secrets_binding});\n        \
         let escaped = {account_binding}.secret_hex();\n        \
         LEAKED.set(escaped.to_string()).ok();"
    );
    let doctored = block.replace(&format!("drop({secrets_binding});"), &leaks);
    assert_ne!(
        doctored, block,
        "the control could not be built: the block no longer drops `{secrets_binding}` on a \
         line of its own, so the flow detector below is unproven:\n{block}"
    );
    let (_, _, leaking) = key_material_flow(&doctored);
    for escape in [
        format!("{secrets_binding}.blockchain_secret_hex() -> std::fs::write(..)"),
        format!(
            "{account_binding}.secret_hex() -> NOTHING (a new binding, an assignment or a bare \
             statement)"
        ),
    ] {
        assert!(
            leaking.contains(&escape),
            "the flow detector cannot see `{escape}`, so the assertion under it is decoration. \
             It saw: {leaking:#?}"
        );
    }

    let permitted = vec![
        format!("{secrets_binding} = {SECRETS_COME_FROM}(..)"),
        format!("{account_binding} = {ACCOUNT_COMES_FROM}(..)"),
        format!("{secrets_binding}.blockchain_secret_hex() -> {ACCOUNT_COMES_FROM}(..)"),
        format!("{secrets_binding} -> drop(..)"),
        format!(
            "{account_binding}.inner() -> \
             l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_channel_init(..)"
        ),
    ];
    assert_eq!(
        flow, permitted,
        "the key is used for something this seam is not allowed to do with it. The unlocked \
         secrets may be bound once, read once as the argument to the account constructor, and \
         dropped; the account may be handed to the one builder as `inner()`. Nothing else may \
         touch either of them, and the return type cannot see the difference:\n{block}"
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
    // Written against the binding the flow detector found rather than against
    // the name `secrets`, so that renaming a local — which is not a boundary
    // change and which the detector above follows correctly — does not fail
    // here with a message about the key being read a different number of
    // times.
    assert_eq!(
        identifier_offsets(&block, &secrets_binding).len(),
        3,
        "the unlocked secrets handle `{secrets_binding}` must be bound once, read once and \
         dropped — three mentions. It now has {}:\n{block}",
        identifier_offsets(&block, &secrets_binding).len()
    );
    assert!(
        flat.contains(&format!(
            "WalletAccount::from_secret_hex( {secrets_binding}.blockchain_secret_hex(), )"
        )),
        "the one read of the blockchain secret is no longer the argument to the account \
         constructor, so the key now goes somewhere else as well:\n{block}"
    );
    assert!(
        flat.contains(&format!("drop({secrets_binding});")),
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
