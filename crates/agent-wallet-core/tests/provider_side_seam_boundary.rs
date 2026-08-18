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
//! # Four guards, and why one is not enough
//!
//! There are three separate ways this seam can end up in a shipped build, and
//! a guard for one of them is blind to the other two.
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
//!    resolves the real feature graph out of the real manifests, across five
//!    crates and both apps, and asserts the exact set of `(crate, feature)`
//!    pairs that reach it.
//!
//! 3. **The seam widens** — a second method behind the same gate, a second
//!    builder call, a return type that hands back key material. Guards 1 and 2
//!    would both stay green.
//!    [`the_gated_block_holds_one_method_that_builds_one_shape_of_transaction`]
//!    counts what is inside the gated `impl` block.
//!
//! And one more, because a guard that names a symbol nobody has can pass
//! forever while guarding nothing — this project has shipped three of those:
//! [`with_the_feature`] fails to compile if the seam is renamed or deleted, so
//! the name the other three guards are written against is a name that exists.

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

/// Every crate whose manifest could possibly turn the seam on, plus both app
/// shells, which are the only two things anybody ships.
fn feature_graph() -> BTreeMap<String, BTreeMap<String, BTreeSet<String>>> {
    [
        ("agent-wallet-core", "crates/agent-wallet-core/Cargo.toml"),
        ("hacash-wallet-core", "crates/wallet-core/Cargo.toml"),
        (
            "wallet-tauri-common",
            "crates/wallet-tauri-common/Cargo.toml",
        ),
        ("hacash-wallet", "apps/desktop/src-tauri/Cargo.toml"),
        ("hacash-wallet-mobile", "apps/mobile/src-tauri/Cargo.toml"),
    ]
    .into_iter()
    .map(|(name, path)| (name.to_owned(), features_of(&read(path))))
    .collect()
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
        assert!(
            table.contains_key("default"),
            "{crate_name} stopped declaring a default feature set, so the assertion above no \
             longer says anything about a default build"
        );
        assert!(
            !reaches_the_seam(&graph, crate_name, "default"),
            "{crate_name}'s default features now reach the seam"
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

    // One builder call, and it is the channel `init`. Anything else behind
    // this gate is a second shape of transaction the wallet's key can sign.
    assert_eq!(
        block.matches("build_hvm_registry_pilot_").count(),
        1,
        "the gated block calls more than one transaction builder:\n{block}"
    );
    assert!(
        block.contains("build_hvm_registry_pilot_channel_init("),
        "the gated block no longer builds the registry channel init:\n{block}"
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
}
