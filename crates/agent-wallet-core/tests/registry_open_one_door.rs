//! There is ONE door into registry funding, and one signature that opens a
//! registry channel.
//!
//! # Why this test reads source
//!
//! The behavioural proof lives next door in `registry_channel_open.rs`, and it
//! proves that *the door this wallet uses* is shut without a countersigned
//! refund. It cannot prove there is no second door, because a second door is
//! by definition one the test does not walk through. That has been this
//! project's recurring defect: a check placed on one of two entrances, three
//! times caught in review.
//!
//! So this counts entrances instead.
//!
//! `HvmRegistryFundingAuthorizationV1` is the value that says "this wallet's
//! money may now enter this channel". It has private fields, no `Deserialize`
//! and no `Default`, so the only way one can come into existence anywhere in
//! this workspace is a struct literal inside the module that defines it. This
//! counts those literals across every shipped line of both wallet crates and
//! insists there is exactly one: the tail of `authorize_registry_funding`,
//! whose first statement validates the bundle.
//!
//! It counts the channel-open signer the same way, for the same reason.
//!
//! # Why comments and tests are cut out first
//!
//! A `contains` cannot tell production code from prose. A tripwire that can be
//! satisfied by writing a comment about the thing it demands is a tripwire
//! that will be. Everything from the first `#[cfg(test)]` onwards is dropped,
//! and so is every comment line, before anything is counted.

use std::fs;
use std::path::{Path, PathBuf};

/// Everything in a source file that a build actually ships: no comments, and
/// nothing from the first `#[cfg(test)]` onwards.
fn shipped_source(source: &str) -> String {
    source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .to_path_buf()
}

fn rust_sources(root: &Path, into: &mut Vec<(PathBuf, String)>) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => panic!("cannot read {}: {error}", root.display()),
    };
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = fs::read_to_string(&path).expect("source file is utf-8");
            into.push((path, text));
        }
    }
}

fn wallet_sources() -> Vec<(PathBuf, String)> {
    let crates = crates_root();
    let mut sources = Vec::new();
    rust_sources(&crates.join("agent-wallet-core").join("src"), &mut sources);
    rust_sources(&crates.join("wallet-core").join("src"), &mut sources);
    assert!(
        sources.len() > 50,
        "the source walk found only {} files; it is looking in the wrong place",
        sources.len()
    );
    sources
}

/// Lines of shipped source that *construct* the named type, as opposed to
/// declaring it or opening an `impl` for it.
fn construction_sites(needle: &str) -> Vec<String> {
    let literal = format!("{needle} {{");
    let mut sites = Vec::new();
    for (path, text) in wallet_sources() {
        for line in shipped_source(&text).lines() {
            if line.contains(&literal)
                && !line.contains("struct ")
                && !line.contains("impl ")
                && !line.contains("enum ")
            {
                sites.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
    sites
}

fn definition_sites(needle: &str) -> Vec<String> {
    let mut sites = Vec::new();
    for (path, text) in wallet_sources() {
        for line in shipped_source(&text).lines() {
            if line.contains(needle) {
                sites.push(format!("{}: {}", path.display(), line.trim()));
            }
        }
    }
    sites
}

/// Exactly one place in either wallet crate can mint permission to fund.
#[test]
fn registry_funding_has_exactly_one_constructor() {
    let sites = construction_sites("HvmRegistryFundingAuthorizationV1");
    assert_eq!(
        sites.len(),
        1,
        "registry funding authorization must have exactly one constructor, and the first \
         statement of that constructor must validate the countersigned refund bundle. Found {} \
         construction sites: {sites:#?}",
        sites.len()
    );
    assert!(
        sites[0]
            .replace('\\', "/")
            .contains("wallet-core/src/hvm_registry_open.rs"),
        "the one constructor moved out of the module whose whole subject is this rule: {sites:#?}"
    );
}

/// The gate cannot be revived from disk, a backup, or a Hub response.
///
/// `Deserialize` on this type would turn "permission to spend the deposit"
/// into a value that can be parsed out of any JSON that reaches the wallet,
/// which is precisely what the private fields are there to prevent.
#[test]
fn registry_funding_permission_cannot_be_parsed_into_existence() {
    let path = crates_root()
        .join("wallet-core")
        .join("src")
        .join("hvm_registry_open.rs");
    let module = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the wallet half of the registry open must exist at {}: {error}",
            path.display()
        )
    });
    let shipped = shipped_source(&module);
    let before_declaration = shipped
        .split("pub struct HvmRegistryFundingAuthorizationV1")
        .next()
        .expect("split always yields a first part");
    assert!(
        before_declaration.len() < shipped.len(),
        "the funding authorization type must be declared in this module"
    );
    let derive = before_declaration
        .rsplit("#[derive(")
        .next()
        .expect("the type carries a derive list");
    assert!(
        !derive.contains("Deserialize"),
        "HvmRegistryFundingAuthorizationV1 must not be deserialisable; permission to fund has \
         to be re-derived from the bundle, never read back from a stored copy"
    );
    assert!(
        !shipped.contains("impl Default for HvmRegistryFundingAuthorizationV1"),
        "a Default for the funding authorization is a way to hold one without a bundle"
    );
}

/// The channel-open signature exists, in shipped code, exactly once.
///
/// Until this passed, no Agent Wallet in this app could hold a provider
/// channel: adoption needs the wallet's own left signature on the serial-1
/// refund bill, that signature can only be made at open, and nothing in
/// `agent-wallet-core` produced one. The proven exit driver had nothing to act
/// on for anybody.
#[test]
fn one_shipped_signing_boundary_left_signs_the_serial_one_refund() {
    let sites = definition_sites("fn sign_exact_registry_channel_open");
    assert_eq!(
        sites.len(),
        1,
        "there must be exactly one signing boundary that left-signs the serial-1 full refund at \
         channel open. Found {}: {sites:#?}",
        sites.len()
    );
    assert!(
        sites[0]
            .replace('\\', "/")
            .contains("agent-wallet-core/src/signer.rs"),
        "the channel-open signature must be made at the wallet's signing boundary: {sites:#?}"
    );
}

/// A comment or a test naming the signer does not satisfy the counts above.
#[test]
fn naming_the_open_signer_in_prose_or_a_test_does_not_satisfy_the_tripwire() {
    let prose_and_tests = concat!(
        "//! fn sign_exact_registry_channel_open\n",
        "/// HvmRegistryFundingAuthorizationV1 {\n",
        "fn nothing() {}\n",
        "#[cfg(test)]\n",
        "mod t { fn t() { let _ = HvmRegistryFundingAuthorizationV1 { a: 1 }; } }"
    );
    let shipped = shipped_source(prose_and_tests);
    assert!(
        !shipped.contains("fn sign_exact_registry_channel_open")
            && !shipped.contains("HvmRegistryFundingAuthorizationV1 {"),
        "a file that only mentions these in comments and in its own tests would still satisfy \
         the counts above"
    );
}
