//! `docs/l2/MAINNET_READINESS_MAP.md` is the document an owner reads before
//! deciding what to work on next, so a wrong sentence in it costs real weeks.
//!
//! Two kinds of wrongness are mechanically checkable and both have already
//! happened once:
//!
//! 1. **A citation that has drifted off its subject.** The map points at
//!    `file.rs:A-B` to prove a claim. Code moves; the citation does not. A
//!    reader who follows it lands on unrelated lines and cannot tell whether
//!    the claim was ever true. Every anchor below is *located in the source at
//!    test time*, so this fails the moment either side moves.
//!
//! 2. **The private pilot chain's exit-contract deployment presented as a
//!    mainnet one.** That single sentence sent the map's conclusion from "this
//!    is protocol work in another repository" to "the remaining work is node
//!    configuration", which is the most expensive wrong instruction the
//!    document can carry. The deployment height it names can never satisfy the
//!    Hub's own verifier, and this test says so in code.

use std::path::{Path, PathBuf};

/// The one deployment of `HPAYChannelExitV1` that exists, and the height it
/// was mined at. On the private pilot chain, chain id 7.
const PILOT_EXIT_DEPLOYMENT_HEIGHT: u64 = 2522;

/// The reason section 1 of the map is not a configuration task: that height is
/// below the checkpoint `is_verified_mainnet_deployment` demands, so no
/// fullnode setting can promote it to a verified mainnet deployment. A compile
/// error here means the premise moved and the map has to be re-argued.
const _: () =
    assert!(PILOT_EXIT_DEPLOYMENT_HEIGHT < l2_fast_pay_hub::node::HACASH_MAINNET_MIN_SAFE_HEIGHT);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must resolve from this crate")
}

fn map() -> String {
    std::fs::read_to_string(repo_root().join("docs/l2/MAINNET_READINESS_MAP.md"))
        .expect("the mainnet readiness map must exist")
}

/// Every `path.rs:A` or `path.rs:A-B` in the map, as (repo-relative path,
/// first line, last line). Paths written bare (`readiness.rs:352`) are
/// resolved against the crate sources when exactly one file carries that
/// name; ambiguous or unknown names are skipped rather than guessed.
fn citations(document: &str) -> Vec<(PathBuf, usize, usize)> {
    let bytes = document.as_bytes();
    let mut found = Vec::new();
    let mut at = 0usize;
    while let Some(hit) = document[at..].find(".rs:") {
        // `colon` indexes the ':', so `start..colon` is the cited path.
        let colon = at + hit + ".rs".len();
        let mut start = at + hit;
        while start > 0 && is_path_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut cursor = colon + 1;
        let first = read_number(bytes, &mut cursor);
        let last = if bytes.get(cursor) == Some(&b'-') {
            cursor += 1;
            read_number(bytes, &mut cursor)
        } else {
            first
        };
        at = cursor.max(colon + 1);
        let (Some(first), Some(last)) = (first, last) else {
            continue;
        };
        if let Some(path) = resolve(&document[start..colon]) {
            found.push((path, first, last));
        }
    }
    found
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
}

fn read_number(bytes: &[u8], cursor: &mut usize) -> Option<usize> {
    let start = *cursor;
    while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
        *cursor += 1;
    }
    if *cursor == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..*cursor])
        .ok()?
        .parse()
        .ok()
}

/// Map a cited path onto a real file. A repo-relative path is taken as
/// written; a shortened one (`node.rs`, `state/hvm_registry.rs`) is accepted
/// only when exactly one file under `crates/` ends with it, so this never
/// invents a subject.
fn resolve(cited: &str) -> Option<PathBuf> {
    let root = repo_root();
    let direct = root.join(cited);
    if direct.is_file() {
        return Some(direct);
    }
    let suffix = cited.replace('\\', "/");
    let mut matches = Vec::new();
    collect_suffix(&root.join("crates"), &suffix, &mut matches);
    (matches.len() == 1).then(|| matches.remove(0))
}

fn collect_suffix(directory: &Path, suffix: &str, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|part| part == "target") {
                continue;
            }
            collect_suffix(&path, suffix, into);
        } else if path
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with(&format!("/{suffix}"))
        {
            into.push(path);
        }
    }
}

/// The 1-based line carrying `needle`, which must appear exactly once.
fn line_of(relative: &str, needle: &str) -> usize {
    let path = repo_root().join(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{relative} must exist to be cited"));
    let hits: Vec<usize> = source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(needle))
        .map(|(index, _)| index + 1)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{needle:?} must appear exactly once in {relative} to anchor a citation, found {hits:?}"
    );
    hits[0]
}

/// The map's section beginning at `heading`, up to the next heading of the
/// same or higher level.
fn section(document: &str, heading: &str) -> String {
    let start = document
        .find(heading)
        .unwrap_or_else(|| panic!("the map must still carry the section {heading:?}"));
    let level = heading
        .chars()
        .take_while(|character| *character == '#')
        .count();
    let mut out = String::from(heading);
    for line in document[start + heading.len()..].lines() {
        let depth = line
            .chars()
            .take_while(|character| *character == '#')
            .count();
        if depth > 0 && depth <= level {
            break;
        }
        out.push('\n');
        out.push_str(line);
    }
    out
}

/// A citation whose line range runs past the end of the file it names is
/// pointing at nothing at all.
#[test]
fn every_source_citation_in_the_map_lands_inside_the_file_it_names() {
    let document = map();
    let citations = citations(&document);
    assert!(
        citations.len() >= 10,
        "the citation parser resolved only {} citations; it is no longer testing anything",
        citations.len()
    );
    for (path, first, last) in citations {
        let lines = std::fs::read_to_string(&path)
            .expect("resolved above")
            .lines()
            .count();
        assert!(
            first >= 1 && last >= first && last <= lines,
            "the map cites {}:{first}-{last} but that file has {lines} lines",
            path.display()
        );
    }
}

/// The claims the map exists to make, each pinned to where its code actually
/// lives right now. Locating the subject in the source at test time is the
/// whole point: a citation cannot rot silently.
#[test]
fn the_map_cites_the_current_location_of_every_flag_it_explains() {
    let document = map();
    let citations = citations(&document);

    for (relative, needle, what) in [
        (
            "crates/l2-fast-pay-hub/src/readiness.rs",
            "    pub fn evaluate(",
            "the evaluator the map calls the authority",
        ),
        (
            "crates/l2-fast-pay-hub/src/readiness.rs",
            "let is_bounded_pilot = profile ==",
            "the branch that separates the two mainnet routes",
        ),
        (
            "crates/l2-fast-pay-hub/src/readiness.rs",
            "trustless_finality: external_rollback_anchor_ready",
            "the assignment that publishes trustless_finality",
        ),
        (
            "crates/l2-fast-pay-hub/src/readiness.rs",
            "let production_mainnet_ready = hub_operational_ready",
            "the internal aggregate the map says is no longer exported",
        ),
        (
            "crates/l2-fast-pay-hub/src/node.rs",
            "pub const HACASH_MAINNET_MIN_SAFE_HEIGHT",
            "the pinned mainnet checkpoint a deployment must clear",
        ),
    ] {
        let line = line_of(relative, needle);
        let path = repo_root().join(relative);
        let covered = citations
            .iter()
            .any(|(cited, first, last)| *cited == path && (*first..=*last).contains(&line));
        assert!(
            covered,
            "{what} is at {relative}:{line}, and no citation in the map covers that line"
        );
    }
}

/// `HPAYChannelExitV1` exists on exactly one chain, and it is not Hacash
/// mainnet. The height it was deployed at is below the pinned checkpoint the
/// Hub's own evidence validator demands
/// (`ChannelUnilateralExitEvidence::is_verified_mainnet_deployment`), so no
/// amount of fullnode configuration can turn that deployment into a verified
/// mainnet one. A map that says otherwise sends an owner to do configuration
/// work in place of protocol work.
#[test]
fn the_map_never_presents_the_pilot_exit_deployment_as_a_mainnet_one() {
    let document = map();
    let dispute = section(&document, "### 1. Unilateral L1 dispute path");

    for forbidden in [
        "is deployed and independently verified on chain",
        "node configuration, not deployment",
    ] {
        assert!(
            !dispute.contains(forbidden),
            "the map still says {forbidden:?} about a deployment that is on the private pilot \
             chain at height {PILOT_EXIT_DEPLOYMENT_HEIGHT}"
        );
    }
    let checkpoint = l2_fast_pay_hub::node::HACASH_MAINNET_MIN_SAFE_HEIGHT.to_string();
    for required in ["private pilot chain", "chain id 7", checkpoint.as_str()] {
        assert!(
            dispute.contains(required),
            "the map must say {required:?} where it describes the exit deployment"
        );
    }
}

/// The other half of the same correction. The fullnode does not withhold the
/// unilateral-exit capability because nobody configured it; it withholds it
/// because the value is a literal `false`, guarded by a comment naming the
/// action-number collision that has to be resolved first. The day that stops
/// being true, this test fails and the map has to be rewritten - which is
/// exactly the moment it should be.
#[test]
fn the_fullnode_still_hardcodes_the_unilateral_exit_capability_false() {
    let node_api = repo_root().join("../hacash-fullnodedev/app/src/node_api.rs");
    let source = std::fs::read_to_string(&node_api).unwrap_or_else(|error| {
        panic!(
            "this crate path-depends on the fullnode tree, so {} must be readable: {error}",
            node_api.display()
        )
    });
    assert!(
        source.contains("let channel_unilateral_exit = false;"),
        "the fullnode no longer hardcodes channel_unilateral_exit; MAINNET_READINESS_MAP.md \
         section 1 is now out of date and must be re-measured"
    );
    // And the same for the profile this system actually settles on. This is
    // the one the dispute-path gate reads, so it is the one whose literal
    // decides whether `unilateral_l1_enforceable` can ever be published true.
    assert!(
        source.contains("let channel_registry_unilateral_exit = false;"),
        "the fullnode no longer hardcodes channel_registry_unilateral_exit; that flag is \
         what measure_node_reported_unilateral_exit reads, so MAINNET_READINESS_MAP.md \
         section 1 must be re-measured before anything downstream is trusted"
    );

    let dispute = section(&map(), "### 1. Unilateral L1 dispute path");
    assert!(
        dispute.contains("node_api.rs:"),
        "the map must cite the literal in the fullnode rather than describing it"
    );
}

/// The documents an operator actually reads must name the capability that
/// actually gates.
///
/// `MAINNET_READINESS_MAP.md` is guarded by the tests above; nothing guarded
/// `HUB-OPERATOR.md` or `L2_SAFETY_MODEL.md`, and both went on telling a Hub
/// operator to wait for `features.channel_unilateral_exit=true` after the gate
/// had moved to the shared registry. That is the same wrong-contract defect the
/// code was corrected for, left standing in the one place a human reads it: an
/// operator following it waits for a flag that opens nothing, and could deploy
/// the wrong contract on the strength of it.
///
/// Checked mechanically rather than by review, because a stale sentence in a
/// document has no compiler.
#[test]
fn the_operator_documents_name_the_capability_that_gates() {
    let profile = l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE;
    for relative in ["docs/HUB-OPERATOR.md", "docs/l2/L2_SAFETY_MODEL.md"] {
        let path = repo_root().join(relative);
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()));

        assert!(
            document.contains("channel_registry_unilateral_exit"),
            "{relative} never names the capability the dispute-path gate reads, so a reader \
             cannot tell which flag they are waiting on"
        );
        assert!(
            document.contains(profile),
            "{relative} must name the settlement profile {profile:?} the gate is about"
        );
        // The exact sentence the defect wore. Any wording that presents the V1
        // per-channel flag as the condition for `mainnet-pilot` is the bug.
        for forbidden in [
            "reports `features.channel_unilateral_exit=true`",
            "requires `features.channel_unilateral_exit=true`",
        ] {
            assert!(
                !document.contains(forbidden),
                "{relative} still says {forbidden:?}; that flag is the V1 per-channel \
                 contract and it gates nothing"
            );
        }
        // V1 may be mentioned - it is still published - but only if the
        // document says out loud that it is not the gate, so the two cannot be
        // confused by someone skimming.
        if document.contains("features.channel_unilateral_exit") {
            assert!(
                document.contains("gates nothing"),
                "{relative} mentions the V1 capability without saying it gates nothing"
            );
        }
    }
}
