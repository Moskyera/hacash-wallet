//! Desktop-only supervised Hacash fullnode.
//!
//! `desktop_relay.rs` is the shape this follows: a converge entry point rather
//! than a command, `managed` as the only thing that authorises the word "ours",
//! the kernel's own answer quoted rather than the intention that asked for it,
//! a sentence for every state that is not ready, and a read-only status command
//! that starts nothing.
//!
//! Six things differ, and every one of them is forced by the node rather than
//! by taste.
//!
//! 1. This is an OS process, not a task. `task.abort()` is total and instant;
//!    a child needs a signal, and Windows has no SIGTERM. So a stop is
//!    "graceful, time-boxed, then killed", and the report says WHICH happened.
//! 2. Crash detection has to exist. The relay's spawned task clears nothing
//!    when it ends, so its report can outlive it. A child dies with an exit
//!    code and stderr and we hold both, so this polls `try_wait` and says so.
//! 3. Binding a socket is not the proof of ownership here. The node binds its
//!    own, and when the API port is taken it prints an error and RETURNS while
//!    the chain and p2p threads keep running. "Our child is alive and 8080
//!    answers" is therefore exactly the false adoption the rules forbid. The
//!    proof is the child's own stdout line.
//! 4. There is a config file, and a path inside it. `resolve_config_path` takes
//!    argv[1], so the wallet passes its OWN config path and structurally cannot
//!    overwrite one somebody edited.
//! 5. A cold sync is minutes, not milliseconds, so the interesting state is
//!    polled rather than returned once.
//! 6. A wrong report here loses the truth about money, and the specific way it
//!    goes wrong is invisible: a real sync and an isolated private chain both
//!    show a climbing height. So the report carries the anchor by name.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hacash_wallet_core::node_capabilities::NodeCapabilities;
use hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH;
use hacash_wallet_core::paths::wallet_data_root;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// The numbers this supervisor is built around, each one measured rather than
// picked.
// ---------------------------------------------------------------------------

/// The API port the wallet's own node serves on. The same port the wallet
/// already points at by default, so a supervised node makes the loopback path
/// the easy one instead of a second thing to configure.
pub const DEFAULT_API_PORT: u16 = 8080;

/// The p2p port. The boot nodes are on 3337 and so is everybody else.
pub const DEFAULT_P2P_PORT: u16 = 3337;

/// THE ONE VALUE THAT IS NOT A DEFAULT.
///
/// The node ships `backbone_peers = 4`. Four signed mainnet transactions left
/// this machine's socket and were never mined, for two days, while the same
/// bytes posted to a well connected node were mined in two minutes. A leaf
/// node publishes only through peers it dialed itself, so outbound count is
/// the one lever a machine behind a router that refuses forwarding has.
pub const BACKBONE_PEERS: u32 = 32;

/// How long a graceful stop is given before the child is killed.
///
/// A sled flush plus a p2p shutdown over a 2.66 GB store is not instant, and
/// an exiting app gets no unbounded grace from the OS. The kill is not a
/// failure; it is the planned second half, and it is survivable because sled
/// is crash-safe. What it costs is the last unflushed writes and a recovery
/// scan, and the claim records that it happened so the next start can say so.
pub const GRACEFUL_STOP_BUDGET: Duration = Duration::from_secs(20);

/// The three mainnet boot nodes, as the working config on this machine carries
/// them.
pub const BOOT_NODES: [&str; 3] = [
    "54.193.49.59:3337",
    "182.92.163.225:3337",
    "54.219.80.127:3337",
];

/// The first line of a config this wallet wrote, and the fingerprint of
/// everything under it.
const CONFIG_MARKER: &str = "; written by HPAY Wallet, fingerprint ";

/// How many lines of the child's own output are kept for the screen.
const KEPT_LINES: usize = 200;

// ---------------------------------------------------------------------------
// Where things live.
// ---------------------------------------------------------------------------

/// Kilobytes of supervisor state, beside the wallet's own.
pub fn node_state_dir() -> PathBuf {
    wallet_data_root().join("node")
}

pub fn node_config_path() -> PathBuf {
    node_state_dir().join("hacash.config.ini")
}

pub fn node_claim_path() -> PathBuf {
    node_state_dir().join("node.claim.json")
}

pub fn node_lock_path() -> PathBuf {
    node_state_dir().join("node.lock")
}

pub fn node_stdout_log_path() -> PathBuf {
    node_state_dir().join("node.out.log")
}

pub fn node_stderr_log_path() -> PathBuf {
    node_state_dir().join("node.err.log")
}

/// THE CHAIN STORE, WHICH DOES NOT GO WHERE THE WALLET'S OWN STATE GOES.
///
/// `wallet_data_root()` is `dirs::data_dir()/HacashWallet`, and on Windows
/// `data_dir()` is ROAMING AppData. The measured store is 2.66 GB and grows.
/// A roaming profile would try to synchronise it, and a domain login would
/// grind. So the chain goes to the local, non-roaming location and only the
/// chain does.
///
/// `HACASH_WALLET_NODE_DATA` mirrors the existing `HACASH_WALLET_DATA`, so a
/// test and a person with a full system drive both have a lever without the
/// screen growing a path field.
pub fn node_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HACASH_WALLET_NODE_DATA") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("HacashWallet")
        .join("chain")
}

// ---------------------------------------------------------------------------
// The config the wallet writes, so nobody has to know any of it.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfigPlan {
    pub data_dir: PathBuf,
    pub api_port: u16,
    pub p2p_port: u16,
}

impl NodeConfigPlan {
    /// The ports are overridable by environment for the same reason the chain
    /// folder is: a lever for a machine whose 8080 is already spoken for, and
    /// for a test that must not go near the node the owner of this machine is
    /// really running. Deliberately not a field on the screen, because a port
    /// number is one of the 22 values this whole feature exists to stop asking
    /// people to understand.
    pub fn standard() -> Self {
        Self {
            data_dir: node_data_dir(),
            api_port: port_from_env("HACASH_WALLET_NODE_API_PORT", DEFAULT_API_PORT),
            p2p_port: port_from_env("HACASH_WALLET_NODE_P2P_PORT", DEFAULT_P2P_PORT),
        }
    }
}

fn port_from_env(key: &str, fallback: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(fallback)
}

/// A value that the node's own ini parser would silently truncate.
///
/// `strip_ini_comment` in `sys/src/config.rs` ends a value at a `;` or a `#`
/// that starts the line or follows whitespace. Trailing and leading spaces are
/// trimmed, so a space in a username survives; a semicolon in a path does not,
/// and the node would then resolve a shorter directory than the one we asked
/// for without saying anything. Refuse to write it rather than find out later.
pub fn ini_value_survives_the_parser(value: &str) -> Result<(), String> {
    let mut previous_is_space = true;
    for character in value.chars() {
        if (character == ';' || character == '#') && previous_is_space {
            return Err(format!(
                "This folder path contains a '{character}' after a space, and the node's own \
config reader treats that as the start of a comment. It would quietly use a shorter folder \
than the one asked for. Set HACASH_WALLET_NODE_DATA to a path without that character."
            ));
        }
        previous_is_space = character.is_whitespace();
    }
    Ok(())
}

/// The config text, in full, with every value the guide currently asks a person
/// to type by hand.
pub fn render_node_config(plan: &NodeConfigPlan) -> Result<String, String> {
    let data_dir = plan.data_dir.display().to_string();
    ini_value_survives_the_parser(&data_dir)?;
    if !plan.data_dir.is_absolute() {
        return Err(format!(
            "The chain folder {data_dir} is not an absolute path. The node resolves a relative \
data_dir next to its own executable, which is not where this wallet keeps it."
        ));
    }
    let boots = BOOT_NODES.join(", ");
    let backbone = BACKBONE_PEERS;
    let api_port = plan.api_port;
    let p2p_port = plan.p2p_port;
    Ok(format!(
        "; This file is written by HPAY Wallet. Edit it and the wallet will stop\n\
; rewriting it and say so on the node screen, rather than overwrite your work.\n\
data_dir = {data_dir}\n\
\n\
[node]\n\
listen = {p2p_port}\n\
boots = {boots}\n\
; false means this node keeps looking for peers. true is how a node ends up\n\
; alone on a private chain that climbs and looks healthy.\n\
not_find_nodes = false\n\
fast_sync = false\n\
; The shipped default is 4. Four signed mainnet transactions left this machine\n\
; and were never mined, for two days, while the identical bytes posted to a\n\
; well connected node were mined in two minutes. Outbound peers is the one\n\
; lever a machine behind a router that refuses port forwarding has.\n\
backbone_peers = {backbone}\n\
offshoot_peers = 200\n\
\n\
[server]\n\
enable = true\n\
listen = {api_port}\n\
bind = 127.0.0.1\n\
\n\
[miner]\n\
enable = false\n\
\n\
[diamondminer]\n\
enable = false\n"
    ))
}

fn fingerprint(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.replace("\r\n", "\n").as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

/// The bytes actually written: a marker line naming the fingerprint of
/// everything under it, then the config.
fn stamp(body: &str) -> String {
    format!("{CONFIG_MARKER}{}\n{body}", fingerprint(body))
}

/// Split a stamped file back into its claimed fingerprint and its body.
fn unstamp(contents: &str) -> Option<(String, String)> {
    let normalised = contents.replace("\r\n", "\n");
    let (first, rest) = normalised.split_once('\n')?;
    let claimed = first.strip_prefix(CONFIG_MARKER)?.trim().to_string();
    Some((claimed, rest.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ConfigWrite {
    /// There was nothing there and now there is.
    Written,
    /// Ours, and already exactly what we would write. Nothing was touched.
    Unchanged,
    /// Ours, untouched since we wrote it, and the template moved. Rewritten.
    Rewritten,
    /// Somebody edited it. Nothing was touched, and the screen says so.
    LeftAlone { reason: String },
}

/// Write the config, and never over somebody's own work.
///
/// The rule is exact rather than hopeful. A file we wrote carries a marker line
/// holding the fingerprint of the rest of itself. If the file is not stamped it
/// was not written here. If it is stamped and the fingerprint no longer matches
/// its body, somebody edited it. Both are left alone and both are reported,
/// because "the wallet ignored my edit" and "the wallet overwrote my edit" are
/// different failures and only one of them is recoverable.
pub fn write_node_config(path: &Path, plan: &NodeConfigPlan) -> Result<ConfigWrite, String> {
    let desired = render_node_config(plan)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create {parent:?}: {error}"))?;
    }
    match fs::read_to_string(path) {
        Ok(existing) => match judge_existing_config(path, &existing, &desired) {
            Some(verdict) => Ok(verdict),
            None => {
                fs::write(path, stamp(&desired))
                    .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
                Ok(ConfigWrite::Rewritten)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(path, stamp(&desired))
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
            Ok(ConfigWrite::Written)
        }
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

/// The read-only half of the rule above.
///
/// `None` means "ours, stale, and safe to rewrite", which is the only outcome
/// that needs a write, so the inspecting caller can report the other three
/// without touching the file.
fn judge_existing_config(path: &Path, existing: &str, desired: &str) -> Option<ConfigWrite> {
    match unstamp(existing) {
        None => Some(ConfigWrite::LeftAlone {
            reason: format!(
                "{} already exists and this wallet did not write it. It has been left exactly \
as it is, so the node runs with whatever is in that file and not with the settings this wallet \
would have chosen. In particular this wallet cannot promise the peer count that keeps a \
transaction from sitting unmined. Delete it if you want the wallet to manage it.",
                path.display()
            ),
        }),
        Some((claimed, body)) if claimed != fingerprint(&body) => Some(ConfigWrite::LeftAlone {
            reason: format!(
                "{} was written by this wallet and has been edited since. It has been left \
exactly as it is, so the node will start with your version and not the wallet's, and the peer \
count and boot nodes this wallet would have set are whatever your file says.",
                path.display()
            ),
        }),
        Some((_, body)) if body == desired.replace("\r\n", "\n") => Some(ConfigWrite::Unchanged),
        Some(_) => None,
    }
}

/// WHAT IS ON DISK, WITHOUT WRITING ANYTHING.
///
/// The status command must be able to say "the config the node is being given
/// is not the one this wallet would write" without that being a side effect of
/// having pressed Start. `None` means there is no config file yet, which is
/// true before a first start and is not a warning.
pub fn inspect_node_config(path: &Path, plan: &NodeConfigPlan) -> Option<ConfigWrite> {
    let desired = render_node_config(plan).ok()?;
    let existing = fs::read_to_string(path).ok()?;
    // A stale file of our own reads as `Unchanged` here rather than as a
    // pending rewrite: nothing on the screen should describe a write that has
    // not happened.
    Some(judge_existing_config(path, &existing, &desired).unwrap_or(ConfigWrite::Unchanged))
}

// ---------------------------------------------------------------------------
// Which binary, and is it even one.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeBinarySource {
    /// Shipped inside the installer. Nothing produces this yet: bundling is a
    /// separate pass, and this arm exists so that pass changes the installer
    /// and one search entry and nothing else in this file.
    Bundled,
    /// The person pointed at it.
    Picked,
    /// Found where a person can drop one by hand.
    Found,
    /// Where the guide told people to build it.
    /// No longer produced. `node_binary_search_paths` used to end at a
    /// hardcoded `C:/hpay/fullnode.exe`; see the comment there for why it went.
    /// The variant stays so a report written by an older build still parses,
    /// and so the tests that exercise report rendering keep their fixture.
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeBinaryReport {
    pub path: Option<String>,
    pub source: Option<NodeBinarySource>,
    pub version: Option<String>,
    pub database_type: Option<u32>,
    /// Every path looked at, and what was found there. "We looked here" is the
    /// difference between a dead end and something a person can fix.
    pub searched: Vec<SearchedPath>,
    /// The path a person pointed the wallet at, whether or not it worked.
    pub picked_path: Option<String>,
    /// Set when that path no longer answers as a fullnode. When this is set
    /// nothing else is chosen, because running a DIFFERENT node than the one
    /// somebody picked, without saying so, is the substitution that does not
    /// crash and lies about money.
    pub picked_problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchedPath {
    pub path: String,
    pub source: NodeBinarySource,
    pub verdict: String,
}

fn executable_name() -> &'static str {
    if cfg!(windows) {
        "fullnode.exe"
    } else {
        "fullnode"
    }
}

/// Where to look, in order.
///
/// The first entry is deliberately the exact place the bundling pass will drop
/// the binary, so that pass adds an installer step and changes nothing here.
pub fn node_binary_search_paths(picked: Option<&Path>) -> Vec<(NodeBinarySource, PathBuf)> {
    let mut out: Vec<(NodeBinarySource, PathBuf)> = Vec::new();
    // A path a person typed comes FIRST, ahead of anything the wallet found on
    // its own. Choosing one and silently getting another is the substitution
    // this file's own copy warns about, and the ordering is half of not doing
    // it; `resolve_node_binary` refusing to fall past a failed pick is the
    // other half.
    if let Some(picked) = picked {
        out.push((NodeBinarySource::Picked, picked.to_path_buf()));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        out.push((
            NodeBinarySource::Bundled,
            dir.join("hacash").join(executable_name()),
        ));
    }
    out.push((
        NodeBinarySource::Found,
        node_state_dir().join("bin").join(executable_name()),
    ));
    // NO HARDCODED WINDOWS PATH. `C:/hpay/fullnode.exe` used to sit here as a
    // last resort, and `resolve_node_binary` does not merely stat a candidate -
    // it RUNS it to read a version, and the supervisor then starts what it
    // found. On this machine that file carries
    // `NT AUTHORITY\Authenticated Users:(I)(M)`, inherited from the Windows
    // default on `C:\` itself, so any account on the computer could replace it
    // and the wallet would execute it while merely showing a settings screen:
    // NodeSupervisorPanel polls every 3000 ms, before any button exists to
    // confirm against. This tree already refuses to install an unattributable
    // Windows binary - `update_download.rs` pins a publisher certificate - and
    // applied none of that here.
    //
    // Removing it costs nothing now that a pick is persisted in
    // `WalletSettings::node_binary_path`: an owner running a node at that path
    // chooses it once and it comes back on every launch, as `Picked`, which is
    // first in this list and which `resolve_node_binary` refuses to fall past.
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBinaryProbe {
    pub version: String,
    pub database_type: Option<u32>,
    pub line: String,
}

/// The version line the node prints before it does anything at all.
///
/// `[Version] full node v1.0.10, build time: 2026/7/10 #1, database type: 8.`
pub fn parse_version_line(text: &str) -> Option<NodeBinaryProbe> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("[Version]"))?
        .trim()
        .to_string();
    let after = line.trim_start().strip_prefix("[Version]")?.trim();
    let version = after.split(',').next().unwrap_or(after).trim().to_string();
    let database_type = line
        .split("database type:")
        .nth(1)
        .and_then(|tail| {
            tail.trim()
                .trim_end_matches('.')
                .split_whitespace()
                .next()
                .map(str::to_string)
        })
        .and_then(|digits| digits.trim_end_matches('.').parse::<u32>().ok());
    Some(NodeBinaryProbe {
        version,
        database_type,
        line,
    })
}

/// Confirm a candidate is a Hacash fullnode, without letting it touch anything.
///
/// Running it with a config path that does not exist is safe by construction:
/// `FullnodeBuilder::from_config_path` errors before `from_ini`, so nothing
/// binds a port, resolves a data directory or opens a database. One probe
/// answers three questions at once: whether it is a fullnode, which version,
/// and which database type, which is the `state_vN` question.
pub fn probe_node_binary(path: &Path) -> Result<NodeBinaryProbe, String> {
    if !path.is_file() {
        return Err("nothing is at this path".to_string());
    }
    let mut command = Command::new(path);
    command
        .arg("/hpay-wallet-probe-config-that-does-not-exist.ini")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_console(&mut command);
    let output = command
        .output()
        .map_err(|error| format!("this file could not be run: {error}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_version_line(&text).ok_or_else(|| {
        let first = text
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("");
        format!("this is not a Hacash fullnode. It answered: {first}")
    })
}

pub fn resolve_node_binary(picked: Option<&Path>) -> NodeBinaryReport {
    let mut searched = Vec::new();
    let mut chosen: Option<(NodeBinarySource, PathBuf, NodeBinaryProbe)> = None;
    let mut picked_problem: Option<String> = None;
    for (source, path) in node_binary_search_paths(picked) {
        if chosen.is_some() || picked_problem.is_some() {
            continue;
        }
        let verdict = match probe_node_binary(&path) {
            Ok(probe) => {
                let verdict = format!("{} answered here", probe.version);
                chosen = Some((source, path.clone(), probe));
                verdict
            }
            Err(reason) => {
                // THE FALL-THROUGH THAT DOES NOT HAPPEN. A pick that has gone
                // missing stops the search instead of quietly promoting the
                // next candidate, because "I chose that one" and "the wallet
                // ran this other one" must never both be true and unsaid.
                if source == NodeBinarySource::Picked {
                    picked_problem = Some(reason.clone());
                }
                reason
            }
        };
        searched.push(SearchedPath {
            path: path.display().to_string(),
            source,
            verdict,
        });
    }
    let picked_path = picked.map(|path| path.display().to_string());
    match chosen {
        Some((source, path, probe)) => NodeBinaryReport {
            path: Some(path.display().to_string()),
            source: Some(source),
            version: Some(probe.version),
            database_type: probe.database_type,
            searched,
            picked_path,
            picked_problem,
        },
        None => NodeBinaryReport {
            path: None,
            source: None,
            version: None,
            database_type: None,
            searched,
            picked_path,
            picked_problem,
        },
    }
}

// ---------------------------------------------------------------------------
// The claim, which is never proof on its own.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeClaim {
    pub pid: u32,
    pub claimed_unix: u64,
    pub binary: String,
    pub data_dir: String,
    pub config_path: String,
    pub api_port: u16,
    pub p2p_port: u16,
    /// True when the graceful stop ran out of time and the child was killed,
    /// so the next start can say the store may need a recovery scan instead of
    /// letting a person watch an unexplained pause.
    #[serde(default)]
    pub stopped_hard: bool,
}

pub fn read_claim(path: &Path) -> Option<NodeClaim> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

pub fn write_claim(path: &Path, claim: &NodeClaim) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create {parent:?}: {error}"))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(claim).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// What a claim file on disk is worth.
///
/// A pid alone is worthless because pids are recycled, and a file existing is
/// not evidence a process does. So the claim is never the proof: the lock file
/// beside it is, because holding it is a thing only a live process can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum ClaimVerdict {
    /// No claim file.
    None,
    /// A claim exists and a live process still holds the lock beside it. This
    /// is the only verdict that refuses a start.
    Held { pid: u32, data_dir: String },
    /// A claim exists and nothing holds the lock, so whatever wrote it is gone.
    Stale { pid: u32, stopped_hard: bool },
}

// ---------------------------------------------------------------------------
// What was seen, and what it means.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForeignAnswer {
    /// The node name and version it reported, when it is a Hacash node.
    pub node: Option<String>,
    /// What it said, when it is not.
    pub said: Option<String>,
}

/// Everything the supervisor read, before any of it is interpreted.
///
/// Every state and every refusal is a function of this struct and nothing else,
/// so each one can be entered by a test without a process, a port or a network.
#[derive(Debug, Clone, Default)]
pub struct NodeObservations {
    pub binary: Option<NodeBinaryReport>,
    /// We hold a Child and `try_wait` says it has not exited.
    pub ours_alive: bool,
    /// Set once the child has exited, from `try_wait`.
    pub ours_exit_code: Option<i32>,
    /// A graceful stop was asked for and the time box has not run out.
    pub stopping: bool,
    /// A stop happened and the child had to be killed.
    pub stopped_hard: bool,
    /// Something answers on the API port and it is not our child.
    pub foreign_on_api_port: Option<ForeignAnswer>,
    /// The p2p port is taken by something that is not ours.
    pub p2p_port_taken: bool,
    /// The child's own confirmation that it, not somebody else, has the API
    /// port. This is the analogue of reading a bound address back off a
    /// listener, and it is the ONLY thing that authorises the word "ours"
    /// about an answering port.
    pub our_api_line: Option<String>,
    /// The child said it could not bind the API port and carried on anyway.
    pub api_bind_error: Option<String>,
    /// The directory the node itself printed, which is compared to the one we
    /// asked for rather than assumed to match it.
    pub engine_data_dir: Option<String>,
    pub asked_data_dir: String,
    /// `[P2P] Connect N boot nodes`.
    pub boot_nodes_connected: Option<usize>,
    /// The answer from `/query/capabilities` on our own node.
    pub capabilities: Option<NodeCapabilities>,
    pub claim: Option<ClaimVerdict>,
    pub config: Option<ConfigWrite>,
    /// Anything that stopped a start before it began.
    pub refusal: Option<String>,
    pub api_port: u16,
    pub p2p_port: u16,
    pub last_error_lines: Vec<String>,
    /// A start was asked for and the child does not exist yet.
    pub start_requested: bool,
    /// WHO HOLDS THE API PORT, asked of the kernel at this poll rather than
    /// remembered from the one line the child printed when it started. This is
    /// what stops a latched announcement from outliving the fact.
    pub api_port_holder: ApiPortHolder,
    /// STICKY. Set the first time the API port is seen free, or in somebody
    /// else's hands, after our child announced it. It exists for the systems
    /// where the kernel will not name the owning pid: there, "something is
    /// listening" is not evidence of who, so once the port has changed hands
    /// even once it is never silently trusted again.
    pub api_port_lost: bool,
    /// How long our child has been alive, so "starting" carries a clock and a
    /// person can tell one second from one hour.
    pub alive_seconds: Option<u64>,
    /// How the last stop actually ended.
    pub last_stop: Option<StopOutcome>,
}

/// What a stop did, rather than what it asked for.
///
/// `killed` false means the wallet never had to call `kill`. It does NOT mean
/// the node flushed: on Windows a process with no Ctrl handler is terminated
/// outright by CTRL_BREAK, which looks identical from here. So the field is
/// named for what was observed and the sentence built from it says only that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StopOutcome {
    pub killed: bool,
    pub seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    NotPresent,
    Blocked,
    Starting,
    CatchingUp,
    Ready,
    Foreign,
    Failed,
    Stopping,
    Stopped,
}

/// Which chain is being watched. A real sync and an isolated private chain
/// both show a climbing height, so this is the only field that tells them
/// apart and it is never omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainAnchor {
    /// Block one is the mainnet block one, on chain 0, with mainnet true.
    Confirmed,
    /// The node has no block one yet. Brief in a real sync. Held, or seen with
    /// zero boot nodes connected, it IS the isolated chain.
    NotYetAvailable,
    /// Block one is present and is not mainnet's.
    Wrong,
    /// Nothing has been read yet.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeSupervisorReport {
    pub state: NodeState,
    /// The one field that authorises the word "ours". A foreign node the wallet
    /// is happy to read from is never this.
    pub ours: bool,
    pub headline: String,
    /// Why this state, built out of something that was read. Every state that
    /// is not Ready has one.
    pub detail: String,
    pub binary: NodeBinaryReport,
    pub api_url: String,
    pub api_port: u16,
    pub p2p_port: u16,
    pub data_dir: String,
    pub config_path: String,
    pub config: Option<ConfigWrite>,
    pub height: Option<u64>,
    pub tip_age_seconds: Option<u64>,
    pub max_tip_age_seconds: Option<u64>,
    /// The node's own timestamp on the newest block it holds, and its own
    /// clock reading at the moment it answered.
    ///
    /// Carried because a percentage needs a denominator, and the only honest
    /// denominator available is one the node itself supplies. Two readings of
    /// these give the average seconds per block across exactly the blocks this
    /// node just took in, and that divided into `tip_age_seconds` is how far
    /// behind it is in blocks. Nothing about the chain is assumed: no block
    /// interval is compiled in here, because a compiled-in one would be an
    /// invented number wearing a measurement's clothes.
    pub tip_timestamp_unix: Option<u64>,
    pub observed_unix: Option<u64>,
    pub fresh: Option<bool>,
    pub anchor: ChainAnchor,
    /// Which chain is being watched, in words.
    pub watching: String,
    pub peer_role: Option<String>,
    pub peers_inbound: Option<u64>,
    pub peers_outbound: Option<u64>,
    /// Ready means the wallet can trust this node about the chain. It does not
    /// mean anybody can reach it, and this is the sentence that says so.
    pub reach: Option<String>,
    pub exit_code: Option<i32>,
    pub last_error_lines: Vec<String>,
    pub stopped_hard: bool,
    pub can_start: bool,
    pub can_stop: bool,
    /// Offered when there is no binary, and never phrased as though one shipped.
    pub offers: Vec<String>,
    /// Who the kernel says holds the API port at this poll. Carried onto the
    /// screen so "ours" is a thing that was checked rather than remembered.
    pub api_port_holder: ApiPortHolder,
}

/// The sentence a person gets when this wallet ships no node binary.
///
/// This pass builds the supervisor. Shipping the binary is a separate pass, so
/// NotPresent is the DEFAULT state rather than an edge case, and it must not
/// read as a broken wallet: the wallet works today against whatever node it is
/// pointed at, and this feature is an offer, not a requirement.
pub const NOTHING_BUNDLED_YET: &str = "This version of the wallet does not carry a Hacash node inside it, so there is nothing here \
to start yet. Your wallet is not broken and nothing is missing from it: it is working against \
the node it is already pointed at, exactly as before.";

/// Downloading one is not on the list, and the reason belongs on the screen.
pub const WHY_NO_DOWNLOAD: &str = "This wallet will not download a node for you. There is no publisher signature to check it \
against, and a substituted node does not crash, it lies about money.";

pub fn anchor_of(capabilities: &NodeCapabilities) -> ChainAnchor {
    if !capabilities.network.block_1_available {
        return ChainAnchor::NotYetAvailable;
    }
    match capabilities.network.block_1_hash.as_deref() {
        Some(hash) if hash.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH) => {
            if capabilities.chain.id == 0 && capabilities.chain.mainnet {
                ChainAnchor::Confirmed
            } else {
                ChainAnchor::Wrong
            }
        }
        Some(_) => ChainAnchor::Wrong,
        None => ChainAnchor::NotYetAvailable,
    }
}

fn watching_sentence(anchor: ChainAnchor, boot_nodes: Option<usize>) -> String {
    match anchor {
        ChainAnchor::Confirmed => format!(
            "Watching Hacash mainnet. This node's block one is {MAINNET_BLOCK_ONE_HASH}, which is \
the one this wallet was built with, on chain 0."
        ),
        ChainAnchor::NotYetAvailable => {
            let alone = matches!(boot_nodes, Some(0));
            if alone {
                format!(
                    "This node has no block one and has connected to 0 boot nodes. A height that \
climbs while that is true is a private chain of its own, not Hacash mainnet, and money sent on it \
reaches nobody. It is not being trusted about anything until its block one is \
{MAINNET_BLOCK_ONE_HASH}."
                )
            } else {
                format!(
                    "This node does not have block one yet, so which chain it is on is not yet \
known. A climbing height on its own proves nothing: a node alone on a private chain climbs too. \
It will be trusted once its block one reads {MAINNET_BLOCK_ONE_HASH}."
                )
            }
        }
        ChainAnchor::Wrong => format!(
            "This node's block one is not Hacash mainnet's. Mainnet's is \
{MAINNET_BLOCK_ONE_HASH}. Whatever this node is following, it is not the chain your money is on."
        ),
        ChainAnchor::Unknown => "Nothing has been read from this node yet.".to_string(),
    }
}

fn reach_sentence(capabilities: &NodeCapabilities) -> Option<String> {
    let peers = capabilities.peers.as_ref()?;
    let role = peers.role.clone().unwrap_or_else(|| "unknown".to_string());
    let inbound = peers.inbound_established_if_measured();
    let outbound = peers.outbound_established;
    match (inbound, outbound) {
        (Some(0), Some(out)) => Some(format!(
            "This node is a {role}: it has dialed out to {out} peers and nobody has dialed in. It \
is right about the chain, because it validated these blocks itself. What is not proven is that a \
transaction you send leaves through it, and four of them did not, here, for two days."
        )),
        (Some(inbound), Some(out)) => Some(format!(
            "This node is a {role}: {inbound} peers have dialed in and it has dialed out to {out}."
        )),
        _ => Some(format!(
            "This node reports its role as {role} and could not count its peers, so whether \
anybody has reached it is unknown rather than fine."
        )),
    }
}

/// EVERY STATE, AS A FUNCTION OF WHAT WAS READ AND NOTHING ELSE.
pub fn decide(observed: &NodeObservations, config_path: &str) -> NodeSupervisorReport {
    let binary = observed.binary.clone().unwrap_or(NodeBinaryReport {
        path: None,
        source: None,
        version: None,
        database_type: None,
        searched: Vec::new(),
        picked_path: None,
        picked_problem: None,
    });
    let capabilities = observed.capabilities.as_ref();
    let anchor = capabilities.map(anchor_of).unwrap_or(ChainAnchor::Unknown);
    let mut report = NodeSupervisorReport {
        state: NodeState::Stopped,
        ours: false,
        headline: String::new(),
        detail: String::new(),
        binary,
        api_url: format!("http://127.0.0.1:{}", observed.api_port),
        api_port: observed.api_port,
        p2p_port: observed.p2p_port,
        data_dir: observed.asked_data_dir.clone(),
        config_path: config_path.to_string(),
        config: observed.config.clone(),
        height: capabilities.map(|c| c.chain.height),
        tip_age_seconds: capabilities.map(|c| c.sync.tip_age_seconds),
        max_tip_age_seconds: capabilities.map(|c| c.sync.max_tip_age_seconds),
        tip_timestamp_unix: capabilities.map(|c| c.sync.tip_timestamp_unix),
        observed_unix: capabilities.map(|c| c.sync.observed_unix),
        fresh: capabilities.map(|c| c.sync.fresh),
        anchor,
        watching: watching_sentence(anchor, observed.boot_nodes_connected),
        peer_role: capabilities
            .and_then(|c| c.peers.as_ref())
            .and_then(|p| p.role.clone()),
        peers_inbound: capabilities
            .and_then(|c| c.peers.as_ref())
            .and_then(|p| p.inbound_established_if_measured()),
        peers_outbound: capabilities
            .and_then(|c| c.peers.as_ref())
            .and_then(|p| p.outbound_established),
        reach: capabilities.and_then(reach_sentence),
        exit_code: observed.ours_exit_code,
        last_error_lines: observed.last_error_lines.clone(),
        stopped_hard: observed.stopped_hard,
        can_start: false,
        can_stop: false,
        offers: Vec::new(),
        api_port_holder: observed.api_port_holder,
    };

    // 8. Stopping. Before everything, because a child that is on its way out is
    // not a child that is running and is not one that has failed.
    if observed.stopping {
        report.state = NodeState::Stopping;
        report.ours = true;
        report.headline = "Stopping your node".to_string();
        report.detail = format!(
            "The node was asked to shut down cleanly. It is given {} seconds to flush the chain \
to disk before it is closed the hard way. On a store this size that is not instant.",
            GRACEFUL_STOP_BUDGET.as_secs()
        );
        return report;
    }

    // 7. Failed. It started and did not survive, or started wrong. Named cases
    // only; a bare exit code is not a diagnosis.
    if let Some(code) = observed.ours_exit_code {
        report.state = NodeState::Failed;
        report.exit_code = Some(code);
        report.can_start = true;
        report.headline = "Your node stopped on its own".to_string();
        let joined = observed.last_error_lines.join(" ").to_ascii_lowercase();
        report.detail = if code == 101 && joined.contains("lock") {
            format!(
                "The node exited immediately because another program is already using the chain \
folder {}. Two programs writing one chain store is how a chain gets corrupted, so it refused \
rather than share it. Close the other node and try again.",
                observed.asked_data_dir
            )
        } else if joined.contains("api server failed to bind") {
            format!(
                "The node could not take port {} for its API and carried on without one, so the \
wallet had a node it could not read. It has been stopped.",
                observed.api_port
            )
        } else if joined.contains("is empty or failed to load") {
            format!(
                "The node could not read the config file this wallet wrote at {config_path}. That \
is this wallet's own bug, not something you did wrong."
            )
        } else if anchor == ChainAnchor::Wrong {
            watching_sentence(ChainAnchor::Wrong, observed.boot_nodes_connected)
        } else {
            format!(
                "The node exited with code {code}. The last thing it printed is below, exactly as \
it printed it."
            )
        };
        return report;
    }

    // 3a. RUNNING WITHOUT AN API. Its own words, and they are a failed start
    // rather than a slow one, because the node keeps the chain and p2p threads
    // going regardless and would otherwise sit in "Starting" for ever while
    // holding the chain folder. Failed, not Starting: the screen used to say
    // "this is being treated as a failed start" while treating it as neither.
    if observed.ours_alive
        && let Some(error) = observed.api_bind_error.as_deref()
    {
        report.state = NodeState::Failed;
        report.ours = true;
        report.can_stop = true;
        report.headline = "Your node is running with no way in".to_string();
        report.detail = format!(
            "The node this wallet started said it could not take port {}: {error}. It keeps the \
chain going without an API, so the wallet has a node it cannot read a single number out of, and \
it is still holding the chain folder. Stop it, free port {}, and start it again.",
            observed.api_port, observed.api_port
        );
        return report;
    }

    // 3b. Starting. The process exists, nothing is proven yet.
    if observed.ours_alive && observed.our_api_line.is_none() {
        report.state = NodeState::Starting;
        report.ours = true;
        report.can_stop = true;
        report.headline = "Starting your node".to_string();
        // ALWAYS A NUMBER. A screen that reads the same at one second and at
        // one hour cannot be told apart from one that has stopped working.
        let elapsed = match observed.alive_seconds {
            Some(seconds) => format!(" It has been running for {seconds} seconds."),
            None => String::new(),
        };
        report.detail = match observed.engine_data_dir.as_deref() {
            Some(dir) => format!(
                "The node has opened its chain folder at {dir} and has not yet said which \
address it is serving its API on. Nothing is being reported about the chain until it does.{elapsed}"
            ),
            None => format!("The node has been started and has not printed anything yet.{elapsed}"),
        };
        return report;
    }

    // 3c. THE PORT IT ANNOUNCED IS NOT THE PORT IT HAS.
    //
    // The child prints `[Api Server] listening on ...` exactly once. Believing
    // that line for the rest of the process's life is how a stranger's node
    // gets reported as ours, with a green header and a block one hash on it:
    // the API thread can end while the chain and p2p threads carry on, and
    // anything at all can then take the port. So the announcement is checked
    // against the kernel at every poll, and losing that check is a failure
    // with its own words rather than a quiet change of subject.
    if observed.ours_alive && observed.our_api_line.is_some() {
        let lost = match observed.api_port_holder {
            ApiPortHolder::Nobody => Some(format!(
                "The node this wallet started said it was serving its API on port {}, and nothing \
is listening on that port now. Its API is gone while the rest of it keeps running, so this wallet \
cannot read it. Nothing on this screen is being reported about the chain, because any answer on \
that port now would be somebody else's.",
                observed.api_port
            )),
            ApiPortHolder::Stranger { pid } => Some(format!(
                "Port {} is now held by a different program on this computer (process {pid}), not \
by the node this wallet started, which is still running. Nothing is being read from that port. A \
node that is not the one you started can say anything it likes about your money, so this wallet \
will not repeat it.",
                observed.api_port
            )),
            _ if observed.api_port_lost => Some(format!(
                "Port {} stopped answering at least once while the node this wallet started was \
running, and something is on it again. This wallet cannot prove on this system that what is there \
now is its own node, so it is reading nothing from it.",
                observed.api_port
            )),
            _ => None,
        };
        if let Some(detail) = lost {
            report.state = NodeState::Failed;
            report.ours = true;
            report.can_stop = true;
            report.headline = "Your node stopped answering".to_string();
            report.detail = detail;
            // Numbers read before the port changed hands are not numbers about
            // the chain now, so none of them are carried onto this screen.
            report.height = None;
            report.tip_age_seconds = None;
            report.max_tip_age_seconds = None;
            report.tip_timestamp_unix = None;
            report.observed_unix = None;
            report.fresh = None;
            report.anchor = ChainAnchor::Unknown;
            report.watching =
                "No chain is being watched. The wallet is not reading anything on this port."
                    .to_string();
            report.peer_role = None;
            report.peers_inbound = None;
            report.peers_outbound = None;
            report.reach = None;
            return report;
        }
    }

    // Ours, alive, and it confirmed the API port is its own.
    if observed.ours_alive {
        report.ours = true;
        report.can_stop = true;
        // The filesystem readback: the node prints the directory it resolved,
        // and it is compared rather than assumed.
        if let Some(engine) = observed.engine_data_dir.as_deref()
            && !same_directory(engine, &observed.asked_data_dir)
        {
            report.state = NodeState::Failed;
            report.headline = "Your node opened a different folder".to_string();
            report.detail = format!(
                "The wallet asked the node to keep the chain in {} and the node reported it \
opened {engine}. Nothing is being reported about a chain that is not the one this wallet set up.",
                observed.asked_data_dir
            );
            return report;
        }
        let Some(capabilities) = capabilities else {
            report.state = NodeState::Starting;
            report.headline = "Starting your node".to_string();
            report.detail = format!(
                "The node says it is serving its API at {}, and it has not answered a question yet.",
                observed.our_api_line.clone().unwrap_or_default()
            );
            return report;
        };
        if anchor == ChainAnchor::Wrong {
            report.state = NodeState::Failed;
            report.headline = "Wrong network".to_string();
            report.detail = watching_sentence(ChainAnchor::Wrong, observed.boot_nodes_connected);
            return report;
        }
        let at_the_tip = anchor == ChainAnchor::Confirmed && capabilities.sync.fresh;
        if at_the_tip {
            report.state = NodeState::Ready;
            report.headline = "Your node is up to date".to_string();
            // Never the bare word "synced". An age, with the budget beside it.
            report.detail = format!(
                "Block {} arrived {} seconds ago, and this node treats anything under {} seconds \
as current.",
                capabilities.chain.height,
                capabilities.sync.tip_age_seconds,
                capabilities.sync.max_tip_age_seconds
            );
        } else {
            report.state = NodeState::CatchingUp;
            report.headline = format!("Catching up, at block {}", capabilities.chain.height);
            report.detail = format!(
                "This node is at block {} and the newest block it holds is {} seconds old, which \
is over its own {} second budget. It is still downloading. This takes about seven minutes from \
nothing on a fast connection and can take considerably longer.",
                capabilities.chain.height,
                capabilities.sync.tip_age_seconds,
                capabilities.sync.max_tip_age_seconds
            );
        }
        return report;
    }

    // 2. Blocked. A binary exists and we refuse to start. Separate from Failed
    // because a refusal before a start is not a failed start and the fixes are
    // different.
    if let Some(refusal) = observed.refusal.as_deref() {
        report.state = NodeState::Blocked;
        report.headline = "The wallet did not start a node".to_string();
        report.detail = refusal.to_string();
        if observed.foreign_on_api_port.is_some() {
            report.offers.push(
                "Use the node that is already answering, exactly as it is. The wallet will read \
it and will not pretend it started it."
                    .to_string(),
            );
        }
        return report;
    }

    // 6. Foreign. A Hacash node answers and we did not start it. Never folded
    // into Ready, and no stop button is drawn for a process that is not ours.
    if let Some(foreign) = observed.foreign_on_api_port.as_ref() {
        report.state = NodeState::Foreign;
        report.ours = false;
        report.can_stop = false;
        match foreign.node.as_deref() {
            Some(node) => {
                report.headline = "A node is already running on this computer".to_string();
                report.detail = format!(
                    "{node} is answering on 127.0.0.1:{}. This wallet did not start it, so it \
cannot stop it and will not claim it. The wallet can read it exactly as it reads any node you \
point it at.",
                    observed.api_port
                );
            }
            None => {
                report.state = NodeState::Blocked;
                report.headline = "Something else has this port".to_string();
                // NOT "it said", which put this wallet's own client error into
                // a stranger's mouth. What is true is that we asked and did not
                // get a Hacash answer back, and the reason is ours to report.
                report.detail = format!(
                    "Something on this computer is using port {} and it did not answer as a \
Hacash node. Asking it failed with: {}. Nothing has been started, and nothing on this port is \
being read.",
                    observed.api_port,
                    foreign
                        .said
                        .clone()
                        .unwrap_or_else(|| "no answer at all".to_string())
                );
            }
        }
        return report;
    }

    // The other port. It has no state of its own, because a node cannot talk to
    // the network without it and a person who cannot start one needs the reason
    // rather than a second row of red.
    if observed.p2p_port_taken {
        report.state = NodeState::Blocked;
        report.headline = "Another program has the network port".to_string();
        report.detail = format!(
            "Something on this computer is already using port {}, which is the port a node needs to talk to the rest of the Hacash network. Nothing has been started.",
            observed.p2p_port
        );
        return report;
    }

    // 1. NotPresent. The default in this pass, and the one that has to read as
    // an offer rather than a fault.
    if report.binary.path.is_none() {
        report.state = NodeState::NotPresent;
        // THE PICK THAT WENT MISSING, said out loud rather than replaced.
        //
        // The wallet knows about other fullnodes on this computer and would
        // happily run one. Doing that after the file somebody chose was
        // deleted or renamed would mean the screen says "Starting your node"
        // about a different program than the one they picked, and the whole
        // reason this wallet refuses to download a node is that a substituted
        // node does not crash, it lies about money. So the search stops at the
        // pick, and the pick is named.
        if let Some(problem) = report.binary.picked_problem.clone() {
            let path = report
                .binary
                .picked_path
                .clone()
                .unwrap_or_else(|| "the path you gave".to_string());
            report.headline = "The node you chose is not there any more".to_string();
            report.detail = format!(
                "You pointed this wallet at {path}, and now {problem}. Nothing has been started. \
This wallet will not quietly run a different fullnode instead, even though it can see others on \
this computer, because a node that is not the one you chose can say anything it likes about your \
money. Put that file back, or point the wallet at another one."
            );
            report.offers = vec![
                "Put the file back where it was, or point the wallet at wherever it is now."
                    .to_string(),
                "Keep using the node this wallet is already pointed at. Nothing here is required."
                    .to_string(),
                WHY_NO_DOWNLOAD.to_string(),
            ];
            return report;
        }
        report.headline = "No node to run yet".to_string();
        report.detail = NOTHING_BUNDLED_YET.to_string();
        report.offers = vec![
            "Point the wallet at a fullnode you already have, by giving it the path.".to_string(),
            "Keep using the node this wallet is already pointed at. Nothing here is required."
                .to_string(),
            "Build one yourself. docs/l2/YOUR-FIRST-MAINNET-CHANNEL.md steps 1 and 2 are the long \
road, and it is the only one that asks you to type commands."
                .to_string(),
            WHY_NO_DOWNLOAD.to_string(),
        ];
        return report;
    }

    // 9. Stopped. Gone, and honest about how.
    report.state = NodeState::Stopped;
    report.can_start = true;
    report.headline = "Your node is not running".to_string();
    report.detail = if observed.stopped_hard {
        format!(
            "The node was closed the hard way when it did not shut down within {} seconds. \
Nothing is lost: the chain store survives that. The next start may pause while it checks the \
last few blocks it had not finished writing.",
            GRACEFUL_STOP_BUDGET.as_secs()
        )
    } else if let Some(stop) = observed.last_stop {
        // NOT "IT FLUSHED CLEANLY", because that is not a thing this wallet
        // can see. All it knows is that it asked, and that the process ended
        // without needing to be killed. On Windows a process with no Ctrl
        // handler is terminated outright by the same request, which looks
        // identical from out here, so the sentence claims only what was
        // observed and names the recovery scan either way.
        format!(
            "The node was asked to shut down and ended {} seconds later, without having to be \
closed the hard way. Whether it finished writing its last blocks is not something this wallet can \
see from outside, so the next start may pause while it checks them. Nothing is lost either way.",
            stop.seconds
        )
    } else {
        let version = report.binary.version.clone().unwrap_or_default();
        format!(
            "{version} is ready to start, and this wallet has not started it. Its chain goes in \
{}, and it will stop when you close the wallet.",
            observed.asked_data_dir
        )
    };
    report
}

fn same_directory(left: &str, right: &str) -> bool {
    let normalise = |value: &str| {
        value
            .trim()
            .trim_end_matches(['/', '\\'])
            .replace('\\', "/")
            .to_ascii_lowercase()
    };
    normalise(left) == normalise(right)
}

// ---------------------------------------------------------------------------
// The live process.
// ---------------------------------------------------------------------------

/// What the child said about itself, filled in by the reader threads.
#[derive(Debug, Default)]
pub struct NodeOutput {
    stdout: Mutex<VecDeque<String>>,
    stderr: Mutex<VecDeque<String>>,
    api_line: Mutex<Option<String>>,
    api_bind_error: Mutex<Option<String>>,
    engine_data_dir: Mutex<Option<String>>,
    boot_nodes: Mutex<Option<usize>>,
}

impl NodeOutput {
    /// Read one line of the child's own output.
    ///
    /// The API line is the whole ownership test. The node binds its own socket,
    /// so this is the only place a claim on that port can honestly come from.
    pub fn observe(&self, line: &str) {
        let trimmed = line.trim_end();
        if trimmed.contains("[Api Server] listening on")
            && let Ok(mut slot) = self.api_line.lock()
        {
            *slot = Some(trimmed.to_string());
        }
        if trimmed.contains("api server failed to bind")
            && let Ok(mut slot) = self.api_bind_error.lock()
        {
            *slot = Some(trimmed.to_string());
        }
        if let Some(rest) = trimmed.split("[Engine] Data:").nth(1) {
            let dir = rest.split(", rebuild").next().unwrap_or(rest).trim();
            if let Ok(mut slot) = self.engine_data_dir.lock() {
                *slot = Some(dir.to_string());
            }
        }
        if let Some(rest) = trimmed.split("[P2P] Connect").nth(1)
            && let Some(count) = rest.split_whitespace().next()
            && let Ok(count) = count.parse::<usize>()
            && let Ok(mut slot) = self.boot_nodes.lock()
        {
            *slot = Some(count);
        }
    }

    fn push(&self, which: &Mutex<VecDeque<String>>, line: String) {
        if let Ok(mut lines) = which.lock() {
            if lines.len() >= KEPT_LINES {
                lines.pop_front();
            }
            lines.push_back(line);
        }
    }

    pub fn api_line(&self) -> Option<String> {
        self.api_line.lock().ok().and_then(|slot| slot.clone())
    }

    pub fn api_bind_error(&self) -> Option<String> {
        self.api_bind_error
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub fn engine_data_dir(&self) -> Option<String> {
        self.engine_data_dir
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub fn boot_nodes(&self) -> Option<usize> {
        self.boot_nodes.lock().ok().and_then(|slot| *slot)
    }

    /// The last lines the node printed, stderr first, because that is where a
    /// reason lives.
    pub fn last_lines(&self, count: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Ok(lines) = self.stderr.lock() {
            out.extend(lines.iter().rev().take(count).cloned());
        }
        if out.len() < count
            && let Ok(lines) = self.stdout.lock()
        {
            out.extend(lines.iter().rev().take(count - out.len()).cloned());
        }
        out
    }
}

struct Supervised {
    child: Child,
    output: Arc<NodeOutput>,
    plan: NodeConfigPlan,
    binary: PathBuf,
    /// Held open for the lifetime of the child. Holding it is the thing only a
    /// live process can do, which is what makes the claim beside it mean
    /// something.
    _lock: fs::File,
    exit_code: Option<i32>,
    stopping_since: Option<Instant>,
    stopped_hard: bool,
    /// When this child was spawned, so "starting" can carry a clock.
    started_at: Instant,
    /// Sticky: the API port has been seen out of this child's hands at least
    /// once since it announced it. See `NodeObservations::api_port_lost`.
    api_port_lost: bool,
}

#[derive(Default)]
pub struct NodeProcess {
    inner: Mutex<Option<Supervised>>,
    /// The path a person pointed at, if they did.
    picked: Mutex<Option<PathBuf>>,
    /// Why the last start was refused, kept so a poll after a refusal still
    /// says why rather than falling back to a bare Stopped.
    refusal: Mutex<Option<String>>,
    /// Whether the last stop had to kill it.
    stopped_hard: Mutex<bool>,
    /// What the last stop actually did, as opposed to what it asked for.
    last_stop: Mutex<Option<StopOutcome>>,
}

impl NodeProcess {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_picked_binary(&self, path: Option<PathBuf>) {
        if let Ok(mut slot) = self.picked.lock() {
            *slot = path;
        }
    }

    pub fn picked_binary(&self) -> Option<PathBuf> {
        self.picked.lock().ok().and_then(|slot| slot.clone())
    }
}

fn hide_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW gives the child a console that is never shown, which
        // is what a console control event needs somewhere to land. The wallet
        // itself is a `windows_subsystem = "windows"` binary and has none.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

fn spawn_flags(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // The group is what makes a clean stop possible at all: the only
        // graceful exit the node has is its Ctrl+C handler, and the vendored
        // ctrlc handler releases its semaphore for any console control event,
        // so CTRL_BREAK to the child's own group works and does not touch us.
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

/// Take the lock beside the claim, or say who has it.
fn take_lock(path: &Path) -> Result<fs::File, String> {
    use fs2::FileExt;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create {parent:?}: {error}"))?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    file.try_lock_exclusive()
        .map_err(|error| format!("another program holds {}: {error}", path.display()))?;
    Ok(file)
}

/// The lock, for a test that needs to enter `launch` directly.
#[doc(hidden)]
pub fn take_lock_for_tests(path: &Path) -> Result<fs::File, String> {
    take_lock(path)
}

/// What the reader threads have picked up off the child's pipes.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct ObservedLines {
    pub api_line: Option<String>,
    pub api_bind_error: Option<String>,
    pub engine_data_dir: Option<String>,
    pub boot_nodes: Option<usize>,
}

#[doc(hidden)]
pub fn observed_for_tests(process: &NodeProcess) -> Option<ObservedLines> {
    let guard = process.inner.lock().ok()?;
    let supervised = guard.as_ref()?;
    Some(ObservedLines {
        api_line: supervised.output.api_line(),
        api_bind_error: supervised.output.api_bind_error(),
        engine_data_dir: supervised.output.engine_data_dir(),
        boot_nodes: supervised.output.boot_nodes(),
    })
}

/// Is the claim on disk still held by something alive.
pub fn claim_verdict(claim_path: &Path, lock_path: &Path) -> ClaimVerdict {
    let Some(claim) = read_claim(claim_path) else {
        return ClaimVerdict::None;
    };
    match take_lock(lock_path) {
        Ok(file) => {
            use fs2::FileExt;
            let _ = FileExt::unlock(&file);
            ClaimVerdict::Stale {
                pid: claim.pid,
                stopped_hard: claim.stopped_hard,
            }
        }
        Err(_) => ClaimVerdict::Held {
            pid: claim.pid,
            data_dir: claim.data_dir,
        },
    }
}

fn port_is_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// WHO HOLDS THE LISTENING SOCKET, asked of the kernel rather than inferred.
///
/// The child printing `[Api Server] listening on ...` is an announcement, not
/// a binding, and it is printed once. server.rs keeps the chain and p2p threads
/// running whether or not the API thread survives, so "our child is alive and
/// it once said it had the port" is a claim that can outlive the fact by hours
/// while something else answers on that port. Comparing the owning pid of the
/// listener to the child's own pid is the only thing that closes that gap.
///
/// `None` means this platform cannot answer, not that nobody is listening.
#[cfg(windows)]
fn listening_pid(port: u16) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    const AF_INET: u32 = 2;
    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    let mut size: u32 = 0;
    // SAFETY: a null table with a zero size is the documented way to ask for
    // the size, and the call writes only through `size`.
    let probe = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if probe != ERROR_INSUFFICIENT_BUFFER && probe != NO_ERROR {
        return None;
    }
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is `size` bytes, which is what the probe above asked
    // for, and the pointer is valid for the length of this call.
    let filled = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            false,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if filled != NO_ERROR {
        return None;
    }
    if buffer.len() < std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>() {
        return None;
    }
    // SAFETY: the kernel filled `buffer` with a MIB_TCPTABLE_OWNER_PID whose
    // header is followed by `dwNumEntries` rows, and the row count is bounded
    // by the buffer length below before any row is read.
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let header = std::mem::size_of::<u32>();
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    for index in 0..count {
        let offset = header + index * row_size;
        if offset + row_size > buffer.len() {
            break;
        }
        // SAFETY: `offset + row_size` is inside `buffer`, checked above.
        let row = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<MIB_TCPROW_OWNER_PID>())
        };
        // dwLocalPort is in network byte order in the low two bytes.
        let local = u16::from_be((row.dwLocalPort & 0xffff) as u16);
        if local == port {
            return Some(row.dwOwningPid);
        }
    }
    None
}

#[cfg(not(windows))]
fn listening_pid(_port: u16) -> Option<u32> {
    None
}

/// What is known about who holds the API port, right now.
///
/// Every arm except `OurChild` forbids reading the port as our node's, and the
/// two that are not `Unknown` are read straight off the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case", tag = "holder")]
pub enum ApiPortHolder {
    /// Nothing has been asked yet.
    #[default]
    NotChecked,
    /// Nobody is listening. If the child already announced the port, its API
    /// is gone, whatever else the process is still doing.
    Nobody,
    /// The kernel names our child's own pid.
    OurChild { pid: u32 },
    /// The kernel names somebody else's pid.
    Stranger { pid: u32 },
    /// Something is listening and this platform will not say who. Weaker than
    /// the arms above and never treated as though it were one of them.
    BoundByUnknown,
}

/// Ask the kernel who has the API port, and compare it to the pid we spawned.
fn api_port_holder(port: u16, our_pid: u32) -> ApiPortHolder {
    if port_is_free(port) {
        return ApiPortHolder::Nobody;
    }
    match listening_pid(port) {
        Some(pid) if pid == our_pid => ApiPortHolder::OurChild { pid },
        Some(pid) => ApiPortHolder::Stranger { pid },
        None => ApiPortHolder::BoundByUnknown,
    }
}

async fn read_capabilities(port: u16) -> Result<NodeCapabilities, String> {
    let url = format!("http://127.0.0.1:{port}/query/capabilities");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {status}: {}",
            body.chars().take(120).collect::<String>()
        ));
    }
    serde_json::from_str::<NodeCapabilities>(&body).map_err(|error| {
        format!(
            "{error}. It answered: {}",
            body.chars().take(120).collect::<String>()
        )
    })
}

/// Who is on the API port, when it is not us.
async fn foreign_answer(port: u16) -> ForeignAnswer {
    match read_capabilities(port).await {
        Ok(capabilities) => ForeignAnswer {
            node: Some(format!(
                "{} {}",
                capabilities.node.name, capabilities.node.version
            )),
            said: None,
        },
        Err(error) => ForeignAnswer {
            node: None,
            said: Some(error),
        },
    }
}

fn attach_readers(child: &mut Child, output: &Arc<NodeOutput>) {
    if let Some(stdout) = child.stdout.take() {
        let output = output.clone();
        let log = node_stdout_log_path();
        std::thread::spawn(move || pump(stdout, output, log, true));
    }
    if let Some(stderr) = child.stderr.take() {
        let output = output.clone();
        let log = node_stderr_log_path();
        std::thread::spawn(move || pump(stderr, output, log, false));
    }
}

fn pump<R: std::io::Read>(source: R, output: Arc<NodeOutput>, log: PathBuf, is_stdout: bool) {
    use std::io::Write;
    if let Some(parent) = log.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .ok();
    for line in BufReader::new(source).lines() {
        let Ok(line) = line else { break };
        output.observe(&line);
        if let Some(file) = file.as_mut() {
            let _ = writeln!(file, "{line}");
        }
        if is_stdout {
            output.push(&output.stdout, line);
        } else {
            output.push(&output.stderr, line);
        }
    }
}

/// Ask a child to shut down cleanly. Returns whether the request could even be
/// made; a refusal here is not fatal, it just means the kill comes sooner.
fn request_graceful_stop(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::{
            AttachConsole, CTRL_BREAK_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
            SetConsoleCtrlHandler,
        };
        unsafe {
            let _ = FreeConsole();
            if AttachConsole(pid).is_err() {
                return false;
            }
            // Our own process must not act on the event we are about to raise.
            let _ = SetConsoleCtrlHandler(None, true);
            let sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid).is_ok();
            let _ = FreeConsole();
            let _ = SetConsoleCtrlHandler(None, false);
            sent
        }
    }
    #[cfg(not(windows))]
    {
        unsafe { libc::kill(pid as i32, libc::SIGTERM) == 0 }
    }
}

/// STOP, AND SAY WHICH HALF DID IT.
///
/// Graceful first, time-boxed, then killed. The kill is not a failure, it is
/// the planned second half: an exiting app gets no unbounded grace, and sled is
/// crash-safe, so what a kill costs is the last unflushed writes and a recovery
/// scan on the next start. `stopped_hard` records that it happened so the next
/// start can say so instead of leaving a person watching an unexplained pause.
pub fn stop_managed_node(process: &NodeProcess, budget: Duration) -> Result<bool, String> {
    let mut guard = process.inner.lock().map_err(|error| error.to_string())?;
    let Some(mut supervised) = guard.take() else {
        // A stop that found nothing to stop must not leave anything on the
        // screen that suggests otherwise.
        if let Ok(mut slot) = process.refusal.lock() {
            *slot = None;
        }
        let _ = fs::remove_file(node_claim_path());
        return Ok(false);
    };
    let pid = supervised.child.id();
    let mut hard = false;
    let began = Instant::now();
    if supervised.child.try_wait().ok().flatten().is_none() {
        supervised.stopping_since = Some(Instant::now());
        let asked = request_graceful_stop(pid);
        let deadline = Instant::now() + budget;
        loop {
            match supervised.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => return Err(error.to_string()),
            }
            if Instant::now() >= deadline || !asked {
                let _ = supervised.child.kill();
                let _ = supervised.child.wait();
                hard = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    {
        use fs2::FileExt;
        let _ = FileExt::unlock(&supervised._lock);
    }
    drop(supervised);
    if let Ok(mut slot) = process.stopped_hard.lock() {
        *slot = hard;
    }
    if let Ok(mut slot) = process.last_stop.lock() {
        *slot = Some(StopOutcome {
            killed: hard,
            seconds: began.elapsed().as_secs(),
        });
    }
    if let Ok(mut slot) = process.refusal.lock() {
        *slot = None;
    }
    let claim_path = node_claim_path();
    if let Some(mut claim) = read_claim(&claim_path) {
        claim.stopped_hard = hard;
        let _ = write_claim(&claim_path, &claim);
    }
    let _ = fs::remove_file(&claim_path);
    Ok(true)
}

/// SPAWN, HOLD, AND CLAIM. The single place a child is created.
///
/// Public and hidden so a test can enter this exact path with a stand-in child
/// instead of a real fullnode. It has to be the same function: a stop that is
/// only ever proven against a mock it also spawned proves nothing about the
/// path a person takes, and the process handling here is the part with no
/// pure-function version of itself.
#[doc(hidden)]
pub fn launch(
    process: &NodeProcess,
    program: &Path,
    args: &[&std::ffi::OsStr],
    plan: &NodeConfigPlan,
    lock: fs::File,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_flags(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", program.display()))?;
    let output = Arc::new(NodeOutput::default());
    attach_readers(&mut child, &output);

    write_claim(
        &node_claim_path(),
        &NodeClaim {
            pid: child.id(),
            claimed_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            binary: program.display().to_string(),
            data_dir: plan.data_dir.display().to_string(),
            config_path: args
                .first()
                .map(|arg| arg.to_string_lossy().to_string())
                .unwrap_or_default(),
            api_port: plan.api_port,
            p2p_port: plan.p2p_port,
            stopped_hard: false,
        },
    )?;

    if let Ok(mut slot) = process.refusal.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = process.stopped_hard.lock() {
        *slot = false;
    }
    // A start clears the last stop: the previous shutdown is not news about the
    // process that is running now.
    if let Ok(mut slot) = process.last_stop.lock() {
        *slot = None;
    }
    let mut guard = process.inner.lock().map_err(|error| error.to_string())?;
    *guard = Some(Supervised {
        child,
        output,
        plan: plan.clone(),
        binary: program.to_path_buf(),
        _lock: lock,
        exit_code: None,
        stopping_since: None,
        stopped_hard: false,
        started_at: Instant::now(),
        api_port_lost: false,
    });
    Ok(())
}

/// CONVERGE, NOT COMMAND.
///
/// Called to bring the world into line with "the wallet should be running a
/// node". Like `sync_managed_relay` it has a cheap path: a live child of ours
/// means there is nothing to do, so a second press changes nothing. Everything
/// it refuses, it records, so the next status poll still says why.
pub async fn sync_managed_node(process: &NodeProcess) -> Result<(), String> {
    {
        let mut guard = process.inner.lock().map_err(|error| error.to_string())?;
        if let Some(supervised) = guard.as_mut() {
            if supervised
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Ok(());
            }
            // REAP IT, or the only button on the screen does nothing for ever.
            //
            // A child that has exited is not a child. Left in place it kept two
            // things alive that made a second press impossible: its own exit
            // code, which `decide` reads before it reads anything else, and its
            // fs2 handle on node.lock, which made the next start refuse itself
            // with "a node this wallet started is already using the chain
            // folder" naming a pid the OS had already reused or retired. Only
            // restarting the whole wallet recovered from that.
            if let Some(dead) = guard.take() {
                use fs2::FileExt;
                let _ = FileExt::unlock(&dead._lock);
                drop(dead);
                let _ = fs::remove_file(node_claim_path());
            }
        }
    }
    let refuse = |reason: String| -> Result<(), String> {
        if let Ok(mut slot) = process.refusal.lock() {
            *slot = Some(reason);
        }
        Ok(())
    };

    let picked = process.picked_binary();
    let binary = resolve_node_binary(picked.as_deref());
    let Some(path) = binary.path.clone() else {
        // A pick that has gone missing is its own refusal. Falling through to
        // the next candidate on the list would start a different program than
        // the one somebody chose and say nothing about it.
        if let Some(problem) = binary.picked_problem.as_deref() {
            let chosen = binary.picked_path.as_deref().unwrap_or("the path you gave");
            return refuse(format!(
                "You pointed this wallet at {chosen}, and now {problem}. Nothing has been \
started, and this wallet will not run a different fullnode in its place without being asked."
            ));
        }
        return refuse(NOTHING_BUNDLED_YET.to_string());
    };
    let plan = NodeConfigPlan::standard();

    // (a) The claim, which only means something because of the lock beside it.
    match claim_verdict(&node_claim_path(), &node_lock_path()) {
        ClaimVerdict::Held { pid, data_dir } => {
            // WHAT IS PROVEN AND WHAT IS ONLY RECORDED, kept apart. The lock
            // being held proves a live program has the folder. The pid does
            // not: it is read out of this wallet's own notes, and if the
            // holder is a second wallet, or an older run, the number can name
            // something else entirely. So it is offered as a note, not a fact.
            return refuse(format!(
                "The chain folder {data_dir} is still locked by a program that is running now. \
Two programs writing one chain store is how a chain gets corrupted, so a second node will not be \
started. This wallet's own notes record process {pid} as the one that took it, which is a note \
rather than a check: whatever holds the folder may be another copy of this wallet."
            ));
        }
        ClaimVerdict::Stale { stopped_hard, .. } if stopped_hard => {
            tracing::info!("the previous node was closed the hard way; the store may be scanned");
        }
        _ => {}
    }

    // (b) The ports, before anything is spawned. The same move the relay makes,
    // and for the same reason: a bind that fails is a refusal, never an
    // adoption.
    if !port_is_free(plan.api_port) {
        let answer = foreign_answer(plan.api_port).await;
        return refuse(match answer.node {
            Some(node) => format!(
                "{node} is already answering on 127.0.0.1:{}. This wallet did not start it, so it \
will not start a second one on top of it and will not claim this one as its own.",
                plan.api_port
            ),
            None => format!(
                "Something on this computer is already using port {} and it did not answer as a \
Hacash node. Asking it failed with: {}. Nothing has been started.",
                plan.api_port,
                answer
                    .said
                    .unwrap_or_else(|| "no answer at all".to_string())
            ),
        });
    }
    if !port_is_free(plan.p2p_port) {
        return refuse(format!(
            "Something is already using port {} on this computer, which is the port a node needs \
to talk to the rest of the network.",
            plan.p2p_port
        ));
    }

    // (c) The chain folder, and the ini's own parser.
    let data_dir = plan.data_dir.display().to_string();
    if let Err(reason) = ini_value_survives_the_parser(&data_dir) {
        return refuse(reason);
    }
    // A REFUSAL, NOT AN ERROR. Returning `Err` here sent an os error number to
    // a toast that vanished and left the panel describing a node that was
    // never started. Anything that stops a start belongs in the state, in
    // words, where it stays put.
    if let Err(error) = fs::create_dir_all(&plan.data_dir) {
        return refuse(format!(
            "The wallet could not make the folder the chain goes in, at {data_dir}. The computer \
said: {error}. Nothing has been started. This is usually a full disk, a folder that is read only, \
or a file sitting where the folder needs to be."
        ));
    }

    // (d) The config, written by us, at our own path, so it structurally cannot
    // land next to somebody else's binary.
    let config_path = node_config_path();
    let written = match write_node_config(&config_path, &plan) {
        Ok(written) => written,
        Err(error) => {
            return refuse(format!(
                "The wallet could not write the settings file the node needs, at {}. The computer \
said: {error}. Nothing has been started.",
                config_path.display()
            ));
        }
    };

    let lock = match take_lock(&node_lock_path()) {
        Ok(lock) => lock,
        Err(error) => {
            return refuse(format!(
                "The wallet could not claim its own node folder. {error}"
            ));
        }
    };

    launch(
        process,
        Path::new(&path),
        &[config_path.as_os_str()],
        &plan,
        lock,
    )?;
    tracing::info!(%path, %data_dir, config = %config_path.display(), ?written, "started the supervised Hacash node");
    Ok(())
}

/// READ-ONLY. Starts nothing, stops nothing, writes no config.
pub async fn node_supervisor_status(process: &NodeProcess) -> Result<NodeSupervisorReport, String> {
    let plan = NodeConfigPlan::standard();
    let mut observed = NodeObservations {
        api_port: plan.api_port,
        p2p_port: plan.p2p_port,
        asked_data_dir: plan.data_dir.display().to_string(),
        refusal: process.refusal.lock().ok().and_then(|slot| slot.clone()),
        stopped_hard: process
            .stopped_hard
            .lock()
            .map(|slot| *slot)
            .unwrap_or(false),
        last_stop: process.last_stop.lock().ok().and_then(|slot| *slot),
        ..NodeObservations::default()
    };
    observed.binary = Some(resolve_node_binary(process.picked_binary().as_deref()));
    // WHAT IS ON DISK, READ RATHER THAN REMEMBERED.
    //
    // This used to be left at `None` on every live path, which meant the one
    // sentence that warns "the node is running with settings this wallet did
    // not choose" could never appear on a real screen. It is the whole point
    // of the pass: the measured peer count that stops a signed transaction
    // sitting unmined for two days lives in that file, and a file somebody
    // edited, or one the wallet never wrote, can be missing it entirely.
    observed.config = inspect_node_config(&node_config_path(), &plan);

    let mut our_port: Option<u16> = None;
    let mut our_pid: Option<u32> = None;
    {
        let mut guard = process.inner.lock().map_err(|error| error.to_string())?;
        if let Some(supervised) = guard.as_mut() {
            match supervised.child.try_wait().map_err(|e| e.to_string())? {
                None => {
                    observed.ours_alive = true;
                    our_port = Some(supervised.plan.api_port);
                    our_pid = Some(supervised.child.id());
                    observed.alive_seconds = Some(supervised.started_at.elapsed().as_secs());
                }
                Some(status) => {
                    // THE DEFECT THE RELAY HAS, NOT INHERITED. A child that
                    // ended is a child that ended, and the report says so
                    // instead of continuing to describe a live one.
                    supervised.exit_code = status.code();
                    observed.ours_exit_code = Some(status.code().unwrap_or(-1));
                }
            }
            observed.stopping = supervised
                .stopping_since
                .map(|since| since.elapsed() < GRACEFUL_STOP_BUDGET)
                .unwrap_or(false);
            observed.stopped_hard |= supervised.stopped_hard;
            observed.our_api_line = supervised.output.api_line();
            observed.api_bind_error = supervised.output.api_bind_error();
            observed.engine_data_dir = supervised.output.engine_data_dir();
            observed.boot_nodes_connected = supervised.output.boot_nodes();
            observed.last_error_lines = supervised.output.last_lines(8);
            // THE BINARY THAT IS RUNNING, NOT THE ONE A FRESH SEARCH FINDS.
            //
            // A person can drop a different fullnode into a search location
            // while one is up. The screen must name what is actually executing,
            // because "which node is telling me this" is the whole question.
            if let Some(binary) = observed.binary.as_mut() {
                let running = supervised.binary.display().to_string();
                if binary.path.as_deref() != Some(running.as_str()) {
                    binary.path = Some(running);
                    binary.version = None;
                    binary.database_type = None;
                }
            }
        }
    }

    if let (Some(port), Some(pid)) = (our_port, our_pid) {
        // THE ANNOUNCEMENT IS CHECKED, NOT BELIEVED.
        //
        // `our_api_line` is printed once and latched for the life of the
        // process. On its own it authorised a capabilities read for as long as
        // the child lived, so a child that announced the port and then lost it
        // let anything that took that port be reported as our node, with a
        // green header, a height and the mainnet block one hash on it. Every
        // poll now asks the kernel who actually holds the listener and
        // compares it to this child's own pid.
        if observed.our_api_line.is_some() {
            let holder = api_port_holder(port, pid);
            observed.api_port_holder = holder;
            // The guard is taken and dropped inside this block, deliberately.
            // Holding a std mutex across the capabilities await below would
            // block every other caller of this supervisor for the length of a
            // network read.
            {
                let mut guard = process.inner.lock().map_err(|error| error.to_string())?;
                if let Some(supervised) = guard.as_mut() {
                    match holder {
                        // The kernel naming our own pid is proof, so an earlier
                        // wobble is genuinely over.
                        ApiPortHolder::OurChild { .. } => supervised.api_port_lost = false,
                        ApiPortHolder::Nobody | ApiPortHolder::Stranger { .. } => {
                            supervised.api_port_lost = true
                        }
                        // Something is listening and this system will not say
                        // who. If the port has already changed hands once, that
                        // stays true.
                        ApiPortHolder::BoundByUnknown | ApiPortHolder::NotChecked => {}
                    }
                    observed.api_port_lost = supervised.api_port_lost;
                }
            }
            let proven = matches!(
                holder,
                ApiPortHolder::OurChild { .. } | ApiPortHolder::BoundByUnknown
            ) && !observed.api_port_lost;
            if proven && let Ok(capabilities) = read_capabilities(port).await {
                observed.capabilities = Some(capabilities);
            }
        }
    } else if !port_is_free(plan.api_port) {
        observed.foreign_on_api_port = Some(foreign_answer(plan.api_port).await);
    } else {
        observed.p2p_port_taken = !port_is_free(plan.p2p_port);
    }

    observed.claim = Some(claim_verdict(&node_claim_path(), &node_lock_path()));
    Ok(decide(&observed, &node_config_path().display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain folder that is absolute on the platform the test runs on.
    ///
    /// `render_node_config` refuses a relative `data_dir`, and correctly: the
    /// node resolves a relative one next to its own executable, which is the
    /// barrier this work exists to remove. But `C:/chain` is absolute only on
    /// Windows. On Linux it is a relative path named `C:`, so the guard fired
    /// on CI and the test panicked on its own `unwrap`, while passing on the
    /// machine it was written on.
    fn absolute_chain_dir() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:/chain")
        } else {
            PathBuf::from("/chain")
        }
    }

    #[test]
    fn the_config_the_wallet_writes_carries_the_peer_count_that_was_measured() {
        let data_dir = absolute_chain_dir();
        let expected = format!("data_dir = {}", data_dir.display());
        let plan = NodeConfigPlan {
            data_dir,
            api_port: 18080,
            p2p_port: 13337,
        };
        let text = render_node_config(&plan).unwrap();
        assert!(text.contains("backbone_peers = 32"), "{text}");
        assert!(text.contains("not_find_nodes = false"));
        assert!(text.contains("fast_sync = false"));
        assert!(text.contains(&expected), "{text}");
        assert!(text.contains("listen = 13337"));
        assert!(text.contains("listen = 18080"));
        assert!(text.contains("bind = 127.0.0.1"));
        for boot in BOOT_NODES {
            assert!(text.contains(boot), "missing boot node {boot}");
        }
        // data_dir belongs at the ROOT, above [node]. Under a section the node
        // reads a default and resolves a folder nobody asked for.
        let root = text.split("[node]").next().unwrap();
        assert!(
            root.contains("data_dir ="),
            "data_dir must be at the ini root"
        );
    }

    #[test]
    fn a_path_the_ini_parser_would_truncate_is_refused_rather_than_written() {
        assert!(ini_value_survives_the_parser("C:/Users/Ana Maria/chain").is_ok());
        assert!(ini_value_survives_the_parser("C:/a#b/chain").is_ok());
        let refused = ini_value_survives_the_parser("C:/Users/Ana ;dev/chain").unwrap_err();
        assert!(refused.contains("comment"), "{refused}");
        // Absolute on this platform on purpose, and the error is read rather
        // than merely counted. `C:/Users/Ana #dev/chain` is relative on Linux,
        // so this refusal would have fired for being relative and the test
        // would have passed without ever exercising the `#` it is named for.
        let hashed = absolute_chain_dir().join("Ana #dev").join("chain");
        let error = render_node_config(&NodeConfigPlan {
            data_dir: hashed,
            api_port: 1,
            p2p_port: 2,
        })
        .unwrap_err();
        assert!(error.contains("comment"), "{error}");
    }

    #[test]
    fn a_relative_chain_folder_is_refused_because_the_node_resolves_it_elsewhere() {
        let error = render_node_config(&NodeConfigPlan {
            data_dir: PathBuf::from("hacash_mainnet_data"),
            api_port: 1,
            p2p_port: 2,
        })
        .unwrap_err();
        assert!(error.contains("next to its own executable"), "{error}");
    }

    #[test]
    fn the_version_line_is_read_rather_than_the_filename_trusted() {
        let probe = parse_version_line(
            "[Version] full node v1.0.10, build time: 2026/7/10 #1, database type: 8.\n\
[Config Error] cannot find config file X",
        )
        .unwrap();
        assert_eq!(probe.version, "full node v1.0.10");
        assert_eq!(probe.database_type, Some(8));
        assert!(parse_version_line("not a node at all").is_none());
    }

    fn capabilities(hash: Option<&str>, height: u64, fresh: bool) -> NodeCapabilities {
        let mut json = serde_json::json!({
            "ret": 0,
            "api_version": 1,
            "node": {"name": "hacash-fullnode", "version": "1.0.10", "build_time": "2026/7/10 #1"},
            "chain": {"id": 0, "height": height, "next_height": height + 1, "mainnet": true},
            "network": {
                "kind": "mainnet",
                "node_profile_id": "x",
                "block_1_available": hash.is_some(),
                "block_1_hash": hash,
                "funding_confirmed": true,
                "transaction_ready": true,
                "current_height": height,
                "transaction_format_version": 1
            },
            "sync": {
                "tip_timestamp_unix": 1,
                "observed_unix": 2,
                "tip_age_seconds": if fresh { 898 } else { 90000 },
                "max_tip_age_seconds": 3600,
                "fresh": fresh
            },
            "istanbul": {"activation_height": 0, "evaluation_height": 0, "active": true},
            "transactions": {"registered": [1, 2, 3], "enabled": [1, 2, 3]},
            "actions": {"registered": [1, 2], "enabled": [1, 2]},
            "features": {
                "action_guard": true, "tx_blob": true, "ast": true, "tex": true,
                "native_assets": true, "hip20": true, "hip20_primitives": true, "hvm": true,
                "p2sh": true, "account_abstraction": true, "intent": true,
                "contract_state_leasing": true, "ir_decompilation": true,
                "req_sign_list": true, "type4_mainnet": true, "exact_unsigned_simulation": true
            },
            "api": {"balance_query": true, "transaction_submit": true, "transaction_submit_bound": true, "transaction_query": true, "reconciliation_by_tx_hash": true},
            "limits": {"max_tx_size": 65536, "max_tx_actions": 200, "max_type3_signers": 200, "gas_max_byte": 255, "gas_max": 100000, "ast_depth": 16},
            "peers": {"measured": true, "total": 10, "inbound_established": 0, "outbound_established": 10, "public": 0, "inbound_proven": false, "role": "leaf"}
        });
        if hash.is_none() {
            json["network"]["block_1_hash"] = serde_json::Value::Null;
        }
        serde_json::from_value(json).expect("capability fixture")
    }

    fn ours_alive(capabilities: Option<NodeCapabilities>) -> NodeObservations {
        NodeObservations {
            binary: Some(NodeBinaryReport {
                path: Some("C:/hpay/fullnode.exe".into()),
                source: Some(NodeBinarySource::Legacy),
                version: Some("full node v1.0.10".into()),
                database_type: Some(8),
                searched: Vec::new(),
                picked_path: None,
                picked_problem: None,
            }),
            ours_alive: true,
            our_api_line: Some("[Api Server] listening on http://127.0.0.1:8080".into()),
            // The kernel naming our own child as the holder of the port. Every
            // fixture that reads a height has to carry this now, because a
            // height read off a port nobody proved is ours is the exact lie
            // this state used to tell.
            api_port_holder: ApiPortHolder::OurChild { pid: 4242 },
            asked_data_dir: "C:/chain".into(),
            api_port: 8080,
            p2p_port: 3337,
            capabilities,
            ..NodeObservations::default()
        }
    }

    #[test]
    fn ready_is_an_age_and_never_the_bare_word_synced() {
        let report = decide(
            &ours_alive(Some(capabilities(
                Some(MAINNET_BLOCK_ONE_HASH),
                776647,
                true,
            ))),
            "cfg",
        );
        assert_eq!(report.state, NodeState::Ready);
        assert!(report.ours);
        assert_eq!(report.anchor, ChainAnchor::Confirmed);
        assert!(
            report.detail.contains("898 seconds ago"),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("3600"), "{}", report.detail);
        assert!(
            !report.headline.to_lowercase().contains("synced")
                && !report.detail.to_lowercase().contains("synced"),
            "the word synced was printed without an age beside it"
        );
        // Ready is about the chain, not about reachability, and the two are
        // never allowed to blur.
        let reach = report.reach.expect("ready must still quote the peer block");
        assert!(reach.contains("leaf"), "{reach}");
        assert!(reach.contains("nobody has dialed in"), "{reach}");
        assert_eq!(report.peers_inbound, Some(0));
        assert_eq!(report.peers_outbound, Some(10));
    }

    #[test]
    fn catching_up_prints_a_number_and_names_the_chain_it_is_watching() {
        let report = decide(
            &ours_alive(Some(capabilities(
                Some(MAINNET_BLOCK_ONE_HASH),
                400000,
                false,
            ))),
            "cfg",
        );
        assert_eq!(report.state, NodeState::CatchingUp);
        assert!(report.headline.contains("400000"), "{}", report.headline);
        assert_eq!(report.anchor, ChainAnchor::Confirmed);
        assert!(report.watching.contains(MAINNET_BLOCK_ONE_HASH));
        assert!(report.watching.contains("mainnet"));
    }

    /// THE TRAP. A real sync and a node alone on a chain of its own both show a
    /// climbing height, so the screen has to name the difference rather than
    /// wait for one of them to look worse.
    #[test]
    fn a_climbing_height_with_no_block_one_and_no_boot_nodes_is_named_as_a_private_chain() {
        let mut observed = ours_alive(Some(capabilities(None, 105, false)));
        observed.boot_nodes_connected = Some(0);
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::CatchingUp);
        assert_eq!(report.anchor, ChainAnchor::NotYetAvailable);
        assert!(
            report.watching.contains("0 boot nodes"),
            "{}",
            report.watching
        );
        assert!(
            report.watching.contains("private chain"),
            "{}",
            report.watching
        );
        assert!(
            report.watching.contains("reaches nobody"),
            "{}",
            report.watching
        );
        assert_eq!(report.height, Some(105));
    }

    #[test]
    fn a_node_with_the_wrong_block_one_fails_rather_than_being_reported_as_catching_up() {
        let wrong = "00deadbeef03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
        let report = decide(
            &ours_alive(Some(capabilities(Some(wrong), 900, true))),
            "cfg",
        );
        assert_eq!(report.state, NodeState::Failed);
        assert_eq!(report.anchor, ChainAnchor::Wrong);
        assert!(
            report.detail.contains(MAINNET_BLOCK_ONE_HASH),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("not the chain your money is on"));
    }

    #[test]
    fn a_live_child_that_has_not_confirmed_the_api_port_is_starting_and_claims_nothing() {
        let mut observed = ours_alive(None);
        observed.our_api_line = None;
        observed.engine_data_dir = Some("C:/chain".into());
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Starting);
        assert!(report.detail.contains("C:/chain"));
        assert_eq!(
            report.height, None,
            "nothing may be reported about a chain not yet read"
        );
    }

    /// The node prints the folder it actually resolved. It is compared, not
    /// assumed, which is the filesystem version of reading a bound address back
    /// off the listener.
    #[test]
    fn a_node_that_opened_a_different_folder_than_we_asked_for_fails_the_start() {
        let mut observed = ours_alive(Some(capabilities(Some(MAINNET_BLOCK_ONE_HASH), 10, true)));
        observed.engine_data_dir = Some("C:/hpay/hacash_mainnet_data".into());
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Failed);
        assert!(
            report.detail.contains("C:/hpay/hacash_mainnet_data"),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("C:/chain"));
        // And the same directory written the other way round is not a failure.
        let mut ok = ours_alive(Some(capabilities(Some(MAINNET_BLOCK_ONE_HASH), 10, true)));
        ok.engine_data_dir = Some("c:\\chain\\".into());
        assert_eq!(decide(&ok, "cfg").state, NodeState::Ready);
    }

    #[test]
    fn a_foreign_hacash_node_is_its_own_state_and_never_ours() {
        let observed = NodeObservations {
            binary: Some(resolve_none()),
            foreign_on_api_port: Some(ForeignAnswer {
                node: Some("hacash-fullnode 1.0.10".into()),
                said: None,
            }),
            api_port: 8080,
            ..NodeObservations::default()
        };
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Foreign);
        assert!(!report.ours);
        assert!(
            !report.can_stop,
            "no stop button may be drawn for a process we did not start"
        );
        assert!(
            report.detail.contains("did not start it"),
            "{}",
            report.detail
        );
    }

    #[test]
    fn something_that_is_not_a_hacash_node_on_the_port_is_blocked_and_quoted() {
        let observed = NodeObservations {
            binary: Some(resolve_none()),
            foreign_on_api_port: Some(ForeignAnswer {
                node: None,
                said: Some("HTTP 404 Not Found".into()),
            }),
            api_port: 8080,
            ..NodeObservations::default()
        };
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Blocked);
        assert!(
            report.detail.contains("HTTP 404 Not Found"),
            "{}",
            report.detail
        );
        // The reason is this wallet's own failed request, so it is not put in
        // the stranger's mouth. "It said: error sending request for url ..."
        // was a sentence nothing on that port ever uttered.
        assert!(
            !report.detail.contains("It said"),
            "our own client error must not be quoted as the stranger's words: {}",
            report.detail
        );
        assert!(report.detail.contains("Asking it failed with"));
    }

    fn resolve_none() -> NodeBinaryReport {
        NodeBinaryReport {
            path: None,
            source: None,
            version: None,
            database_type: None,
            searched: vec![SearchedPath {
                path: "C:/HPAY/hacash/fullnode.exe".into(),
                source: NodeBinarySource::Bundled,
                verdict: "nothing is at this path".into(),
            }],
            picked_path: None,
            picked_problem: None,
        }
    }

    #[test]
    fn nothing_bundled_reads_as_an_offer_and_never_as_a_broken_wallet() {
        let report = decide(
            &NodeObservations {
                binary: Some(resolve_none()),
                api_port: 8080,
                ..NodeObservations::default()
            },
            "cfg",
        );
        assert_eq!(report.state, NodeState::NotPresent);
        assert!(report.detail.contains("not broken"), "{}", report.detail);
        assert!(!report.can_start, "there is nothing to start");
        assert!(
            report
                .offers
                .iter()
                .any(|o| o.contains("already pointed at"))
        );
        assert!(report.offers.iter().any(|o| o.contains("lies about money")));
        assert_eq!(
            report.binary.searched.len(),
            1,
            "the screen must show where it looked"
        );
    }

    #[test]
    fn the_network_port_being_taken_is_named_rather_than_shown_as_a_second_red_row() {
        let report = decide(
            &NodeObservations {
                binary: Some(resolve_none()),
                p2p_port_taken: true,
                api_port: 8080,
                p2p_port: 3337,
                ..NodeObservations::default()
            },
            "cfg",
        );
        assert_eq!(report.state, NodeState::Blocked);
        assert!(report.detail.contains("port 3337"), "{}", report.detail);
        assert!(report.detail.contains("Nothing has been started"));
    }

    #[test]
    fn a_refusal_before_a_start_is_blocked_and_not_failed() {
        let report = decide(
            &NodeObservations {
                binary: Some(resolve_none()),
                refusal: Some("A node this wallet started (process 42) is already using the chain folder C:/chain.".into()),
                api_port: 8080,
                ..NodeObservations::default()
            },
            "cfg",
        );
        assert_eq!(report.state, NodeState::Blocked);
        assert!(report.detail.contains("process 42"));
        assert!(report.exit_code.is_none(), "a refusal is not an exit");
    }

    #[test]
    fn the_sled_lock_panic_is_translated_into_the_sentence_it_actually_means() {
        let mut observed = ours_alive(None);
        observed.ours_alive = false;
        observed.ours_exit_code = Some(101);
        observed.last_error_lines =
            vec!["thread 'main' panicked: could not acquire lock on \"db\"".into()];
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Failed);
        assert!(
            report
                .detail
                .contains("another program is already using the chain folder"),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("C:/chain"));
        assert!(report.can_start);
    }

    #[test]
    fn a_config_the_wallet_cannot_read_back_is_named_as_the_wallets_own_bug() {
        let mut observed = ours_alive(None);
        observed.ours_alive = false;
        observed.ours_exit_code = Some(1);
        observed.last_error_lines =
            vec!["[Fatal] config './hacash.config.ini' is empty or failed to load".into()];
        let report = decide(&observed, "C:/state/hacash.config.ini");
        assert_eq!(report.state, NodeState::Failed);
        assert!(
            report.detail.contains("this wallet's own bug"),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("C:/state/hacash.config.ini"));
    }

    #[test]
    fn a_stop_that_had_to_kill_says_so_so_the_next_start_is_not_a_mystery() {
        let report = decide(
            &NodeObservations {
                binary: Some(NodeBinaryReport {
                    path: Some("C:/hpay/fullnode.exe".into()),
                    source: Some(NodeBinarySource::Legacy),
                    version: Some("full node v1.0.10".into()),
                    database_type: Some(8),
                    searched: Vec::new(),
                    picked_path: None,
                    picked_problem: None,
                }),
                stopped_hard: true,
                asked_data_dir: "C:/chain".into(),
                api_port: 8080,
                ..NodeObservations::default()
            },
            "cfg",
        );
        assert_eq!(report.state, NodeState::Stopped);
        assert!(
            report.detail.contains("Nothing is lost"),
            "{}",
            report.detail
        );
        assert!(report.detail.contains("recovery") || report.detail.contains("checks the"));
        assert!(report.can_start);
    }

    #[test]
    fn stopping_is_its_own_state_because_the_button_is_not_instant() {
        let mut observed = ours_alive(None);
        observed.stopping = true;
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Stopping);
        assert!(report.detail.contains("20 seconds"), "{}", report.detail);
    }

    #[test]
    fn a_node_that_could_not_bind_its_api_port_is_failed_and_not_starting_for_ever() {
        let mut observed = ours_alive(None);
        observed.our_api_line = None;
        observed.api_bind_error =
            Some("[Error] api server failed to bind 127.0.0.1:8080: address in use".into());
        let report = decide(&observed, "cfg");
        // This used to sit in Starting for ever while its own detail said it
        // was "being treated as a failed start". Nothing treated it as one, and
        // the old test asserted the contradiction rather than catching it.
        assert_eq!(report.state, NodeState::Failed);
        assert!(report.detail.contains("could not take port 8080"));
        assert!(
            !report.detail.contains("being treated as"),
            "the screen must do the thing rather than describe doing it: {}",
            report.detail
        );
        assert!(
            report.can_stop,
            "it is still running and still ours to stop"
        );
        assert!(!report.can_start, "one is already running");
        assert_eq!(report.height, None);
    }

    #[test]
    fn a_port_our_child_announced_and_no_longer_holds_is_never_read_as_ours() {
        // THE LIE THIS CHECK EXISTS FOR. The child announces the port once; the
        // API thread can end while the chain and p2p threads carry on; anything
        // at all can then take the port. Believing the announcement for the
        // life of the process reported the stranger's height, its freshness and
        // the mainnet block one hash under a green header, with a Stop button,
        // as though it were our node.
        let mut observed = ours_alive(Some(capabilities(
            Some(MAINNET_BLOCK_ONE_HASH),
            776_647,
            true,
        )));
        observed.api_port_holder = ApiPortHolder::Stranger { pid: 9001 };
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Failed);
        assert!(report.detail.contains("process 9001"), "{}", report.detail);
        assert_eq!(report.height, None, "a stranger's height is not our height");
        assert_eq!(report.tip_age_seconds, None);
        assert_eq!(report.anchor, ChainAnchor::Unknown);
        assert!(
            !report.watching.contains(MAINNET_BLOCK_ONE_HASH),
            "the anchor sentence exists to be the one thing you can trust, so it \
is the last thing allowed to vouch for a stranger: {}",
            report.watching
        );
        assert!(report.reach.is_none());
        assert_ne!(report.headline, "Your node is up to date");
    }

    #[test]
    fn a_port_that_stopped_answering_is_a_failure_with_its_own_words() {
        let mut observed = ours_alive(Some(capabilities(
            Some(MAINNET_BLOCK_ONE_HASH),
            776_647,
            true,
        )));
        observed.api_port_holder = ApiPortHolder::Nobody;
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Failed);
        assert!(
            report.detail.contains("nothing \nis listening")
                || report.detail.contains("nothing is listening"),
            "{}",
            report.detail
        );
        assert_eq!(report.height, None);
        assert!(report.ours, "it is still our process, it just has no API");
        assert!(report.can_stop);
    }

    #[test]
    fn a_port_that_changed_hands_once_is_not_trusted_again_where_the_owner_cannot_be_named() {
        // On a system whose kernel will not name the owning pid, "something is
        // listening" is not evidence of who. Once the port has been out of our
        // child's hands even once, it is never quietly believed again.
        let mut observed = ours_alive(Some(capabilities(
            Some(MAINNET_BLOCK_ONE_HASH),
            776_647,
            true,
        )));
        observed.api_port_holder = ApiPortHolder::BoundByUnknown;
        observed.api_port_lost = true;
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Failed);
        assert!(report.detail.contains("cannot prove"), "{}", report.detail);
        assert_eq!(report.height, None);
    }

    #[test]
    fn a_proven_port_is_still_read_normally() {
        // The check must not cost the feature. The kernel naming our own child
        // is the ordinary case and it reads exactly as before.
        let observed = ours_alive(Some(capabilities(
            Some(MAINNET_BLOCK_ONE_HASH),
            776_647,
            true,
        )));
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Ready);
        assert_eq!(report.height, Some(776_647));
        assert!(report.watching.contains(MAINNET_BLOCK_ONE_HASH));
    }

    #[test]
    fn the_binary_a_person_chose_going_missing_is_said_rather_than_substituted() {
        // Measured before this fix: pointing the wallet at mynode.exe, deleting
        // it and pressing Start ran C:/hpay/fullnode.exe instead and said
        // "Starting your node". A node that is not the one you chose does not
        // crash; it lies about money.
        let mut binary = resolve_none();
        binary.picked_path = Some("C:/mine/mynode.exe".into());
        binary.picked_problem = Some("nothing is at this path".into());
        let observed = NodeObservations {
            binary: Some(binary),
            asked_data_dir: "C:/chain".into(),
            api_port: 8080,
            p2p_port: 3337,
            ..NodeObservations::default()
        };
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::NotPresent);
        assert!(report.headline.contains("not there any more"));
        assert!(report.detail.contains("C:/mine/mynode.exe"));
        assert!(
            report.detail.contains("will not quietly run a different"),
            "{}",
            report.detail
        );
        assert!(!report.can_start, "there is nothing it may start");
    }

    #[test]
    fn a_config_this_wallet_did_not_write_is_read_off_disk_rather_than_left_null() {
        // `report.config` was never populated on the live path, so the sentence
        // that warns "the node is running with settings this wallet did not
        // choose" could not appear on a real screen at all. The peer count that
        // fixes the two-day stranding lives in that file.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hacash.config.ini");
        std::fs::write(&path, "[node]\nbackbone_peers = 4\n").expect("write");
        let plan = NodeConfigPlan {
            data_dir: dir.path().join("chain"),
            ..NodeConfigPlan::standard()
        };
        let seen = inspect_node_config(&path, &plan).expect("a file that is there is reported");
        match seen {
            ConfigWrite::LeftAlone { reason } => {
                assert!(reason.contains("this wallet did not write it"), "{reason}");
                assert!(reason.contains("peer count"), "{reason}");
            }
            other => panic!("a file the wallet never wrote must be left alone: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "[node]\nbackbone_peers = 4\n",
            "inspecting a config must never touch it"
        );
    }

    #[test]
    fn an_edited_config_of_our_own_is_reported_as_edited_without_being_rewritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hacash.config.ini");
        let plan = NodeConfigPlan {
            data_dir: dir.path().join("chain"),
            ..NodeConfigPlan::standard()
        };
        assert_eq!(
            write_node_config(&path, &plan).expect("first write"),
            ConfigWrite::Written
        );
        let ours = std::fs::read_to_string(&path).expect("read");
        let edited = ours.replace("backbone_peers = 32", "backbone_peers = 4");
        assert_ne!(ours, edited, "the fixture has to actually change something");
        std::fs::write(&path, &edited).expect("edit");
        match inspect_node_config(&path, &plan).expect("a file that is there is reported") {
            ConfigWrite::LeftAlone { reason } => {
                assert!(reason.contains("has been edited since"), "{reason}");
            }
            other => panic!("an edited file of ours is left alone: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            edited,
            "inspecting must never rewrite"
        );
    }

    #[test]
    fn nothing_is_reported_about_a_config_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = NodeConfigPlan {
            data_dir: dir.path().join("chain"),
            ..NodeConfigPlan::standard()
        };
        assert!(
            inspect_node_config(&dir.path().join("nothing.ini"), &plan).is_none(),
            "no file is not a warning"
        );
    }

    #[test]
    fn a_stop_that_did_not_need_a_kill_does_not_claim_the_node_flushed() {
        // "We did not have to call kill" is not "it flushed". On Windows a
        // process with no Ctrl handler is terminated outright by the same
        // request and dies in milliseconds, which looks identical from here.
        let observed = NodeObservations {
            binary: Some(NodeBinaryReport {
                path: Some("C:/hpay/fullnode.exe".into()),
                source: Some(NodeBinarySource::Legacy),
                version: Some("full node v1.0.10".into()),
                database_type: Some(8),
                searched: Vec::new(),
                picked_path: None,
                picked_problem: None,
            }),
            asked_data_dir: "C:/chain".into(),
            api_port: 8080,
            p2p_port: 3337,
            last_stop: Some(StopOutcome {
                killed: false,
                seconds: 0,
            }),
            ..NodeObservations::default()
        };
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Stopped);
        assert!(
            !report.detail.contains("flushed") && !report.detail.contains("cleanly"),
            "a flush this wallet cannot see must not be claimed: {}",
            report.detail
        );
        assert!(report.detail.contains("not something this wallet can see"));
        assert!(report.detail.contains("may pause while it checks"));
    }

    #[test]
    fn starting_carries_a_clock_so_one_second_and_one_hour_read_differently() {
        let mut observed = ours_alive(None);
        observed.our_api_line = None;
        observed.alive_seconds = Some(412);
        let report = decide(&observed, "cfg");
        assert_eq!(report.state, NodeState::Starting);
        assert!(report.detail.contains("412 seconds"), "{}", report.detail);
    }

    #[test]
    fn ready_moves_back_to_catching_up_when_the_tip_goes_stale() {
        let ready = decide(
            &ours_alive(Some(capabilities(
                Some(MAINNET_BLOCK_ONE_HASH),
                776647,
                true,
            ))),
            "cfg",
        );
        assert_eq!(ready.state, NodeState::Ready);
        let stalled = decide(
            &ours_alive(Some(capabilities(
                Some(MAINNET_BLOCK_ONE_HASH),
                776647,
                false,
            ))),
            "cfg",
        );
        assert_eq!(
            stalled.state,
            NodeState::CatchingUp,
            "a screen whose states only move forward is how it ends up claiming a dead tip is current"
        );
    }
}
