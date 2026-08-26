//! THE PARTS THAT HAVE NO PURE-FUNCTION VERSION OF THEMSELVES.
//!
//! `desktop_node.rs` holds unit tests for every state and every refusal, and
//! those are functions of a struct, which is exactly why they are cheap enough
//! to have one each. What they cannot prove is the part that is an operating
//! system: that a child really gets spawned, that its own words really get read
//! off its pipe, that the lock beside the claim really refuses a second one,
//! and that a stop really ends it and clears what it left behind.
//!
//! So this file runs real processes. It never runs a fullnode against mainnet:
//! the only real fullnode it touches is touched through the version probe,
//! which errors before anything binds a port, resolves a data directory or
//! opens a database. Every other child here is a stand-in that prints the exact
//! lines the node prints and then waits.

#![cfg(feature = "desktop")]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use wallet_tauri_common::desktop_node::{
    self, ChainAnchor, ConfigWrite, NodeConfigPlan, NodeOutput, NodeProcess, NodeState,
};

/// Every path this module writes to is under a temporary directory, because
/// `node_state_dir()` reads `HACASH_WALLET_DATA` and the wallet's real one is
/// where a person's vault lives.
/// These tests move process-wide environment variables, so they take a turn.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Sandbox {
    _turn: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    root: PathBuf,
    api_port: u16,
    p2p_port: u16,
}

/// A port nobody has, asked of the OS rather than picked.
///
/// A hard coded test port is a landmine: this suite already lost a run to one,
/// and it lost another to a stray fullnode from an earlier session still
/// listening on the number that had been written down here. Neither failure was
/// about the product. Asking for port 0 and reading back what was granted makes
/// the tests independent of whatever else this machine happens to be running.
fn free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("the OS has a spare local port");
    let port = listener
        .local_addr()
        .expect("a bound socket has an address")
        .port();
    drop(listener);
    port
}

impl Sandbox {
    fn new() -> Self {
        let turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        // NEVER 8080 and NEVER 3337. The owner of this machine has a real node
        // and a real Hub up, and a status poll probes whatever port it is
        // configured for. Nothing here may go near either of them, and these
        // are ports the OS just told us nobody holds.
        let api_port = free_port();
        let mut p2p_port = free_port();
        while p2p_port == api_port {
            p2p_port = free_port();
        }
        assert!(api_port != 8080 && api_port != 3337 && api_port != 8790);
        assert!(p2p_port != 8080 && p2p_port != 3337 && p2p_port != 8790);
        // SAFETY: the tests that use this run in one thread, see `ONE_AT_A_TIME`.
        unsafe {
            std::env::set_var("HACASH_WALLET_DATA", &root);
            std::env::set_var("HACASH_WALLET_NODE_DATA", root.join("chain"));
            std::env::set_var("HACASH_WALLET_NODE_API_PORT", api_port.to_string());
            std::env::set_var("HACASH_WALLET_NODE_P2P_PORT", p2p_port.to_string());
        }
        Self {
            _turn: turn,
            _dir: dir,
            root,
            api_port,
            p2p_port,
        }
    }
}

/// A child that prints what the node prints and then stays up.
///
/// Not a fullnode, deliberately. What is under test is the supervisor's grip on
/// an OS process and its reading of that process's own words, and a real
/// fullnode would have to reach mainnet to say any of them.
fn stand_in_node(lines: &[&str]) -> (PathBuf, Vec<String>) {
    if cfg!(windows) {
        let mut script = String::new();
        for line in lines {
            script.push_str(&format!("Write-Output '{line}'; "));
        }
        script.push_str("Start-Sleep -Seconds 120");
        (
            PathBuf::from("powershell.exe"),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                script,
            ],
        )
    } else {
        let mut script = String::new();
        for line in lines {
            script.push_str(&format!("echo \"{line}\"; "));
        }
        script.push_str("sleep 120");
        (PathBuf::from("/bin/sh"), vec!["-c".to_string(), script])
    }
}

fn launch_stand_in(process: &NodeProcess, plan: &NodeConfigPlan, lines: &[&str]) {
    let (program, args) = stand_in_node(lines);
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let lock = desktop_node::take_lock_for_tests(&desktop_node::node_lock_path())
        .expect("the sandbox lock is free");
    desktop_node::launch(process, &program, &args, plan, lock).expect("the stand-in node started");
}

fn wait_for(mut ready: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

fn plan_in(sandbox: &Sandbox) -> NodeConfigPlan {
    NodeConfigPlan {
        data_dir: sandbox.root.join("chain"),
        // The ports the OS handed this sandbox, never the owner's 8080 / 3337.
        api_port: sandbox.api_port,
        p2p_port: sandbox.p2p_port,
    }
}

/// A REAL CHILD, ITS REAL WORDS, AND A REAL STOP.
///
/// The claim on the API port comes from the child's own stdout line and from
/// nowhere else, because the node binds its own socket: when the port is taken
/// it prints an error and RETURNS while the rest of it keeps running, so "our
/// child is alive and the port answers" would be a false claim on somebody
/// else's node.
#[test]
fn a_real_child_is_read_off_its_own_pipe_and_a_stop_really_ends_it() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();

    launch_stand_in(
        &process,
        &plan,
        &[
            &format!(
                "[Engine] Data: {}, rebuild (102)...",
                plan.data_dir.display()
            ),
            &format!("[P2P] Start and listening on {}", plan.p2p_port),
            "[P2P] Connect 3 boot nodes",
            &format!(
                "[Api Server] listening on http://127.0.0.1:{} (loopback, no token)",
                plan.api_port
            ),
        ],
    );

    // The claim is written the moment the child exists, not after it is proven.
    let claim = desktop_node::read_claim(&desktop_node::node_claim_path())
        .expect("a claim is written for a child we hold");
    assert_eq!(claim.api_port, plan.api_port);
    assert!(claim.pid > 0);

    let saw_api = || {
        desktop_node::observed_for_tests(&process)
            .map(|o| o.api_line.is_some())
            .unwrap_or(false)
    };
    wait_for(saw_api, "the child's own API line");

    let observed = desktop_node::observed_for_tests(&process).unwrap();
    assert_eq!(
        observed.api_line,
        Some(format!(
            "[Api Server] listening on http://127.0.0.1:{} (loopback, no token)",
            plan.api_port
        ))
    );
    assert_eq!(
        observed.engine_data_dir.as_deref(),
        Some(plan.data_dir.display().to_string().as_str()),
        "the folder the node reported is what gets compared, never what we asked for"
    );
    assert_eq!(observed.boot_nodes, Some(3));

    // The log the person can open afterwards is really being written.
    let log = fs::read_to_string(desktop_node::node_stdout_log_path()).unwrap_or_default();
    assert!(log.contains("[Api Server] listening"), "stdout log: {log}");

    let pid = claim.pid;
    let stopped =
        desktop_node::stop_managed_node(&process, Duration::from_secs(6)).expect("the stop ran");
    assert!(
        stopped,
        "a stop of a child we hold reports that it stopped something"
    );
    assert!(!process_is_alive(pid), "process {pid} outlived its stop");
    assert!(
        !desktop_node::node_claim_path().exists(),
        "a claim must not outlive the process it claims"
    );

    // And a second stop finds nothing and says nothing untrue, exactly as
    // `stop_managed_relay` returns Ok when there was nothing to stop.
    assert!(!desktop_node::stop_managed_node(&process, Duration::from_secs(1)).unwrap());
}

/// THE ONE THAT ACTUALLY PROTECTS THE CHAIN.
///
/// Two nodes on one data directory is the corruption case, and a port test does
/// not answer it: a second node on a different port against the same store gets
/// past every port check there is. The lock beside the claim is what refuses
/// it, and it refuses because holding a file open is something only a live
/// process can do. A pid on its own is worthless: pids are recycled.
#[test]
fn a_second_start_against_a_held_chain_folder_is_refused_and_names_the_holder() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();
    launch_stand_in(
        &process,
        &plan,
        &[&format!(
            "[Api Server] listening on http://127.0.0.1:{}",
            plan.api_port
        )],
    );

    let verdict = desktop_node::claim_verdict(
        &desktop_node::node_claim_path(),
        &desktop_node::node_lock_path(),
    );
    let held = serde_json::to_value(&verdict).unwrap();
    assert_eq!(held["verdict"], "held", "{held}");
    assert_eq!(
        held["data_dir"],
        plan.data_dir.display().to_string(),
        "the refusal has to name the folder that is held"
    );

    // A second supervisor in this same process cannot take the lock either.
    let second = desktop_node::take_lock_for_tests(&desktop_node::node_lock_path());
    assert!(second.is_err(), "the lock let a second holder in");

    desktop_node::stop_managed_node(&process, Duration::from_secs(6)).unwrap();

    // And once it is gone the claim is worth nothing, which is the point: a
    // file existing is never evidence that a process does.
    fs::write(
        desktop_node::node_claim_path(),
        serde_json::to_vec(&serde_json::json!({
            "pid": 999999, "claimed_unix": 1, "binary": "x", "data_dir": "y",
            "config_path": "z", "api_port": 18099, "p2p_port": 13399, "stopped_hard": true
        }))
        .unwrap(),
    )
    .unwrap();
    let stale = serde_json::to_value(desktop_node::claim_verdict(
        &desktop_node::node_claim_path(),
        &desktop_node::node_lock_path(),
    ))
    .unwrap();
    assert_eq!(stale["verdict"], "stale", "{stale}");
    assert_eq!(stale["stopped_hard"], true);
}

/// A child that ends is a child that ended, and the report says so.
///
/// This is the defect the relay has and the one thing from it that must not be
/// copied: its spawned task logs that it stopped and clears neither `managed`
/// nor `bound`, so `relay_endpoint` keeps reporting a live listen address for a
/// relay that is gone.
#[test]
fn a_child_that_exits_stops_being_reported_as_running() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();
    let (program, args) = if cfg!(windows) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Write-Output 'thread main panicked: could not acquire lock on db'; exit 101"
                    .to_string(),
            ],
        )
    } else {
        (
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "echo 'thread main panicked: could not acquire lock on db'; exit 101".to_string(),
            ],
        )
    };
    let os_args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let lock = desktop_node::take_lock_for_tests(&desktop_node::node_lock_path()).unwrap();
    desktop_node::launch(&process, &program, &os_args, &plan, lock).unwrap();

    let report = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            wait_for_async(&process).await;
            desktop_node::node_supervisor_status(&process)
                .await
                .unwrap()
        });

    assert_eq!(report.state, NodeState::Failed);
    assert_eq!(report.exit_code, Some(101));
    assert!(
        !report.ours,
        "a child that ended is not a node we are running"
    );
    assert!(
        report
            .detail
            .contains("another program is already using the chain folder"),
        "an exit 101 with a lock message has to become the sentence it means, not a bare code: {}",
        report.detail
    );
    assert_eq!(report.anchor, ChainAnchor::Unknown);
    assert!(
        report.height.is_none(),
        "nothing may be said about a chain nobody read"
    );
    desktop_node::stop_managed_node(&process, Duration::from_secs(2)).unwrap();
}

/// THE DEAD END, AND THE PRESS THAT NOW DOES SOMETHING.
///
/// Measured before this fix: after the node exited on its own, the only button
/// on the screen was Start, and three presses produced a byte-identical report,
/// no new child, and a green toast saying "The node was asked to start." It was
/// not. Two things held it there: the dead `Child` was never taken out of the
/// supervisor, so `decide` read its exit code before anything else for ever;
/// and that dead child's own fs2 handle still held node.lock, so the refusal
/// being generated underneath said "a node this wallet started (process N) is
/// already using the chain folder" about a process the OS had already retired.
/// Only restarting the whole wallet recovered.
#[test]
fn a_start_after_the_node_died_really_starts_one_rather_than_freezing() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();

    // A child that prints a lock panic and exits at once, which is the case a
    // person actually meets.
    let (program, args) = if cfg!(windows) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                "Write-Output 'thread main panicked: could not acquire lock on db'; exit 101"
                    .to_string(),
            ],
        )
    } else {
        (
            PathBuf::from("/bin/sh"),
            vec![
                "-c".to_string(),
                "echo 'thread main panicked: could not acquire lock on db'; exit 101".to_string(),
            ],
        )
    };
    let os_args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let lock = desktop_node::take_lock_for_tests(&desktop_node::node_lock_path()).unwrap();
    desktop_node::launch(&process, &program, &os_args, &plan, lock).unwrap();

    // NOTHING REAL MAY BE SPAWNED HERE. `sync_managed_node` would otherwise
    // find the fullnode this machine has at C:/hpay/fullnode.exe and start it
    // against mainnet, which is out of bounds for a test: the first run of this
    // test did exactly that and left a real node running against a temp folder.
    // Pointing the pick at a path that does not exist stops the resolver at the
    // pick, so the press reaches a refusal instead of a process.
    let nowhere = sandbox.root.join("a-node-that-is-not-there.exe");
    process.set_picked_binary(Some(nowhere.clone()));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        wait_for_async(&process).await;
        let died = desktop_node::node_supervisor_status(&process)
            .await
            .unwrap();
        assert_eq!(died.state, NodeState::Failed);
        assert_eq!(died.exit_code, Some(101));
        assert!(died.can_start, "the only offer left has to be Start");

        // THE PRESS. What must change is that the wallet gets past its own dead
        // child and reaches a real, current reason. What it must never do is
        // repeat the previous corpse's exit code for ever.
        desktop_node::sync_managed_node(&process).await.unwrap();
        let after = desktop_node::node_supervisor_status(&process)
            .await
            .unwrap();

        assert_ne!(
            after, died,
            "three presses used to produce a byte-identical report"
        );
        assert_eq!(
            after.exit_code, None,
            "a dead child's exit code must not outlive the attempt to replace it"
        );
        assert_ne!(
            after.state,
            NodeState::Failed,
            "the state has to leave Failed once the corpse is cleared"
        );
        assert!(
            !after.detail.contains("already using the chain folder"),
            "the stale self-refusal is the sentence that made this a dead end: {}",
            after.detail
        );
        // And the reason it now gives is the true, current one.
        assert!(
            after
                .detail
                .contains(nowhere.display().to_string().as_str()),
            "the refusal has to be about what is wrong now: {}",
            after.detail
        );
    });

    // The lock the corpse was holding is genuinely free again, which is the
    // thing that made the old refusal self-inflicted.
    assert!(
        desktop_node::take_lock_for_tests(&desktop_node::node_lock_path()).is_ok(),
        "the dead child's own handle was still holding the chain folder lock"
    );
    assert!(
        !desktop_node::node_claim_path().exists(),
        "a claim must not outlive the process it claims"
    );
    desktop_node::stop_managed_node(&process, Duration::from_secs(2)).unwrap();
}

/// FALSE ADOPTION, WITH A REAL STRANGER ON THE PORT.
///
/// The child announces `[Api Server] listening on ...` once and never binds.
/// Something else then takes the port and answers. Before this fix the wallet
/// reported the stranger's height, its freshness and the mainnet block one hash
/// under "Your node is up to date", with ours true and a Stop button: every
/// number came from a process the wallet did not start, and the anchor
/// sentence, which exists to be the one thing you can trust, was the loudest
/// part of the lie.
#[test]
fn a_stranger_on_the_port_our_child_announced_is_never_reported_as_ours() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();

    // The child says it has the port and never binds it, which is exactly what
    // server.rs allows: it prints and RETURNS while the chain and p2p threads
    // carry on.
    launch_stand_in(
        &process,
        &plan,
        &[
            &format!(
                "[Engine] Data: {}, rebuild (102)...",
                plan.data_dir.display()
            ),
            &format!(
                "[Api Server] listening on http://127.0.0.1:{} (loopback, no token)",
                plan.api_port
            ),
        ],
    );
    wait_for(
        || {
            desktop_node::observed_for_tests(&process)
                .map(|o| o.api_line.is_some())
                .unwrap_or(false)
        },
        "the child's own API line",
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Nobody on the port at all: the announcement alone must not buy a state
    // that says anything about a chain.
    let alone = runtime
        .block_on(desktop_node::node_supervisor_status(&process))
        .unwrap();
    assert_eq!(
        alone.state,
        NodeState::Failed,
        "an announced port with nothing listening is a failure, not a green header"
    );
    assert!(
        alone.ours,
        "the process is still ours; its API is not there"
    );
    assert_eq!(alone.height, None);

    // Now a stranger takes it, in this same process so its pid is provably not
    // the child's.
    let stranger = std::net::TcpListener::bind(("127.0.0.1", plan.api_port))
        .expect("the port the child never bound is free");
    let taken = runtime
        .block_on(desktop_node::node_supervisor_status(&process))
        .unwrap();
    drop(stranger);

    assert_eq!(taken.state, NodeState::Failed);
    assert_ne!(taken.headline, "Your node is up to date");
    assert_eq!(
        taken.height, None,
        "a stranger's height was reported as our node's"
    );
    assert_eq!(taken.anchor, ChainAnchor::Unknown);
    assert!(
        !taken
            .watching
            .contains("001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56"),
        "the mainnet anchor must never be printed about a port we cannot prove \
is ours: {}",
        taken.watching
    );

    desktop_node::stop_managed_node(&process, Duration::from_secs(6)).unwrap();
}

/// The config the node is being given is on the screen, not in a log line.
///
/// `report.config` was null on every live path, so the one sentence warning
/// that the node runs with settings this wallet did not choose could not appear
/// at all. That sentence is the whole pass: the measured peer count that keeps
/// a signed transaction from sitting unmined for two days lives in that file.
#[test]
fn a_config_the_wallet_did_not_write_reaches_the_report_rather_than_a_log() {
    let sandbox = Sandbox::new();
    let plan = plan_in(&sandbox);
    let process = NodeProcess::new();

    let config_path = desktop_node::node_config_path();
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(
        &config_path,
        "data_dir = D:/somewhere_else\n[node]\nnot_find_nodes = true\nbackbone_peers = 4\n",
    )
    .unwrap();

    launch_stand_in(
        &process,
        &plan,
        &[&format!(
            "[Engine] Data: {}, rebuild (102)...",
            plan.data_dir.display()
        )],
    );

    let report = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(desktop_node::node_supervisor_status(&process))
        .unwrap();

    match report.config {
        Some(ConfigWrite::LeftAlone { ref reason }) => {
            assert!(reason.contains("did not write it"), "{reason}");
            assert!(
                reason.contains("peer count"),
                "the warning has to name what is at stake: {reason}"
            );
        }
        other => panic!("a config the wallet never wrote must reach the screen: {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        "data_dir = D:/somewhere_else\n[node]\nnot_find_nodes = true\nbackbone_peers = 4\n",
        "reading the config for the screen must never rewrite it"
    );

    desktop_node::stop_managed_node(&process, Duration::from_secs(6)).unwrap();
}

/// A CHAIN FOLDER THAT CANNOT BE MADE IS A SENTENCE, NOT AN OS ERROR NUMBER.
///
/// Measured before this fix: a file sitting where the folder had to go made
/// `sync_managed_node` return `Err`, which reached the person as a transient red
/// toast reading "cannot create ...: Cannot create a file when that file already
/// exists. (os error 183)" while the panel underneath carried on describing a
/// node that was never started. Anything that stops a start belongs in the
/// state, in words that stay put.
///
/// Nothing is spawned here: the folder is created before the binary is ever
/// run, so the refusal happens first.
#[test]
fn a_chain_folder_that_cannot_be_made_is_a_refusal_with_words_rather_than_an_error() {
    let sandbox = Sandbox::new();
    let process = NodeProcess::new();

    // A file exactly where the chain folder has to go.
    let blocker = sandbox.root.join("chain");
    fs::create_dir_all(blocker.parent().unwrap()).unwrap();
    fs::write(&blocker, b"not a folder").unwrap();

    // This needs a binary to resolve, so that the run reaches the folder step at
    // all. The only one this machine may have is the one the guide tells people
    // to build, and it is never executed here.
    if !Path::new("C:/hpay/fullnode.exe").is_file() {
        return;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        desktop_node::sync_managed_node(&process)
            .await
            .expect("a folder that cannot be made is a refusal, never a hard error");
        let report = desktop_node::node_supervisor_status(&process)
            .await
            .unwrap();
        assert_eq!(
            report.state,
            NodeState::Blocked,
            "detail was: {}",
            report.detail
        );
        assert!(
            report
                .detail
                .contains("could not make the folder the chain goes in"),
            "{}",
            report.detail
        );
        assert!(
            report.detail.contains("Nothing has been started"),
            "{}",
            report.detail
        );
        assert!(
            report.detail.contains("read only") || report.detail.contains("full disk"),
            "the sentence has to suggest what is actually wrong: {}",
            report.detail
        );
    });

    // Nothing was spawned and nothing claimed the folder.
    assert!(
        !desktop_node::node_claim_path().exists(),
        "a refusal must not leave a claim behind"
    );
    desktop_node::stop_managed_node(&process, Duration::from_secs(2)).unwrap();
}

/// A pick that has gone missing stops the search instead of promoting the next
/// candidate. Measured before this fix: pointed at mynode.exe, deleted it, and
/// `resolve_node_binary` returned C:/hpay/fullnode.exe with no complaint.
#[test]
fn a_missing_pick_is_never_replaced_by_whatever_else_is_on_this_computer() {
    let dir = tempfile::tempdir().unwrap();
    let gone = dir.path().join("mynode.exe");

    let report = desktop_node::resolve_node_binary(Some(&gone));
    assert!(
        report.path.is_none(),
        "the wallet chose a different binary than the one that was picked: {:?}",
        report.path
    );
    assert_eq!(
        report.picked_path.as_deref(),
        Some(gone.display().to_string().as_str())
    );
    assert!(
        report
            .picked_problem
            .as_deref()
            .is_some_and(|reason| reason.contains("nothing is at this path")),
        "{:?}",
        report.picked_problem
    );
    // And the search really did stop there rather than carrying on quietly.
    assert_eq!(
        report.searched.len(),
        1,
        "the search must stop at a failed pick: {:?}",
        report.searched
    );
}

async fn wait_for_async(process: &NodeProcess) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(report) = desktop_node::node_supervisor_status(process).await
            && report.exit_code.is_some()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the child never exited");
}

/// THE CONFIG, AND THE PROMISE NOT TO OVERWRITE SOMEBODY'S WORK.
#[test]
fn the_config_is_written_once_left_alone_when_edited_and_never_written_over() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hacash.config.ini");
    let plan = NodeConfigPlan {
        data_dir: dir.path().join("chain"),
        api_port: 18099,
        p2p_port: 13399,
    };

    assert_eq!(
        desktop_node::write_node_config(&path, &plan).unwrap(),
        ConfigWrite::Written
    );
    let first = fs::read_to_string(&path).unwrap();
    assert!(first.contains("backbone_peers = 32"));

    // A second call changes nothing at all, which is what makes this safe to
    // run on every start.
    assert_eq!(
        desktop_node::write_node_config(&path, &plan).unwrap(),
        ConfigWrite::Unchanged
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), first);

    // Somebody edits it. The wallet leaves it exactly as it is and says so.
    let edited = first.replace("backbone_peers = 32", "backbone_peers = 64");
    fs::write(&path, &edited).unwrap();
    match desktop_node::write_node_config(&path, &plan).unwrap() {
        ConfigWrite::LeftAlone { reason } => {
            assert!(reason.contains("edited"), "{reason}");
            assert!(reason.contains("left"), "{reason}");
        }
        other => panic!("an edited config was not left alone: {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        edited,
        "the wallet overwrote a config somebody had edited"
    );

    // And a config the wallet never wrote is not touched either, whatever is
    // in it.
    let foreign = dir.path().join("someone-elses.ini");
    fs::write(&foreign, "data_dir = D:/their_chain\n").unwrap();
    match desktop_node::write_node_config(&foreign, &plan).unwrap() {
        ConfigWrite::LeftAlone { reason } => {
            assert!(reason.contains("did not write it"), "{reason}")
        }
        other => panic!("a config this wallet never wrote was not left alone: {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(&foreign).unwrap(),
        "data_dir = D:/their_chain\n"
    );
}

/// The reader really is what turns a node's words into the supervisor's facts.
#[test]
fn the_lines_a_node_prints_are_what_the_supervisor_believes() {
    let output = NodeOutput::default();
    for line in [
        "[Engine] Data: C:\\Users\\a\\chain, rebuild (102)...",
        "[P2P] Start and listening on 3337",
        "[P2P] Connect 0 boot nodes",
        "[Error] api server failed to bind 127.0.0.1:8080: address in use",
    ] {
        output.observe(line);
    }
    assert_eq!(
        output.engine_data_dir().as_deref(),
        Some("C:\\Users\\a\\chain")
    );
    assert_eq!(output.boot_nodes(), Some(0));
    assert!(output.api_bind_error().is_some());
    assert!(
        output.api_line().is_none(),
        "a failed bind must never be read as the node owning the port"
    );
    output.observe("[Api Server] listening on http://127.0.0.1:8080 (loopback, no token)");
    assert!(output.api_line().is_some());
}

/// THE PROBE, AGAINST A REAL FULLNODE WHEN THERE IS ONE ON THIS MACHINE.
///
/// Safe by construction: run with a config path that does not exist, the node
/// errors before `from_ini`, so nothing binds a port, resolves a data directory
/// or opens a database. It is also the only thing here that touches a real
/// fullnode at all.
#[test]
fn a_candidate_is_confirmed_by_running_it_and_never_by_its_filename() {
    let dir = tempfile::tempdir().unwrap();
    let not_a_node = dir.path().join("fullnode.exe");
    fs::write(&not_a_node, b"MZ this is not a node").unwrap();
    assert!(
        desktop_node::probe_node_binary(&not_a_node).is_err(),
        "a file named fullnode.exe was accepted as one"
    );
    assert!(desktop_node::probe_node_binary(dir.path()).is_err());
    assert!(desktop_node::probe_node_binary(&dir.path().join("nothing-here")).is_err());

    let real = Path::new("C:/hpay/fullnode.exe");
    if real.is_file() {
        let probe = desktop_node::probe_node_binary(real).expect("the real fullnode answered");
        assert!(probe.version.contains("full node"), "{}", probe.line);
        assert!(
            probe.database_type.is_some(),
            "the probe has to answer the state_vN question too: {}",
            probe.line
        );
    }
}

fn process_is_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        match out {
            Ok(out) => String::from_utf8_lossy(&out.stdout).contains(&pid.to_string()),
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
}
