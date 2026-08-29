//! A ceiling on how big these async state machines are allowed to get.
//!
//! # Why this file exists
//!
//! On 2026-08-29 the desktop wallet died with `0xC00000FD`
//! (`STACK_OVERFLOW`) the moment the owner pressed "Confirm exact setup" on
//! the first mainnet Fast Pay channel. The fault offset resolved to
//! `_alloca_probe`, the MSVC stack probe emitted for a function reserving a
//! large frame, so it was never runaway recursion. It was a handful of
//! enormous frames.
//!
//! Nothing in the wallet's own code reserved those frames. The generic spawn
//! plumbing did. A `#[tauri::command] pub async fn` compiles to
//! `InvokeResolver::respond_async_serialized`, which calls
//! `tauri::async_runtime::spawn`, which calls `tokio::task::spawn`. All three
//! are ordinary synchronous calls made on the thread dispatching the IPC
//! message, before the future ever reaches the runtime, and each one takes the
//! future BY VALUE. Measured against the shipped `hacash-wallet.exe`, LLVM
//! materialises the future roughly six times per level:
//!
//! ```text
//!   respond_async_serialized   6.02 x command future size
//!   tauri::async_runtime::spawn 12.04 x command future size
//!   tokio::task::spawn::spawn   6.02 x command future size
//!   ------------------------------------------------------
//!   total                      24.1 x, on top of a constant
//!                              261,832-byte generate_handler! dispatch frame
//! ```
//!
//! The confirm command's future was 75,656 bytes, so those four frames came to
//! 2,083,888 bytes. The thread they run on is the WebView2 UI thread, and the
//! exe's PE header says `SizeOfStackReserve = 1,048,576`. Twice the stack.
//!
//! # What is actually being asserted
//!
//! Every byte added to one of these futures costs about twenty-four bytes of
//! stack on a 1 MiB thread. A future is therefore a budgeted resource, and
//! these tests are the budget. They are deliberately about `size_of`, not
//! about behaviour: the fix for an overflow here is to move the state machine
//! to the heap (`Box::pin`), never to relax the number.
//!
//! # If one of these assertions fails
//!
//! Do NOT raise the constant. A failure means a newly added `.await`, local,
//! or nested call has grown a state machine that the release binary will
//! reserve roughly twenty-four times over on a 1 MiB stack. Raising the number
//! buys a wallet that crashes on a money path, and the crash is only harmless
//! while it happens to land BEFORE the durable `SignatureMayExist` marker. Land
//! it after that marker and the wallet refuses by design to sign a second time,
//! and that channel's only unilateral exit is gone permanently.
//!
//! The fix is to wrap the offending `async fn` body in a private `_inner`
//! method and have the public method be `Box::pin(self._inner(..)).await`.
//! That leaves behaviour byte-identical and puts the state machine on the
//! heap, which is what `confirm_l2_channel_setup` and
//! `take_l2_channel_close_voucher` already do for exactly this reason.
//!
//! # How the sizes are obtained
//!
//! `future_size` never calls the closure it is given. It only needs the
//! closure's return type, so no service is constructed, no I/O happens, and no
//! wallet state is touched. Future layout is decided in MIR, so these numbers
//! are identical in debug and release.

use crate::service::AgentWalletManager;
use crate::types::AgentWalletId;

/// Ceiling on any single `AgentWalletManager` future, in bytes.
///
/// Chosen from the stack arithmetic above, working backwards from the
/// measured crash rather than from taste:
///
/// * 1,048,576 bytes of main-thread stack reserve in the shipped exe
/// * minus the constant 261,832-byte `generate_handler!` dispatch frame
/// * leaves 786,744 bytes for the 24.1x spawn plumbing
/// * 786,744 / 24.1 = 32,645 bytes of future before the wallet dies
///
/// 16 KiB is half of that. The margin is not decoration: it is what absorbs
/// whatever depth the WebView2 message pump has already used before the
/// dispatch frame is even entered, and it is what makes a build with slightly
/// different inlining still fit.
///
/// `confirm_l2_channel_setup` was 74,696 bytes when it crashed the wallet.
const MAX_MANAGER_FUTURE_BYTES: usize = 16 * 1024;

/// Returns `size_of` the future the closure would return. The closure is
/// never called, so nothing here constructs a manager or performs I/O.
fn future_size<A, F, Fut>(_never_called: F) -> usize
where
    F: FnOnce(A) -> Fut,
    Fut: core::future::Future,
{
    core::mem::size_of::<Fut>()
}

/// Every manager future that a Tauri command can spawn, with its measured
/// size. Anything reachable from a `#[tauri::command]` belongs in this list.
fn measured_manager_futures() -> Vec<(&'static str, usize)> {
    type Ctx<'a> = (&'a mut AgentWalletManager, &'a AgentWalletId);

    // `mut` is used only by the pilot-gated `extend` below, so a default build
    // sees it as unnecessary.
    #[allow(unused_mut)]
    let mut sizes = vec![
        (
            "prepare_l2_channel_setup",
            future_size(|(m, w): Ctx<'_>| m.prepare_l2_channel_setup(w, "", "", 0)),
        ),
        (
            "confirm_l2_channel_setup",
            future_size(|(m, w): Ctx<'_>| m.confirm_l2_channel_setup(w, "", "", 0)),
        ),
        (
            "recover_l2_channel_setup",
            future_size(|(m, w): Ctx<'_>| m.recover_l2_channel_setup(w, 0)),
        ),
        (
            "verify_and_bind_l2_channel",
            future_size(|(m, w): Ctx<'_>| m.verify_and_bind_l2_channel(w, "", "", 0)),
        ),
    ];

    #[cfg(feature = "agent-wallet-testnet-pilot")]
    sizes.extend([
        (
            "execute_approved_hvm_payment",
            future_size(
                |(m, w, o): (
                    &mut AgentWalletManager,
                    &AgentWalletId,
                    &crate::types::OperationId,
                )| { m.execute_approved_hvm_payment(w, o, 0) },
            ),
        ),
        (
            "take_l2_channel_close_voucher",
            future_size(|(m, w): Ctx<'_>| m.take_l2_channel_close_voucher(w, 0)),
        ),
        (
            "prepare_l2_channel_close",
            future_size(|(m, w): Ctx<'_>| m.prepare_l2_channel_close(w, 0)),
        ),
        (
            "confirm_l2_channel_close",
            future_size(|(m, w): Ctx<'_>| m.confirm_l2_channel_close(w, "", "", 0)),
        ),
        (
            "recover_l2_channel_close",
            future_size(|(m, w): Ctx<'_>| m.recover_l2_channel_close(w, 0)),
        ),
        (
            "broadcast_l2_channel_close_voucher",
            future_size(|(m, w): Ctx<'_>| m.broadcast_l2_channel_close_voucher(w, 0)),
        ),
    ]);

    sizes
}

/// The budget, asserted over every manager future a command can reach.
///
/// Read the module comment before changing `MAX_MANAGER_FUTURE_BYTES`. The
/// answer to a failure here is `Box::pin`, not a bigger number.
#[test]
fn manager_futures_stay_within_the_stack_budget() {
    let mut over = Vec::new();
    for (name, size) in measured_manager_futures() {
        println!("{size:>8}  {name}");
        if size > MAX_MANAGER_FUTURE_BYTES {
            over.push(format!(
                "{name} is {size} bytes, over the {MAX_MANAGER_FUTURE_BYTES}-byte budget by {} \
                 (about {} bytes of release stack at the measured 24.1x spawn multiplier)",
                size - MAX_MANAGER_FUTURE_BYTES,
                (size as f64 * 24.1) as u64,
            ));
        }
    }
    assert!(
        over.is_empty(),
        "async state machines exceeded the stack budget; Box::pin them, do not raise the \
         constant (see the module comment in service/l2/stack_budget.rs):\n  {}",
        over.join("\n  ")
    );
}

/// The two paths this budget was written for, pinned by name.
///
/// `confirm_l2_channel_setup` is the button that crashed the wallet with real
/// money on screen. `take_l2_channel_close_voucher` is the exit, and it runs
/// inside a 300 second envelope immediately after the deposit is committed,
/// which is the worst possible moment to lose the process: a crash there costs
/// the owner their only unilateral way out of a funded channel.
///
/// A generic loop over a list is easy to quietly shorten. These two are named
/// so that deleting the guard has to be deliberate.
#[test]
#[cfg(feature = "agent-wallet-testnet-pilot")]
fn the_money_paths_are_heap_allocated() {
    // A boxed state machine is the arguments plus one pointer. The exact
    // number is not the point; a few hundred bytes proves the body moved to
    // the heap, and tens of thousands proves it did not.
    const BOXED_CEILING: usize = 512;

    let confirm = future_size(|(m, w): (&mut AgentWalletManager, &AgentWalletId)| {
        m.confirm_l2_channel_setup(w, "", "", 0)
    });
    let voucher = future_size(|(m, w): (&mut AgentWalletManager, &AgentWalletId)| {
        m.take_l2_channel_close_voucher(w, 0)
    });

    assert!(
        confirm <= BOXED_CEILING,
        "confirm_l2_channel_setup is {confirm} bytes, so its body is on the stack again. \
         It was 74,696 bytes when it crashed the wallet at 0xC00000FD. Restore the \
         Box::pin wrapper."
    );
    assert!(
        voucher <= BOXED_CEILING,
        "take_l2_channel_close_voucher is {voucher} bytes, so its body is on the stack \
         again. This is the exit, taken inside the 300 second envelope after the deposit \
         is committed. Restore the Box::pin wrapper."
    );
}
