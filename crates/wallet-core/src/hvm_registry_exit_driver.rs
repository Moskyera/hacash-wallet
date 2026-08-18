//! The loop that actually walks a user out of an HVM registry channel.
//!
//! # What was missing
//!
//! [`crate::hvm_registry_exit`] decides and builds.
//! [`crate::hvm_registry_exit_record`] remembers. Neither of them *does*
//! anything, and until this module nothing else did either: the only code that
//! ever put those two together was a test, twice over. A mechanism whose only
//! caller is a test is not a way out of a channel, and this workspace has
//! shipped that shape before.
//!
//! # Shape
//!
//! One call, [`advance_registry_exit`], makes **at most one unit of progress**
//! and returns what it did. It never sleeps, never mines and never loops
//! waiting for a block, because the thing it is waiting for — an objection
//! window measured in blocks — outlives the process by design. A surface polls
//! it; a wallet restarted halfway through calls it again and it picks the exit
//! up from the durable record rather than from memory.
//!
//! The order inside one pass is fixed and is the order the durable record's
//! doc comments prescribe:
//!
//! 1. read the chain and plan from it, never from the record;
//! 2. ask the record what may be done about the planned step;
//! 3. announce the possibility of a signature **before** the key is used;
//! 4. make the exact bytes durable **before** any node sees them;
//! 5. record the submission **before** the wire;
//! 6. and only then let a confirmation update the record.
//!
//! Every one of those orderings is what makes a process killed at that instant
//! recoverable rather than ambiguous.
//!
//! # What this module may not do
//!
//! It holds no key and it has no opinion about who may sign. The signer is a
//! trait, implemented above this crate by whoever owns the secret, and it is
//! handed the durable record rather than a free choice of terms — so a driver
//! cannot ask for a signature at a timestamp the record does not already
//! carry. It also cannot choose *whether* to sign: that answer comes from
//! [`HvmRegistryExitResumeV1::may_sign`], which is the record's, not the
//! driver's.

use l2_fast_pay_hub::hvm_registry_watchtower::SignedHvmRegistryCallTransactionV2;

use crate::error::{WalletError, WalletResult};
use crate::hvm_registry_exit::{
    HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep, plan_user_exit_step,
};
use crate::hvm_registry_exit_record::{
    HvmRegistryExitIntentV1, HvmRegistryExitPhase, HvmRegistryExitResumeV1,
    PersistedHvmRegistryExitStepV1, deterministic_exit_transaction_timestamp,
};
use crate::l2_safety::ClientL2Safety;

/// What one exit transaction is allowed to cost.
///
/// Supplied by the caller rather than guessed here, because the ceiling an
/// owner was shown on screen and the fee this driver spends must be the same
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvmRegistryExitTermsV1 {
    pub network_fee_zhu: u64,
    pub gas_max: u8,
}

/// What a node knows about one transaction hash.
///
/// The three answers are genuinely different and collapsing any two of them
/// loses money. `Unknown` means re-submitting the stored bytes is the right
/// move; `Pending` means it is a duplicate; `Mined` means the record may be
/// retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvmRegistryExitSightingV1 {
    /// Neither a block nor this node's mempool carries it.
    Unknown,
    /// The node holds it and no block carries it yet.
    Pending,
    Mined {
        block_height: u64,
        block_hash: String,
    },
}

/// Everything this driver needs from a chain, and nothing it needs from a Hub.
///
/// Deliberately four methods, all read-or-submit, all answerable by an
/// ordinary pinned fullnode. There is no method here that a provider would
/// have to be alive to answer, because the entire point of the exit is that
/// the provider is not.
#[allow(async_fn_in_trait)]
pub trait HvmRegistryExitChainV1 {
    /// Live contract storage for this channel, read from the caller's own
    /// pinned fullnode.
    async fn registry_snapshot(
        &self,
    ) -> WalletResult<l2_fast_pay_hub::hvm_registry::HvmRegistryLiveSnapshotV2>;

    /// The node's own tip height and how old that tip is in seconds. Both are
    /// needed: a snapshot behind the node's tip and a node behind the chain are
    /// two different lies about the same deadline.
    async fn chain_tip(&self) -> WalletResult<(u64, u64)>;

    /// What this node knows about one transaction hash.
    async fn transaction_sighting(&self, hash: &str) -> WalletResult<HvmRegistryExitSightingV1>;

    /// Hand exact signed bytes to the node. Implementations must treat a
    /// duplicate as success: the bytes are idempotent by hash, and the caller
    /// has already made them durable.
    async fn submit_exit_transaction(
        &self,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> WalletResult<()>;
}

/// The one thing this module cannot do for itself.
///
/// The implementation lives wherever the secret does. It is handed the durable
/// record, not a free choice of terms, so the transaction it produces is the
/// one the record already committed to.
pub trait HvmRegistryExitSignerV1 {
    fn sign_exit_step(
        &self,
        kit: &HvmRegistryExitKitV1,
        plan: &HvmRegistryExitPlanV1,
        record: &PersistedHvmRegistryExitStepV1,
    ) -> WalletResult<SignedHvmRegistryCallTransactionV2>;
}

/// What one pass of the driver did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvmRegistryExitProgressV1 {
    /// Nothing to do right now. Carries the chain facts behind that, so a
    /// surface can say "finalize opens at block N" rather than spin.
    Waiting {
        reason: String,
        observed_height: u64,
        status: u8,
        deadline: u64,
    },
    /// One step moved. `phase` is where that step's durable record now stands.
    Stepped {
        step: HvmRegistryExitStep,
        transaction_hash: String,
        phase: HvmRegistryExitPhase,
    },
    /// The channel is settled and this wallet's payout has been made.
    Complete { claimed_zhu: u64 },
}

/// Make at most one unit of progress on this wallet's exit.
///
/// See the module documentation for the ordering and why each step of it is
/// load bearing. Returns without doing anything at all when the chain asks for
/// nothing, which is the ordinary answer for most of an objection window.
pub async fn advance_registry_exit<C, S>(
    store: &mut ClientL2Safety,
    kit: &HvmRegistryExitKitV1,
    chain: &C,
    signer: &S,
    terms: HvmRegistryExitTermsV1,
) -> WalletResult<HvmRegistryExitProgressV1>
where
    C: HvmRegistryExitChainV1,
    S: HvmRegistryExitSignerV1,
{
    if terms.network_fee_zhu == 0 || terms.gas_max == 0 {
        return Err(WalletError::Policy(
            "an exit transaction needs a network fee and a gas ceiling".into(),
        ));
    }
    let binding_commitment = kit
        .binding
        .commitment()
        .map_err(|error| WalletError::L2(error.to_string()))?;

    // 1. The chain, then the plan. Never the record first: a record is a
    //    memory of what this wallet meant to do, and the question is what the
    //    contract needs done now.
    let snapshot = chain.registry_snapshot().await?;
    let (tip_height, tip_age_seconds) = chain.chain_tip().await?;
    let plan = plan_user_exit_step(kit, &snapshot, tip_height, tip_age_seconds)?;
    let step = match &plan {
        HvmRegistryExitPlanV1::Wait { reason } => {
            if snapshot.channel.status.value == 4 && snapshot.channel.left_claimed.value {
                return Ok(HvmRegistryExitProgressV1::Complete {
                    claimed_zhu: snapshot.channel.left_balance.value,
                });
            }
            return Ok(HvmRegistryExitProgressV1::Waiting {
                reason: reason.clone(),
                observed_height: snapshot.observed_height,
                status: snapshot.channel.status.value,
                deadline: snapshot.channel.deadline.value,
            });
        }
        HvmRegistryExitPlanV1::Call { step, .. } => *step,
        HvmRegistryExitPlanV1::Claim { .. } => HvmRegistryExitStep::Claim,
    };

    // 2. What may be done about that step, decided by the record.
    //
    //    The attempt number is read before the intent is built because it is
    //    an input to the derived timestamp: the one legitimate second
    //    transaction for a step — a lease renewal replacing a mined one after
    //    a long objection window — must not derive the same bytes as the
    //    first, or the chain would reject it as a duplicate of something it
    //    already has.
    let existing = store.exit_step_record(&binding_commitment, step);
    let attempt = match &existing {
        Some(record) if record.phase.is_terminal() && step.is_lease_renewal() => {
            record.attempt.saturating_add(1)
        }
        Some(record) => record.attempt,
        None => 1,
    };
    let intent = HvmRegistryExitIntentV1::from_plan(
        kit,
        &plan,
        &snapshot,
        terms.network_fee_zhu,
        deterministic_exit_transaction_timestamp(&binding_commitment, step, attempt),
        terms.gas_max,
    )?;
    let resumed = store.begin_or_resume_exit_step(kit, &intent)?;

    let (signed_transaction_hex, transaction_hash) = match resumed {
        HvmRegistryExitResumeV1::Done { record } => {
            return retired_step_the_chain_still_wants(
                store,
                kit,
                chain,
                &binding_commitment,
                &record,
            )
            .await;
        }
        HvmRegistryExitResumeV1::AwaitChain {
            transaction_hash,
            signed_transaction_hex,
            ..
        } => {
            // Exact bytes exist. The key is not touched on this path under any
            // circumstances; the only questions are whether the chain has them
            // and, if not, whether to hand them over again.
            match chain.transaction_sighting(&transaction_hash).await? {
                HvmRegistryExitSightingV1::Mined {
                    block_height,
                    block_hash,
                } => {
                    let record = store.mark_exit_step_confirmed(
                        kit,
                        &binding_commitment,
                        step,
                        &transaction_hash,
                        block_height,
                        &block_hash,
                    )?;
                    return Ok(HvmRegistryExitProgressV1::Stepped {
                        step,
                        transaction_hash,
                        phase: record.phase,
                    });
                }
                HvmRegistryExitSightingV1::Pending => {
                    return Ok(HvmRegistryExitProgressV1::Waiting {
                        reason: format!(
                            "this wallet's {} transaction {transaction_hash} is with the network and no block carries it yet",
                            step.slug()
                        ),
                        observed_height: snapshot.observed_height,
                        status: snapshot.channel.status.value,
                        deadline: snapshot.channel.deadline.value,
                    });
                }
                HvmRegistryExitSightingV1::Unknown => (signed_transaction_hex, transaction_hash),
            }
        }
        resume @ (HvmRegistryExitResumeV1::SignFresh { .. }
        | HvmRegistryExitResumeV1::ResignExact { .. }) => {
            let record = resume.record().clone();
            // 3. The possibility of a signature is durable before the key.
            if record.phase == HvmRegistryExitPhase::IntentPersisted {
                store.mark_exit_step_signature_may_exist(kit, &binding_commitment, step)?;
            }
            let signed = signer.sign_exit_step(kit, &plan, &record)?;
            // 4. The exact bytes are durable before any node sees them.
            store.persist_exit_step_signature(
                kit,
                &binding_commitment,
                step,
                &signed.signed_transaction_hex,
                &signed.transaction_hash,
            )?;
            (signed.signed_transaction_hex, signed.transaction_hash)
        }
    };

    // 5. Submission is durable before the wire, so bytes that reach a node
    //    while this process dies are bytes the next process knows about.
    let phase = store
        .exit_step_record(&binding_commitment, step)
        .map(|record| record.phase);
    if phase == Some(HvmRegistryExitPhase::Signed) {
        store.mark_exit_step_submitted(kit, &binding_commitment, step)?;
    }
    chain
        .submit_exit_transaction(&signed_transaction_hex, &transaction_hash)
        .await?;
    Ok(HvmRegistryExitProgressV1::Stepped {
        step,
        transaction_hash,
        phase: HvmRegistryExitPhase::Submitted,
    })
}

/// The chain is asking for a step this wallet's record has already retired.
///
/// Two ways that happens, and they need opposite answers.
///
/// * **The block went away.** A confirmation taken one block deep is not a
///   fact; a reorg can take it back. The record would otherwise say `Done`
///   forever for a transaction the chain no longer carries, and nothing could
///   move it — `settled elsewhere` refuses from `Confirmed` and a second
///   confirmation in a different block refuses too. So the record is put back
///   to what it truthfully is, `Submitted`, keeping its exact bytes, and the
///   next pass re-submits *those* bytes. No new signature is produced, here or
///   anywhere on this path.
/// * **Somebody else did it, and the chain still wants it.** That is a
///   contradiction rather than a state to act on, and inventing a second
///   transaction to resolve it is exactly the wrong instinct. Report it.
async fn retired_step_the_chain_still_wants<C>(
    store: &mut ClientL2Safety,
    kit: &HvmRegistryExitKitV1,
    chain: &C,
    binding_commitment: &str,
    record: &PersistedHvmRegistryExitStepV1,
) -> WalletResult<HvmRegistryExitProgressV1>
where
    C: HvmRegistryExitChainV1,
{
    let step = record.step;
    if record.phase == HvmRegistryExitPhase::Confirmed
        && let (Some(hash), Some(height), Some(block_hash)) = (
            record.transaction_hash.as_deref(),
            record.confirmed_block_height,
            record.confirmed_block_hash.as_deref(),
        )
        && !matches!(
            chain.transaction_sighting(hash).await?,
            HvmRegistryExitSightingV1::Mined { .. }
        )
    {
        let record =
            store.mark_exit_step_reorged_out(kit, binding_commitment, step, height, block_hash)?;
        return Ok(HvmRegistryExitProgressV1::Stepped {
            step,
            transaction_hash: hash.to_owned(),
            phase: record.phase,
        });
    }
    Err(WalletError::Policy(format!(
        "the chain is asking for the {} step of this exit and this wallet's own record of it is \
         already {:?}; nothing further can be signed for it",
        step.slug(),
        record.phase
    )))
}
