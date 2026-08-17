//! Can a key that is not the Hub's build the registry exit transactions?
//!
//! This file is deliberately tiny and deliberately depends on nothing this
//! work added. It calls one pre-existing function,
//! `user_key_can_build_registry_exit_transactions`, whose signature and
//! meaning are unchanged: it synthesises a reviewed-profile binding and asks
//! the two real builders to work for the channel's *left* party, using a
//! throwaway key, no chain and no network.
//!
//! It is here rather than beside the probe so that the question is asked from
//! the wallet's side of the workspace, which is where a user's exit would have
//! to be built and where nothing could build one.
//!
//! Because it names no new type and no new module, its source compiles
//! identically before and after the builders were made role-aware. Before, it
//! fails: the builders refused every signer that was not the Hub. After, it
//! passes, and it passes because the builders changed rather than because this
//! assertion was weakened.

#[test]
fn a_user_key_can_build_the_registry_exit_transactions() {
    assert!(
        l2_fast_pay_hub::hvm_registry_watchtower::user_key_can_build_registry_exit_transactions(),
        "a user holding their own key must be able to build the finalize and the Action 14 \
         payout for their own channel; the chain permits it and this software must not be the \
         thing that refuses"
    );
}
