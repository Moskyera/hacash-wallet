use hacash_wallet_core::authorization::{
    AuthorizationRequirement, OperationKind, PreparedOperationState, TrustedOperationDisplay,
};

fn prepare(
    state: &mut PreparedOperationState<&'static str>,
    body: &[u8],
) -> hacash_wallet_core::WalletResult<hacash_wallet_core::authorization::PreparedOperationView> {
    state.prepare(
        OperationKind::HacL1,
        "1PreparedWallet",
        "testnet",
        Some(1),
        body,
        TrustedOperationDisplay {
            title: "Send HAC".into(),
            summary: "Exact test operation".into(),
            fields: Vec::new(),
        },
        AuthorizationRequirement::AnyPlatformFactor,
        "stored-payload",
    )
}

#[test]
fn failed_reprepare_invalidates_an_already_authorized_ticket() {
    let mut state = PreparedOperationState::default();
    let approved = prepare(&mut state, b"original-body").unwrap();
    let challenge = state.begin_native(&approved.id).unwrap();
    state.finish_native(&approved.id, &challenge.nonce).unwrap();

    assert!(prepare(&mut state, b"").is_err());
    assert!(state.take(&approved.id, OperationKind::HacL1).is_err());
}

#[test]
fn unauthenticated_execute_attempt_consumes_the_ticket() {
    let mut state = PreparedOperationState::default();
    let prepared = prepare(&mut state, b"single-use-body").unwrap();

    assert!(state.take(&prepared.id, OperationKind::HacL1).is_err());
    assert!(state.begin_native(&prepared.id).is_err());
}
