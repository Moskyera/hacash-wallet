//! Milestone: air-gapped QR L1 send protocol.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir, with_protocol_setup};
use hacash_wallet_core::airgap::{
    encode_envelope_qr, parse_airgap_qr_parts, AirgapEnvelope, AirgapUnsigned, AIRGAP_VERSION,
};
use hacash_wallet_core::{WalletError, WalletService};

fn sample_unsigned(from: &str) -> AirgapUnsigned {
    AirgapUnsigned {
        v: AIRGAP_VERSION,
        from: from.to_owned(),
        to: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into(),
        amount_mei: 0.5,
        amount_wire: "0:500".into(),
        fee: "1:244".into(),
        body_hex: "0102030405".into(),
        summary: "airgap test".into(),
    }
}

#[test]
fn milestone_airgap_encode_decode_roundtrip() {
    tier0_gate("airgap_roundtrip", || {
        let unsigned = sample_unsigned("1FromAddr");
        let env = AirgapEnvelope::Unsigned(unsigned.clone());
        let parts = encode_envelope_qr(&env).unwrap();
        let parsed = parse_airgap_qr_parts(&parts).unwrap();
        assert!(!parsed.needs_more_parts);
        assert_eq!(parsed.envelope, Some(env));
    });
}

#[test]
fn milestone_airgap_signer_address_mismatch_rejected() {
    tier0_gate("airgap_addr_mismatch", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let mut svc = WalletService::new(None, None).unwrap();
                svc.create_wallet("airgap-passphrase12").unwrap();
                let addr = svc.status().address.unwrap();
                let unsigned = sample_unsigned("1WrongAddress");
                let err = svc.sign_airgap_unsigned(&unsigned).unwrap_err();
                match &err {
                    WalletError::Policy(msg) => {
                        assert!(msg.contains("does not match"));
                    }
                    other => panic!("expected address mismatch policy, got {other:?}"),
                }
                let unsigned_ok = sample_unsigned(&addr);
                let sign_result = svc.sign_airgap_unsigned(&unsigned_ok);
                if let Err(WalletError::Policy(msg)) = &sign_result {
                    assert!(
                        !msg.contains("does not match"),
                        "correct address must not trigger mismatch: {msg}"
                    );
                }
            });
        });
    });
}

#[test]
fn milestone_airgap_watch_only_cannot_sign() {
    tier0_gate("airgap_watch_only", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            let addr = svc
                .import_watch_only("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS")
                .unwrap();
            let unsigned = sample_unsigned(&addr);
            let err = svc.sign_airgap_unsigned(&unsigned).unwrap_err();
            assert!(matches!(err, WalletError::Policy(_)));
        });
    });
}

#[test]
fn milestone_airgap_rejects_invalid_qr() {
    tier0_gate("airgap_bad_qr", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet("airgap-passphrase12").unwrap();
            assert!(svc.parse_airgap_qr("not-valid").is_err());
            assert!(svc.parse_airgap_qr("").is_err());
        });
    });
}