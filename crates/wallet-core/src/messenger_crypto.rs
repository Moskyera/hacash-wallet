//! secp256k1 ECDH + HKDF message encryption and inbox auth signatures.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use secp256k1::{PublicKey, SecretKey, ecdh::SharedSecret};
use sha2::{Digest, Sha256};
use sys::Account;
use zeroize::Zeroizing;

use crate::error::{WalletError, WalletResult};

pub const MESSENGER_CRYPTO_V1: u8 = 1;
pub const MESSENGER_CRYPTO_V2: u8 = 2;
const MESSENGER_HKDF_INFO: &[u8] = b"hacash-messenger-v2";
const MESSENGER_V1_INFO: &[u8] = b"hacash-messenger-v1";
const STORE_INFO: &[u8] = b"hacash-messenger-store-v1";
const INBOX_AUTH_DOMAIN: &[u8] = b"hacash-messenger-inbox-v1";
const NONCE_LEN: usize = 12;

/// Plaintext is padded up to a multiple of this many bytes before encryption.
///
/// AES-GCM ciphertext is exactly as long as its plaintext plus a 16-byte tag, so
/// without this the relay operator reads the length of every body it cannot
/// open: 50 more characters typed produced exactly 50 more bytes on the wire,
/// measured rather than estimated. Padding does not hide that a message was
/// sent, or to whom, or when. It turns an exact character count into a bucket.
const PAD_BUCKET: usize = 256;
/// What `,"pad":""` costs in the serialized body, before the spaces inside it.
const PAD_FIELD_OVERHEAD: usize = 9;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PlainBody {
    pub body: String,
    pub sent_at: String,
    /// Spaces, discarded on read. Present only to round the plaintext length up
    /// to a `PAD_BUCKET` boundary; older records have no such field and still
    /// deserialize.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pad: String,
}

/// The envelope fields a body is cryptographically tied to.
///
/// The AAD used to be a fixed constant, so a ciphertext was bound to nothing
/// about the envelope carrying it. A correspondent (or anyone who saw the wire)
/// could take a sealed message, re-wrap the same ciphertext under a fresh id
/// with the direction reversed, sign that envelope with their own key, and the
/// victim's wallet filed their own words back at them as an incoming sealed
/// message - the pair key is the same in both directions, and nothing else was
/// checked. Binding id, sender, recipient and version into the AAD makes a
/// re-wrapped ciphertext fail to decrypt at all.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeBinding<'a> {
    pub id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub v: u8,
}

fn aad_for(info: &[u8], binding: &EnvelopeBinding<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        info.len() + 1 + binding.id.len() + binding.from.len() + binding.to.len() + 24,
    );
    out.extend_from_slice(info);
    out.push(binding.v);
    for part in [binding.id, binding.from, binding.to] {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

pub fn storage_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STORE_INFO);
    h.update(secret);
    h.finalize().into()
}

pub fn pubkey_hex(account: &Account) -> String {
    hex::encode(account.public_key().serialize_compressed())
}

pub fn parse_pubkey_hex(hex_str: &str) -> WalletResult<[u8; 33]> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| WalletError::Other(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| WalletError::Other("pubkey must be 33 bytes".into()))
}

pub fn verify_pubkey_address(pubkey: &[u8; 33], expected_addr: &str) -> bool {
    let derived = Account::get_address_by_public_key(*pubkey);
    Account::to_readable(&derived) == expected_addr
}

/// A peer key this wallet is willing to seal to, or nothing at all.
///
/// # Why this is the whole trust decision
///
/// A Hacash account address is `base58check(0 || RIPEMD160(SHA256(pubkey)))`
/// (`sys::Account::get_address_by_public_key`). So a public key that derives to
/// address X is *the* key of X. Finding a second, different key that also
/// derives to X is a second preimage on that hash, not a claim somebody can
/// make. That is what lets this wallet accept a key from a source it does not
/// trust at all - a relay, a directory, a stranger - and still seal to it: it
/// is not believing the source, it is checking the key.
///
/// Three things have to hold, and the third is not decoration. `PublicKey::
/// from_slice` is what rejects 33 bytes that are not a point on the curve; an
/// unchecked one would sail past the address check only via a hash collision,
/// but would then fail inside `encrypt_body_v2` and turn a lookup that should
/// have quietly fallen back to v1 into a send that fails outright.
///
/// `None` means "no key", and every caller has to treat that exactly as it
/// treats never having asked.
pub fn verified_peer_pubkey(pubkey_hex_str: &str, peer_addr: &str) -> Option<[u8; 33]> {
    let parsed = parse_pubkey_hex(pubkey_hex_str).ok()?;
    if !verify_pubkey_address(&parsed, peer_addr) {
        return None;
    }
    PublicKey::from_slice(&parsed).ok()?;
    Some(parsed)
}

fn pair_key_v1(addr_a: &str, addr_b: &str) -> [u8; 32] {
    let (lo, hi) = if addr_a < addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };
    let mut h = Sha256::new();
    h.update(MESSENGER_V1_INFO);
    h.update(lo.as_bytes());
    h.update(hi.as_bytes());
    h.finalize().into()
}

fn ecdh_shared(my_sk: &[u8; 32], peer_pk: &[u8; 33]) -> WalletResult<[u8; 32]> {
    let peer = PublicKey::from_slice(peer_pk).map_err(|e| WalletError::Other(e.to_string()))?;
    let secret =
        SecretKey::from_byte_array(*my_sk).map_err(|e| WalletError::Other(e.to_string()))?;
    Ok(SharedSecret::new(&peer, &secret).secret_bytes())
}

fn derive_message_key(shared: &[u8; 32], addr_a: &str, addr_b: &str) -> [u8; 32] {
    let (lo, hi) = if addr_a < addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };
    let mut salt = Vec::with_capacity(lo.len() + hi.len());
    salt.extend_from_slice(lo.as_bytes());
    salt.extend_from_slice(hi.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; 32];
    hk.expand(MESSENGER_HKDF_INFO, &mut key)
        .expect("hkdf expand");
    key
}

/// Serialize the body and round its length up to a `PAD_BUCKET` boundary.
fn padded_plaintext(body: &str, sent_at: &str) -> Zeroizing<Vec<u8>> {
    let mut plain = PlainBody {
        body: body.into(),
        sent_at: sent_at.into(),
        pad: String::new(),
    };
    let bare = Zeroizing::new(serde_json::to_vec(&plain).expect("serialize"));
    let with_field = bare.len() + PAD_FIELD_OVERHEAD;
    // At least one space, so the field is always emitted and the finished
    // length always lands exactly on a boundary.
    let target = (with_field + 1).div_ceil(PAD_BUCKET) * PAD_BUCKET;
    // A space is never escaped in JSON, so one space is one byte here.
    plain.pad = " ".repeat(target - with_field);
    Zeroizing::new(serde_json::to_vec(&plain).expect("serialize"))
}

fn encrypt_with_key(key: &[u8; 32], body: &str, sent_at: &str, aad: &[u8]) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("aes key");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let plaintext = padded_plaintext(body, sent_at);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .expect("encrypt");
    (hex::encode(nonce_bytes), hex::encode(ciphertext))
}

fn decrypt_with_key(
    key: &[u8; 32],
    nonce_hex: &str,
    ciphertext_hex: &str,
    aad: &[u8],
) -> WalletResult<PlainBody> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(WalletError::Other("invalid messenger nonce".into()));
    }
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| WalletError::Other("messenger decrypt failed".into()))?,
    );
    serde_json::from_slice(&plaintext).map_err(|e| WalletError::Other(e.to_string()))
}

pub fn encrypt_body_v2(
    my: &Account,
    my_addr: &str,
    peer_addr: &str,
    peer_pubkey: &[u8; 33],
    body: &str,
    sent_at: &str,
    binding: &EnvelopeBinding<'_>,
) -> WalletResult<(String, String)> {
    if !verify_pubkey_address(peer_pubkey, peer_addr) {
        return Err(WalletError::Other(
            "peer pubkey does not match address".into(),
        ));
    }
    let secret = Zeroizing::new(my.secret_key().serialize());
    let shared = Zeroizing::new(ecdh_shared(&secret, peer_pubkey)?);
    let key = Zeroizing::new(derive_message_key(&shared, my_addr, peer_addr));
    Ok(encrypt_with_key(
        &key,
        body,
        sent_at,
        &aad_for(MESSENGER_HKDF_INFO, binding),
    ))
}

pub fn encrypt_body_v1(
    my_addr: &str,
    peer_addr: &str,
    body: &str,
    sent_at: &str,
    binding: &EnvelopeBinding<'_>,
) -> (String, String) {
    let key = Zeroizing::new(pair_key_v1(my_addr, peer_addr));
    encrypt_with_key(&key, body, sent_at, &aad_for(MESSENGER_V1_INFO, binding))
}

/// Open a body, under the version named by the binding it is tied to.
///
/// The version lives on the binding rather than beside it because the two must
/// agree: it is inside the AAD, so a body encrypted as one version cannot be
/// opened as another, and passing them separately only created a way to say
/// something the crypto would then refuse.
pub fn decrypt_body(
    my: &Account,
    my_addr: &str,
    peer_addr: &str,
    peer_pubkey: Option<&[u8; 33]>,
    nonce_hex: &str,
    ciphertext_hex: &str,
    binding: &EnvelopeBinding<'_>,
) -> WalletResult<PlainBody> {
    match binding.v {
        MESSENGER_CRYPTO_V2 => {
            let peer_pk = peer_pubkey
                .ok_or_else(|| WalletError::Other("v2 envelope missing peer pubkey".into()))?;
            if !verify_pubkey_address(peer_pk, peer_addr) {
                return Err(WalletError::Other("peer pubkey mismatch".into()));
            }
            let secret = Zeroizing::new(my.secret_key().serialize());
            let shared = Zeroizing::new(ecdh_shared(&secret, peer_pk)?);
            let key = Zeroizing::new(derive_message_key(&shared, my_addr, peer_addr));
            decrypt_with_key(
                &key,
                nonce_hex,
                ciphertext_hex,
                &aad_for(MESSENGER_HKDF_INFO, binding),
            )
        }
        MESSENGER_CRYPTO_V1 => {
            let key = Zeroizing::new(pair_key_v1(my_addr, peer_addr));
            decrypt_with_key(
                &key,
                nonce_hex,
                ciphertext_hex,
                &aad_for(MESSENGER_V1_INFO, binding),
            )
        }
        other => Err(WalletError::Other(format!(
            "unsupported messenger crypto v{other}"
        ))),
    }
}

pub fn inbox_auth_digest(to: &str, nonce: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INBOX_AUTH_DOMAIN);
    h.update(to.as_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

pub fn sign_inbox_auth(account: &Account, to: &str, nonce: &str) -> String {
    let digest = inbox_auth_digest(to, nonce);
    hex::encode(account.do_sign(&digest))
}

pub fn verify_inbox_auth(
    to: &str,
    nonce: &str,
    claimant_pubkey: &[u8; 33],
    signature_hex: &str,
) -> WalletResult<()> {
    if !verify_pubkey_address(claimant_pubkey, to) {
        return Err(WalletError::Other(
            "claimant pubkey does not match address".into(),
        ));
    }
    let sig_bytes = hex::decode(signature_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| WalletError::Other("signature must be 64 bytes".into()))?;
    let digest = inbox_auth_digest(to, nonce);
    if Account::verify_signature(&digest, claimant_pubkey, &sig) {
        Ok(())
    } else {
        Err(WalletError::Other("invalid inbox auth signature".into()))
    }
}

pub fn encrypt_store(plaintext: &[u8], key: &[u8; 32]) -> WalletResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: STORE_INFO,
            },
        )
        .map_err(|e| WalletError::Other(e.to_string()))?;
    let out = serde_json::json!({
        "v": 1,
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(ciphertext),
    });
    serde_json::to_vec(&out).map_err(|e| WalletError::Other(e.to_string()))
}

pub fn decrypt_store(blob: &[u8], key: &[u8; 32]) -> WalletResult<Zeroizing<Vec<u8>>> {
    let wrapper: serde_json::Value =
        serde_json::from_slice(blob).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_hex = wrapper["nonce"]
        .as_str()
        .ok_or_else(|| WalletError::Other("missing store nonce".into()))?;
    let ciphertext_hex = wrapper["ciphertext"]
        .as_str()
        .ok_or_else(|| WalletError::Other("missing store ciphertext".into()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Other(e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| WalletError::Other(e.to_string()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: STORE_INFO,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| WalletError::Other("messenger store decrypt failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_roundtrip() {
        let a = Account::create_by("test-a").unwrap();
        let b = Account::create_by("test-b").unwrap();
        let a_addr = a.readable().to_string();
        let b_addr = b.readable().to_string();
        let b_pk = b.public_key().serialize_compressed();
        let binding = EnvelopeBinding {
            id: "env-1",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V2,
        };
        let (n, c) = encrypt_body_v2(
            &a,
            &a_addr,
            &b_addr,
            &b_pk,
            "hello",
            "2026-01-01T00:00:00Z",
            &binding,
        )
        .unwrap();
        let p = decrypt_body(
            &b,
            &b_addr,
            &a_addr,
            Some(&a.public_key().serialize_compressed()),
            &n,
            &c,
            &binding,
        )
        .unwrap();
        assert_eq!(p.body, "hello");
    }

    /// The victim's own words, handed back to them as an incoming message.
    ///
    /// The AAD was a fixed constant and the pair key is the same in both
    /// directions, so a correspondent could take one of Alice's sealed
    /// ciphertexts, put it in a fresh envelope with the direction reversed and
    /// their own signature on it, and Alice's wallet decrypted it and filed it
    /// as an inbound SEALED message from them. The bytes are hers; the meaning
    /// is theirs to choose.
    #[test]
    fn a_ciphertext_cannot_be_re_wrapped_into_a_different_envelope() {
        let alice = Account::create_by("reflect-alice").unwrap();
        let bob = Account::create_by("reflect-bob").unwrap();
        let a_addr = alice.readable().to_string();
        let b_addr = bob.readable().to_string();
        let bob_pk = bob.public_key().serialize_compressed();
        let alice_pk = alice.public_key().serialize_compressed();

        let outbound = EnvelopeBinding {
            id: "alice-original",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V2,
        };
        let (nonce, ciphertext) = encrypt_body_v2(
            &alice,
            &a_addr,
            &b_addr,
            &bob_pk,
            "the safe combination is 4471",
            "2026-01-01T00:00:00Z",
            &outbound,
        )
        .unwrap();

        // Bob really can read what was written to him.
        assert_eq!(
            decrypt_body(
                &bob,
                &b_addr,
                &a_addr,
                Some(&alice_pk),
                &nonce,
                &ciphertext,
                &outbound
            )
            .unwrap()
            .body,
            "the safe combination is 4471"
        );

        // The same bytes, re-wrapped as a message FROM Bob TO Alice under a
        // fresh id, which is the whole attack. Alice's wallet must not open it.
        let reflected = EnvelopeBinding {
            id: "bob-reflected",
            from: &b_addr,
            to: &a_addr,
            v: MESSENGER_CRYPTO_V2,
        };
        let opened = decrypt_body(
            &alice,
            &a_addr,
            &b_addr,
            Some(&bob_pk),
            &nonce,
            &ciphertext,
            &reflected,
        );
        assert!(
            opened.is_err(),
            "Alice's own ciphertext came back at her as an incoming message: {:?}",
            opened.map(|p| p.body)
        );

        // The id alone is enough to break it, so a replay under a new id in the
        // original direction fails too.
        let same_direction_new_id = EnvelopeBinding {
            id: "some-other-id",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V2,
        };
        assert!(
            decrypt_body(
                &bob,
                &b_addr,
                &a_addr,
                Some(&alice_pk),
                &nonce,
                &ciphertext,
                &same_direction_new_id
            )
            .is_err(),
            "the same ciphertext opened under a different envelope id"
        );
    }

    /// v1 is readable by the relay operator by design. It must still not be
    /// re-wrappable, or an operator could move an opening message into a
    /// conversation it was never part of and it would still read correctly.
    #[test]
    fn a_v1_ciphertext_is_bound_to_its_envelope_too() {
        let alice = Account::create_by("v1-bind-alice").unwrap();
        let bob = Account::create_by("v1-bind-bob").unwrap();
        let a_addr = alice.readable().to_string();
        let b_addr = bob.readable().to_string();
        let real = EnvelopeBinding {
            id: "v1-original",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V1,
        };
        let (nonce, ciphertext) = encrypt_body_v1(
            &a_addr,
            &b_addr,
            "you there?",
            "2026-01-01T00:00:00Z",
            &real,
        );
        assert_eq!(
            decrypt_body(&bob, &b_addr, &a_addr, None, &nonce, &ciphertext, &real)
                .unwrap()
                .body,
            "you there?"
        );
        let moved = EnvelopeBinding {
            id: "v1-original",
            from: &b_addr,
            to: &a_addr,
            v: MESSENGER_CRYPTO_V1,
        };
        assert!(
            decrypt_body(&alice, &a_addr, &b_addr, None, &nonce, &ciphertext, &moved).is_err(),
            "a v1 body was moved into the other direction and still read"
        );
    }

    /// What the relay operator can measure.
    ///
    /// Ciphertext length used to be plaintext length: fifty more characters
    /// typed were fifty more bytes on the wire, so the operator read the size of
    /// every body it could not open. Bodies now land on a bucket instead.
    #[test]
    fn body_length_does_not_leak_character_for_character() {
        let a = Account::create_by("pad-a").unwrap();
        let b = Account::create_by("pad-b").unwrap();
        let a_addr = a.readable().to_string();
        let b_addr = b.readable().to_string();
        let binding = EnvelopeBinding {
            id: "pad-1",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V1,
        };
        let mut sizes = Vec::new();
        for len in [1usize, 10, 11, 50, 60, 61] {
            let body = "x".repeat(len);
            let (_, ciphertext) =
                encrypt_body_v1(&a_addr, &b_addr, &body, "2026-01-01T00:00:00Z", &binding);
            // Hex, so two characters per byte.
            let bytes = ciphertext.len() / 2;
            assert_eq!(
                (bytes - 16) % PAD_BUCKET,
                0,
                "a {len}-character body produced {bytes} ciphertext bytes, which is not a padded bucket"
            );
            sizes.push(bytes);
        }
        assert_eq!(
            sizes[0], sizes[5],
            "a 1-character body and a 61-character body must be the same size on the wire, \
             they were {} and {}",
            sizes[0], sizes[5]
        );
        // And the padding really is discarded on read.
        let (nonce, ciphertext) =
            encrypt_body_v1(&a_addr, &b_addr, "short", "2026-01-01T00:00:00Z", &binding);
        let plain =
            decrypt_body(&b, &b_addr, &a_addr, None, &nonce, &ciphertext, &binding).unwrap();
        assert_eq!(plain.body, "short");
    }

    /// The one check that lets this wallet take a key from a source it does
    /// not trust.
    ///
    /// An address is `base58check(0 || RIPEMD160(SHA256(pubkey)))`, so a key
    /// that derives to an address is that address's key and there is no second
    /// one short of a preimage. Everything a hostile relay can actually send
    /// back is below, and every one of them has to come out as `None`, because
    /// `None` is what puts the sender back on the v1 path it was already on.
    #[test]
    fn a_key_is_taken_only_from_the_address_it_derives_to() {
        let bob = Account::create_by("verified-bob").unwrap();
        let mallory = Account::create_by("verified-mallory").unwrap();
        let bob_addr = bob.readable().to_string();
        let bob_pk = hex::encode(bob.public_key().serialize_compressed());

        assert_eq!(
            verified_peer_pubkey(&bob_pk, &bob_addr),
            Some(bob.public_key().serialize_compressed()),
            "Bob's own key, checked against Bob's own address, has to be accepted"
        );

        // A real, valid, on-curve public key belonging to somebody else. This
        // is the answer a hostile relay gives when it wants to read the first
        // message: it is a key it holds the secret for.
        let mallory_pk = hex::encode(mallory.public_key().serialize_compressed());
        assert_eq!(
            verified_peer_pubkey(&mallory_pk, &bob_addr),
            None,
            "a key that derives to somebody else's address was accepted for Bob"
        );

        // 33 bytes that are not a point on the curve at all. This cannot reach
        // the address check without a collision, but if it ever did it would
        // fail inside `encrypt_body_v2` and turn a quiet fallback into a failed
        // send, so it is refused here instead.
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 0x01;
        assert_eq!(
            verified_peer_pubkey(&hex::encode(off_curve), &bob_addr),
            None
        );

        // And everything that is not a key at all.
        for junk in ["", "  ", "zz", &bob_pk[..64], &format!("{bob_pk}00")] {
            assert_eq!(
                verified_peer_pubkey(junk, &bob_addr),
                None,
                "{junk:?} was accepted as a peer key"
            );
        }

        // Trailing whitespace is not a different key: `parse_pubkey_hex` trims,
        // and the honest case must not be lost to a stray newline off a wire.
        assert_eq!(
            verified_peer_pubkey(&format!("  {bob_pk}\n"), &bob_addr),
            Some(bob.public_key().serialize_compressed())
        );
    }

    /// A key that passes the check is a key only its owner can open, which is
    /// the property the whole directory idea rests on. Sealing to a key served
    /// by a third party is safe precisely because the third party cannot read
    /// what was sealed to it.
    #[test]
    fn sealing_to_a_verified_key_is_readable_only_by_that_address() {
        let alice = Account::create_by("seal-alice").unwrap();
        let bob = Account::create_by("seal-bob").unwrap();
        let operator = Account::create_by("seal-operator").unwrap();
        let a_addr = alice.readable().to_string();
        let b_addr = bob.readable().to_string();

        // Alice never met Bob. Some untrusted party handed her this hex.
        let handed_over = hex::encode(bob.public_key().serialize_compressed());
        let bob_pk = verified_peer_pubkey(&handed_over, &b_addr)
            .expect("it derives to Bob's address, so it is Bob's key");

        let binding = EnvelopeBinding {
            id: "first-contact",
            from: &a_addr,
            to: &b_addr,
            v: MESSENGER_CRYPTO_V2,
        };
        let (nonce, ciphertext) = encrypt_body_v2(
            &alice,
            &a_addr,
            &b_addr,
            &bob_pk,
            "the opening message",
            "2026-01-01T00:00:00Z",
            &binding,
        )
        .unwrap();

        // Bob reads it.
        assert_eq!(
            decrypt_body(
                &bob,
                &b_addr,
                &a_addr,
                Some(&alice.public_key().serialize_compressed()),
                &nonce,
                &ciphertext,
                &binding
            )
            .unwrap()
            .body,
            "the opening message"
        );

        // The party that handed the key over cannot, with its own key or with
        // the v1 key it derives from the two addresses on the envelope.
        assert!(
            decrypt_body(
                &operator,
                &b_addr,
                &a_addr,
                Some(&alice.public_key().serialize_compressed()),
                &nonce,
                &ciphertext,
                &binding
            )
            .is_err()
        );
        assert!(
            decrypt_body(
                &operator,
                &a_addr,
                &b_addr,
                None,
                &nonce,
                &ciphertext,
                &EnvelopeBinding {
                    v: MESSENGER_CRYPTO_V1,
                    ..binding
                }
            )
            .is_err(),
            "the address-derived key opened a message sealed to a verified peer key"
        );
    }

    #[test]
    fn inbox_auth_roundtrip() {
        let a = Account::create_by("inbox-test").unwrap();
        let addr = a.readable().to_string();
        let nonce = "abc123";
        let sig = sign_inbox_auth(&a, &addr, nonce);
        verify_inbox_auth(&addr, nonce, &a.public_key().serialize_compressed(), &sig).unwrap();
    }

    #[test]
    fn encrypted_store_plaintext_is_owned_by_a_wiping_buffer() {
        let key = Zeroizing::new([7u8; 32]);
        let plaintext = b"sensitive messenger state";
        let blob = encrypt_store(plaintext, &key).unwrap();
        let decrypted: Zeroizing<Vec<u8>> = decrypt_store(&blob, &key).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
        assert!(
            !blob
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }
}
