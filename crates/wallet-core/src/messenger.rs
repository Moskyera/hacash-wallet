//! Encrypted wallet-to-wallet chat via DUST Whisper relay + encrypted local history.

use std::fs;

use chrono::Utc;
use dust_whisper::protocol::{MessengerAckRequest, MessengerInboxRequest, MessengerEnvelope};
use serde::{Deserialize, Serialize};
use sys::Account;
use uuid::Uuid;

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::messenger_crypto::{
    decrypt_body, decrypt_store, encrypt_body_v1, encrypt_body_v2, encrypt_store,
    parse_pubkey_hex, pubkey_hex, sign_inbox_auth, storage_key_from_secret,
    MESSENGER_CRYPTO_V1, MESSENGER_CRYPTO_V2,
};
use crate::paths::{messenger_path, secure_write};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: String,
    pub peer: String,
    pub direction: MessageDirection,
    pub body: String,
    pub timestamp_utc: String,
    pub delivered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatThread {
    pub peer: String,
    pub last_message: String,
    pub last_timestamp_utc: String,
    pub unread: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MessengerStore {
    messages: Vec<ChatMessage>,
}

struct MessengerCtx<'a> {
    account: &'a Account,
    my_address: &'a str,
    storage_key: [u8; 32],
}

impl MessengerStore {
    fn load(ctx: &MessengerCtx<'_>) -> WalletResult<Self> {
        let path = messenger_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read(&path).map_err(|e| WalletError::Other(e.to_string()))?;
        if let Ok(text) = std::str::from_utf8(&raw) {
            if text.trim_start().starts_with('{') && text.contains("\"messages\"") {
                return serde_json::from_str(text).map_err(|e| WalletError::Other(e.to_string()));
            }
        }
        match decrypt_store(&raw, &ctx.storage_key) {
            Ok(plain) => {
                serde_json::from_slice(&plain).map_err(|e| WalletError::Other(e.to_string()))
            }
            Err(_) => {
                let backup = path.with_extension(format!(
                    "bak.{}",
                    Utc::now().format("%Y%m%d%H%M%S")
                ));
                let _ = fs::rename(&path, &backup);
                Ok(Self::default())
            }
        }
    }

    fn save(&self, ctx: &MessengerCtx<'_>) -> WalletResult<()> {
        let json = serde_json::to_vec(self).map_err(|e| WalletError::Other(e.to_string()))?;
        let enc = encrypt_store(&json, &ctx.storage_key)?;
        secure_write(&messenger_path(), &enc).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn threads(&self) -> Vec<ChatThread> {
        let mut map: std::collections::HashMap<String, ChatThread> = std::collections::HashMap::new();
        for m in &self.messages {
            let entry = map.entry(m.peer.clone()).or_insert_with(|| ChatThread {
                peer: m.peer.clone(),
                last_message: String::new(),
                last_timestamp_utc: String::new(),
                unread: 0,
            });
            if m.timestamp_utc >= entry.last_timestamp_utc {
                entry.last_message = m.body.clone();
                entry.last_timestamp_utc = m.timestamp_utc.clone();
            }
            if m.direction == MessageDirection::In && !m.delivered {
                entry.unread += 1;
            }
        }
        let mut out: Vec<_> = map.into_values().collect();
        out.sort_by(|a, b| b.last_timestamp_utc.cmp(&a.last_timestamp_utc));
        out
    }

    pub fn messages_for(&self, peer: &str) -> Vec<ChatMessage> {
        let mut out: Vec<_> = self
            .messages
            .iter()
            .filter(|m| m.peer == peer)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.timestamp_utc.cmp(&b.timestamp_utc));
        out
    }

    fn push(&mut self, msg: ChatMessage) {
        self.messages.push(msg);
    }

    fn mark_read(&mut self, peer: &str) {
        for m in &mut self.messages {
            if m.peer == peer && m.direction == MessageDirection::In {
                m.delivered = true;
            }
        }
    }

    fn has_id(&self, id: &str) -> bool {
        self.messages.iter().any(|m| m.id == id)
    }
}

fn messenger_ctx<'a>(account: &'a WalletAccount, my_address: &'a str) -> MessengerCtx<'a> {
    let sk = account.inner().secret_key().serialize();
    MessengerCtx {
        account: account.inner(),
        my_address,
        storage_key: storage_key_from_secret(&sk),
    }
}

fn encrypt_for_send(
    ctx: &MessengerCtx<'_>,
    peer: &str,
    body: &str,
    sent_at: &str,
    peer_pubkey: Option<&[u8; 33]>,
) -> WalletResult<(u8, String, String, Option<String>)> {
    if let Some(peer_pk) = peer_pubkey {
        let (nonce, ciphertext) = encrypt_body_v2(ctx.account, ctx.my_address, peer, peer_pk, body, sent_at)?;
        Ok((
            MESSENGER_CRYPTO_V2,
            nonce,
            ciphertext,
            Some(pubkey_hex(ctx.account)),
        ))
    } else {
        let (nonce, ciphertext) = encrypt_body_v1(ctx.my_address, peer, body, sent_at);
        Ok((MESSENGER_CRYPTO_V1, nonce, ciphertext, Some(pubkey_hex(ctx.account))))
    }
}

pub async fn messenger_send(
    http: &reqwest::Client,
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
    body: &str,
    relay_urls: &[String],
    peer_pubkey_hex: Option<&str>,
) -> WalletResult<ChatMessage> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Other("empty message".into()));
    }
    let ctx = messenger_ctx(account, my_address);
    let sent_at = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    let peer_pk = peer_pubkey_hex.map(parse_pubkey_hex).transpose()?;
    let (crypto_v, nonce, ciphertext, from_pubkey) =
        encrypt_for_send(&ctx, peer, trimmed, &sent_at, peer_pk.as_ref())?;

    let envelope = MessengerEnvelope {
        v: crypto_v,
        id: id.clone(),
        to: peer.to_string(),
        from: my_address.to_string(),
        from_pubkey,
        nonce,
        ciphertext,
        sent_at: sent_at.clone(),
    };

    let mut relay_ok = false;
    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        if dust_whisper::messenger_client::send_envelope(http, u, envelope.clone())
            .await
            .is_ok()
        {
            relay_ok = true;
            break;
        }
    }

    let msg = ChatMessage {
        id,
        peer: peer.to_string(),
        direction: MessageDirection::Out,
        body: trimmed.to_string(),
        timestamp_utc: sent_at,
        delivered: relay_ok,
    };

    let mut store = MessengerStore::load(&ctx)?;
    store.push(msg.clone());
    store.save(&ctx)?;
    Ok(msg)
}

pub async fn messenger_poll_inbox(
    http: &reqwest::Client,
    account: &WalletAccount,
    my_address: &str,
    relay_urls: &[String],
) -> WalletResult<u32> {
    let ctx = messenger_ctx(account, my_address);
    let mut store = MessengerStore::load(&ctx)?;
    let mut added = 0u32;
    let claimant_pubkey = pubkey_hex(ctx.account);
    let mut ack_ids: Vec<String> = Vec::new();

    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        let challenge = match dust_whisper::messenger_client::fetch_challenge(http, u, my_address).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let signature = sign_inbox_auth(ctx.account, my_address, &challenge.nonce);
        let request = MessengerInboxRequest {
            to: my_address.to_string(),
            claimant_pubkey: claimant_pubkey.clone(),
            nonce: challenge.nonce.clone(),
            signature: signature.clone(),
        };
        let envelopes = match dust_whisper::messenger_client::fetch_inbox(http, u, &request).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        for env in envelopes {
            if store.has_id(&env.id) {
                ack_ids.push(env.id.clone());
                continue;
            }
            let peer_pk = env
                .from_pubkey
                .as_deref()
                .map(parse_pubkey_hex)
                .transpose()?;
            let plain = match decrypt_body(
                ctx.account,
                my_address,
                &env.from,
                peer_pk.as_ref(),
                env.v,
                &env.nonce,
                &env.ciphertext,
            ) {
                Ok(p) => p,
                Err(_) => continue,
            };
            store.push(ChatMessage {
                id: env.id.clone(),
                peer: env.from,
                direction: MessageDirection::In,
                body: plain.body,
                timestamp_utc: plain.sent_at,
                delivered: false,
            });
            ack_ids.push(env.id);
            added += 1;
        }

        if !ack_ids.is_empty() {
            if let Ok(challenge) =
                dust_whisper::messenger_client::fetch_challenge(http, u, my_address).await
            {
                let sig = sign_inbox_auth(ctx.account, my_address, &challenge.nonce);
                let _ = dust_whisper::messenger_client::ack_messages(
                    http,
                    u,
                    &MessengerAckRequest {
                        to: my_address.to_string(),
                        claimant_pubkey: claimant_pubkey.clone(),
                        nonce: challenge.nonce,
                        signature: sig,
                        ids: ack_ids.clone(),
                    },
                )
                .await;
            }
        }
    }

    if added > 0 {
        store.save(&ctx)?;
    }
    Ok(added)
}

pub fn messenger_threads(account: &WalletAccount, my_address: &str) -> WalletResult<Vec<ChatThread>> {
    let ctx = messenger_ctx(account, my_address);
    Ok(MessengerStore::load(&ctx)?.threads())
}

pub fn messenger_messages(
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
) -> WalletResult<Vec<ChatMessage>> {
    let ctx = messenger_ctx(account, my_address);
    Ok(MessengerStore::load(&ctx)?.messages_for(peer))
}

pub fn messenger_mark_read(
    account: &WalletAccount,
    my_address: &str,
    peer: &str,
) -> WalletResult<()> {
    let ctx = messenger_ctx(account, my_address);
    let mut store = MessengerStore::load(&ctx)?;
    store.mark_read(peer);
    store.save(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrip_encrypted() {
        let acc = WalletAccount::from_secret_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let addr = acc.address();
        let ctx = messenger_ctx(&acc, &addr);
        let mut store = MessengerStore::default();
        store.push(ChatMessage {
            id: "1".into(),
            peer: "peer".into(),
            direction: MessageDirection::Out,
            body: "hi".into(),
            timestamp_utc: "t".into(),
            delivered: true,
        });
        store.save(&ctx).unwrap();
        let loaded = MessengerStore::load(&ctx).unwrap();
        assert_eq!(loaded.messages.len(), 1);
    }
}