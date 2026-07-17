//! Pending dApp transfer/sign requests. user must Accept or Decline in wallet UI.

use std::collections::HashMap;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct DappApprovalView {
    pub id: String,
    pub origin: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub detail: String,
}

#[derive(Debug)]
pub enum ApprovalDecision {
    Approved,
    Rejected(String),
}

struct PendingEntry {
    view: DappApprovalView,
    responder: oneshot::Sender<ApprovalDecision>,
}

pub struct DappApprovalQueue {
    pending: Mutex<HashMap<String, PendingEntry>>,
}

impl DappApprovalQueue {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get_pending(&self) -> Option<DappApprovalView> {
        let guard = self.pending.lock().await;
        guard.values().next().map(|e| e.view.clone())
    }

    pub async fn request(
        &self,
        origin: &str,
        kind: &str,
        title: &str,
        summary: &str,
        detail: &str,
        timeout: Duration,
    ) -> Result<ApprovalDecision, String> {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            if guard.len() >= 4 {
                return Err("too many pending dApp approval requests".into());
            }
            if guard
                .values()
                .any(|entry| entry.view.origin == origin && entry.view.kind == kind)
            {
                return Err("a matching dApp approval request is already pending".into());
            }
            guard.insert(
                id.clone(),
                PendingEntry {
                    view: DappApprovalView {
                        id: id.clone(),
                        origin: origin.to_string(),
                        kind: kind.to_string(),
                        title: title.to_string(),
                        summary: summary.to_string(),
                        detail: detail.to_string(),
                    },
                    responder: tx,
                },
            );
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => Ok(decision),
            Ok(Err(_)) => Err("approval channel closed".into()),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err("approval timed out (120s)".into())
            }
        }
    }

    pub async fn approve(&self, id: &str) -> Result<(), String> {
        let entry = self.pending.lock().await.remove(id);
        match entry {
            Some(e) => {
                let _ = e.responder.send(ApprovalDecision::Approved);
                Ok(())
            }
            None => Err("no pending dApp request".into()),
        }
    }

    pub async fn reject(&self, id: &str, reason: &str) -> Result<(), String> {
        let entry = self.pending.lock().await.remove(id);
        match entry {
            Some(e) => {
                let _ = e
                    .responder
                    .send(ApprovalDecision::Rejected(reason.to_string()));
                Ok(())
            }
            None => Err("no pending dApp request".into()),
        }
    }
}

impl Default for DappApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}
