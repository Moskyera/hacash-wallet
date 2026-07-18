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

    /// Reject and remove every pending request for one disconnected origin.
    pub async fn reject_origin(&self, origin: &str, reason: &str) -> usize {
        let mut guard = self.pending.lock().await;
        let ids = guard
            .iter()
            .filter_map(|(id, entry)| (entry.view.origin == origin).then_some(id.clone()))
            .collect::<Vec<_>>();
        let mut rejected = 0;
        for id in ids {
            if let Some(entry) = guard.remove(&id) {
                let _ = entry
                    .responder
                    .send(ApprovalDecision::Rejected(reason.to_string()));
                rejected += 1;
            }
        }
        rejected
    }
}

impl Default for DappApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn disconnect_rejects_only_requests_from_that_origin() {
        let queue = Arc::new(DappApprovalQueue::new());
        let first_queue = queue.clone();
        let first = tokio::spawn(async move {
            first_queue
                .request(
                    "https://hacd.it",
                    "sign",
                    "Sign",
                    "Summary",
                    "Detail",
                    Duration::from_secs(2),
                )
                .await
        });
        let second_queue = queue.clone();
        let second = tokio::spawn(async move {
            second_queue
                .request(
                    "http://localhost:8788",
                    "connect",
                    "Connect",
                    "Summary",
                    "Detail",
                    Duration::from_secs(2),
                )
                .await
        });

        for _ in 0..20 {
            if queue.pending.lock().await.len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            queue
                .reject_origin("https://hacd.it", "Wallet disconnected")
                .await,
            1
        );
        assert_eq!(
            queue
                .reject_origin("http://localhost:8788", "test cleanup")
                .await,
            1
        );

        assert!(
            matches!(first.await.unwrap(), Ok(ApprovalDecision::Rejected(reason)) if reason == "Wallet disconnected")
        );
        assert!(
            matches!(second.await.unwrap(), Ok(ApprovalDecision::Rejected(reason)) if reason == "test cleanup")
        );
    }
}
