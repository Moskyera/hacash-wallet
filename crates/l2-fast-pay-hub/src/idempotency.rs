//! Durable idempotency-index lookup for Fast Pay operations.

use crate::api::{FastPayRequest, FastPayResponse};
use crate::error::{HubError, HubResult};
use crate::storage::HubPersistedState;

pub(crate) fn response_from_state(
    state: &HubPersistedState,
    request: &FastPayRequest,
    commitment: &str,
) -> HubResult<Option<FastPayResponse>> {
    if let Some(existing) = state.idempotency.get(request.idempotency_key.trim()) {
        if existing.request_commitment != commitment
            || existing.operation_id != request.operation_id
        {
            return Err(HubError::Payment(
                "idempotency conflict: key was already bound to a different request".into(),
            ));
        }
        if let Some(response) = state.payments.get(&existing.operation_id) {
            return Ok(Some(response.clone()));
        }
        if let Some(pending) = state.pending.get(&existing.operation_id) {
            return Ok(Some(pending.response.clone()));
        }
        return Err(HubError::State(
            "idempotency index refers to missing operation state".into(),
        ));
    }
    if state
        .idempotency
        .values()
        .any(|existing| existing.operation_id == request.operation_id)
    {
        return Err(HubError::Payment(
            "idempotency conflict: operation_id was already used".into(),
        ));
    }
    Ok(None)
}
