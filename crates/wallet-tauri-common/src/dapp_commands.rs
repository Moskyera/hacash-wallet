//! dApp / MoneyNex bridge commands and webview helpers.

use std::time::Duration;

use tauri::{AppHandle, Manager, State, Webview};

use crate::dapp_approval::{ApprovalDecision, DappApprovalView};
use crate::state::{AppState, WALLET_BUSY_RETRY};

#[tauri::command]
pub fn wallet_bump_activity(webview: Webview, state: State<'_, AppState>) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    let mut svc = state.inner.blocking_lock();
    svc.bump_unlock_activity();
    Ok(())
}

#[tauri::command]
pub async fn wallet_dapp_connect(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, true)?;
    {
        let mut svc = state.inner.lock().await;
        if svc.dapp_session_is_authorized(&origin) {
            return svc.dapp_wallet(&origin).map_err(|e| e.to_string());
        }
    }
    require_approval(
        &state,
        &origin,
        "connect",
        "Connect dApp",
        "Share the active wallet address with this dApp.",
        &format!("Origin: {origin}"),
    )
    .await?;
    let mut svc = state.inner.lock().await;
    svc.dapp_connect(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_disconnect(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, true)?;
    let result = {
        let mut svc = state.inner.lock().await;
        svc.dapp_disconnect(&origin).map_err(|e| e.to_string())?
    };
    state
        .dapp_approval
        .reject_origin(&origin, "Wallet disconnected")
        .await;
    Ok(result)
}

#[tauri::command]
pub fn wallet_dapp_wallet(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, true)?;
    let mut svc = state
        .inner
        .try_lock()
        .map_err(|_| WALLET_BUSY_RETRY.to_string())?;
    svc.dapp_wallet(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_dapp_heartbeat(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, true)?;
    let mut svc = state
        .inner
        .try_lock()
        .map_err(|_| WALLET_BUSY_RETRY.to_string())?;
    svc.dapp_heartbeat(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_transfer(
    origin: String,
    txobj: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, false)?;
    let detail =
        hacash_wallet_core::dapp::describe_txobj_for_approval(&txobj).map_err(|e| e.to_string())?;
    require_approval(
        &state,
        &origin,
        "transfer",
        "Approve dApp transaction",
        "Review every action before the wallet signs and broadcasts it.",
        &detail,
    )
    .await?;
    let mut svc = state.inner.lock().await;
    svc.dapp_transfer(&origin, &txobj)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_sign_tx(
    origin: String,
    txbody: String,
    autosubmit: Option<bool>,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, false)?;
    let canonical =
        hacash_wallet_core::tx_binding::decode_transaction(&txbody).map_err(|e| e.to_string())?;
    hacash_wallet_core::dapp::validate_raw_sign_transaction(&canonical)
        .map_err(|e| e.to_string())?;
    let autosubmit = autosubmit.unwrap_or(false);
    let title = if autosubmit {
        "Approve signing and broadcast"
    } else {
        "Approve transaction signature"
    };
    require_approval(
        &state,
        &origin,
        "sign",
        title,
        "The wallet will sign exactly the decoded transaction shown below.",
        &canonical.approval_summary(),
    )
    .await?;
    let mut svc = state.inner.lock().await;
    svc.dapp_sign_tx(&origin, &txbody, autosubmit)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wallet_dapp_chain(
    origin: String,
    chain_id: Option<u64>,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    trusted_caller_origin(&origin, &webview, false)?;
    let node_url = {
        let svc = state.inner.lock().await;
        svc.get_settings().node_url
    };
    let node =
        hacash_wallet_core::node::NodeClient::new(node_url).map_err(|error| error.to_string())?;
    let capabilities = node
        .capabilities()
        .await
        .map_err(|error| error.to_string())?;
    let (current_chain_id, source) = match capabilities.source {
        hacash_wallet_core::CapabilitySource::Reported => (Some(capabilities.chain.id), "reported"),
        hacash_wallet_core::CapabilitySource::LegacyType2 => (None, "legacy_type2"),
    };
    Ok(hacash_wallet_core::dapp::chain_status_for_node(
        chain_id,
        current_chain_id,
        source,
    ))
}

#[tauri::command]
pub async fn wallet_dapp_pending(
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<Option<DappApprovalView>, String> {
    require_wallet_shell(&webview)?;
    Ok(state.dapp_approval.get_pending().await)
}

#[tauri::command]
pub async fn wallet_dapp_approve(
    id: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    state.dapp_approval.approve(&id).await
}

#[tauri::command]
pub async fn wallet_dapp_reject(
    id: String,
    reason: Option<String>,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<(), String> {
    require_wallet_shell(&webview)?;
    state
        .dapp_approval
        .reject(&id, reason.as_deref().unwrap_or("rejected by user"))
        .await
}

#[tauri::command]
pub fn wallet_webview_eval(
    app: AppHandle,
    label: String,
    expected_origin: String,
    script: String,
    caller: Webview,
) -> Result<(), String> {
    require_wallet_shell(&caller)?;
    if label != "launchpad" {
        return Err("script injection is restricted to the launchpad webview".into());
    }
    if script.len() > 128 * 1024 {
        return Err("launchpad injection script is too large".into());
    }
    let target = app
        .get_webview(&label)
        .ok_or_else(|| format!("webview '{label}' not found"))?;
    let target_url = target.url().map_err(|e| e.to_string())?;
    let target_origin = target_url.origin().ascii_serialization();
    require_matching_trusted_origin(&expected_origin, &target_origin)?;
    target.eval(&script).map_err(|e| e.to_string())
}

fn require_matching_trusted_origin(
    expected_origin: &str,
    target_origin: &str,
) -> Result<(), String> {
    let expected = hacash_wallet_core::dapp::normalized_trusted_origin(expected_origin)
        .ok_or_else(|| "expected script injection origin is not trusted".to_string())?;
    let target = hacash_wallet_core::dapp::normalized_trusted_origin(target_origin)
        .ok_or_else(|| "script injection target is not a trusted dApp origin".to_string())?;
    if target != expected {
        return Err("script injection target origin changed".into());
    }
    Ok(())
}
async fn require_approval(
    state: &State<'_, AppState>,
    origin: &str,
    kind: &str,
    title: &str,
    summary: &str,
    detail: &str,
) -> Result<(), String> {
    match state
        .dapp_approval
        .request(
            origin,
            kind,
            title,
            summary,
            detail,
            Duration::from_secs(120),
        )
        .await?
    {
        ApprovalDecision::Approved => Ok(()),
        ApprovalDecision::Rejected(reason) => Err(format!("dApp request rejected: {reason}")),
    }
}

fn trusted_caller_origin(
    claimed_origin: &str,
    webview: &Webview,
    allow_wallet_shell: bool,
) -> Result<String, String> {
    let claimed = hacash_wallet_core::dapp::normalized_trusted_origin(claimed_origin)
        .ok_or_else(|| format!("untrusted dApp origin: {claimed_origin}"))?;
    if allow_wallet_shell && webview.label() == "main" {
        require_wallet_shell(webview)?;
        return Ok(claimed);
    }

    let page = webview.url().map_err(|e| e.to_string())?;
    let actual =
        hacash_wallet_core::dapp::normalized_trusted_origin(&page.origin().ascii_serialization())
            .ok_or_else(|| "dApp command came from an untrusted webview URL".to_string())?;
    if actual != claimed {
        return Err(format!(
            "dApp origin mismatch: page is {actual}, request claimed {claimed}"
        ));
    }
    Ok(claimed)
}

fn require_wallet_shell(webview: &Webview) -> Result<(), String> {
    if webview.label() != "main" {
        return Err("command is restricted to the wallet UI".into());
    }
    let url = webview.url().map_err(|e| e.to_string())?;
    let local_shell = url.scheme() == "tauri"
        || url.host_str() == Some("tauri.localhost")
        || (cfg!(debug_assertions)
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
            && url.port() == Some(1421));
    if !local_shell {
        return Err("wallet UI is not on a trusted local origin".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_matching_trusted_origin;

    #[test]
    fn script_injection_requires_the_selected_exact_origin() {
        assert!(require_matching_trusted_origin("https://hacd.it", "https://hacd.it:443").is_ok());
        assert!(require_matching_trusted_origin("https://hacd.it", "https://www.hacd.it").is_err());
        assert!(require_matching_trusted_origin("https://www.hacd.it", "https://hacd.it").is_err());
        assert!(
            require_matching_trusted_origin("https://hacd.it", "https://hacd.it.evil.example")
                .is_err()
        );
    }
}
