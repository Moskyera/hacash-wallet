//! dApp / MoneyNex bridge commands and webview helpers.

use std::time::Duration;

use tauri::{AppHandle, Manager, State, Webview};

use crate::dapp_approval::{ApprovalDecision, DappApprovalView};
use crate::state::AppState;

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
pub fn wallet_dapp_wallet(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, false)?;
    let mut svc = state.inner.blocking_lock();
    svc.dapp_wallet(&origin).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn wallet_dapp_heartbeat(
    origin: String,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, false)?;
    let mut svc = state.inner.blocking_lock();
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
pub fn wallet_dapp_chain(
    origin: String,
    chain_id: Option<u64>,
    webview: Webview,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let origin = trusted_caller_origin(&origin, &webview, false)?;
    let svc = state.inner.blocking_lock();
    svc.dapp_chain_status(&origin, chain_id)
        .map_err(|e| e.to_string())
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
    target.eval(&script).map_err(|e| e.to_string())
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
