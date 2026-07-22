export const MONEYNEX_INITIAL_INJECTION_DELAYS_MS = Object.freeze([250, 1_200, 3_000] as const);
export const MONEYNEX_REINJECT_INTERVAL_MS = 5_000;
/** Build the reviewed MoneyNex adapter injected only into an allowlisted dApp webview. */
export function createMoneyNexInjectScript(walletVersion: string): string {
  const version = JSON.stringify(walletVersion.replace(/^v/, "").slice(0, 32));
  return `(function(){
  if (window.MoneyNex) return;
  var invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (!invoke) return;
  var origin = location.origin;
  function call(cmd, args, cb) {
    invoke(cmd, args || {})
      .then(function(result){ if (cb) cb(result); })
      .catch(function(error){ if (cb) cb({ err: String(error), ret: 1 }); });
  }
  window.MoneyNex = {
    info: { name: 'Hacash Wallet', version: ${version}, icon: '' },
    wallet: function(params, cb) { call('wallet_dapp_wallet', { origin: origin }, cb); },
    connect: function(params, cb) { call('wallet_dapp_connect', { origin: origin }, cb); },
    disconnect: function(params, cb) { call('wallet_dapp_disconnect', { origin: origin }, cb); },
    transfer: function(params, cb) {
      call('wallet_dapp_transfer', {
        origin: origin,
        txobj: params && params.txobj,
        chain_id: params && params.chain_id
      }, cb);
    },
    signtx: function(params, cb) {
      call('wallet_dapp_sign_tx', {
        origin: origin,
        txbody: params && params.txbody,
        autosubmit: !!(params && params.autosubmit)
      }, cb);
    },
    chain: function(params, cb) {
      call('wallet_dapp_chain', {
        origin: origin,
        chain_id: params && (params.chain_id != null ? params.chain_id : params.id)
      }, cb);
    },
    switchchain: function(params, cb) {
      if (cb) cb({ chain_id: 0, switched: true, already_current: true });
    },
    raisefee: function(params, cb) {
      if (cb) cb({ err: 'Raise fee is not supported by this wallet', ret: 1 });
    }
  };
  if (typeof window.MoneyNexInit === 'function') {
    try { window.MoneyNexInit(window.MoneyNex.info, window.MoneyNex); } catch (error) {}
  }
})();`;
}
