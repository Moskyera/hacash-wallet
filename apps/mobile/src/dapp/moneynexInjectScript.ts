/** Injected into the HACD Launchpad webview (hacd.it) to provide MoneyNex-compatible APIs. */
import { WALLET_VERSION } from "../walletVersion";

const APP_VERSION = WALLET_VERSION.replace(/^v/, "");

export const MONEYNEX_INJECT_SCRIPT = `(function(){
  if (window.MoneyNex) return;
  var invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (!invoke) {
    console.warn('Hacash Wallet: Tauri invoke unavailable in launchpad webview');
    return;
  }
  var origin = location.origin;
  function api(name, args, cb) {
    invoke('plugin:hacash-wallet-mobile|' + name, args || {})
      .then(function(r){ if (cb) cb(r); })
      .catch(function(e){ if (cb) cb({ err: String(e), ret: 1 }); });
  }
  function bind(name) {
    return function(params, cb) {
      var args = Object.assign({}, params || {}, { origin: origin });
      api(name, args, cb);
    };
  }
  window.MoneyNex = {
    info: { name: 'Hacash Wallet', version: '${APP_VERSION}', icon: '' },
    wallet: bind('wallet_dapp_wallet'),
    connect: bind('wallet_dapp_connect'),
    transfer: function(p, cb) {
      api('wallet_dapp_transfer', { origin: origin, txobj: p && p.txobj, chain_id: p && p.chain_id }, cb);
    },
    signtx: function(p, cb) {
      api('wallet_dapp_sign_tx', {
        origin: origin,
        txbody: p && p.txbody,
        autosubmit: !!(p && p.autosubmit)
      }, cb);
    },
    chain: function(p, cb) {
      api('wallet_dapp_chain', { origin: origin, chain_id: p && (p.chain_id != null ? p.chain_id : p.id) }, cb);
    },
    switchchain: function(p, cb) {
      if (cb) cb({ chain_id: 0, switched: true, already_current: true });
    },
    raisefee: function(p, cb) {
      if (cb) cb({ err: 'Raise fee not supported in mobile wallet yet', ret: 1 });
    }
  };
  console.log('hacash api runtime ok.');
  console.log('MoneyNex SDK ok.');
  if (typeof window.MoneyNexInit === 'function') {
    try { window.MoneyNexInit(window.MoneyNex.info, window.MoneyNex); } catch (e) {}
  }
})();`;

/** Tauri 2 invoke uses command names directly when not using plugin prefix. */
export const MONEYNEX_INJECT_SCRIPT_V2 = `(function(){
  if (window.MoneyNex) return;
  var invoke = window.__TAURI_INTERNALS__ && window.__TAURI_INTERNALS__.invoke;
  if (!invoke) {
    console.warn('Hacash Wallet: Tauri invoke unavailable in launchpad webview');
    return;
  }
  var origin = location.origin;
  function call(cmd, args, cb) {
    invoke(cmd, args || {})
      .then(function(r){ if (cb) cb(r); })
      .catch(function(e){ if (cb) cb({ err: String(e), ret: 1 }); });
  }
  window.MoneyNex = {
    info: { name: 'Hacash Wallet', version: '${APP_VERSION}', icon: '' },
    wallet: function(p, cb) { call('wallet_dapp_wallet', { origin: origin }, cb); },
    connect: function(p, cb) { call('wallet_dapp_connect', { origin: origin }, cb); },
    transfer: function(p, cb) {
      call('wallet_dapp_transfer', { origin: origin, txobj: p && p.txobj, chain_id: p && p.chain_id }, cb);
    },
    signtx: function(p, cb) {
      call('wallet_dapp_sign_tx', {
        origin: origin,
        txbody: p && p.txbody,
        autosubmit: !!(p && p.autosubmit)
      }, cb);
    },
    chain: function(p, cb) {
      call('wallet_dapp_chain', { origin: origin, chain_id: p && (p.chain_id != null ? p.chain_id : p.id) }, cb);
    },
    switchchain: function(p, cb) {
      if (cb) cb({ chain_id: 0, switched: true, already_current: true });
    },
    raisefee: function(p, cb) {
      if (cb) cb({ err: 'Raise fee not supported in mobile wallet yet', ret: 1 });
    }
  };
  console.log('hacash api runtime ok.');
  console.log('MoneyNex SDK ok.');
  if (typeof window.MoneyNexInit === 'function') {
    try { window.MoneyNexInit(window.MoneyNex.info, window.MoneyNex); } catch (e) {}
  }
})();`;
