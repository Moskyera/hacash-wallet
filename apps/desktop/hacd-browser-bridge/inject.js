(function () {
  if (window.MoneyNex) return;

  var BRIDGE = "http://127.0.0.1:9477";
  var ORIGIN = location.origin;

  function post(path, body, cb) {
    fetch(BRIDGE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    })
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        if (cb) cb(data);
      })
      .catch(function (e) {
        if (cb) cb({ err: String(e), ret: 1 });
      });
  }

  window.MoneyNex = {
    info: { name: "Hacash Wallet", version: "0.1.19", icon: "" },
    wallet: function (_p, cb) {
      post("/v1/wallet", { origin: ORIGIN }, cb);
    },
    connect: function (_p, cb) {
      post("/v1/connect", { origin: ORIGIN }, cb);
    },
    transfer: function (p, cb) {
      post("/v1/transfer", { origin: ORIGIN, txobj: p && p.txobj }, cb);
    },
    signtx: function (p, cb) {
      post("/v1/signtx", {
        origin: ORIGIN,
        txbody: p && p.txbody,
        autosubmit: !!(p && p.autosubmit),
      }, cb);
    },
    chain: function (p, cb) {
      post("/v1/chain", {
        origin: ORIGIN,
        chain_id: p && (p.chain_id != null ? p.chain_id : p.id),
      }, cb);
    },
    switchchain: function (_p, cb) {
      if (cb) cb({ chain_id: 0, switched: true, already_current: true });
    },
    raisefee: function (_p, cb) {
      if (cb) cb({ err: "Raise fee not supported yet", ret: 1 });
    },
  };

  console.log("hacash api runtime ok.");
  console.log("MoneyNex SDK ok.");

  if (typeof window.MoneyNexInit === "function") {
    try {
      window.MoneyNexInit(window.MoneyNex.info, window.MoneyNex);
    } catch (_e) {}
  }

  // Keep wallet unlocked while this tab is open and connected.
  setInterval(function () {
    if (document.hidden) return;
    fetch(BRIDGE + "/v1/heartbeat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ origin: ORIGIN }),
    }).catch(function () {});
  }, 30000);
})();