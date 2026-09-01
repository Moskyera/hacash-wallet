# HPAY Fast Pay Hub — Windows x64

This is the Hub the HPAY wallet talks to. Run it beside a synchronized
HPAY-compatible Hacash full node.

## The two ports, because this is the question everyone asks first

| Program | Listens on | Calls |
|---------|-----------|-------|
| Hacash full node | `127.0.0.1:8080` | — |
| Fast Pay Hub | `127.0.0.1:8790` | the node on `8080` |

They are different ports, so **both run on the same machine at the same time**.
The `8080` in the Hub's own configuration is the node it reads from, not a port
it takes.

## Before you start

- A synchronized HPAY-compatible Hacash full node on `127.0.0.1:8080`.
  A fresh node takes minutes to hours to download the chain. Wait for it.
- A **dedicated, low-balance** Hacash address for the Hub. Never the address
  holding your savings: the Hub signs channel bills automatically.
- Keep `fast-pay-hub.exe` and `START-HUB.bat` in the same folder.

## Run it

The Hub reads its address and its keys from the environment. Set them in the
window you are about to start it from, so they are not written to a file:

```bat
set HACASH_HUB_ADDRESS=your-dedicated-hub-address
set HACASH_HUB_SECRET_HEX=...
set HACASH_HUB_STATE_KEY_HEX=...
set HACASH_HUB_JOURNAL_KEY_HEX=...
START-HUB.bat
```

`START-HUB.bat` refuses to start and names any variable that is missing. It
never prints a value and never stores one. Do not put these keys inside the
`.bat` file — that puts them in a file, in your command history, and in every
backup of both.

To check it is up, from the same machine:

```bat
curl http://127.0.0.1:8790/v1/health
```

## Do not open port 8790 to the internet

Publish the Hub only through an HTTPS reverse proxy that terminates TLS and
forwards to `127.0.0.1:8790`. The port itself must stay private, as must the
node's `8080`.

If you put a proxy in front of it, set `HACASH_HUB_TRUSTED_PROXY_IP` to that
proxy's exact socket IP. Without it the Hub will not trust a forwarded
client-address header, which is the safe default.

## What this pilot is, honestly

Fast Pay here is **Hub-coordinated**, not unilaterally final on L1. A Hub
confirmation is coordinated L2 state. A channel closes only if the Hub
co-signs — this rail has no unilateral exit — so a Hub that stops answering
leaves what is in a channel locked until it returns.

It uses official Hacash ChannelPay bills and changes nothing about Hacash
consensus. Do not describe it as trustless.

## Verify what you downloaded

Check the `SHA256SUMS-*.txt` file published beside the archive, and the GitHub
build provenance attestation, before running anything.
