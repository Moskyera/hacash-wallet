# Local mining and funding

## Executed bootstrap

The dedicated CPU poworker used the real fullnode miner API and mined blocks 1 through 12. No block file, state database or balance was edited directly.

The bootstrap reward address was the previously declared public Treasury address:

```text
1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW
```

At height 12 the node balance API reported `12 HAC` for that address. This proves normal coinbase state credit. It does not prove control of its private key inside Agent Wallet.

## Maturity rule

No separate consensus coinbase maturity rule was found in this fullnode revision. Coinbase execution credits the reward during normal block state execution. A pool-specific 16-block payout rule must not be described as consensus maturity.

## Agent funding gate

Agent Wallet funding is not complete. A real Agent Wallet must first be created by the user with its own passphrase and isolated vault. Only its public address should then be supplied to the node launcher as both:

```text
-RewardAddress <agent-address>
-PilotFundingAddress <agent-address>
```

Mining one or more additional blocks to that address is the safest local funding path. The capability endpoint will remain `funding_confirmed = false` and `transaction_ready = false` until the positive balance is visible through canonical state.

Never provide an Agent private key or passphrase to a script, document, chat, log or node configuration.
