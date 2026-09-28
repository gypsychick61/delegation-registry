# Agent Delegation Registry

An MCP server for the [Prometheus Protocol](https://prometheusprotocol.org) app store: scoped, expiring, revocable grants from a principal to an agent, with ckUSDC spending the registry enforces on-chain.

**Status:** v0.1.0, built and locally verified against a real ICRC-2 ledger. Not yet on mainnet.

## What it does

- **"This agent may spend up to X, for purpose Y, until date Z."** You write the rule once; the registry holds it, every agent can read it, and the money side is enforced rather than hoped for.
- **Your agent never holds your key.** `add_agent` issues the agent its own principal and API key. Everything that key can do is exactly the grants you give it — it can't grant itself more, can't touch your allowance directly, and nobody can use an issued principal outside this registry.
- **Spending is enforced.** You approve one ckUSDC allowance to the registry. Agents pay only through `pay`, which checks the recipient list, the per-payment cap, the period budget, and the expiry before the ledger ever sees a transfer. Over-limit payments never leave your account.
- **The ledger is a second wall.** Your allowance is a hard ceiling the ledger enforces on its own. Even if everything in this canister failed, it could not move more than you approved. `spending_status` compares the two and gives you the exact approve call.
- **Any other action, declared and checkable.** Grant "may sign contracts with these two suppliers, up to 500 USD, twice a month." The agent records each use with `use_permission`; any other app or agent can ask `check_permission` before trusting yours.
- **A kill switch.** Pause an agent and every grant it holds stops at once. Resume when you are ready.
- **You see every attempt.** Payments, recorded uses, and — most usefully — refusals: an agent trying something its grant doesn't cover lands in your `activity` log.

## Tools

| Tool | Who | Does |
|---|---|---|
| `add_agent` | owner | Issue an agent (its own principal + key), or link an existing principal |
| `list_agents` | owner | Agents, status, principal, active grants |
| `set_agent_status` | owner | Pause, resume, or remove an agent |
| `new_agent_key` | owner | Replace an issued agent's key; the old one stops working |
| `grant_spend` | owner | Caps, period budget, recipients, expiry — enforced on-chain |
| `grant_action` | owner | A named action with optional limits and counterparties |
| `revoke_grant` | owner | End a grant now |
| `list_grants` | owner | Used and left this period, reset time, expiry, lifetime totals |
| `spending_status` | owner | Live allowance and balance vs. your grants; the exact approve call |
| `activity` | owner | Payments, uses, refusals, and third-party checks, newest first |
| `my_grants` | agent | What am I allowed to do, and how much is left |
| `pay` | agent | Pay under a spend grant; retry-safe with a `request_id` |
| `use_permission` | agent | Check and record one use of an action grant |
| `check_permission` | anyone | Is this agent allowed to do X (for this amount, with this party)? |

## Setting up an agent that can pay

```
owner                                            agent (with its issued key)
-----                                            ---------------------------
add_agent {name: "Groceries"}          -> api_key (shown once; hand it to the agent)
grant_spend {agent, per_payment_max: 20,
             budget: 50, period: "week",
             recipients: [{label: "Fresh Market",
                           principal: ...}]}
spending_status                        -> icrc2_approve args; approve on the ledger
                                                 my_grants
                                                 pay {grant, to: "Fresh Market",
                                                      amount: 18.50, request_id}
activity                               -> "Paid 18.50 ckUSDC to Fresh Market (block …)"
```

## Rules the registry holds to

- **`from` is always the grant's owner.** No tool takes a `from`.
- **Budget is reserved before the ledger call.** Two simultaneous payments can't both squeeze under the same budget. A ledger refusal releases the reservation; a call with an unknown outcome keeps it and is marked `uncertain`.
- **Every grant expires** — 30 days by default, a year at most.
- **Spend grants need a per-payment cap, a period budget, and a recipient list** (unless you explicitly allow any recipient).
- **Money is never sent where it would be stuck:** not to an issued agent principal, not to the registry itself, not to the anonymous principal.
- **Periods are calendar periods in UTC:** a weekly budget resets Monday 00:00 UTC.
- **Caps count what the recipient receives;** the ledger fee (0.01 ckUSDC) is paid by the owner on top.
- **Grants aren't edited** — revoke and grant again, so the record shows both.
- **v1 caps:** 1,000 ckUSDC per payment, 10,000 per period. Only allowlisted ledgers (ckUSDC).

## Local development

```bash
mops install
dfx start --background
cp ../escrow-work-marketplace/local-ledger -r .   # ic-icrc1-ledger.wasm.gz + ledger.did
python3 scripts/local-verify.py                   # 67 end-to-end checks against a real ICRC-2 ledger
```

Auth follows the store pattern: mint a key with `create_my_api_key`, send it as `x-api-key`. Issued agents get their key from `add_agent` instead. Times are shown in UTC.

## Deferred (v1.1+)

- Wildcard actions (`contract.*`)
- Over-limit requests the owner approves once
- Contract Vault, Escrow, and Dispatch calling `check_permission` natively
- Refusal alerts through Encrypted Mailbox or a Notifications bridge
