# Agent Delegation Registry — MCP Server Spec

Status: **v0.1.0 built and locally verified 2026-09-28** (67 checks against a real ICRC-2 ledger). This is the top pick on the Prometheus App Store
opportunity map (infrastructure: "Agent Identity & Delegation Registry"). It was chosen because the
three money-moving openings left on the map (Payroll, Bill Autopilot, Family Hub) each need an
answer to *"how much is this agent allowed to do?"*. Without this, each would invent its own.

## Why this exists

Today an agent that can pay holds its owner's key, which means it can do anything the owner can.
The only limits are whatever the prompt says. This registry replaces "trust the prompt" with rules
the owner writes once and the chain enforces:

> *Agent "Groceries" may pay up to 20 ckUSDC per payment and 50 ckUSDC per week, only to Fresh
> Market or the pharmacy, until December 31.*

## Two kinds of grant (the hybrid)

1. **Spend grants are enforced.** The owner approves ONE ckUSDC allowance to this canister on the
   ledger. Agents cannot touch that allowance directly. They call `pay`, and the registry checks
   the grant before it calls `icrc2_transfer_from(owner → recipient)`. If the payment is over the
   cap, over the budget, to an unlisted recipient, expired, revoked or paused, it never reaches the
   ledger.
2. **Action grants are declared and checked.** Examples: "may sign contracts with these two
   counterparties", "may accept bookings up to 500 USD". The registry cannot stop an agent doing
   something in another app. What it can do is let that agent record each use against a budget
   (`use_permission`), and let any other app or agent ask before trusting it (`check_permission`).

## Agents get their own key, never the owner's

`add_agent` with no principal **issues** an agent. The registry derives a fresh principal for it
(an opaque id: sha256 of canister | owner | agent id, 28 bytes + 0x01) and mints an API key bound
to that principal directly in the SDK's key store. The key is shown once. The owner hands the agent
that key instead of their own. Nobody holds a private key for an issued principal, so it cannot
call the ledger itself, mint its own keys, or act as an owner here. Its only powers are the grants.

`add_agent` with a principal **links** an existing identity instead, such as an agent with its own
dfx identity, or another business's agent that should do a job for you.

## Invariants

1. **`from` is always the grant's owner.** A payment is keyed by grant id, the grant must belong
   to the calling agent, and the grant fixes the owner. No tool takes a `from`.
2. **Reserve before await.** A payment's amount is added to the grant's period usage *before* the
   ledger call, so two concurrent `pay` calls can't both pass the budget check. A ledger error
   releases the reservation. A call that throws (outcome unknown) keeps it and is marked
   `uncertain`, because refunding budget for money that may have moved is the unsafe direction.
3. **The allowance is the hard ceiling, enforced by the ledger rather than by this code.** Even a
   bug here cannot move more than the owner approved. `spending_status` compares the allowance
   with the budgets.
4. **Expiry is mandatory.** The default is 30 days and the maximum is 366. A grant that never
   expires is the thing this registry exists to prevent.
5. **Spend grants need both a per-payment cap and a period budget**, and a recipient allowlist
   unless the owner explicitly sets `any_recipient`.
6. **Unspendable destinations are refused:** issued agent principals (no one can move funds out),
   this canister, the anonymous principal, and the owner's own default account.
7. **Retries are safe.** `pay` takes an optional `request_id`. A repeat returns the first result
   and does not pay twice. Ledger calls also carry `created_at_time` and a per-payment memo, so the
   ledger's own dedup window applies.
8. **Refusals are logged.** An agent trying something it can't do is the most useful thing the
   owner can see in `activity`.

## Decided in the build

- **Periods are calendar periods in UTC:** day, week (Monday start), month, or total (lifetime).
  "50 a week" resets Monday 00:00 UTC. That is easier to reason about than a rolling window.
- **Caps count the amount the recipient receives.** The ledger fee (0.01 ckUSDC) is paid by the
  owner on top and shown on every payment.
- **Grants are not edited.** To change one, revoke it and grant again, so the audit trail shows
  both. Usage is tracked per grant, so a replacement starts a fresh period count.
- **`check_permission` is open to any authenticated caller** and answers yes or no, with the owner,
  grant and expiry. It does not reveal remaining budgets. With no matching grant it names no owner.
  The owner's activity log records who checked.
- **Pause is reversible and remove is not.** Remove revokes every grant and deletes an issued
  agent's key.
- **v1 caps:** 1,000 ckUSDC per payment and 10,000 per period budget. Only allowlisted ledgers are
  accepted (ckUSDC on mainnet), the same way Escrow closes the hostile-ledger hole.

## Tools (14)

| Tool | Who | Does |
|---|---|---|
| `add_agent` | owner | Issue an agent (fresh principal + key) or link an existing principal |
| `list_agents` | owner | Agents, status, principal, active grants |
| `set_agent_status` | owner | Pause, resume, or remove an agent |
| `new_agent_key` | owner | Replace an issued agent's key (the old one stops working) |
| `grant_spend` | owner | Let an agent pay: caps, budget, period, recipients, expiry |
| `grant_action` | owner | Let an agent do a named action: limits, counterparties, expiry |
| `revoke_grant` | owner | End a grant now |
| `list_grants` | owner | Grants with usage and remaining budget this period |
| `spending_status` | owner | Live allowance and balance vs. budgets; the exact approve call |
| `activity` | owner | Payments, uses, refusals, checks — newest first |
| `my_grants` | agent | What am I allowed to do, and how much is left |
| `pay` | agent | Pay under a spend grant (enforced on-chain) |
| `use_permission` | agent | Check and record one use of an action grant |
| `check_permission` | anyone | Is this agent allowed to do X (for this amount, with this party)? |

## Deferred (v1.1+)

- Wildcard actions (`contract.*`)
- Owner approval for over-limit requests (agent asks, owner approves once)
- Contract Vault, Escrow, and Dispatch calling `check_permission` natively
- Notifications on refusals through Encrypted Mailbox or a Notifications bridge
