#!/usr/bin/env python3
"""Local end-to-end verification for the Agent Delegation Registry.

Stands up a throwaway ICRC-1/2 ledger, reinstalls the registry, and walks both
kinds of grant with four principals: an owner (default), a merchant
(crm-customer), an outside agent with its own identity (escrow-worker), and a
stranger (crm-stranger). Money is checked against the LEDGER, never against
what the registry says about itself.

Covered: issued agent keys (and that they cannot act as owners), recipient
allowlists, per-payment caps, period budgets, exact decimal amounts, retry
dedup, the budget reservation holding under concurrent payments, pause /
resume, key rotation, revocation, removal, action grants with counterparties
and use limits, third-party checks that leak nothing without a grant, the
activity log, and upgrade persistence.

Not covered: a period actually rolling over (the reset time is checked as a
value instead), and the ledger call throwing mid-flight (the `uncertain`
path), which a healthy local ledger never does.

Usage:  python3 scripts/local-verify.py      (needs dfx with a replica running,
        and local-ledger/ic-icrc1-ledger.wasm.gz — copy it from a sibling project)
"""

import datetime
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ["DFX_WARNING"] = "-mainnet_plaintext_identity"

passed = 0


def say(t):
    print(f"\n\033[1m{t}\033[0m")


def ok(t):
    global passed
    passed += 1
    print(f"  ok   {t}")


def check(cond, t, detail=None):
    if not cond:
        print(f"  FAIL {t}")
        if detail is not None:
            print(json.dumps(detail, indent=2)[:3000])
        sys.exit(1)
    ok(t)


def sh(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def principal(identity):
    return sh("dfx", "identity", "get-principal", "--identity", identity)


for ident in ("crm-customer", "crm-stranger", "escrow-worker"):
    subprocess.run(["dfx", "identity", "new", ident, "--storage-mode", "plaintext"], capture_output=True)

OWNER_P = principal("default")
MERCHANT_P = principal("crm-customer")
STRANGER_P = principal("crm-stranger")
OUTSIDE_P = principal("escrow-worker")
MINTER_P = principal("ledger-minter") if subprocess.run(["dfx", "identity", "get-principal", "--identity", "ledger-minter"], capture_output=True).returncode == 0 else OWNER_P

say("Deploying a throwaway ledger and the registry")
sh("dfx", "deploy", "test_ledger", "--mode", "reinstall", "--yes", "--argument", f"""(variant {{ Init = record {{
  token_symbol = "TESTUSD"; token_name = "Test USD";
  minting_account = record {{ owner = principal "{MINTER_P}" }};
  transfer_fee = 10_000; decimals = opt (6 : nat8); metadata = vec {{}};
  initial_balances = vec {{ record {{ record {{ owner = principal "{OWNER_P}" }}; 1_000_000_000 : nat }} }};
  feature_flags = opt record {{ icrc2 = true }};
  archive_options = record {{
    num_blocks_to_archive = 1000 : nat64; trigger_threshold = 2000 : nat64;
    controller_id = principal "{MINTER_P}";
  }};
}} }})""")
sh("dfx", "deploy", "delegation_registry", "--mode", "reinstall", "--yes")
REG = sh("dfx", "canister", "id", "delegation_registry")
LEDGER = sh("dfx", "canister", "id", "test_ledger")
# The allowlist is deployer-only and not a tool, so the local ledger is added on purpose.
sh("dfx", "canister", "call", "delegation_registry", "admin_allow_asset", f'("{LEDGER}", "TESTUSD", 6 : nat8, 100_000_000 : nat)')


def mint(identity):
    return sh("dfx", "canister", "call", "delegation_registry", "create_my_api_key", '("verify", vec {})', "--identity", identity).split('"')[1]


OWNER, MERCHANT, STRANGER, OUTSIDE = mint("default"), mint("crm-customer"), mint("crm-stranger"), mint("escrow-worker")
URL = f"http://127.0.0.1:4943/mcp?canisterId={REG}"
ok(f"registry {REG}, ledger {LEDGER}, four keys minted")


def rpc(key, method, params):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if key:
        headers["x-api-key"] = key
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(URL, data=body, headers=headers)) as r:
        return json.load(r)


def call(key, tool, args=None):
    res = rpc(key, "tools/call", {"name": tool, "arguments": args or {}})
    if "result" not in res:
        return {"_error": True, "_text": json.dumps(res)}
    result = res["result"]
    out = dict(result.get("structuredContent") or {})
    out["_error"] = bool(result.get("isError"))
    out["_text"] = result["content"][0]["text"] if result.get("content") else ""
    return out


def good(key, tool, args=None):
    r = call(key, tool, args)
    if r["_error"]:
        print(f"  FAIL {tool} errored: {r['_text']}")
        sys.exit(1)
    return r


def refused(key, tool, args, needle, t):
    r = call(key, tool, args)
    check(r["_error"] and needle.lower() in r["_text"].lower(), t, r)


def http_status(key, tool):
    try:
        call(key, tool)
        return 200
    except urllib.error.HTTPError as e:
        return e.code


def balance(p):
    out = sh("dfx", "canister", "call", "test_ledger", "icrc1_balance_of", f'(record {{ owner = principal "{p}" }})')
    return int("".join(c for c in out.split(":")[0] if c.isdigit()))


def approve(amount, identity="default"):
    sh("dfx", "canister", "call", "test_ledger", "icrc2_approve",
       f'(record {{ spender = record {{ owner = principal "{REG}" }}; amount = {amount} : nat }})', "--identity", identity)


# ---------------------------------------------------------------------------
say("1. Tool surface and auth")
tools = [t["name"] for t in rpc(OWNER, "tools/list", {})["result"]["tools"]]
check(len(tools) == 14, f"14 tools listed ({len(tools)})")
check(http_status(None, "list_agents") == 401, "no key is refused with HTTP 401")

# ---------------------------------------------------------------------------
say("2. An issued agent gets its own principal and key, and cannot act as an owner")
r = good(OWNER, "add_agent", {"name": "Groceries"})
AGENT = r["api_key"]
AGENT_P = r["agent"]["principal"]
AGENT_ID = r["agent"]["id"]
check(r["agent"]["kind"] == "issued" and AGENT_P != OWNER_P, f"issued agent #{AGENT_ID} with principal {AGENT_P[:11]}…")
check(AGENT_P.endswith("-cai") is False and len(AGENT_P) > 27, "the issued principal is a 29-byte opaque id, not a canister id")
r = good(AGENT, "my_grants")
check(r["your_principal"] == AGENT_P and r["as"][0]["grants"] == [], "the agent's key authenticates as the issued principal, with no grants yet")
refused(AGENT, "add_agent", {"name": "Sub-agent"}, "agent's key", "an agent key cannot add agents")
refused(AGENT, "grant_spend", {"agent": "Groceries", "purpose": "self-grant", "per_payment_max": 1, "budget": 1, "any_recipient": True, "ledger": LEDGER},
        "agent's key", "an agent key cannot grant itself spending")
refused(OWNER, "add_agent", {"name": "groceries"}, "already have an agent", "agent names are unique, case-insensitively")
refused(OWNER, "add_agent", {"name": "Me", "principal": OWNER_P}, "your own principal", "the owner cannot be their own agent")
refused(OWNER, "add_agent", {"name": "Borrowed", "principal": AGENT_P}, "issued by this registry", "another registry-issued principal cannot be linked")

# ---------------------------------------------------------------------------
say("3. Spend grants are validated before they exist")
base = {"agent": "Groceries", "purpose": "Weekly groceries", "ledger": LEDGER,
        "recipients": [{"label": "Fresh Market", "principal": MERCHANT_P}]}
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20}, "'budget' is required", "a budget is required")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 60, "budget": 50}, "larger than 'budget'", "per-payment cap above budget is refused")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20, "budget": 50, "recipients": []}, "any_recipient", "no recipients and no any_recipient is refused")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20, "budget": 50, "expires_in_days": 400}, "1-366", "a grant longer than a year is refused")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20, "budget": 50, "recipients": [{"label": "Agent", "principal": AGENT_P}]},
        "issued agent principal", "paying an issued agent principal is refused (nobody could move it out)")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20, "budget": 50, "ledger": "aaaaa-aa"}, "allowlist", "an unknown ledger is refused")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 150, "budget": 500}, "v1 caps a single payment", "the per-payment cap holds")
refused(OWNER, "grant_spend", {**base, "per_payment_max": 20.1234567, "budget": 50}, "at most 6 decimals", "more precision than the token has is refused, not rounded")

r = good(OWNER, "grant_spend", {**base, "per_payment_max": 20, "budget": 50, "period": "week"})
G = r["grant"]["id"]
check(r["grant"]["budget"] == "50.00 TESTUSD" and r["grant"]["per_use_max"] == "20.00 TESTUSD", f"spend grant #{G}: 20 per payment, 50 per week")
today = datetime.datetime.now(datetime.timezone.utc).date()
monday = today + datetime.timedelta(days=7 - today.weekday())
check(r["grant"]["period_resets"] == f"{monday.isoformat()} 00:00 UTC", f"the week resets next Monday 00:00 UTC ({monday})", r["grant"])
expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).date().isoformat()
check(r["grant"]["expires"].startswith(expiry), "the default expiry is 30 days")

# ---------------------------------------------------------------------------
say("4. Without an allowance the ledger refuses, and the budget is not consumed")
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 10}, "allowance", "paying before any approve is refused by the ledger")
check(good(OWNER, "list_grants")["grants"][0]["used_this_period"] == "0.00 TESTUSD", "the failed payment released its reservation")
s = good(OWNER, "spending_status", {"ledger": LEDGER})["ledgers"][0]
check(s["grants_left_this_period"] == "50.00 TESTUSD" and "below" in s["advice"], "spending_status sees a zero allowance under a 50 budget")
suggested = s["approve_args"]["amount"]
check(suggested > 50_000_000, f"it suggests an allowance of one full period plus fees ({suggested / 1e6:.2f})")
approve(suggested)
s = good(OWNER, "spending_status", {"ledger": LEDGER})["ledgers"][0]
check(s["allowance_to_registry"].startswith(f"{suggested / 1e6:.2f}".rstrip("0").rstrip(".")) and "covers" in s["advice"], "after approving, the allowance covers the grants")

# ---------------------------------------------------------------------------
say("5. Paying works — checked against the ledger")
m0, o0 = balance(MERCHANT_P), balance(OWNER_P)
r = good(AGENT, "pay", {"grant": G, "to": "fresh market", "amount": 18.5, "note": "Groceries 9/28", "request_id": "groc-1"})
check(r["payment"]["status"] == "sent", f"paid 18.50 to Fresh Market (block {r['payment']['ledger_block']})")
check(balance(MERCHANT_P) - m0 == 18_500_000, "the merchant received exactly 18.500000 — per the ledger")
check(o0 - balance(OWNER_P) == 18_510_000, "the owner paid 18.50 plus the 0.01 fee")
r = good(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 18.5, "request_id": "groc-1"})
check("already paid" in r["message"].lower() and balance(MERCHANT_P) - m0 == 18_500_000, "retrying the same request_id does not pay twice")
r = good(AGENT, "pay", {"grant": G, "to": MERCHANT_P, "amount": "1.1"})
check(balance(MERCHANT_P) - m0 == 19_600_000, "paying by principal works, and 1.1 is exactly 1.100000")

# ---------------------------------------------------------------------------
say("6. The grant's limits hold")
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 25}, "limit of 20.00", "over the per-payment cap is refused")
refused(AGENT, "pay", {"grant": G, "to": STRANGER_P, "amount": 5}, "not a recipient", "an unlisted recipient is refused")
refused(AGENT, "pay", {"grant": G, "to": "Corner Store", "amount": 5}, "fresh market", "an unknown label is refused, and the refusal names who it may pay")
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 0}, "greater than zero", "a zero payment is refused")
good(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 20})
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 15}, "10.40 TESTUSD is left", "over the week's budget is refused, saying what is left")
refused(STRANGER, "pay", {"grant": G, "to": "Fresh Market", "amount": 1}, "no grant #", "another principal cannot use the agent's grant")
refused(OWNER, "pay", {"grant": G, "to": "Fresh Market", "amount": 1}, "no grant #", "not even the owner's own key can pay through an agent's grant")

# ---------------------------------------------------------------------------
say("7. Concurrent payments cannot overspend (reserve before await)")
m1 = balance(MERCHANT_P)
with ThreadPoolExecutor(max_workers=3) as pool:
    results = list(pool.map(lambda i: call(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 5, "request_id": f"race-{i}"}), range(3)))
sent = [x for x in results if not x["_error"]]
check(len(sent) == 2, f"three simultaneous 5.00 payments against 10.40 left: {len(sent)} sent, {3 - len(sent)} refused", results)
check(balance(MERCHANT_P) - m1 == 10_000_000, "the ledger shows exactly 10.00 moved")
check(good(OWNER, "list_grants")["grants"][0]["left_this_period"] == "0.40 TESTUSD", "0.40 is left this week")

# ---------------------------------------------------------------------------
say("8. Pause is the kill switch; resume restores it")
good(OWNER, "set_agent_status", {"agent": "Groceries", "status": "pause"})
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 0.4}, "agent paused", "a paused agent cannot pay")
check("PAUSED" in good(AGENT, "my_grants")["as"][0]["status"], "the agent is told it is paused")
good(OWNER, "set_agent_status", {"agent": AGENT_ID, "status": "resume"})
good(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 0.4})
check(good(OWNER, "list_grants")["grants"][0]["left_this_period"] == "0.00 TESTUSD", "resumed: the last 0.40 goes through and the budget is exactly spent")

# ---------------------------------------------------------------------------
say("9. Keys rotate, and revocation is immediate")
r = good(OWNER, "new_agent_key", {"agent": "Groceries"})
NEW_AGENT = r["api_key"]
check(http_status(AGENT, "my_grants") == 401, "the old agent key stops working")
check(good(NEW_AGENT, "my_grants")["your_principal"] == AGENT_P, "the new key is the same principal, with the same grants")
AGENT = NEW_AGENT
good(OWNER, "revoke_grant", {"grant": G})
refused(AGENT, "pay", {"grant": G, "to": "Fresh Market", "amount": 0.01}, "revoked", "a revoked grant refuses")
check(good(OWNER, "list_grants")["count"] == 0 and good(OWNER, "list_grants", {"include_ended": True})["count"] == 1, "revoked grants leave the default list but stay on record")

# ---------------------------------------------------------------------------
say("10. Action grants: declared, recorded, and checkable by others")
r = good(OWNER, "add_agent", {"name": "Office manager", "principal": OUTSIDE_P})
check(r["agent"]["kind"] == "linked" and "api_key" not in r, "linked an outside agent by its own principal — no key issued")
r = good(OWNER, "grant_action", {"agent": "Office manager", "action": "Contract.Sign", "purpose": "Sign renewals with our supplier",
                                 "per_use_max": 500, "unit": "USD", "max_uses": 2, "period": "month", "counterparties": [MERCHANT_P]})
A = r["grant"]["id"]
check(r["grant"]["action"] == "contract.sign", f"action grant #{A}: contract.sign, up to 500 USD, twice a month, with one counterparty")
r = good(OUTSIDE, "use_permission", {"action": "contract.sign", "amount": 300, "counterparty": MERCHANT_P, "note": "Renewal #12"})
check(r["allowed"] and r["grant"]["uses_this_period"] == 1, "the agent's use is allowed and recorded")
r = good(OUTSIDE, "use_permission", {"action": "contract.sign", "amount": 600, "counterparty": MERCHANT_P})
check(not r["allowed"] and "per use" in r["message"], "600 USD is over the per-use limit")
r = good(OUTSIDE, "use_permission", {"action": "contract.sign", "amount": 100, "counterparty": STRANGER_P})
check(not r["allowed"] and "counterparty" in r["message"], "an unnamed counterparty is refused")
refused(OUTSIDE, "use_permission", {"action": "invoice.send"}, "no grant for 'invoice.send'", "an action with no grant is refused")

r = good(MERCHANT, "check_permission", {"agent": OUTSIDE_P, "action": "contract.sign", "amount": 100, "counterparty": MERCHANT_P})
check(r["allowed"] and r["owner"] == OWNER_P and "left" not in json.dumps(r), "the merchant can confirm the agent's authority and owner, and sees no budget")
r = good(STRANGER, "check_permission", {"agent": OUTSIDE_P, "action": "invoice.send"})
check(not r["allowed"] and "owner" not in r, "with no grant, a check names no owner")
good(OUTSIDE, "use_permission", {"action": "contract.sign", "amount": 50, "counterparty": MERCHANT_P})
r = good(OUTSIDE, "use_permission", {"action": "contract.sign", "amount": 50, "counterparty": MERCHANT_P})
check(not r["allowed"] and "all of them are used" in r["message"], "the third use this month is refused")
r = good(MERCHANT, "check_permission", {"agent": OUTSIDE_P, "action": "contract.sign", "amount": 50, "counterparty": MERCHANT_P})
check(not r["allowed"] and r["reason"] == "use limit reached", "a third party sees the short reason only")

# ---------------------------------------------------------------------------
say("11. The owner sees everything, including attempts that failed")
ev = good(OWNER, "activity", {"limit": 100})["events"]
kinds = {e["event"] for e in ev}
check({"paid", "pay_refused", "pay_failed", "action_used", "use_refused", "checked", "grant_revoked", "key_replaced"} <= kinds, "activity has payments, refusals, ledger failures, uses, checks, and key changes", sorted(kinds))
refusals = good(OWNER, "activity", {"refusals_only": True, "limit": 100})["events"]
check(all(not e["ok"] for e in refusals) and len(refusals) >= 8, f"refusals_only returns {len(refusals)} refused attempts and nothing else")
check(any("checked 'contract.sign'" in e["detail"] for e in ev), "the merchant's check is on the owner's record")

# ---------------------------------------------------------------------------
say("12. Remove is permanent: grants revoked, issued key deleted")
good(OWNER, "set_agent_status", {"agent": "Groceries", "status": "remove"})
check(http_status(AGENT, "my_grants") == 401, "the removed agent's key no longer authenticates")
good(OWNER, "set_agent_status", {"agent": "Office manager", "status": "remove"})
r = good(MERCHANT, "check_permission", {"agent": OUTSIDE_P, "action": "contract.sign", "counterparty": MERCHANT_P})
check(not r["allowed"], "a removed linked agent's grants stop checking as allowed")
check(good(OWNER, "list_agents")["count"] == 0 and good(OWNER, "list_agents", {"include_removed": True})["count"] == 2, "removed agents stay on record")

# ---------------------------------------------------------------------------
say("13. State survives an upgrade")
r = good(OWNER, "add_agent", {"name": "Survivor"})
SURV = r["api_key"]
good(OWNER, "grant_action", {"agent": "Survivor", "action": "booking.accept", "purpose": "Accept bookings", "max_uses": 5})
good(SURV, "use_permission", {"action": "booking.accept"})
sh("dfx", "deploy", "delegation_registry", "--upgrade-unchanged", "--yes")
r = good(SURV, "my_grants")
check(r["as"][0]["grants"][0]["uses_this_period"] == 1, "after an upgrade the issued key still works and usage is intact")
check(len(good(OWNER, "activity", {"limit": 100})["events"]) > 20, "the activity log survives the upgrade")

print(f"\n\033[1mAll {passed} checks passed.\033[0m")
