"""Run the five live PhishPatrol cases on Studio Next and record the proof.

    .venv/bin/python scripts/interact_live.py [--phish-url https://<fixture-host>/]

Each case is a real transaction sequence against the contract recorded in
deployments/studio-next.json. After every settlement the script asserts the exact
ledger movement (bond, reward, slash, fee) against the pre-transaction overview,
and for every write it records the transaction hash, the validators' votes and the
contract state hash each validator computed.

  1  register_brand  Uniswap (uniswap.org, app.uniswap.org), 0.5 GEN seed
  2  register_brand  MetaMask (metamask.io), 0.5 GEN seed
  3  confirmed phishing: a mimic of the brand -> blacklisted + bounty paid
        (needs --phish-url: a reachable page that really does mimic the brand)
  4  false positive: an official, benign Uniswap page -> rejected, bond slashed 50/50
  5  unreachable / 404 page -> AMBIGUOUS_VOID, 80/20 fee split
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from common import (
    ATTO, DEPLOYMENT_FILE, Chain, ChainError, account_for, describe_consensus, explorer_tx, save_json,
)

SEED = ATTO // 2
MIN_BOND = ATTO // 10

BENIGN_OFFICIAL_URL = "https://blog.uniswap.org/"  # Uniswap-owned, answers 200, not a registered official host
NOT_FOUND_URL = "https://example.com/phishpatrol-uniswap-claim-404"  # answers 404


def log(msg: str = "") -> None:
    print(msg, flush=True)


def tx_entry(label: str, out: dict) -> dict:
    c = out["consensus"]
    return {
        "label": label,
        "tx_hash": out["tx_hash"],
        "explorer_url": explorer_tx(out["tx_hash"]),
        "execution_result": c["execution"],
        "consensus_result": c["result_name"],
        "validator_votes": c["votes"],
        "votes_by_validator": c["votes_by_validator"],
        "leader": c["leader"],
        "no_dissent": c["no_dissent"],
        "rotations": c["rotations"],
        "contract_state_hashes": c["state_hashes"],
        "state_hashes_identical": c["state_hashes_identical"],
        "returned": out.get("returned"),
    }


def check(label: str, got, want) -> dict:
    ok = got == want
    log(f"      {'OK ' if ok else 'BAD'} {label}: {got}" + ("" if ok else f"  (expected {want})"))
    if not ok:
        raise AssertionError(f"{label}: got {got!r}, expected {want!r}")
    return {"check": label, "value": str(got), "expected": str(want), "ok": True}


class Live:
    def __init__(self, address: str):
        self.gov = Chain(account_for("governor"), address)
        self.owner = Chain(account_for("brand"), address)
        self.rep = Chain(account_for("reporter"), address)
        self.address = address

    def overview(self) -> dict:
        return self.gov.read("get_protocol_overview")

    def fund(self) -> None:
        for chain, role in ((self.owner, "brand"), (self.rep, "reporter")):
            have = chain.ensure_funded(20 * ATTO)
            log(f"  {role:8s} {chain.account.address} holds {have / ATTO:.2f} GEN")

    def file_and_adjudicate(self, brand_id: int, url: str, txs: list, retries: int = 3) -> tuple[int, dict]:
        """Reporter files, a third party (the governor key) adjudicates. A round
        the validators could not score returns EXEC_FAILURE and leaves the report
        pending; that is retried, as the contract intends."""
        bond = int(self.gov.read("required_bond", brand_id))
        out = self.rep.write("report_phishing", brand_id, url, value=bond, label=f"report {url}")
        txs.append(tx_entry("report_phishing", out))
        report_id = int(self.overview()["report_count"])
        for attempt in range(1, retries + 1):
            adj = self.gov.write("adjudicate_report", report_id, label=f"adjudicate #{report_id} (attempt {attempt})")
            txs.append(tx_entry(f"adjudicate_report attempt {attempt}", adj))
            rec = self.gov.read("get_report", report_id)
            if int(rec["status"]) != 0:
                return report_id, rec
            log(f"      report #{report_id} still pending after attempt {attempt} (exec_failures={rec['exec_failures']})")
        raise ChainError(f"report #{report_id} was not settled after {retries} adjudication attempts")


def case1_2(live: Live, name: str, domains: list[str], expect_id: int) -> dict:
    txs: list = []
    before = live.overview()
    out = live.owner.write("register_brand", name, domains, value=SEED, label=f"register {name}")
    txs.append(tx_entry("register_brand", out))
    brand = live.gov.read("get_brand", expect_id)
    after = live.overview()
    checks = [
        check("brand_id", int(brand["brand_id"]), expect_id),
        check("brand_name", brand["brand_name"], name),
        check("canonical_domains", brand["canonical_domains"], domains),
        check("bounty_pool", int(brand["bounty_pool"]), SEED),
        check("is_active", brand["is_active"], True),
        check("total_bounties delta", int(after["total_bounties"]) - int(before["total_bounties"]), SEED),
        check("contract balance delta", int(after["balance"]) - int(before["balance"]), SEED),
        check("solvent", after["solvent"], True),
    ]
    return {"txs": txs, "checks": checks, "brand": brand}


def case3(live: Live, url: str) -> dict:
    txs: list = []
    before = live.overview()
    pool_before = int(live.gov.read("get_brand", 1)["bounty_pool"])
    report_id, rec = live.file_and_adjudicate(1, url, txs)
    reward = min(pool_before * 2000 // 10000, ATTO)
    after = live.overview()
    me = live.rep.account.address
    checks = [
        check("verdict", rec["verdict"], "CONFIRMED_PHISHING"),
        check("status", int(rec["status"]), 1),
        check("is_phishing(url)", live.gov.read("is_phishing", url), True),
        check("bond refunded + 20% reward credited", int(live.gov.read("claimable_of", me)), MIN_BOND + reward),
        check("brand pool after reward", int(live.gov.read("get_brand", 1)["bounty_pool"]), pool_before - reward),
        check("total_locked_bonds delta", int(after["total_locked_bonds"]) - int(before["total_locked_bonds"]), 0),
        check("solvent", after["solvent"], True),
    ]
    return {"txs": txs, "checks": checks, "report_id": report_id, "report": rec}


def case4(live: Live) -> dict:
    txs: list = []
    before = live.overview()
    pool_before = int(live.gov.read("get_brand", 1)["bounty_pool"])
    claim_before = int(live.gov.read("claimable_of", live.rep.account.address))
    report_id, rec = live.file_and_adjudicate(1, BENIGN_OFFICIAL_URL, txs)
    after = live.overview()
    to_brand = MIN_BOND * 5000 // 10000
    checks = [
        check("verdict", rec["verdict"], "REJECTED_FALSE_POSITIVE"),
        check("status", int(rec["status"]), 2),
        check("is_phishing(url)", live.gov.read("is_phishing", BENIGN_OFFICIAL_URL), False),
        check("50% of bond to brand pool", int(live.gov.read("get_brand", 1)["bounty_pool"]) - pool_before, to_brand),
        check("50% of bond to protocol vault", int(after["protocol_vault"]) - int(before["protocol_vault"]), MIN_BOND - to_brand),
        check("reporter credit unchanged", int(live.gov.read("claimable_of", live.rep.account.address)), claim_before),
        check("solvent", after["solvent"], True),
    ]
    return {"txs": txs, "checks": checks, "report_id": report_id, "report": rec}


def case5(live: Live) -> dict:
    txs: list = []
    before = live.overview()
    claim_before = int(live.gov.read("claimable_of", live.rep.account.address))
    report_id, rec = live.file_and_adjudicate(1, NOT_FOUND_URL, txs)
    after = live.overview()
    fee = MIN_BOND * 20 // 100
    checks = [
        check("verdict", rec["verdict"], "AMBIGUOUS_VOID"),
        check("status", int(rec["status"]), 3),
        check("is_phishing(url)", live.gov.read("is_phishing", NOT_FOUND_URL), False),
        check("20% bandwidth fee to vault", int(after["protocol_vault"]) - int(before["protocol_vault"]), fee),
        check("80% refund credited", int(live.gov.read("claimable_of", live.rep.account.address)) - claim_before, MIN_BOND - fee),
        check("solvent", after["solvent"], True),
    ]
    return {"txs": txs, "checks": checks, "report_id": report_id, "report": rec}


def settle(live: Live) -> dict:
    """Pull-pattern payouts: the reporter withdraws its credit, the governor
    sweeps the vault. Transfers settle at finalization, so poll until the
    solvency identity holds again and report what was observed."""
    txs: list = []
    me = live.rep.account.address
    credit = int(live.gov.read("claimable_of", me))
    vault = int(live.overview()["protocol_vault"])
    out = live.rep.write("pull_withdraw", label="pull_withdraw (reporter)")
    txs.append(tx_entry("pull_withdraw", out))
    out2 = live.gov.write("sweep_vault", label="sweep_vault (governor)")
    txs.append(tx_entry("sweep_vault", out2))
    checks = [
        check("reporter credit before withdraw", credit > 0, True),
        check("credit after withdraw", int(live.gov.read("claimable_of", me)), 0),
        check("protocol_vault after sweep", int(live.overview()["protocol_vault"]), 0),
    ]
    # emit_transfer(on="finalized") is applied at finalization, so wait for both
    # transactions to finalize and then read what actually happened to each
    # message from the transaction's own fee accounting.
    effects = []
    for entry in txs:
        tx = None
        for _ in range(60):
            tx = live.gov.client.get_transaction(entry["tx_hash"])
            if (tx.get("lifecycle") or {}).get("state") == "finalized":
                break
            time.sleep(6)
        fx = ((tx or {}).get("data", {}).get("fee_accounting", {}) or {}).get("message_value_effects") or {}
        for _, e in fx.items():
            effects.append({"tx": entry["label"], "value": e.get("value"), "phase": e.get("phase"),
                            "skipped": bool(e.get("skipped")), "declaredBudget": e.get("declaredBudget")})
    ov = live.overview()
    delivered = bool(effects) and not any(e["skipped"] for e in effects)
    surplus = int(ov["balance"]) - int(ov["tracked"])
    checks.append({"check": "contract accounting after withdraw + sweep: credits and vault debited",
                   "value": json.dumps({k: str(ov[k]) for k in ("total_claimable", "protocol_vault")}),
                   "expected": "0, 0", "ok": int(ov["total_claimable"]) == 0 and int(ov["protocol_vault"]) == 0})
    log(f"      transfers delivered by the network: {delivered}  (effects: {effects})")
    log(f"      balance={ov['balance']} tracked={ov['tracked']} surplus={surplus}")
    return {
        "txs": txs, "checks": checks, "credit_withdrawn": str(credit), "vault_swept": str(vault),
        "transfer_effects": effects, "transfers_delivered": delivered,
        "surplus_wei": str(surplus), "overview_after": ov,
        "status": "DELIVERED" if delivered and surplus == 0 else "TRANSFER_SKIPPED_BY_PLATFORM",
        "note": ("Studio Next marked each emit_transfer message skipped (declaredBudget 0) and returned the value to "
                 "the contract: the debit happened, the payout did not. balance - tracked is the undelivered amount; "
                 "it is never a deficit. See README section 8."),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish-url", default=os.environ.get("PHISH_FIXTURE_URL"),
                    help="a reachable page that mimics the registered brand (Case 3)")
    ap.add_argument("--only", help="comma list of cases to run, e.g. 3 or 4,5 (default: all)")
    ap.add_argument("--no-settle", action="store_true", help="skip the final withdraw/sweep")
    args = ap.parse_args()
    only = {int(x) for x in args.only.split(",")} if args.only else {1, 2, 3, 4, 5}

    record = json.loads(DEPLOYMENT_FILE.read_text())
    live = Live(record["contract_address"])
    log(f"PhishPatrol live cases @ {record['contract_address']} ({record['network']}, chain {record['chain_id']})")
    live.fund()

    # Refresh the deploy block with the full consensus evidence for that tx.
    dtx = live.gov.client.get_transaction(record["deploy"]["tx_hash"])
    dc = describe_consensus({}, dtx)
    record["deploy"].update({
        "execution_result": dc["execution"], "consensus_result": dc["result_name"],
        "validator_votes": dc["votes"], "votes_by_validator": dc["votes_by_validator"],
        "leader": dc["leader"], "no_dissent": dc["no_dissent"],
        "contract_state_hashes": dc["state_hashes"], "state_hashes_identical": dc["state_hashes_identical"],
    })
    record["deploy"].pop("unanimous_agree", None)

    start = live.overview()
    if int(start["brand_count"]) != 0 and (1 in only or 2 in only):
        log("  this instance already has brands; redeploy (scripts/deploy.py) for a clean run or use --only 3,4,5")
        return 1

    results: dict[int, dict] = {}
    plan = [
        (1, "Register brand Uniswap (uniswap.org, app.uniswap.org), seed 0.5 GEN",
         lambda: case1_2(live, "Uniswap", ["uniswap.org", "app.uniswap.org"], 1)),
        (2, "Register brand MetaMask (metamask.io), seed 0.5 GEN",
         lambda: case1_2(live, "MetaMask", ["metamask.io"], 2)),
        (3, "Confirmed phishing: brand mimic -> blacklisted + bounty paid",
         lambda: case3(live, args.phish_url)),
        (4, "False positive: official benign Uniswap page -> rejected, bond slashed 50/50",
         lambda: case4(live)),
        (5, "Unreachable / 404 page -> AMBIGUOUS_VOID, 80/20 fee split",
         lambda: case5(live)),
    ]
    cases_out: list[dict] = []
    for n, title, fn in plan:
        if n not in only:
            continue
        log(f"\nCase {n}: {title}")
        if n == 3 and not args.phish_url:
            log("      NOT RUN: Case 3 needs --phish-url (a reachable page that mimics the brand)")
            cases_out.append({"case": n, "title": title, "status": "NOT_RUN", "reason": "no --phish-url fixture supplied"})
            continue
        try:
            res = fn()
            cases_out.append({"case": n, "title": title, "status": "PASS", **res})
            results[n] = res
        except Exception as exc:  # noqa: BLE001
            log(f"      FAIL: {exc}")
            cases_out.append({"case": n, "title": title, "status": "FAIL", "error": str(exc)})

    if not args.no_settle and results:
        log("\nSettlement: pull_withdraw (reporter) + sweep_vault (governor)")
        try:
            record["settlement"] = settle(live)
        except Exception as exc:  # noqa: BLE001
            log(f"      FAIL: {exc}")
            record["settlement"] = {"status": "FAIL", "error": str(exc)}

    # Merge by case number so a later `--only 3` run does not erase cases 1, 2, 4, 5.
    merged = {c["case"]: c for c in record.get("live_cases", []) if isinstance(c, dict) and "case" in c}
    for c in cases_out:
        if c["status"] == "NOT_RUN" and merged.get(c["case"], {}).get("status") == "PASS":
            continue  # never let a skipped placeholder replace a recorded pass
        merged[c["case"]] = c
    record["live_cases"] = [merged[k] for k in sorted(merged)]
    record["final_overview"] = live.overview()
    record["accounts"] = {
        "governor": live.gov.account.address, "brand_owner": live.owner.account.address,
        "reporter": live.rep.account.address,
    }
    record["live_run_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    save_json(DEPLOYMENT_FILE, record)

    log("\nSummary")
    for c in record["live_cases"]:
        log(f"  case {c['case']}: {c['status']}  {c['title']}")
    bad = [c for c in record["live_cases"] if c["status"] == "FAIL"]
    skipped = [c for c in record["live_cases"] if c["status"] == "NOT_RUN"]
    return 1 if bad else (2 if skipped else 0)


if __name__ == "__main__":
    sys.exit(main())
