"""Deploy contracts/phish_patrol.py to GenLayer Studio Next (chain 61997).

    .venv/bin/python scripts/deploy.py

Creates the project's governor account on first run (key in .env, gitignored),
funds it from the Studio faucet, deploys, reads the contract back to confirm the
genesis state, and writes deployments/studio-next.json. Re-running deploys a NEW
instance and keeps the previous one under "predecessors".
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from common import (
    ATTO, CHAIN_ID, CONTRACT_PATH, DEPLOYMENT_FILE, EXPLORER, NETWORK, RPC_URL, Chain, ChainError,
    _find, account_for, explorer_address, explorer_tx, runner_of, save_json, sha256_of,
)

DEPLOYER_FUNDING = 200 * ATTO


def contract_address_of(deploy: dict) -> str | None:
    for src in (deploy["receipt"], deploy["tx"]):
        addr = _find(src, "contract_address", "contractAddress", "recipient")
        if isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42 and int(addr, 16) != 0:
            return addr
    return None


def main() -> int:
    print(f"PhishPatrol deploy -> {NETWORK} (chain {CHAIN_ID}) via {RPC_URL}")
    governor = account_for("governor")
    chain = Chain(governor)
    bal = chain.ensure_funded(DEPLOYER_FUNDING)
    print(f"  governor {governor.address} holds {bal / ATTO:.2f} GEN")

    code = CONTRACT_PATH.read_bytes()
    src_hash = sha256_of(CONTRACT_PATH)
    print(f"  source sha256 {src_hash}")

    out = chain.deploy(code)
    c = out["consensus"]
    print(f"  deploy tx {out['tx_hash']} exec={c['execution']} consensus={c['result_name']} votes={c['votes']}")
    if c["execution"] not in (None, "FINISHED_WITH_RETURN"):
        raise ChainError(f"deploy did not finish: {c}")
    address = contract_address_of(out)
    if address is None:
        raise ChainError(f"no contract address in deploy receipt: {json.dumps(out['receipt'])[:600]}")
    print(f"  contract {address}")

    chain.address = address
    overview = chain.read("get_protocol_overview")
    print(f"  genesis overview: {overview}")
    assert overview["balance"] == 0 and overview["solvent"] is True, overview
    assert overview["governor"].lower() == governor.address.lower(), overview

    previous = None
    if DEPLOYMENT_FILE.exists():
        previous = json.loads(DEPLOYMENT_FILE.read_text())
    record = {
        "network": NETWORK,
        "chain_id": CHAIN_ID,
        "rpc_url": RPC_URL,
        "contract_address": address,
        "explorer_url": explorer_address(address),
        "source": "contracts/phish_patrol.py",
        "runner": runner_of(CONTRACT_PATH),
        "source_sha256_at_record": src_hash,
        "deployed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "governor": governor.address,
        "deploy": {
            "tx_hash": out["tx_hash"],
            "explorer_url": explorer_tx(out["tx_hash"]),
            "execution_result": c["execution"],
            "consensus_result": c["result_name"],
            "validator_votes": c["votes"],
            "votes_by_validator": c["votes_by_validator"],
            "leader": c["leader"],
            "no_dissent": c["no_dissent"],
            "contract_state_hashes": c["state_hashes"],
            "state_hashes_identical": c["state_hashes_identical"],
        },
        "genesis_overview": overview,
        "live_cases": [],
    }
    if previous:
        record["predecessors"] = [
            {k: previous.get(k) for k in ("contract_address", "explorer_url", "source_sha256_at_record", "deployed_at")}
        ] + previous.get("predecessors", [])
    save_json(DEPLOYMENT_FILE, record)
    print(f"  wrote {DEPLOYMENT_FILE.relative_to(DEPLOYMENT_FILE.parent.parent)}")
    print(f"  explorer: {EXPLORER}/address/{address}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
