"""Shared GenLayer Studio Next plumbing for deploy.py and interact_live.py.

Accounts are generated fresh for this project and kept in a gitignored `.env`
(`PHISH_<ROLE>_KEY`); nothing here reads another project's keystore. Studio Next
is a devnet, so its faucet (`sim_fundAccount`) funds them.

All money amounts are atto-scale wei (1 GEN == 10**18).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, cast

from eth_account import Account
from eth_typing import ChecksumAddress
from genlayer_py import create_client
from genlayer_py.chains import studio_devnet  # type: ignore[reportAttributeAccessIssue]

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
CONTRACT_PATH = ROOT / "contracts" / "phish_patrol.py"
DEPLOYMENT_FILE = ROOT / "deployments" / "studio-next.json"

NETWORK = "studio-next"
CHAIN_ID = 61997
RPC_URL = os.environ.get("PHISH_RPC_URL", "https://studio-next.genlayer.com/api")
EXPLORER = "https://explorer-studio-next.genlayer.com"

ATTO = 10**18
OK_EXEC = "FINISHED_WITH_RETURN"
OK_CONSENSUS = "MAJORITY_AGREE"


class ChainError(Exception):
    pass


# ------------------------------------------------------------------ accounts
def _read_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def account_for(role: str):
    """The project's key for `role` (governor, brand, reporter ...), created on
    first use. Only the address is ever printed."""
    name = f"PHISH_{role.upper()}_KEY"
    key = os.environ.get(name) or _read_env().get(name)
    if not key:
        acct = Account.create()
        with ENV_FILE.open("a") as fh:
            fh.write(f"{name}={acct.key.hex()}\n")
        os.chmod(ENV_FILE, stat.S_IRUSR | stat.S_IWUSR)
        print(f"  created {role} account {acct.address} (key stored in .env)")
        return acct
    return Account.from_key(key)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runner_of(path: Path) -> str:
    for line in path.read_text().splitlines()[:5]:
        if '"Depends"' in line:
            return line.split('"Depends":')[1].split('"')[1]
    return ""


# -------------------------------------------------------------------- client
def _retry(fn, attempts: int = 4, wait_s: float = 6.0):
    """Studio occasionally drops a connection. Retry transport failures with a
    short backoff; a ChainError is a verdict about a transaction and propagates."""
    last: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except ChainError:
            raise
        except Exception as exc:  # noqa: BLE001 - transient network errors
            last = exc
            if i + 1 < attempts:
                time.sleep(wait_s * (i + 1))
    raise ChainError(f"transient RPC failure after {attempts} attempts: {last}")


def _fees_from(estimate: Any) -> Any:
    fees: Any = {
        "distribution": estimate["distribution"],
        "feeValue": estimate.get("feeValue") or estimate.get("fee_value") or 0,
    }
    if estimate.get("messageAllocations") is not None:
        fees["messageAllocations"] = estimate["messageAllocations"]
    return fees


def _tx_hash_hex(tx_hash: Any) -> str:
    h = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
    return h if h.startswith("0x") else "0x" + h


class Chain:
    """One account, one (optional) contract."""

    def __init__(self, account, address: str | None = None):
        self.account = account
        self.address: Any = cast(ChecksumAddress, address) if address else None
        self.client = create_client(chain=studio_devnet, endpoint=RPC_URL, account=account)

    # -- accounts
    def balance(self, who: str | None = None) -> int:
        def call():
            r = self.client.provider.make_request("eth_getBalance", [who or self.account.address, "latest"])
            return int(r.get("result", "0x0"), 16)

        return _retry(call)

    def ensure_funded(self, target_wei: int) -> int:
        have = self.balance()
        if have < target_wei:
            _retry(lambda: self.client.fund_account(self.account.address, target_wei - have + 1))
            have = self.balance()
        return have

    # -- fees
    def _fees(self, method: str | None, args: list, value: int) -> dict:
        """Simulation-based estimate for a write when possible, else the SDK's
        policy-derived estimate (a failed simulation says nothing about the real
        transaction, which carries a real block clock)."""
        if method is not None and self.address:
            try:
                est = _retry(
                    lambda: self.client.estimate_transaction_fees_for_write(
                        self.address, method, args=args, value=value
                    ),
                    attempts=1,
                )
                return _fees_from(est)
            except ChainError:
                pass
        return _fees_from(_retry(lambda: self.client.estimate_transaction_fees()))

    # -- reads
    def read(self, method: str, *args) -> Any:
        return _retry(lambda: self.client.read_contract(self.address, method, args=list(args)))

    # -- writes
    def _await(self, tx_hash, label: str) -> dict:
        print(f"    tx {label}: {_tx_hash_hex(tx_hash)} -> waiting for consensus...", flush=True)
        receipt = _retry(
            lambda: cast(dict, self.client.wait_for_transaction_receipt(
                tx_hash, wait_until="decided", interval=4, retries=150,  # type: ignore[reportCallIssue]
            )),
            attempts=3,
        )
        tx = _retry(lambda: cast(dict, self.client.get_transaction(tx_hash)))
        return {"receipt": receipt, "tx": tx, "tx_hash": _tx_hash_hex(tx_hash)}

    def write(self, method: str, *args, value: int = 0, label: str = "", allow_exec_failure: bool = False) -> dict:
        """Submit a write and block until consensus decides it. Submissions are
        never retried: a duplicate would double-spend a bond."""
        fees = self._fees(method, list(args), value)
        tx_hash = _retry(
            lambda: self.client.write_contract(self.address, method, args=list(args), value=value, fees=fees),
            attempts=1,
        )
        out = self._await(tx_hash, label or method)
        out["consensus"] = describe_consensus(out["receipt"], out["tx"])
        out["returned"] = decoded_return(out["tx"])
        c = out["consensus"]
        print(f"      -> exec={c['execution']} consensus={c['result_name']} votes={c['votes']}", flush=True)
        if not allow_exec_failure:
            if c["execution"] not in (None, OK_EXEC):
                raise ChainError(f"{label or method} execution failed ({c['execution']})")
            if c["result_name"] not in (None, OK_CONSENSUS):
                raise ChainError(f"{label or method} consensus {c['result_name']}")
        return out

    def deploy(self, code: bytes, args: list | None = None) -> dict:
        fees = self._fees(None, [], 0)
        tx_hash = _retry(lambda: self.client.deploy_contract(code=code, args=args or [], fees=fees), attempts=1)
        out = self._await(tx_hash, "deploy")
        out["consensus"] = describe_consensus(out["receipt"], out["tx"])
        return out


# ------------------------------------------------------------- tx inspection
def _find(d: Any, *names: str) -> Any:
    """First value for any of `names`, searched breadth-first through nested
    dicts: the receipt and transaction spell fields in camelCase or snake_case
    depending on the SDK path."""
    queue = [d]
    while queue:
        cur = queue.pop(0)
        if isinstance(cur, dict):
            for n in names:
                if n in cur and cur[n] is not None:
                    return cur[n]
            queue.extend(v for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            queue.extend(v for v in cur if isinstance(v, (dict, list)))
    return None


def describe_consensus(receipt: dict, tx: dict) -> dict:
    """The validator-consensus facts for one transaction.

    Studio Next runs five validators and stops collecting once a quorum agrees:
    the proposing leader and any validator not needed are recorded as `idle`,
    not as `agree`. So `no_dissent` means "nobody voted disagree or timed out
    and a quorum agreed" -- it does NOT mean all five validators voted agree,
    and the raw per-validator votes are kept so a reader can check."""
    consensus = tx.get("consensus_data") or {}
    votes_raw = consensus.get("votes") or _find(receipt, "votes") or {}
    votes = {str(k): str(v).upper() for k, v in votes_raw.items()} if isinstance(votes_raw, dict) else {}
    tally: dict[str, int] = {}
    for v in votes.values():
        tally[v] = tally.get(v, 0) + 1

    state_hashes: list[str] = []
    leader_hash = None
    for leader in consensus.get("leader_receipt") or []:
        h = leader.get("contract_state_hash")
        if h:
            leader_hash = leader_hash or h
            state_hashes.append(h)
    for val in consensus.get("validators") or []:
        h = val.get("contract_state_hash")
        if h:
            state_hashes.append(h)

    result_name = tx.get("result_name") or _find(receipt, "result_name", "resultName")
    return {
        "execution": _find(receipt, "txExecutionResultName", "tx_execution_result_name") or tx.get("txExecutionResultName"),
        "result_name": result_name,
        "leader": tx.get("last_leader"),
        "votes": tally,
        "votes_by_validator": votes,
        "validators": len(votes),
        "no_dissent": tally.get("AGREE", 0) >= 3 and not tally.get("DISAGREE") and not tally.get("TIMEOUT"),
        "leader_state_hash": leader_hash,
        "state_hashes": sorted(set(state_hashes)),
        "state_hashes_identical": len(set(state_hashes)) == 1,
        "rotations": tx.get("rotation_count"),
    }


def decoded_return(tx: dict) -> str | None:
    """The value the contract returned as agreed by consensus (a bare string
    token such as a verdict). GenVM marks a return payload with a leading `|`."""
    consensus = tx.get("consensus_data") or {}
    for leader in consensus.get("leader_receipt") or []:
        res = leader.get("result")
        value: str | None = None
        if isinstance(res, str):
            value = res
        elif isinstance(res, dict):
            payload = res.get("payload")
            if isinstance(payload, str) and payload:
                value = payload
            elif isinstance(res.get("raw"), str) and res["raw"]:
                try:
                    value = base64.b64decode(res["raw"]).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    value = None
        if value:
            return value.lstrip("|").strip("\x00-\x1f ")
    return None


def explorer_tx(tx_hash: str) -> str:
    return f"{EXPLORER}/tx/{tx_hash}"


def explorer_address(addr: str) -> str:
    return f"{EXPLORER}/address/{addr}"


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
