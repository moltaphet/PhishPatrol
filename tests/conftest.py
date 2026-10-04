"""Shared fixtures for the PhishPatrol direct-mode suite.

Direct mode runs the real contract bytecode in-process with web and LLM mocked.
Two things it does not model are modelled here, deliberately OUTSIDE the
contract, so the solvency check is a genuine cross-check and not the contract
grading itself:

  * value transfer -- the harness never credits `self.balance` when a payable
    call carries value, and `emit_transfer` never debits it. `Env` mirrors both
    from the caller's side (balance += attached value on a successful payable
    call, balance -= amount on a successful withdrawal), so `balance` is an
    independent ledger of what really flowed in and out.
  * revert atomicity -- every call routed through `Env.rev` asserts the
    protocol overview and queue are byte-identical before and after.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

# Pin the GenVM SDK the harness runs the contract under. Left unpinned, every
# deploy asks the GitHub releases API for the latest version (rate-limited, ~1.5s
# per test, and a moving target for reproducibility). rc8 is the SDK `genvm-lint`
# validates this contract against.
os.environ.setdefault("GENVM_VERSION", "v0.6.0-rc8")

CONTRACT = "contracts/phish_patrol.py"

ATTO = 10**18
SEED = ATTO // 2  # minimum brand seed, 0.5 GEN
MIN_BOND = ATTO // 10  # 0.1 GEN
APPEAL_BOND = ATTO // 2  # 0.5 GEN

# Terminal report statuses.
PENDING, CONFIRMED, REJECTED, VOIDED = 0, 1, 2, 3

V_CONFIRMED = "CONFIRMED_PHISHING"
V_REJECTED = "REJECTED_FALSE_POSITIVE"
V_VOID = "AMBIGUOUS_VOID"
V_STALE = "STALE_VOID"
V_FAIL = "EXEC_FAILURE"

PHISH_HTML = (
    "<html><head><title>Uniswap | Claim Airdrop</title></head><body>"
    "<h1>Uniswap Airdrop</h1><p>Connect wallet to claim airdrop.</p>"
    "<p>Enter your secret recovery phrase to validate wallet.</p>"
    "<form><input type='password' name='seed'></form>"
    "<script>ethereum.request({method:'eth_sign'}); setApprovalForAll(true)</script>"
    "</body></html>"
)
BENIGN_HTML = (
    "<html><head><title>Docs</title></head><body><h1>Developer documentation</h1>"
    "<p>This page explains how automated market makers work.</p></body></html>"
)


def scores(lex, imp, mal, reasoning="Analyst reasoning."):
    """A model reply, double-encoded the way the direct harness expects: the
    harness json.loads() the mock once, and exec_prompt(response_format="json")
    decodes the result again."""
    return json.dumps(json.dumps({
        "lexical_similarity": lex,
        "deceptive_impersonation": imp,
        "malicious_signatures": mal,
        "reasoning": reasoning,
    }))


PHISH_SCORES = (80, 85, 90)
BENIGN_SCORES = (2, 3, 0)


class Env:
    def __init__(self, vm, contract, governor, alice, bob, carol, dave):
        self.vm = vm
        self.c = contract
        self.governor = governor
        self.alice, self.bob, self.carol, self.dave = alice, bob, carol, dave
        self.balance = 0  # independent ledger of value held by the contract
        self.paid_in = 0
        self.paid_out = 0
        self.vm.value = 0

    # ----------------------------------------------------------- invariants
    def ov(self) -> dict:
        return self.c.get_protocol_overview()

    def assert_solvent(self):
        """balance == bounties + locked bonds + claimable + vault, where
        `balance` is the harness-side ledger, and the in-contract view agrees."""
        self.vm.deal(self.vm._contract_address, self.balance)
        o = self.ov()
        assert o["balance"] == self.balance
        assert o["tracked"] == (
            o["total_bounties"] + o["total_locked_bonds"] + o["total_claimable"] + o["protocol_vault"]
        )
        assert o["solvent"] is True
        assert self.c.check_invariant() is True
        assert self.balance == self.paid_in - self.paid_out

    # ---------------------------------------------------------- transactions
    def tx(self, who, fn, *args, value=0, solvent=True):
        self.vm.sender = who
        self.vm.value = value
        try:
            out = getattr(self.c, fn)(*args)
        finally:
            self.vm.value = 0
        self.balance += value
        self.paid_in += value
        if solvent:
            self.assert_solvent()
        return out

    def rev(self, code, who, fn, *args, value=0):
        """Expects a revert whose message contains `code`, and that nothing in
        the protocol state moved."""
        before = (self.ov(), self.c.get_queue_state())
        self.vm.sender = who
        self.vm.value = value
        try:
            with self.vm.expect_revert(code):
                getattr(self.c, fn)(*args)
        finally:
            self.vm.value = 0
        assert (self.ov(), self.c.get_queue_state()) == before

    def try_tx(self, who, fn, *args, value=0):
        """Fuzz helper: attempt a call and roll the harness back on revert, as
        the chain would. Returns (ok, result)."""
        snap = self.vm.snapshot()
        self.vm.sender = who
        self.vm.value = value
        try:
            out = getattr(self.c, fn)(*args)
        except Exception:
            self.vm.revert(snap)
            return False, None
        finally:
            self.vm.value = 0
        self.balance += value
        self.paid_in += value
        return True, out

    # --------------------------------------------------------------- actions
    def register(self, who, name, domains, value=SEED, verify=True):
        """Registers a brand and, by default, has the governor verify it, since
        only verified brands can be reported against."""
        bid = self.tx(who, "register_brand", name, domains, value=value)
        if verify:
            self.tx(self.governor, "verify_brand", bid)
        return bid

    def bond(self, brand_id):
        return self.c.required_bond(brand_id)

    def report(self, who, brand_id, url, value=None):
        if value is None:
            value = self.bond(brand_id)
        return self.tx(who, "report_phishing", brand_id, url, value=value)

    def adjudicate(self, report_id, who=None):
        return self.tx(who or self.dave, "adjudicate_report", report_id)

    def withdraw(self, who):
        amount = self.tx(who, "pull_withdraw", solvent=False)
        self.balance -= amount
        self.paid_out += amount
        self.assert_solvent()
        return amount

    def sweep(self):
        amount = self.tx(self.governor, "sweep_vault", solvent=False)
        self.balance -= amount
        self.paid_out += amount
        self.assert_solvent()
        return amount

    # ------------------------------------------------------------- mocks
    def page(self, url_regex, body=PHISH_HTML, status=200, headers=None):
        resp = {
            "status": status,
            "headers": {k: v.encode() for k, v in (headers or {}).items()},
            "body": body if isinstance(body, bytes) else body.encode(),
        }
        self.vm.mock_web(url_regex, {"method": "GET", "response": resp})

    def llm(self, lex, imp, mal, reasoning="Analyst reasoning."):
        self.vm.mock_llm(r".*", scores(lex, imp, mal, reasoning))

    def llm_raw(self, payload):
        """`payload` is exactly what the harness hands back for the prompt."""
        self.vm.mock_llm(r".*", payload)

    def reset_mocks(self):
        self.vm.clear_mocks()

    def phish_world(self, url_regex=r".*"):
        self.reset_mocks()
        self.page(url_regex, PHISH_HTML)
        self.llm(*PHISH_SCORES)

    def benign_world(self, url_regex=r".*"):
        self.reset_mocks()
        self.page(url_regex, BENIGN_HTML)
        self.llm(*BENIGN_SCORES)

    # ------------------------------------------------------------------ clock
    def now(self) -> int:
        return int(self._vm_time().timestamp())

    def _vm_time(self) -> datetime:
        return datetime.fromisoformat(str(self.vm._datetime).replace("Z", "+00:00")).astimezone(timezone.utc)

    def advance(self, seconds: int):
        later = self._vm_time() + timedelta(seconds=seconds)
        self.vm.warp(later.strftime("%Y-%m-%dT%H:%M:%SZ"))


@pytest.fixture
def env(direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob, direct_charlie, direct_accounts):
    direct_vm.sender = direct_owner  # the deployer becomes governor
    contract = direct_deploy(CONTRACT)
    dave = direct_accounts[4]
    return Env(direct_vm, contract, direct_owner, direct_alice, direct_bob, direct_charlie, dave)


@pytest.fixture
def uni(env):
    """Uniswap registered by alice with the minimum seed; returns its id."""
    return env.register(env.alice, "Uniswap", ["uniswap.org", "app.uniswap.org"])


@pytest.fixture
def uni_meta(env, uni):
    """Uniswap plus MetaMask (carol), the two brands used across the suite."""
    mm = env.register(env.carol, "MetaMask", ["metamask.io"])
    return uni, mm
