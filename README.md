# PhishPatrol

**An autonomous on-chain phishing firewall and scam-domain adjudication oracle on GenLayer.**

Wallets, DeFi gateways and security researchers query one view, `is_phishing(host_or_url)`, and get a verdict that a quorum of independent validators reached by fetching the suspect page, reading it, and scoring it. Brands fund bounty pools; anyone can report a suspect URL by posting a bond; reports are adjudicated strictly in order; honest reporters are paid, false reporters are slashed, and every wei is accounted for.

This repository is a pure smart-contract protocol: the contract, its test suite, the deployment and live-verification scripts, and the on-chain proof. There is no frontend.

| | |
|---|---|
| Contract | [`contracts/phish_patrol.py`](contracts/phish_patrol.py) |
| Network | GenLayer Studio Next, chain `61997` |
| Live instance | `0x632B117d0096277a4aA132bCa909d11841a5A225` ([explorer](https://explorer-studio-next.genlayer.com/address/0x632B117d0096277a4aA132bCa909d11841a5A225)) |
| Deployment record | [`deployments/studio-next.json`](deployments/studio-next.json) |
| Tests | 285 direct-mode tests, 4,410 executed assertions, `genvm-lint` clean |

> **Read §8 before integrating.** Studio Next currently *skips* `emit_transfer` payouts, so `pull_withdraw` debits a credit without delivering the GEN on that network. It is documented, reproduced in isolation, and never creates a deficit.

---

## Contents

1. [Protocol overview](#1-protocol-overview)
2. [Threat model](#2-threat-model)
3. [Oracle architecture](#3-oracle-architecture)
4. [Canonicalisation and anti-SSRF](#4-canonicalisation-and-anti-ssrf)
5. [Economics](#5-economics)
6. [Proof of solvency](#6-proof-of-solvency)
7. [Integration guide](#7-integration-guide)
8. [Architectural boundaries and disclosures](#8-architectural-boundaries-and-disclosures)
9. [Tests, mutation testing and lint](#9-tests-mutation-testing-and-lint)
10. [Deployment and live verification](#10-deployment-and-live-verification)
11. [Repository layout and commands](#11-repository-layout-and-commands)

---

## 1. Protocol overview

**Actors**

| Actor | Does | Gets / risks |
|---|---|---|
| Brand owner | `register_brand` with official domains and a seed of at least 0.5 GEN; `fund_bounty` to top up | Pool compensates them for slashed false reports |
| Reporter | `report_phishing(brand_id, url)` with a bond of `max(0.1 GEN, 2% of pool)` | Confirmed: bond back plus 20% of the pool (cap 1 GEN). Rejected: half the bond slashed to the brand, half to the vault. Void: 20% fee |
| Keeper | Anyone calls `adjudicate_report` on the head of the queue | Nothing; it is a public good, so the queue cannot be captured |
| Governor | `sweep_vault`, `transfer_governor`, may `deactivate_brand` | Cannot touch bonds, pools or credits |
| Integrator | Reads `is_phishing` | Free view |

**Lifecycle of a report**

```
report_phishing ──► PENDING (bond locked, queued FIFO)
                       │
                       ▼ adjudicate_report (only the head of the queue)
        every validator fetches the page and runs the same pipeline
                       │
      ┌────────────────┼─────────────────────┬──────────────────┐
      ▼                ▼                     ▼                  ▼
 CONFIRMED_PHISHING  REJECTED_FALSE_POSITIVE  AMBIGUOUS_VOID   EXEC_FAILURE
 host blacklisted    bond slashed 50/50       80/20 refund     counted, stays pending
 bond + reward paid                                                │
                                                                   ▼ 24h + 2 failures (or 7 days)
                                                              void_stale_report: 100% refund
```

**Public surface** (22 methods, 13 views and 9 writes)

| Method | Kind | Notes |
|---|---|---|
| `register_brand(brand_name, canonical_domains)` | payable | seed ≥ 0.5 GEN; returns `brand_id` (1-based) |
| `fund_bounty(brand_id)` | payable | `ERR_CHALLENGE_IN_PROGRESS` while any report against the brand is pending |
| `report_phishing(brand_id, suspect_url)` | payable | bond `max(0.1, 2%·pool)`; excess is credited back |
| `adjudicate_report(report_id)` | write | head of queue only; returns the verdict |
| `void_stale_report(report_id)` | write | head-of-line protection |
| `pull_withdraw()` / `sweep_vault()` | write | pull pattern only |
| `deactivate_brand(brand_id)` / `transfer_governor(hex)` | write | |
| `is_phishing(host_or_url)` | view | the oracle query |
| `get_report` / `get_brand` / `get_queue_state` / `get_protocol_overview` / `check_invariant` / `required_bond` / `claimable_of` / `canonicalize` / `canonical_host` / `blacklist_source` / `get_brand_id_by_domain` / `whoami` | view | |

---

## 2. Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| SSRF via a reported URL: `127.0.0.1`, `[::1]`, `10/8`, `172.16/12`, `192.168/16`, `169.254.169.254`, `0x7f000001`, `2130706433`, `127.1`, `localhost`, `*.internal`, nip.io | Strict canonicaliser rejects them before they reach storage or the fetcher (§4) | DNS names that *resolve* to private IPs (§8.2) |
| URL tricks: `https://uniswap.org@evil.com`, backslashes, userinfo, `:8080`, `//host`, `javascript:` | Last-`@` userinfo handling, backslash/whitespace/control rejection, 443-only, https-only | none known; mutation-tested |
| Homoglyph hosts | Non-ASCII rejected: submit punycode. Leet-folded and punycode lexical signals in the prompt | A punycode lookalike the model scores low |
| Prompt injection from the page | Sanitisation, fencing, code-derived verdict, validator re-derivation | A page that fools every validator's model |
| Queue clogging / head-of-line stall | FIFO with permissionless keepers; `void_stale_report` after 24 h and 2 failures, or 7 days | A cheap griefer can delay the queue for ≤ 24 h per slot |
| Bond / reward ratio gaming | `fund_bounty` frozen while a report is pending; bond fixed at report time | A griefer can hold a brand's funding frozen (§8.5) |
| Duplicate-report farming | One pending report per host; reports against a blacklisted host *or any subdomain of it* revert | |
| False-positive harassment | 50% of the bond slashed to the target brand | |
| Brand squatting: registering "Uniswap" with the attacker's own domains | Names and domains unique; governor/owner `deactivate_brand` releases both | First-come registration (§8.5) |
| Insolvency | Conservation proof (§6), `check_invariant`, a randomised ledger test | Platform payout skip leaves *surplus* (§8.7) |
| Governor abuse | Governor can only sweep the *vault*; it cannot touch pools, bonds or credits | Key compromise can sweep fees and rotate the governor |

---

## 3. Oracle architecture

An adjudication is one equivalence round (`gl.vm.run_nondet`). The leader and every validator run the *same* function independently:

1. **Fetch.** `gl.nondet.web.get(canonical_url)`. A request failure, any non-2xx status (3xx, 4xx, 5xx), an empty body, or a body larger than 4 MiB is `AMBIGUOUS_VOID`, decided by code with no model involved.
2. **Ground truth in code.** Before the model sees anything, the contract computes facts deterministically:
   * *Lexical:* brand name inside the host, the same after leet-folding (`0→o`, `1→l`, `rn→m`, `vv→w`), brand only in a subdomain, hyphenated brand host, punycode labels, an official domain embedded in the host (`uniswap.org.evil.xyz`), and the second-level-label edit distance to each official domain.
   * *Page:* which of 26 drainer/credential signatures occur in the raw body (`setApprovalForAll`, `eth_sign`, `seed phrase`, `unlimited allowance` …), password inputs, brand mentions, script and form counts, and a sanitised subset of response headers.
3. **Model scoring.** The prompt carries those facts plus the page title and visible text, and asks for three integer scores (0-100):

   | Dimension | Question |
   |---|---|
   | `lexical_similarity` | Typo-squatting, deceptive hyphenation or subdomains, homoglyph mimicry of the brand or its official domains |
   | `deceptive_impersonation` | Copying the brand's name, interface prompts or wallet-connect dialogs on an unauthorised host |
   | `malicious_signatures` | Approval traps, drainer patterns, credential or seed-phrase harvesting |

4. **Verdict derived by code.** The model's own label is never read. With `nexus = lexical ≥ 40 or impersonation ≥ 40`:

   ```
   CONFIRMED_PHISHING   if nexus and (malicious ≥ 50 or impersonation ≥ 70)
   REJECTED_FALSE_POSITIVE   otherwise
   ```

   A drainer with no tie to this brand is rejected; a lookalike *name* with a benign page is rejected. Tests pin every boundary (39/40, 49/50, 69/70).
5. **Validator agreement.** A validator accepts the leader's result only if (a) the leader's verdict is consistent with the leader's own scores, and (b) the validator, running the whole pipeline itself, reaches the **same verdict**. Scores and prose may differ. `EXEC_FAILURE` counts as a verdict: two validators that both cannot score the page agree that it cannot be scored, while a validator that can scores it and disagrees, which forces a rotation.

**Prompt-injection hygiene.** Page text is tag-stripped, restricted to printable ASCII, has `<` and `>` removed so no page can forge a closing delimiter, is truncated, and is fenced inside `<untrusted_page>`. Even a fully successful injection can only move scores, and the verdict function plus validator re-derivation bound what scores can do.

**Execution failures are state, not reverts.** If the model returns unusable output, `adjudicate_report` *returns* `EXEC_FAILURE` after incrementing `exec_failures`. A reverted transaction would discard that counter, and `void_stale_report` needs it.

## 4. Canonicalisation and anti-SSRF

`canonicalize(x)` is a pure function of the string. Inputs and outputs:

| Rule | Example |
|---|---|
| Lower-case host, keep path case | `HTTPS://WWW.Evil.COM/Path` → `https://evil.com/Path` |
| Strip userinfo (last `@` wins) | `https://good.com@bad.com@evil.com/` → `evil.com` |
| Strip query and fragment | `evil.com/a?x=1#f` → `https://evil.com/a` |
| Strip **every** leading `www.` (never below two labels) | `www.www.evil.com` → `evil.com`; `www.com` stays |
| HTTPS only; bare hosts read as https | `http://`, `ftp://`, `file://`, `ws://` → `ERR_BAD_SCHEME` |
| Port must be empty or 443 | `:8080`, `:80`, `:0443` → `ERR_BAD_PORT` |
| No raw IPs in any notation, v4 or v6 | dotted, decimal, hex, octal-ish, `[::1]`, `127.1` → `ERR_IP_HOST` |
| No embedded dotted quads | `127.0.0.1.evil.com` → `ERR_IP_HOST` |
| No localhost, reserved suffixes or wildcard-DNS | `localhost`, `*.local`, `*.internal`, `*.lan`, `*.corp`, `*.test`, `*.invalid`, `*.onion`, `nip.io`, `sslip.io` … → `ERR_LOCAL_HOST` |
| FQDN structure | ≥ 2 labels; each 1-63 chars of `[a-z0-9-]`, no edge hyphen, no `--` at positions 3-4 unless `xn--`; total ≤ 253; TLD alphabetic or punycode (`ERR_INVALID_FQDN`) |
| ASCII only | `uniswаp.org` (Cyrillic а) → `ERR_NON_ASCII_HOST`; use `xn--…` |
| Hostile characters | backslash, whitespace, control chars, > 2048 chars → `ERR_INVALID_URL` |

`is_phishing` runs the same canonicaliser but answers **False** (not a revert) for input it rejects, so an integrating contract never bricks on bad input. Integrators that need to *reject* such input should call `canonicalize`, which reverts.

`is_phishing` also answers True for **subdomains of a confirmed host**: blacklisting `evil.com` covers `login.evil.com`. A confirmed *subdomain* does not blacklist its parent.

---

## 5. Economics

All amounts atto-scale (1 GEN = 10¹⁸).

| Constant | Value |
|---|---|
| Minimum brand seed | 0.5 GEN |
| Bond | `max(0.1 GEN, 2% of pool)`, fixed when the report is filed |
| Confirmed | bond refunded 100%, plus `min(20% of pool, 1.0 GEN)` from the pool |
| Rejected | bond slashed: `⌊B/2⌋` to the brand pool, `B − ⌊B/2⌋` to the vault |
| Void | fee `⌊20% · B⌋` to the vault (0.02 GEN at the minimum bond), remainder to the reporter |
| Stale void | 100% refund, no fee |
| Max official domains per brand | 16 |
| Page ceiling | 4 MiB |

Integer division always rounds toward the *vault* (rejected) or the *reporter* (void), and the two parts always sum to the bond, so odd bonds conserve every wei (tested with a 200000000000000001-wei bond).

The reward is a *fraction of the current pool*, so successive rewards shrink geometrically and a pool can never be emptied by confirmations alone.

---

## 6. Proof of solvency

**Claim.** After every transaction,

```
self.balance  ==  total_bounties + total_locked_bonds + total_claimable + protocol_vault        (I)
```

where `total_bounties = Σ brand.bounty_pool`, `total_locked_bonds = Σ bond of PENDING reports`, `total_claimable = Σ claimable_credits`.

**Proof by induction over transactions.** Genesis: all five terms are 0. Assume (I) before a transaction; each method changes the left side by the value it carries in or out and the right side by exactly the same amount:

| Method | Δ balance | Δ bounties | Δ locked | Δ claimable | Δ vault | Net |
|---|---|---|---|---|---|---|
| `register_brand` (value v) | +v | +v | | | | 0 |
| `fund_bounty` (v) | +v | +v | | | | 0 |
| `report_phishing` (v ≥ B) | +v | | +B | +(v−B) | | 0 |
| confirmed | | −R | −B | +(B+R) | | 0 |
| rejected | | +⌊B/2⌋ | −B | | +(B−⌊B/2⌋) | 0 |
| void (fee f = ⌊B/5⌋) | | | −B | +(B−f) | +f | 0 |
| `void_stale_report` | | | −B | +B | | 0 |
| `deactivate_brand` (pool P) | | −P | | +P | | 0 |
| `pull_withdraw` (A) | −A | | | −A | | 0 |
| `sweep_vault` (A) | −A | | | | −A | 0 |
| `EXEC_FAILURE`, views, `transfer_governor` | | | | | | 0 |

Every row sums to zero, so (I) is preserved. In `pull_withdraw` and `sweep_vault` the bucket is debited *before* the transfer is queued, and the debit is restored if queuing raises. ∎

**Evidence.** The test fixture keeps an *independent* ledger (value attached to successful payable calls minus value withdrawn) and, after every state-changing call, asserts the contract's buckets equal it. A seeded random walk of 200 operations, covering registers, funds, reports, all four adjudication outcomes, stale voids, withdrawals, sweeps, deactivations and clock jumps, asserts (I) after every step and drains to a final state with only the brand pools left. Live, the identity held after every case on Studio Next (`solvent: True` in each case record).

**Caveat on delivery (§8.7).** (I) is an identity over *accounted* value. On Studio Next a withdrawal's transfer is not delivered, so `balance` stays above the right-hand side by exactly the undelivered amount. That is a surplus, never a deficit: no credit is ever under-collateralised.

---

## 7. Integration guide

### A GenLayer contract (wallet gateway, DeFi router, intent solver)

```python
import genlayer as gl
from genlayer import Address

PHISH_PATROL = Address("0x632B117d0096277a4aA132bCa909d11841a5A225")  # your instance

class Gateway(gl.contract.Contract):
    @gl.public.write
    def swap(self, dapp_url: str, ...) -> None:
        # Synchronous read of another contract. Do this OUTSIDE any
        # nondeterministic block: cross-contract calls are forbidden inside one.
        oracle = gl.get_contract_at(PHISH_PATROL)
        if oracle.view().is_phishing(dapp_url):
            raise gl.vm.UserError("[EXPECTED] destination is a confirmed phishing host")
        ...
```

### A wallet or backend (genlayer-py)

```python
from genlayer_py import create_client
from genlayer_py.chains import studio_devnet

client = create_client(chain=studio_devnet, endpoint="https://studio-next.genlayer.com/api")
oracle = "0x632B117d0096277a4aA132bCa909d11841a5A225"

def is_blocked(url: str) -> bool:
    return bool(client.read_contract(oracle, "is_phishing", args=[url]))
```

A view needs no account and no fee. `genlayer-js` is the same call (`readContract`).

### Integration checklist

* **Fail closed on input you cannot canonicalise.** `is_phishing` answers `False` for `http://`, raw IPs and junk. Call `canonicalize(url)` first (it reverts on those) if your policy is "https FQDN only".
* **Pass what the user will actually visit.** Userinfo, `www.`, query and fragment are normalised away, so you do not need to pre-clean.
* **Subdomains are covered**, so checking `login.evil.com` hits a confirmed `evil.com`.
* **The oracle is an opinion at a moment (§8.4), not a guarantee.** Absence from the list means "no confirmed report", not "safe". Keep your own heuristics.
* **Pair it with a freshness policy.** A host confirmed today may be cleaned tomorrow; the contract has no un-blacklist, so treat `blacklist_source(url).report_id` and the report's `resolved_at` as inputs to your own TTL.
* **Surface `blacklist_source`** in wallet UIs: it returns the covering host and the report id, so a user can read the validators' reasoning with `get_report`.

---

## 8. Architectural boundaries and disclosures

### 8.1 Static versus dynamic scraping

The oracle fetches the page with a single `gl.nondet.web.get` and analyses the **raw HTML body** and headers. It does **not** execute JavaScript, follow client-side redirects, wait for hydration, or take screenshots. Trade-offs:

* *For:* a plain GET is cheap, bounded (4 MiB) and, being the same request in every validator, far more likely to produce the same body, which is what consensus needs. Drainer signatures usually sit in the shipped HTML or inline script, which static analysis sees.
* *Against:* a page that assembles its drainer at runtime (obfuscated or remote-loaded script, content behind a click) shows the validators a harmless shell. Single-page apps may expose almost no visible text. A visual clone that is mostly images and canvas scores low on text-based impersonation.
* HTTP redirects are the runtime's concern; a 3xx that is not followed reads as a non-2xx and is voided, which is why the live Case 4 uses a page that answers 200 directly.

`gl.nondet.web.render` exists for rendered text but exposes no status, so it is not used for the gate.

### 8.2 Server IP cloaking and DNS SSRF boundaries

* **Cloaking.** Phishing kits routinely serve a benign page to scanners, datacentre IP ranges, headless user agents and non-target geographies, and the real page to victims. Validators fetch from infrastructure that a kit can fingerprint, so a cloaked site can be adjudicated `REJECTED` or `VOID`. The oracle cannot detect cloaking; a `REJECTED` verdict means "the validators saw nothing malicious", not "this host is benign".
* **Redirect-based cloaking and lures.** A link that bounces through a clean host first is judged by what the validators' fetch ends up with.
* **DNS SSRF.** The canonicaliser is a **lexical** gate: it blocks IPs in every notation, `localhost`, reserved suffixes, wildcard-DNS services and embedded quads. It cannot resolve names, so an attacker-controlled public name whose A record points at `10.0.0.5` or `169.254.169.254`, or that rebinds between a check and the fetch, passes it. Defence in depth for that case belongs to the validators' network sandbox; this contract never uses the fetched content for anything but scoring, never returns it, and never follows it into a second request, so the exposure is limited to a blind request from a validator.
* The reported host is stored and fetched as canonicalised, so redirect targets are not re-validated.

### 8.3 What the three dimensions can and cannot see

Typosquat and homoglyph signals are lexical heuristics (edit distance, leet folding, punycode), not a confusables database. A homoglyph registered under a TLD with Unicode rules reaches the contract only as punycode, where `xn--` is flagged but not decoded.

### 8.4 Time-T assessment semantics

A verdict is a statement about **the page as the validators fetched it at adjudication time T**, which is *after* the report time and can be long after: a report waits behind the queue. It is not a statement about the page when it was reported, nor about the future. Consequences: a kit taken down before T is voided (and the reporter pays the 20% fee); a kit that flips behaviour after T stays blacklisted; a page that was clean at T and turned malicious later is not re-checked. There is no re-adjudication or expiry; a host's status changes only through a new report, and a confirmed host cannot be re-reported.

### 8.5 Economic and governance boundaries

* **Bounty farming with decoys.** An actor can build a lookalike page against a brand that others funded, report it, and collect 20% of the pool (cap 1 GEN). The geometric decay bounds the loss per brand but does not remove the incentive. Brands should fund pools they can afford to see paid out.
* **First-come brand registration.** Anyone can register a brand name and domains with 0.5 GEN. A squatter can register "Uniswap" with their own domains; the real owner then cannot register the name until the squatter or the governor calls `deactivate_brand`, which also refunds the squatter's own pool to them. There is no proof of domain ownership.
* **Funding freeze as griefing.** While any report against a brand is pending, `fund_bounty` and `deactivate_brand` revert for that brand. A griefer can keep a report pending, at the cost of a bond that is refunded minus the void fee.
* **Governor** can sweep the vault, rotate the governor key, and deactivate any brand, nothing else.
* **Official-domain match is exact.** `evil.uniswap.org` is not exempt unless listed, and reporting it goes to adjudication.

### 8.6 Consensus and model boundaries

* The verdict is a deterministic function of three model-supplied integers, which narrows but does not remove model variance. A borderline page can make validators disagree; the result is a leader rotation, and after repeated failure an undetermined transaction.
* **`EXEC_FAILURE`** (unusable model output) is persisted and counted. Validator *deadlocks* leave no trace, so `void_stale_report` has a **7-day age backstop** that voids the head report with a full refund even with zero recorded failures. This goes beyond the 24 h + repeated-failure rule and is a deliberate liveness guarantee.
* **Validator vote semantics on Studio Next.** The network runs five validators and stops at quorum. Every recorded transaction shows `{AGREE: 3, IDLE: 2}`: the proposing leader and one validator not needed are `IDLE`. No transaction recorded a `DISAGREE`, but "unanimous" must be read as *no dissent among voting validators*, not "5 of 5 voted AGREE".

### 8.7 Studio Next skips `emit_transfer` payouts

On Studio Next, a contract's `gl.chain.Account(eoa).emit_transfer(value, on="finalized")` reaches the `finalized` phase and is then marked `skipped` with `declaredBudget: 0`; the value returns to the contract and the recipient is not paid. `on="accepted"` fails outright. The SDK's simulated fee allocation is typed `1` while the emitted transfer is typed `0`, and an allocation retyped to `0` is rejected on-chain (`ExternalAllocationInvalid`). The `use_balance` fee mode would draw message fees from the contract's own balance, which would break (I), so it is not used.

This is **not specific to PhishPatrol**: a 12-line contract that only deposits and pays out reproduces it ([`deployments/studio-next.json`](deployments/studio-next.json) → `platform_findings`, with the transaction hashes and the recorded effect). It was also observed on PhishPatrol itself: `pull_withdraw` debited a reporter's 0.28 GEN credit and `sweep_vault` debited the 0.07 GEN vault, both transfers were skipped, and the contract's balance stayed 0.35 GEN above its accounted total.

What this means in practice:

* On this network a withdrawal **clears the on-chain credit without paying** it. Do not point real value at a Studio Next instance.
* The result is a **surplus** (`balance − tracked` > 0), never a deficit, so no outstanding credit is under-collateralised, and `check_invariant()` will read `false` after a withdrawal because it tests strict equality.
* No current method recovers the surplus. A governor-only reinstatement path was considered and **not** added: it would trust the governor and could misfire on a transfer still in flight. If the network's behaviour is fixed, the contract needs no change.

### 8.8 Other boundaries

* The contract has no un-blacklist, appeal or expiry; those are out of scope.
* `Studio Next` finalises in about a minute; payouts and `finalized` effects lag the decided transaction.
* Brand names are matched case- and punctuation-insensitively (`Uni-Swap` collides with `Uniswap`).

---

## 9. Tests, mutation testing and lint

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements.txt
.venv/bin/python -m pytest -q            # 285 passed in ~25 s
.venv/bin/genvm-lint check contracts/phish_patrol.py
```

* **285 tests, 4,410 executed passing assertions** (counted with pytest's assertion-pass hook; the requirement was ≥ 180). The suite runs the real contract in-process with web and LLM mocked.
* **Canonicalisation:** 26 accepted and 84 rejected URL forms across every category in §4, idempotence, userinfo smuggling.
* **Registration, funding, reporting:** every bound and error code, name and domain uniqueness, dynamic-bond table, overpayment credit.
* **Adjudication:** the confirmed, rejected and void paths with exact wei movement, odd-bond conservation, the reward cap boundary, 16 score-boundary cases, label-ignoring, score coercion, prompt contents, sanitisation, 11 non-2xx statuses, unreachable host, empty and 4 MiB ± 1 payloads.
* **FIFO, freeze, head-of-line:** out-of-order revert, shared queue, freeze release, 24 h and 7-day boundaries to the second, head-clock restart.
* **Validators:** agreement, disagreement, forged leader output, leader error, agreement on failure.
* **Solvency:** the independent ledger asserted after every call, and the 200-step random walk.
* **Atomicity:** every expected revert asserts the overview and queue are unchanged.
* **Lint:** a test runs `genvm-lint check` and requires zero errors.

**Mutation testing.** 29 deliberate bugs were injected into a copy of the contract (50/50 slash → 60/40, reward cap doubled, FIFO check removed, freeze removed, bond never unlocked, IPv6 allowed, parent-domain walk removed, validator always agrees, sweep open to all, and so on). The first pass killed 28; the survivor (`rsplit("@")` → `split("@")`, i.e. which `@` ends userinfo) exposed a missing test, which was added, and all 29 are now killed.

**What the direct suite cannot show:** real validator agreement, real LLM variance and real network behaviour. That is what §10 is for.

---

## 10. Deployment and live verification

```bash
.venv/bin/python scripts/deploy.py                       # deploys, writes deployments/studio-next.json
.venv/bin/python scripts/interact_live.py --phish-url <fixture URL>   # the five live cases
```

Accounts are created fresh for this project on first run (keys in a gitignored `.env`) and funded from the Studio faucet. Nothing reads another project's keystore.

**Deployed:** `0x632B117d0096277a4aA132bCa909d11841a5A225` on Studio Next (chain 61997). The deployed bytecode's SHA-256 (`9b2efcb3…322e`), fetched from the explorer, equals the in-tree source's.

| Case | What ran | Observed |
|---|---|---|
| 1 | Register **Uniswap** (`uniswap.org`, `app.uniswap.org`), 0.5 GEN | brand 1, pool 0.5 GEN |
| 2 | Register **MetaMask** (`metamask.io`), 0.5 GEN | brand 2, pool 0.5 GEN |
| 3 | Report a Uniswap-impersonating wallet-drainer fixture | `CONFIRMED_PHISHING`; host blacklisted; reporter credited bond + 20% reward = 0.2 GEN; pool 0.5 → 0.4 |
| 4 | Report `https://blog.uniswap.org/` (Uniswap's own benign blog) | `REJECTED_FALSE_POSITIVE`; 0.05 GEN to pool, 0.05 GEN to vault |
| 5 | Report `https://example.com/phishpatrol-uniswap-claim-404` | `AMBIGUOUS_VOID`; 0.02 GEN fee to vault, 0.08 GEN refund credited |

Every case asserts the exact ledger delta against the pre-transaction overview, and `solvent: True` held after each. For Case 3 the live validators' own reasoning is stored on-chain: *"the page heavily impersonates Uniswap by using the brand name and an 'official airdrop portal' claim, while explicitly requesting a 12/24-word recovery phrase and unlimited approvals, which are hallmark wallet-drainer behaviors"* (scores: lexical 2, impersonation 95, malicious 100). The host is a tunnel subdomain with no lexical resemblance to Uniswap, so the confirmation rests on the page content, as designed.

**Consensus.** Every transaction finished `FINISHED_WITH_RETURN` with consensus result **`MAJORITY_AGREE`**, zero rotations, and a vote tally of `{AGREE: 3, IDLE: 2}` with no `DISAGREE` (see §8.6 for what `IDLE` means). On every transaction the validators that reported a contract state hash reported the *same* one.

| Case | Step | Tx hash | Votes | State hash |
|---|---|---|---|---|
| deploy | deploy | `0xd52a4e014b60aab21caaa6897f69e7281b27d1325aa076f3a895e58243241d29` | AGREE 3, IDLE 2 | `7c8f024add54d80d…` |
| 1 | register_brand | `0x3389148279dcdbc6abc5da4ecffe41e20e63cab142d5f56278d5063beb6eb92e` | AGREE 3, IDLE 2 | `9115768de56b830b…` |
| 2 | register_brand | `0x4fbc4119196a367ac0c8ef5eed9b6dabef2507c6da84cf8329f5b3565c78a632` | AGREE 3, IDLE 2 | `c5df45c23129194b…` |
| 3 | report_phishing | `0xc2df210d4cd0db6034a74626468628b2321bb3a86cf5818fc0e2ae36fa4ca6c9` | AGREE 3, IDLE 2 | `c0a058eb12e2f5bf…` |
| 3 | adjudicate_report | `0x9c356ceaf2ba84f4970c15ccf2cd1b15b543231a01e97350b187d9cf2a8dca34` | AGREE 3, IDLE 2 | `529e0cb9935f8a4b…` |
| 4 | report_phishing | `0xa5c89fbd5d5f9a5bd3c5354a35290fabf1ee7d92f3ffe2e30b87dd7de9194c9c` | AGREE 3, IDLE 2 | `348a304bbdece680…` |
| 4 | adjudicate_report | `0xe8c51595a4cab10860324b37821cbfc04408b7481acd622be142094d78c305cf` | AGREE 3, IDLE 2 | `841acf3d4768da28…` |
| 5 | report_phishing | `0xe98ffecaafeceeec3a907b94d2422e402036198a99836787240263689e13b0b5` | AGREE 3, IDLE 2 | `a5c0f06214827868…` |
| 5 | adjudicate_report | `0xcbc7d841b6d129276ee014da7c56b1fe85d9c844a7481929871cc1f2512f5eb1` | AGREE 3, IDLE 2 | `80254340a98aacfd…` |
| settle | pull_withdraw | `0x788a09e79b700a919365b18f5f01ae2a2f33347ed5f7d2189863bda9826463d4` | AGREE 3, IDLE 2 | `8d387e4caf126b21…` |
| settle | sweep_vault | `0x7fd460d9a8b3804b9e82663d645147a35cd6c564f03cbd4a7fe90952d7b679b4` | AGREE 3, IDLE 2 | `ae6df7a84711ebd5…` |

Full hashes of every state hash, every validator's vote by address, and the explorer links are in [`deployments/studio-next.json`](deployments/studio-next.json).

**Settlement.** The withdraw and sweep transactions were accepted and debited the on-chain credits, but Studio Next skipped both transfers (§8.7). The final live overview therefore reports `solvent: false` with a 0.35 GEN surplus, and the record says so rather than hiding it.

**The Case 3 fixture.** A live confirmation needs a page the validators can fetch. [`fixtures/uniswap_claim_fixture.html`](fixtures/uniswap_claim_fixture.html) is inert: no form action, no executing script, no network calls, nothing collected. It was served from a local port through an ephemeral Cloudflare quick tunnel for the duration of one run and then torn down; the tunnel host (now HTTP 530) is the blacklisted host. Nothing was published to any hosting account.

---

## 11. Repository layout and commands

```
contracts/phish_patrol.py        the protocol
tests/conftest.py                Env fixture: independent ledger, atomicity checks, mocks
tests/test_phish_patrol.py       285 tests
scripts/common.py                chain plumbing: accounts, fees, consensus + state-hash extraction
scripts/deploy.py                deploy to Studio Next, write the deployment record
scripts/interact_live.py         the five live cases and settlement
fixtures/uniswap_claim_fixture.html   inert Case 3 page
deployments/studio-next.json     addresses, tx hashes, votes, state hashes, findings
requirements.txt, pyproject.toml pinned toolchain (Python 3.12, genlayer-test 0.30.0rc2, genvm-linter 0.11.1rc2)
```

The test harness pins `GENVM_VERSION=v0.6.0-rc8` (the SDK the linter validates against). Unpinned, every deploy queries GitHub's rate-limited releases API and a test costs ~1.5 s instead of ~0.06 s.
