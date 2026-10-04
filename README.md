# PhishPatrol

**An autonomous on-chain phishing firewall and scam-domain adjudication oracle on GenLayer.**

Wallets, DeFi gateways and security researchers query one view, `is_phishing(host_or_url)`, and get a verdict that a quorum of independent validators reached by fetching the suspect page, reading it, and scoring it. Brands fund bounty pools and are verified by the governor; anyone can report a suspect URL against a verified brand by posting a bond; every pending report settles independently; honest reporters are paid, false reporters are slashed, wrongly listed hosts can be appealed, and every wei is accounted for.

The repository is the contract, its test suite, the deployment and live-verification scripts and the on-chain proof, plus a demo web interface in [`frontend/`](frontend/) (Next.js) that reads the live contract: a Spotlight-style domain checker, brand vaults, a validator feed with consensus telemetry, a report sheet and a reward widget. See [`frontend/README.md`](frontend/README.md).

| | |
|---|---|
| Contract | [`contracts/phish_patrol.py`](contracts/phish_patrol.py) |
| Network | GenLayer Studio Next, chain `61997` |
| Live instance | `0x2f74318e2E0FA48B1665007Cc3210d6b3a141f9e` ([explorer](https://explorer-studio-next.genlayer.com/address/0x2f74318e2E0FA48B1665007Cc3210d6b3a141f9e)) |
| Deployment record | [`deployments/studio-next.json`](deployments/studio-next.json) |
| Tests | 321 direct-mode tests, 6,427 executed assertions, `genvm-lint` clean |
| Interface | [`frontend/`](frontend/): `pnpm install && pnpm dev` |

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
| Brand owner | `register_brand` with official domains and a seed of at least 0.5 GEN; `fund_bounty` to top up (owner and governor only) | Pool compensates them for slashed false reports. The brand must be verified before it can be reported against |
| Reporter | `report_phishing(brand_id, url)` with a bond of `max(0.1 GEN, 2% of pool)` | Confirmed: bond back plus 20% of the pool (cap 1 GEN). Rejected: half the bond slashed to the brand, half to the vault. Void: 20% fee |
| Keeper | Anyone calls `adjudicate_report` on any pending report | Nothing; it is a public good, so settlement cannot be captured |
| Governor | `verify_brand` / `unverify_brand`, `unblacklist_host`, `sweep_vault`, `transfer_governor`, may `deactivate_brand` and fund any pool | Cannot touch bonds or credits |
| Appellant | `appeal_blacklist(host)` with a 0.5 GEN bond | Wins: entry removed, bond back. Loses: bond slashed 50/50 |
| Integrator | Reads `is_phishing` | Free view |

**Lifecycle of a report**

```
report_phishing ──► PENDING (bond locked; brand must be verified)
                       │
                       ▼ adjudicate_report (any pending report, any order)
        every validator fetches the page and runs the same pipeline
                       │
      ┌────────────────┼─────────────────────┬──────────────────┐
      ▼                ▼                     ▼                  ▼
 CONFIRMED_PHISHING  REJECTED_FALSE_POSITIVE  AMBIGUOUS_VOID   EXEC_FAILURE
 host blacklisted    bond slashed 50/50       80/20 refund     counted, stays pending
 bond + reward paid                                                │
                                                                   ▼ 2h (reporter/governor) or 24h (anyone)
                                                              void_stale_report: 100% refund
```

**Public surface** (26 methods, 13 views and 13 writes)

| Method | Kind | Notes |
|---|---|---|
| `register_brand(brand_name, canonical_domains)` | payable | seed ≥ 0.5 GEN; starts **unverified** (verified at once if the governor registers); returns `brand_id` (1-based) |
| `verify_brand(brand_id)` / `unverify_brand(brand_id)` | write | governor only |
| `fund_bounty(brand_id)` | payable | brand owner or governor only (`ERR_NOT_BRAND_OWNER`); `ERR_CHALLENGE_IN_PROGRESS` while any report against the brand is pending |
| `report_phishing(brand_id, suspect_url)` | payable | verified brands only (`ERR_BRAND_UNVERIFIED`); bond `max(0.1, 2%·pool)`; excess credited back; the target brand's own domains are exempt (`ERR_OFFICIAL_DOMAIN`) |
| `adjudicate_report(report_id)` | write | any pending report, in any order; returns the verdict |
| `void_stale_report(report_id)` | write | after 2 h by the reporter or governor, after 24 h by anyone; full refund |
| `appeal_blacklist(host)` | payable | 0.5 GEN bond; re-adjudicates the host now (§8.9) |
| `unblacklist_host(host)` | write | governor review (§8.9) |
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
| A rogue leader attaching fabricated scores or reasoning to the right verdict | Validators check the leader's scores against their own measurements (±25 each) and bound and sanitise the reasoning | The reasoning text is the leader's own commentary and is not verified (§8.6) |
| Head-of-line stall | There is no queue gate: any pending report is adjudicated independently, so a stuck page blocks nothing. `void_stale_report` frees a stuck bond after 2 h (reporter/governor) or 24 h (anyone) | A report may wait up to 2 h for a keeper; the reporter can adjudicate it themselves at once |
| Bond / reward ratio gaming | `fund_bounty` frozen while a report is pending and restricted to the brand owner or governor; bond fixed at report time | A griefer can hold a brand's funding frozen (§8.5) |
| Funder theft via `deactivate_brand` | Strangers cannot deposit into a pool, so deactivation can only return the owner's own deposits plus the brand's share of slashed bonds | The governor can also fund a pool; that money goes to the owner on deactivation |
| Duplicate-report farming | One pending report per host; reports against a blacklisted host *or any subdomain of it* revert | |
| False-positive harassment | 50% of the bond slashed to the target brand | |
| Brand squatting and weaponising the oracle: registering a legitimate dApp's name and reporting its rivals | Brands start unverified and cannot be reported against until the governor calls `verify_brand`; names and domains unique; the governor can `deactivate_brand` a squatter | The governor must check ownership off-chain (§8.5, §8.9) |
| Erroneous blacklist entry | `appeal_blacklist` (0.5 GEN, re-adjudicated by validators) and governor `unblacklist_host` | A cloaking page can win an appeal (§8.9) |
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
5. **Validator agreement.** A validator accepts the leader's result only if (a) the leader's scores are integers in 0-100 and derive the leader's own verdict, (b) the leader's reasoning is at most 600 characters with no markup, (c) the validator, running the whole pipeline itself, reaches the **same verdict**, and (d) each of the leader's three scores is within **25 points** of the validator's own. A rogue leader therefore cannot attach invented scores to the right verdict. An exact hash of the scores would be stricter but would make validators disagree on ordinary model variance, so a tolerance is used. `EXEC_FAILURE` counts as a verdict: two validators that both cannot score the page agree that it cannot be scored, while a validator that can scores it and disagrees, which forces a rotation.

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
| `appeal_blacklist` (v ≥ A), page cleared | +v | | | +v | | 0 |
| `appeal_blacklist`, denied | +v | +⌊A/2⌋ | | +(v−A) | +(A−⌊A/2⌋) | 0 |
| `appeal_blacklist`, inconclusive (f = ⌊A/5⌋) | +v | | | +(v−f) | +f | 0 |
| `appeal_blacklist`, model failure | +v | | | +v | | 0 |
| `deactivate_brand` (pool P) | | −P | | +P | | 0 |
| `pull_withdraw` (A) | −A | | | −A | | 0 |
| `sweep_vault` (A) | −A | | | | −A | 0 |
| `EXEC_FAILURE`, `verify_brand`, `unblacklist_host`, views, `transfer_governor` | | | | | | 0 |

Every row sums to zero, so (I) is preserved. In `pull_withdraw` and `sweep_vault` the bucket is debited *before* the transfer is queued, and the debit is restored if queuing raises. ∎

**Evidence.** The test fixture keeps an *independent* ledger (value attached to successful payable calls minus value withdrawn) and, after every state-changing call, asserts the contract's buckets equal it. A seeded random walk of 200 operations, covering registers, funds, reports, all four adjudication outcomes, stale voids, withdrawals, sweeps, deactivations and clock jumps, asserts (I) after every step and drains to a final state with only the brand pools left. Live, the identity held after every case on Studio Next (`solvent: True` in each case record).

**Caveat on delivery (§8.7).** (I) is an identity over *accounted* value. On Studio Next a withdrawal's transfer is not delivered, so `balance` stays above the right-hand side by exactly the undelivered amount. That is a surplus, never a deficit: no credit is ever under-collateralised.

---

## 7. Integration guide

### A GenLayer contract (wallet gateway, DeFi router, intent solver)

```python
import genlayer as gl
from genlayer import Address

PHISH_PATROL = Address("0x2f74318e2E0FA48B1665007Cc3210d6b3a141f9e")  # your instance

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
oracle = "0x2f74318e2E0FA48B1665007Cc3210d6b3a141f9e"

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
* **First-come registration, governor verification.** Anyone can register a brand name and domains with 0.5 GEN, so a squatter can take "Uniswap" first. The squatter's brand is *unverified*: it cannot be reported against and nothing about it is presented as authentic by the frontend, but it does hold the name until the governor calls `deactivate_brand`, which returns only the squatter's own pool. The contract cannot prove domain ownership, so verification is the governor's off-chain judgement and the governor is a trusted role.
* **Funding freeze as griefing.** While any report against a brand is pending, `fund_bounty` and `deactivate_brand` revert for that brand. A griefer can keep a report pending, at the cost of a bond that is refunded minus the void fee.
* **Governor** can verify and unverify brands, unblacklist hosts, sweep the vault, rotate the governor key, deactivate any brand and fund any pool. It cannot touch bonds or credits.
* **Official-domain exemption is scoped to the targeted brand and exact.** A report against Uniswap for `metamask.io` is accepted and adjudicated (the reporter bears the cost of a mistake), `evil.uniswap.org` is not exempt unless listed, and a squatter's claimed domains shield nothing.
* **Only the owner can fund a pool.** This stops a stranger's deposit being handed to the owner by `deactivate_brand`. The pool legitimately also contains half of every slashed false-positive bond, which deactivation returns to the owner; that is the brand's compensation, not a stranger's money.

### 8.6 Consensus and model boundaries

* The verdict is a deterministic function of three model-supplied integers, which narrows but does not remove model variance. A borderline page can make validators disagree; the result is a leader rotation, and after repeated failure an undetermined transaction.
* **`EXEC_FAILURE`** (unusable model output) is persisted and counted. Validator *deadlocks* leave no trace, so liveness rests on `void_stale_report`: a report pending for 2 hours can be voided with a full refund by its reporter or the governor, and after 24 hours by anyone. Because voiding is open to a stranger only after 24 hours, a hostile party cannot void a report merely to keep a host off the list; any reporter can also adjudicate their own report immediately, which closes the same window from the other side.
* **The leader's reasoning text is not verified.** Scores are bounded against each validator's own measurement, but the stored reasoning is the leader's commentary, length-bounded and markup-free. Treat it as explanation, not evidence; the scores and the page are the evidence.
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

### 8.9 Verified brands and the appeal path

**Verified-brand protection.** A brand is registered by its owner but starts *unverified*. Until the governor calls `verify_brand`, `report_phishing` against it reverts with `ERR_BRAND_UNVERIFIED`. This closes the weaponisation path in which someone registers a legitimate dApp's name, then reports that dApp's rivals so the oracle blacklists them. A brand the governor registers itself is verified immediately; `unverify_brand` revokes it. The contract cannot prove who owns a brand or domain, so verification is the governor's off-chain check and the governor is a trusted role. Registration stays open and permissionless; verification is what gates the oracle.

**Appeals.** A blacklist entry is not permanent:

| Path | Who | What happens |
|---|---|---|
| `appeal_blacklist(host)` | anyone, 0.5 GEN bond | Validators re-read the page now, in one transaction. Cleared: entry removed, bond returned. Still phishing: appeal denied, bond slashed 50/50 (the original brand's pool, or the vault if that brand is retired). Unreachable: inconclusive, 20% fee kept, entry stays. Model failure: nothing changes, bond returned. Any overpayment is credited back. |
| `unblacklist_host(host)` | governor | Direct removal after off-chain review. |

Limits worth knowing:

* **Identity is not checked.** The contract cannot tell a domain's owner from anyone else, so the bond is the gate. A cleared page wins the appeal whoever submits it.
* **Appeals inherit the cloaking weakness (§8.2).** A phishing kit that shows validators a clean page can win an appeal and be removed, then switch back. The only remedy is a new report, which costs a new bond, and the original reporter's reward is not clawed back.
* **A takedown does not clear a listing.** An unreachable page is inconclusive, so a host stays listed while offline.
* **Only an exact listed host can be appealed.** A subdomain covered by a listed parent is appealed through the parent. Removing a parent frees its subdomains.
* **History is kept.** The report stays `CONFIRMED` and is flagged `overturned`.

---

## 9. Tests, mutation testing and lint

```bash
uv venv --python 3.12 && uv pip install --prerelease=allow -r requirements.txt
.venv/bin/python -m pytest -q            # 321 passed in ~25 s
.venv/bin/genvm-lint check contracts/phish_patrol.py
```

* **321 tests, 6,427 executed passing assertions** (counted with pytest's assertion-pass hook; the requirement was ≥ 180). The suite runs the real contract in-process with web and LLM mocked.
* **Canonicalisation:** 26 accepted and 84 rejected URL forms across every category in §4, idempotence, userinfo smuggling.
* **Registration, funding, reporting:** every bound and error code, name and domain uniqueness, dynamic-bond table, overpayment credit, owner-only funding.
* **Verified brands and scoped domains:** unverified brands refuse reports, only the governor verifies, a squatter cannot weaponise the oracle, the official-domain exemption is per target brand and a squatter's claimed domains shield nothing.
* **Appeals:** cleared, denied, inconclusive and model-failure outcomes with exact wei movement, overpayment, retired brands, governor unblacklisting, subdomain handling.
* **Adjudication:** the confirmed, rejected and void paths with exact wei movement, odd-bond conservation, the reward cap boundary, 16 score-boundary cases, label-ignoring, score coercion, prompt contents, sanitisation, 11 non-2xx statuses, unreachable host, empty and 4 MiB ± 1 payloads.
* **Independent settlement, freeze, stale reports:** any pending report settles in any order, a stuck page blocks nothing, freeze release, the 2-hour reporter window and 24-hour public window to the second, per-report stale clocks, pending-counter bookkeeping.
* **Validators:** agreement, disagreement, forged leader output, leader error, agreement on failure, and the score-tolerance binding (±25 per dimension, exact edges), score types and reasoning bounds.
* **Solvency:** the independent ledger asserted after every call, and the 260-step random walk (now including verification, owner funding, appeals, governor unblacklisting and stale voids).
* **Atomicity:** every expected revert asserts the overview and queue are unchanged.
* **Lint:** a test runs `genvm-lint check` and requires zero errors.

**Mutation testing.** Two rounds of deliberate bugs were injected into copies of the contract. Round one (29 bugs: 50/50 slash → 60/40, reward cap doubled, FIFO check removed, freeze removed, IPv6 allowed, validator always agrees, sweep open to all, and so on) killed 28; the survivor exposed a missing test for which `@` ends userinfo, which was added. Round two targeted the security changes (27 bugs: official check made global again, verification check removed, funding opened to everyone, stranger voiding after 2 hours, tolerance widened or narrowed, reasoning and score-type checks removed, every appeal branch, governor checks removed on `verify_brand` and `unblacklist_host`, auto-verification for everyone, counters not decremented). It killed all but two: one was a malformed mutant that changed nothing, the other exposed a genuine gap (nothing asserted the overview's `pending_count` after settlement), which was closed with new tests. Re-run properly, both are killed.

**What the direct suite cannot show:** real validator agreement, real LLM variance and real network behaviour. That is what §10 is for.

---

## 10. Deployment and live verification

```bash
.venv/bin/python scripts/deploy.py                                    # deploys, writes deployments/studio-next.json
.venv/bin/python scripts/interact_live.py --phish-url <fixture URL>   # the live cases
.venv/bin/python scripts/interact_live.py --only 7                    # the appeal case, once the fixture host is gone
```

Accounts are created fresh for this project on first run (keys in a gitignored `.env`) and funded from the Studio faucet. Nothing reads another project's keystore.

**Deployed:** `0x2f74318e2E0FA48B1665007Cc3210d6b3a141f9e` on Studio Next (chain 61997), deploy transaction `0x693208fa04eefe1c1000f85fef90c7d8c57125ca1f422249c1369ef99d64a63b`. This is the hardened revision with verified brands, independent adjudication, owner-only funding, score-bound validator equivalence and appeals. The earlier instances are kept as `predecessors` in the deployment record. The source submitted in the deploy transaction hashes (SHA-256 `0360d7e8…2529`) to the in-tree `contracts/phish_patrol.py`; the check reads the deploy payload because the explorer's address endpoint no longer returns the source for this instance.

| Case | What ran | Observed |
|---|---|---|
| 1 | Register **Uniswap** (`uniswap.org`, `app.uniswap.org`), 0.5 GEN, then governor `verify_brand` | starts unverified, verified after; pool 0.5 GEN |
| 2 | Register **MetaMask** (`metamask.io`), 0.5 GEN, then verify | brand 2, pool 0.5 GEN |
| 3 | Report a Uniswap-impersonating wallet-drainer fixture | `CONFIRMED_PHISHING`; blacklisted; reporter credited bond + 20% reward = 0.2 GEN; pool 0.5 → 0.4 |
| 4 | Report `https://blog.uniswap.org/` (Uniswap's own benign blog) | `REJECTED_FALSE_POSITIVE`; 0.05 GEN to pool, 0.05 GEN to vault |
| 5 | Report `https://example.com/phishpatrol-uniswap-claim-404` | `AMBIGUOUS_VOID`; 0.02 GEN fee to vault, 0.08 GEN refund credited |
| 6 | Report against an **unverified** brand; fund a pool as a **non-owner** | both transactions end `FINISHED_WITH_ERROR`; no report created, no bond locked, pool unchanged, no stray value left in the contract once the refunds finalize |
| 7 | Appeal the Case 3 host after its fixture host was torn down | `APPEAL_INCONCLUSIVE`; entry stays listed; 0.1 GEN fee to vault, 0.4 GEN refund credited |
| 8 | File two reports, adjudicate the **newer** first | newer settles `REJECTED_FALSE_POSITIVE` while the older stays pending; then the older settles `AMBIGUOUS_VOID`; nothing pending |

Every case asserts the exact ledger delta against the pre-transaction overview. For Case 3 the live validators' own reasoning is stored on-chain, and the host is a tunnel subdomain with no lexical resemblance to Uniswap, so the confirmation rests on the page content, as designed.

**Consensus.** Every transaction finished `FINISHED_WITH_RETURN` (the two refused calls in Case 6 finished `FINISHED_WITH_ERROR`, as intended) with consensus result **`MAJORITY_AGREE`**, zero rotations, and a tally of `{AGREE: 3, IDLE: 2}` with no `DISAGREE` (§8.6 explains `IDLE`). On every transaction the validators that reported a state hash reported the *same* one.

| Case | Step | Tx hash | Votes | State hash |
|---|---|---|---|---|
| deploy | deploy | `0x693208fa04eefe1c1000f85fef90c7d8c57125ca1f422249c1369ef99d64a63b` | AGREE 3, IDLE 2 | `987a0a249934e1b4…` |
| 1 | register_brand | `0xc61fca46a49ef1a9e1906bc63f5eb58482f8d26bfb52d75a5104140c283d96ad` | AGREE 3, IDLE 2 | `1a9f055afb23dff3…` |
| 1 | verify_brand | `0x7377da9a1ee6d889f53551d4c010362394f4ee9776febf84f2c0fe33f5e40294` | AGREE 3, IDLE 2 | `f40255d4c9fe277b…` |
| 2 | register_brand | `0x4ff511404024d9b4f69c8f9e6978407d8ca1bd4ddca7ae24220f6bfa553ce940` | AGREE 3, IDLE 2 | `f677eb04d6c10c66…` |
| 2 | verify_brand | `0xb3726bb60682f69c5d532199d9562f572ef7b3975b29a52ab5e85c13b7b71fdf` | AGREE 3, IDLE 2 | `8bf7c0034c2cf362…` |
| 3 | report_phishing | `0x0f4ce2b15ed5fb9722367b99922e2572afe6f4ae05df1834a6530e127ab77664` | AGREE 3, IDLE 2 | `9812dab9e52a3a2b…` |
| 3 | adjudicate_report attempt 1 | `0x4222babe3f47e6c40644f0f76998e05ae2e438bf08c616a769a07a58330a6d38` | AGREE 3, IDLE 2 | `015ed6fe58d5a0cf…` |
| 4 | report_phishing | `0x81b0ed28ce73df0d88fc3d5b3ba8b848c073693a0cd419cb36999e27d04fc289` | AGREE 3, IDLE 2 | `1ea412d929f0709b…` |
| 4 | adjudicate_report attempt 1 | `0xc47270da57d160e5be38d30d4f0ceff0f58b3c21e6bf0328519b399495e8928e` | AGREE 3, IDLE 2 | `05028feedf4bb32d…` |
| 5 | report_phishing | `0xec03e20c6f01ac0329194a1921a1d585b319bb8a99932b405e043c2dffb4e15e` | AGREE 3, IDLE 2 | `6d9a7659b00d3be7…` |
| 5 | adjudicate_report attempt 1 | `0xc9ee9ed528b52c5e0dc5db6c19903f42d97fe465dd7a1ca044085f6246cd5275` | AGREE 3, IDLE 2 | `64d9e4e36362fb1d…` |
| 6 | report_phishing (unverified brand) | `0x6deb540c3cd3ebaa8769884885f51caf9cd98ed60a09d701410b755a31635c5b` | AGREE 3, IDLE 2 | `2395cd7d7c1a8566…` |
| 6 | fund_bounty (non-owner) | `0x8a14e3d702f519683a24bcba569c47dadd97e11f652108ff977664b525c4ea50` | AGREE 3, IDLE 2 | `2395cd7d7c1a8566…` |
| 7 | appeal_blacklist | `0x7b37c5c6871090f4c1a09e9890e033ef098914138ae401f80602304fdbf6661b` | AGREE 3, IDLE 2 | `2bcb0338e045fbe7…` |
| 8 | report_phishing | `0x6cc8c48a2032e10200ff76e2e59c02bff2b8746f136863128ce065cc816047a8` | AGREE 3, IDLE 2 | `38919ebd9ba8eb89…` |
| 8 | report_phishing | `0x5280fe8801663292e6629712142d798694a63ac204a3e454792ade8281fc69d7` | AGREE 3, IDLE 2 | `12a767506d175b04…` |
| 8 | adjudicate_report attempt 1 | `0xb310bd280c1e8a2b8a379978ae449db26abbd4c7db2b173ab585e3f9c07c9d76` | AGREE 3, IDLE 2 | `89f11444c291d21c…` |
| 8 | adjudicate_report attempt 1 | `0xb451e747eb2f833e431ce746dcaed2c7a8df49ad179dae8949031e832301a497` | AGREE 3, IDLE 2 | `06679c5de30c9a99…` |
| settle | pull_withdraw | `0x5852eec137dcbd236d59dd828ec015f5ab1bcdbfe0c0615e11e6584b96dd851b` | AGREE 3, IDLE 2 | `4d0db315609e2edb…` |
| settle | sweep_vault | `0xb84a05116ae11cacbbf1ec3937048ddf1a29b16700b635f036651e5f0ed24b56` | AGREE 3, IDLE 2 | `2395cd7d7c1a8566…` |

The refused calls and the final `sweep_vault` share a state hash because they leave the contract in the same state as before: a refused call changes nothing, and three inconclusive appeals plus a full withdraw and sweep net back to it. Full state hashes, per-validator votes and explorer links are in [`deployments/studio-next.json`](deployments/studio-next.json).

**Settlement.** The withdraw (1.2 GEN of credits) and sweep (0.3 GEN of vault) were accepted and debited the on-chain balances, but Studio Next skipped both transfers (§8.7), so this instance's final overview reports `solvent: false` with a 2.0 GEN surplus equal to all undelivered payouts. The record says so rather than hiding it. For the same reason the live script checks the solvency identity as a *delta* (`balance − tracked` unchanged by the call under test) rather than as absolute equality.

**Two script details worth knowing.** A fee *simulation* of the appeal runs the contract against the unreachable host and can hang, so Case 7 uses the SDK's policy-based estimate instead. And a reverted payable call's value is refunded at finalization, not at decision, so Case 6 waits for finalization before checking.

**The Case 3 fixture.** A live confirmation needs a page the validators can fetch. [`fixtures/uniswap_claim_fixture.html`](fixtures/uniswap_claim_fixture.html) is inert: no form action, no executing script, no network calls, nothing collected. It was served from a local port through an ephemeral Cloudflare quick tunnel for the duration of the run and then torn down; the tunnel host (now HTTP 530) is the blacklisted host and is the one Case 7 appealed. Nothing was published to any hosting account.

---

## 11. Repository layout and commands

```
contracts/phish_patrol.py        the protocol
tests/conftest.py                Env fixture: independent ledger, atomicity checks, mocks
tests/test_phish_patrol.py       321 tests
scripts/common.py                chain plumbing: accounts, fees, consensus + state-hash extraction
scripts/deploy.py                deploy to Studio Next, write the deployment record
scripts/interact_live.py         the five live cases and settlement
fixtures/uniswap_claim_fixture.html   inert Case 3 page
deployments/studio-next.json     addresses, tx hashes, votes, state hashes, findings
requirements.txt, pyproject.toml pinned toolchain (Python 3.12, genlayer-test 0.30.0rc2, genvm-linter 0.11.1rc2)
```

The test harness pins `GENVM_VERSION=v0.6.0-rc8` (the SDK the linter validates against). Unpinned, every deploy queries GitHub's rate-limited releases API and a test costs ~1.5 s instead of ~0.06 s.
