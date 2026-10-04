# PhishPatrol frontend

Next.js 16 (App Router), Tailwind v4, Framer Motion, `genlayer-js`. It talks directly to the PhishPatrol contract on GenLayer Studio Next; there is no backend.

```bash
pnpm install
pnpm dev          # http://localhost:3000
pnpm build && pnpm lint
```

## Configuration

| Variable | Default |
|---|---|
| `NEXT_PUBLIC_PHISH_PATROL_ADDRESS` | `0x632B117d0096277a4aA132bCa909d11841a5A225` (the instance in `../deployments/studio-next.json`) |
| `NEXT_PUBLIC_RPC_URL` | `https://studio-next.genlayer.com/api` |

## Structure

| Path | What it is |
|---|---|
| `src/lib/phishPatrol.ts` | Contract client: `isPhishing`, `getReport`, `getBrand`, `getClaimableBalance`, `reportPhishing`, `fundBounty`, `pullWithdraw` |
| `src/lib/validate.ts` | Client-side mirror of the contract's URL canonicaliser and bond formula |
| `src/lib/inspect.ts` | Domain check: official-domain registry, then `is_phishing`, then the covering report |
| `src/lib/store.tsx` | Snapshot polling, wallet, network pill, toasts, demo fallback |
| `src/data/proof.json` | Transaction hashes, votes and state hashes for the live reports, generated from `deployments/studio-next.json` |
| `src/components/*` | Header, Spotlight, VerdictCard, BrandVaults, LiveFeed, ReportSheet, ClaimWidget |

## Behaviour worth knowing

* **Reads need no wallet.** If the RPC cannot be reached, the app switches to clearly labelled demo data so the interface stays explorable. Submissions are then simulated locally and nothing is sent.
* **`genlayer-js` is on the `rc` tag.** 1.1.8 encodes calls in an older calldata layout that Studio Next's contracts reject (`malformed_entry`); 2.0.0-rc.1 works.
* **Writes carry an explicit fee estimate.** Studio Next rejects a transaction with no fee deposit (`FeeValueMustBeNonZero`).
* **Consensus telemetry** in the feed comes from `proof.json` for the reports it covers (votes, state hash, explorer links). The contract does not store transaction hashes, so reports filed later show the stored verdict and scores without a hash.
* **Verified brands.** Only governor-verified brands show as protected or accept reports; an unverified registrant's domains are never shown as authentic. Only a brand's owner can top up its pool, so the Top up button is disabled for other wallets.
* **Withdrawals:** Studio Next currently skips payout transfers, so `Withdraw Rewards` clears the on-chain credit without delivering GEN there. The widget says so. See the root README section 8.7.
* **Scam classes** (Typosquat, Impersonation, Drainer) are derived from the stored scores with the contract's own thresholds (40, 40, 50).
