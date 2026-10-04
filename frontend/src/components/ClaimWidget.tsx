"use client";

import { useState } from "react";
import { formatGen } from "@/lib/format";
import * as pp from "@/lib/phishPatrol";
import { useStore } from "@/lib/store";
import { Button, Spinner } from "./ui";

/** Pull-payment balance with a one-tap Withdraw action. */
export function ClaimWidget() {
  const { wallet, claimable, refreshClaimable, snapshot, toast, connect } = useStore();
  const [busy, setBusy] = useState(false);
  const demo = snapshot?.source === "demo";
  const amount = claimable ?? BigInt(0);

  async function withdraw() {
    if (!wallet.address) return;
    setBusy(true);
    try {
      await pp.pullWithdraw(wallet.address);
      toast("green", "Withdrawal accepted. Your credit has been cleared on-chain.");
      await refreshClaimable();
    } catch (e) {
      toast("red", e instanceof Error && e.message ? e.message.split("\n")[0] : "The withdrawal could not be sent.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-[0.12em] text-zinc-500">Reward balance</p>
      <p className="mt-1 text-3xl font-semibold tracking-tight text-zinc-50 tabular-nums">
        {wallet.address ? (claimable === null ? "—" : formatGen(amount, 4)) : "0"}
        <span className="ml-1.5 text-base font-medium text-zinc-500">GEN</span>
      </p>
      {wallet.address ? (
        <Button variant="pay" className="mt-4 w-full py-3 text-[15px]" disabled={busy || demo || amount === BigInt(0)} onClick={withdraw}>
          {busy && <Spinner />}
          Withdraw Rewards
        </Button>
      ) : (
        <Button variant="primary" className="mt-4 w-full py-3" onClick={connect}>
          Connect wallet
        </Button>
      )}
      {demo && <p className="mt-3 text-xs text-zinc-500">Demo mode: the network is unreachable, so withdrawals are disabled.</p>}
      <p className="mt-3 text-xs leading-relaxed text-zinc-500">
        Payouts are pull-based. Note: Studio Next currently skips payout transfers, so a withdrawal clears your on-chain credit
        without delivering the GEN. Use a different network before moving real value.
      </p>
    </div>
  );
}
