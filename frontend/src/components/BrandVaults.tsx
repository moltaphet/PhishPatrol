"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useState } from "react";
import { formatGen, parseGen } from "@/lib/format";
import * as pp from "@/lib/phishPatrol";
import { useStore } from "@/lib/store";
import type { Brand } from "@/lib/types";
import { BrandBadge, brandHue } from "./BrandBadge";
import { Button, Chip, GlassCard, Icon, SectionTitle, Skeleton, Spinner, spring } from "./ui";

function Vault({ brand }: { brand: Brand }) {
  const { wallet, connect, refresh, snapshot, toast, openReport } = useStore();
  const [funding, setFunding] = useState(false);
  const [amount, setAmount] = useState("1");
  const [busy, setBusy] = useState(false);
  const hue = brandHue(brand.name);
  const frozen = brand.pending > 0;
  const isOwner = !wallet.address || wallet.address.toLowerCase() === brand.owner.toLowerCase();
  const demo = snapshot?.source === "demo";
  const wei = parseGen(amount);

  async function topUp() {
    if (!wei || wei <= BigInt(0)) return;
    if (demo) {
      toast("blue", "Demo mode: nothing was sent. Connect to the live network to fund a pool.");
      return;
    }
    if (!wallet.address) {
      await connect();
      return;
    }
    setBusy(true);
    try {
      await pp.fundBounty(wallet.address, brand.id, { value: wei });
      toast("green", `Added ${amount} GEN to the ${brand.name} bounty pool.`);
      setFunding(false);
      await refresh();
    } catch (e) {
      toast("red", e instanceof Error && e.message ? e.message.split("\n")[0] : "The top-up could not be sent.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <GlassCard className="flex h-full min-w-[17.5rem] snap-start flex-col overflow-hidden p-0 sm:min-w-0">
      <div
        className="relative p-5 pb-6"
        style={{ background: `radial-gradient(120% 140% at 0% 0%, hsl(${hue} 80% 55% / 0.28), transparent 60%), linear-gradient(180deg, hsl(${hue} 60% 40% / 0.14), transparent)` }}
      >
        <div className="flex items-center justify-between">
          <BrandBadge name={brand.name} size="lg" />
          <Chip tone={!brand.active ? "neutral" : brand.verified ? "green" : "amber"}>
            <Icon.shield className="h-3 w-3" />
            {!brand.active ? "Retired" : brand.verified ? "Protected" : "Pending verification"}
          </Chip>
        </div>
        <h3 className="mt-5 text-xl font-semibold tracking-tight text-zinc-50">{brand.name}</h3>
        <p className="mt-0.5 text-xs text-zinc-400">Active bounty pool</p>
        <p className="text-3xl font-semibold tabular-nums tracking-tight text-zinc-50">
          {formatGen(brand.pool)} <span className="text-base font-medium text-zinc-400">GEN</span>
        </p>
      </div>

      <div className="flex flex-1 flex-col gap-4 p-5 pt-4">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-zinc-500">Official root domains</p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {brand.domains.map((d) => (
              <Chip key={d} className="font-mono">{d}</Chip>
            ))}
          </div>
        </div>
        {frozen && <p className="text-xs text-sys-amber">{brand.pending} report{brand.pending > 1 ? "s" : ""} awaiting adjudication. Funding is frozen until they settle.</p>}

        <div className="mt-auto">
          <AnimatePresence initial={false} mode="wait">
            {funding ? (
              <motion.div key="fund" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={spring} className="space-y-2">
                <div className="flex items-center gap-2 rounded-full border border-white/10 bg-black/20 pl-4 pr-1.5">
                  <input
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    inputMode="decimal"
                    aria-label={`Amount of GEN to add to the ${brand.name} pool`}
                    className="min-w-0 flex-1 bg-transparent py-2 text-sm tabular-nums text-zinc-50 outline-none"
                  />
                  <span className="text-xs text-zinc-500">GEN</span>
                  <Button variant="primary" className="h-8 px-3.5" disabled={!wei || wei <= BigInt(0) || busy} onClick={topUp}>
                    {busy ? <Spinner /> : "Add"}
                  </Button>
                </div>
                <button onClick={() => setFunding(false)} className="w-full text-center text-xs text-zinc-500 hover:text-zinc-300">Cancel</button>
              </motion.div>
            ) : (
              <motion.div key="actions" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={spring} className="flex gap-2">
                <Button variant="glass" className="flex-1" disabled={frozen || !brand.active || !isOwner} onClick={() => setFunding(true)} title={!isOwner ? "Only the brand owner can fund this pool" : frozen ? "Funding is frozen while a report is pending" : undefined}>
                  <Icon.plus className="h-4 w-4" />
                  Top up
                </Button>
                <Button variant="glass" className="flex-1" disabled={!brand.active || !brand.verified} onClick={() => openReport({ brandId: brand.id })} title={!brand.verified ? "This brand has not been verified yet" : undefined}>
                  Report
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </GlassCard>
  );
}

export function BrandVaults() {
  const { snapshot } = useStore();
  return (
    <section aria-labelledby="vaults-title">
      <SectionTitle
        id="vaults"
        eyebrow="Brand protection"
        title="Protection vaults"
        hint={snapshot?.source === "demo" && <Chip tone="amber">Demo data</Chip>}
      />
      <div className="-mx-4 flex snap-x snap-mandatory gap-4 overflow-x-auto px-4 pb-2 scrollbar-none sm:mx-0 sm:grid sm:grid-cols-2 sm:overflow-visible sm:px-0 lg:grid-cols-3 xl:grid-cols-4">
        {snapshot === null
          ? Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-[23rem] min-w-[17.5rem] sm:min-w-0" />)
          : snapshot.brands.length === 0
            ? <p className="text-sm text-zinc-500">No brands are registered yet.</p>
            : snapshot.brands.map((b) => <Vault key={b.id} brand={b} />)}
      </div>
    </section>
  );
}
