"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import { explorerTx } from "@/lib/config";
import { formatGen } from "@/lib/format";
import * as pp from "@/lib/phishPatrol";
import { useStore } from "@/lib/store";
import type { Report } from "@/lib/types";
import { dynamicBond, normalizeInput } from "@/lib/validate";
import { BrandBadge } from "./BrandBadge";
import { Button, cn, Icon, Spinner, spring } from "./ui";

const CONTRACT_ERRORS: [string, string][] = [
  ["ERR_ALREADY_BLACKLISTED", "That domain, or its parent, is already blacklisted."],
  ["ERR_DUPLICATE_REPORT", "A report for that domain is already waiting for adjudication."],
  ["ERR_OFFICIAL_DOMAIN", "That is an official brand domain and cannot be reported."],
  ["ERR_INSUFFICIENT_BOND", "The bond changed. Reopen the sheet to refresh the required amount."],
  ["ERR_BRAND_INACTIVE", "That brand has been retired."],
];
const friendly = (e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  return CONTRACT_ERRORS.find(([c]) => msg.includes(c))?.[1] ?? (msg.split("\n")[0] || "The report could not be sent.");
};

function SheetBody({ onClose }: { onClose: () => void }) {
  const { snapshot, sheet, wallet, connect, refresh, toast, addDemoReport } = useStore();
  const brands = useMemo(() => (snapshot?.brands ?? []).filter((b) => b.active), [snapshot]);
  const [brandId, setBrandId] = useState<number>(sheet.prefill.brandId ?? brands[0]?.id ?? 0);
  const [url, setUrl] = useState(sheet.prefill.url ?? "");
  const [busy, setBusy] = useState(false);
  const [liveBond, setLiveBond] = useState<{ id: number; wei: bigint } | null>(null);
  const demo = snapshot?.source === "demo";

  const brand = brands.find((b) => b.id === brandId) ?? brands[0];
  const parsed = useMemo(() => (url.trim() ? normalizeInput(url) : null), [url]);
  const official = parsed?.ok ? snapshot?.brands.find((b) => b.domains.includes(parsed.host)) : undefined;
  const localBond = brand ? dynamicBond(brand.pool) : BigInt(0);
  const bond = liveBond && brand && liveBond.id === brand.id ? liveBond.wei : localBond;

  // Prefer the contract's own figure so the bond can never be mis-quoted.
  useEffect(() => {
    if (!brand || demo) return;
    let alive = true;
    pp.getRequiredBond(brand.id).then((wei) => alive && setLiveBond({ id: brand.id, wei })).catch(() => undefined);
    return () => { alive = false; };
  }, [brand, demo]);

  const problem = !parsed ? null : !parsed.ok ? parsed.error : official ? `${parsed.host} is an official ${official.name} domain.` : null;
  const ready = Boolean(brand && parsed?.ok && !problem);

  async function submit() {
    if (!ready || !brand || !parsed?.ok) return;
    if (demo) {
      const r: Report = {
        id: Date.now() % 100000, brandId: brand.id, url: parsed.url, host: parsed.host, reporter: wallet.address ?? "0x0",
        bond, status: "pending", verdict: "", reasoning: "", lexical: 0, impersonation: 0, malicious: 0,
        execFailures: 0, timestamp: Math.floor(Date.now() / 1000), resolvedAt: 0,
      };
      addDemoReport(r);
      toast("blue", "Demo mode: this report was simulated locally. Nothing was sent to the chain.");
      onClose();
      return;
    }
    if (!wallet.address) {
      await connect();
      return;
    }
    setBusy(true);
    try {
      if (await pp.isPhishing(parsed.host)) throw new Error("ERR_ALREADY_BLACKLISTED");
      const { hash } = await pp.reportPhishing(wallet.address, brand.id, parsed.url, { value: bond });
      toast("green", `Report submitted and queued for adjudication. ${explorerTx(hash).slice(-12)}`);
      await refresh();
      onClose();
    } catch (e) {
      toast("red", friendly(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-start justify-between gap-4 p-6 pb-2">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight text-zinc-50">Report a suspect URL</h2>
          <p className="mt-1 text-sm text-zinc-400">Validators will read the page and score it. You are bonded until they decide.</p>
        </div>
        <button onClick={onClose} aria-label="Close" className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-white/[0.07] text-zinc-300 transition-colors hover:bg-white/[0.12]">
          <Icon.close className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 space-y-6 overflow-y-auto p-6 pt-4">
        <fieldset>
          <legend className="text-xs font-medium uppercase tracking-[0.12em] text-zinc-500">Targeted brand</legend>
          <div className="mt-3 flex flex-wrap gap-2">
            {brands.map((b) => (
              <button
                key={b.id}
                onClick={() => setBrandId(b.id)}
                aria-pressed={brand?.id === b.id}
                className={cn(
                  "flex items-center gap-2 rounded-full border py-1.5 pl-1.5 pr-3.5 text-sm transition-colors",
                  brand?.id === b.id ? "border-sys-blue/60 bg-sys-blue/15 text-zinc-50" : "border-white/10 bg-white/[0.04] text-zinc-300 hover:bg-white/[0.08]",
                )}
              >
                <BrandBadge name={b.name} size="sm" />
                {b.name}
              </button>
            ))}
          </div>
        </fieldset>

        <div>
          <label htmlFor="suspect" className="text-xs font-medium uppercase tracking-[0.12em] text-zinc-500">Suspect domain or URL</label>
          <input
            id="suspect"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example-claim.xyz"
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            inputMode="url"
            className="mt-3 w-full rounded-2xl border border-white/10 bg-black/25 px-4 py-3.5 font-mono text-sm text-zinc-50 outline-none transition-colors placeholder:text-zinc-600 focus:border-sys-blue/60"
          />
          <div className="mt-2 min-h-5 text-xs">
            {problem ? (
              <p className="text-sys-red" role="alert">{problem}</p>
            ) : parsed?.ok ? (
              <p className="text-sys-green">Will be checked as <span className="font-mono">{parsed.host}</span></p>
            ) : (
              <p className="text-zinc-500">HTTPS only. We strip www, queries and fragments, and block IPs, localhost and private networks.</p>
            )}
          </div>
        </div>

        <div className="rounded-3xl border border-white/[0.08] bg-white/[0.03] p-5">
          <div className="flex items-baseline justify-between">
            <p className="text-sm text-zinc-400">Required bond</p>
            <p className="text-2xl font-semibold tabular-nums text-zinc-50">{formatGen(bond)} <span className="text-sm font-medium text-zinc-500">GEN</span></p>
          </div>
          <p className="mt-1 text-xs text-zinc-500">max(0.1 GEN, 2% of the {brand?.name ?? "brand"} pool)</p>
          <ul className="mt-4 space-y-2 border-t border-white/[0.07] pt-4 text-sm">
            <li className="flex gap-3"><span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-sys-green" /><span className="text-zinc-300">Confirmed: bond refunded plus 20% of the pool, up to 1 GEN.</span></li>
            <li className="flex gap-3"><span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-sys-red" /><span className="text-zinc-300">False positive: half the bond goes to the brand, half to the protocol.</span></li>
            <li className="flex gap-3"><span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-sys-amber" /><span className="text-zinc-300">Unreachable page: a 20% fee is kept, the rest is refunded.</span></li>
          </ul>
        </div>
        {demo && <p className="text-xs text-sys-amber">Demo mode: the network is unreachable. Submitting simulates the flow locally.</p>}
      </div>

      <div className="border-t border-white/[0.07] p-6 pt-4 pb-[max(1.5rem,env(safe-area-inset-bottom))]">
        <Button variant="primary" className="w-full py-3.5 text-[15px]" disabled={busy || (!demo && !wallet.address ? false : !ready)} onClick={submit}>
          {busy && <Spinner />}
          {busy ? "Waiting for the network…" : !demo && !wallet.address ? "Connect wallet to submit" : `Submit report · ${formatGen(bond)} GEN bond`}
        </Button>
      </div>
    </div>
  );
}

export function ReportSheet() {
  const { sheet, closeReport } = useStore();

  useEffect(() => {
    if (!sheet.open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && closeReport();
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [sheet.open, closeReport]);

  // Rendered only after a user action, so reading the viewport here is safe.
  const wide = sheet.open && typeof window !== "undefined" && window.matchMedia("(min-width: 640px)").matches;

  return (
    <AnimatePresence>
      {sheet.open && (
        <>
          <motion.div
            key="scrim"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={closeReport}
            className="fixed inset-0 z-[60] bg-black/50 backdrop-blur-sm"
          />
          <motion.aside
            key="sheet"
            role="dialog"
            aria-modal="true"
            aria-label="Report a suspect URL"
            initial={wide ? { x: "105%" } : { y: "100%" }}
            animate={wide ? { x: 0 } : { y: 0 }}
            exit={wide ? { x: "105%" } : { y: "100%" }}
            transition={{ ...spring, stiffness: 320, damping: 34 }}
            drag={wide ? false : "y"}
            dragConstraints={{ top: 0, bottom: 0 }}
            dragElastic={{ top: 0, bottom: 0.5 }}
            onDragEnd={(_, i) => (i.offset.y > 120 || i.velocity.y > 600) && closeReport()}
            className="glass glass-specular fixed inset-x-0 bottom-0 z-[61] flex max-h-[92dvh] flex-col rounded-t-[32px] bg-zinc-950/75 sm:inset-y-3 sm:bottom-3 sm:left-auto sm:right-3 sm:max-h-none sm:w-[30rem] sm:rounded-[32px]"
          >
            <div className="mx-auto mt-2.5 h-1.5 w-10 shrink-0 rounded-full bg-white/20 sm:hidden" />
            <SheetBody key={`${sheet.prefill.brandId ?? ""}|${sheet.prefill.url ?? ""}`} onClose={closeReport} />
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
