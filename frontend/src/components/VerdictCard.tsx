"use client";

import { motion } from "framer-motion";
import { formatGen } from "@/lib/format";
import { useStore } from "@/lib/store";
import type { Verdict } from "@/lib/types";
import { BrandBadge } from "./BrandBadge";
import { Button, Chip, GlassCard, Icon, spring } from "./ui";

const enter = { initial: { opacity: 0, y: 14, scale: 0.985 }, animate: { opacity: 1, y: 0, scale: 1 }, exit: { opacity: 0, y: -8 }, transition: spring };

function Bar({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div>
      <div className="flex justify-between text-xs text-zinc-400">
        <span>{label}</span>
        <span className="tabular-nums text-zinc-300">{value}</span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/[0.07]">
        <motion.div className={`h-full rounded-full ${tone}`} initial={{ width: 0 }} animate={{ width: `${value}%` }} transition={{ ...spring, delay: 0.1 }} />
      </div>
    </div>
  );
}

export function VerdictCard({ verdict }: { verdict: Exclude<Verdict, { kind: "invalid" }> }) {
  const { openReport, snapshot } = useStore();

  if (verdict.kind === "authentic") {
    const { brand, host } = verdict;
    return (
      <motion.div {...enter}>
        <GlassCard className="overflow-hidden border-sys-green/25 bg-sys-green/[0.05] p-6 shadow-[0_0_80px_-30px_rgb(52_199_89/0.55)] sm:p-8">
          <div className="flex flex-wrap items-start gap-5">
            <div className="grid h-16 w-16 shrink-0 place-items-center rounded-[22px] border border-sys-green/30 bg-sys-green/15 text-sys-green">
              <Icon.shield className="h-9 w-9" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Chip tone="green">Verified official domain</Chip>
                <Chip>Registered on-chain</Chip>
              </div>
              <h3 className="mt-3 flex items-center gap-3 text-2xl font-semibold tracking-tight text-zinc-50">
                <BrandBadge name={brand.name} size="sm" />
                {brand.name}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-zinc-400">
                <span className="font-mono text-zinc-200">{host}</span> exactly matches an official domain registered by {brand.name}.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                {brand.domains.map((d) => (
                  <Chip key={d} tone={d === host ? "green" : "neutral"} className="font-mono">
                    {d === host && "✓ "}
                    {d}
                  </Chip>
                ))}
              </div>
              <p className="mt-4 text-xs text-zinc-500">Bounty pool protecting this brand: {formatGen(brand.pool)} GEN</p>
            </div>
          </div>
        </GlassCard>
      </motion.div>
    );
  }

  if (verdict.kind === "blacklisted") {
    const { report, covering, host, classes } = verdict;
    return (
      <motion.div {...enter}>
        <GlassCard className="overflow-hidden border-sys-red/30 bg-sys-red/[0.06] p-6 shadow-[0_0_90px_-25px_rgb(255_59_48/0.6)] sm:p-8">
          <div className="flex flex-wrap items-start gap-5">
            <div className="grid h-16 w-16 shrink-0 place-items-center rounded-[22px] border border-sys-red/35 bg-sys-red/15 text-sys-red shadow-[0_0_40px_-8px_rgb(255_59_48/0.7)]">
              <Icon.hazard className="h-9 w-9" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Chip tone="red">Confirmed phishing</Chip>
                {classes.map((c) => (
                  <Chip key={c} tone="red">{c}</Chip>
                ))}
              </div>
              <h3 className="mt-3 break-all font-mono text-xl font-semibold tracking-tight text-zinc-50 sm:text-2xl">{host}</h3>
              <p className="mt-2 text-sm leading-relaxed text-zinc-300">
                Do not connect a wallet or enter a recovery phrase on this site.
                {covering !== host && <> It is covered because its parent domain <span className="font-mono">{covering}</span> was confirmed.</>}
              </p>
              {report && (
                <>
                  {report.reasoning && <p className="mt-4 rounded-2xl border border-white/[0.08] bg-black/20 p-4 text-sm leading-relaxed text-zinc-300">“{report.reasoning}”</p>}
                  <div className="mt-5 grid gap-4 sm:grid-cols-3">
                    <Bar label="Lexical match" value={report.lexical} tone="bg-sys-amber" />
                    <Bar label="Visual mimicry" value={report.impersonation} tone="bg-sys-red" />
                    <Bar label="Drainer signatures" value={report.malicious} tone="bg-[#ff6259]" />
                  </div>
                  <div className="mt-5">
                    <Button
                      variant="glass"
                      onClick={() => {
                        document.getElementById("feed")?.scrollIntoView({ behavior: "smooth" });
                        window.dispatchEvent(new CustomEvent("pp:focus-report", { detail: report.id }));
                      }}
                    >
                      View validator consensus report #{report.id}
                      <Icon.chevron className="h-4 w-4 -rotate-90" />
                    </Button>
                  </div>
                </>
              )}
            </div>
          </div>
        </GlassCard>
      </motion.div>
    );
  }

  // unknown
  const demo = snapshot?.source === "demo";
  return (
    <motion.div {...enter}>
      <GlassCard className="p-6 sm:p-8">
        <div className="flex flex-wrap items-start gap-5">
          <div className="grid h-16 w-16 shrink-0 place-items-center rounded-[22px] border border-sys-amber/30 bg-sys-amber/12 text-sys-amber">
            <Icon.question className="h-9 w-9" />
          </div>
          <div className="min-w-0 flex-1">
            <Chip tone="amber">No verdict on record</Chip>
            <h3 className="mt-3 break-all font-mono text-xl font-semibold tracking-tight text-zinc-50 sm:text-2xl">{verdict.host}</h3>
            <p className="mt-2 max-w-xl text-sm leading-relaxed text-zinc-400">
              This domain is neither an official brand domain nor a confirmed phishing site. That does not mean it is safe. If you think it
              impersonates a protected brand, report it: when validators confirm it you get your bond back plus 20% of the brand&apos;s bounty
              pool, up to 1 GEN.
              {demo && " (Demo data is showing; the network is unreachable.)"}
            </p>
            <Button variant="primary" className="mt-5" onClick={() => openReport({ url: verdict.host })}>
              <Icon.plus className="h-4 w-4" />
              Report this domain
            </Button>
          </div>
        </div>
      </GlassCard>
    </motion.div>
  );
}
