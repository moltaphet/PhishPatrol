"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import proof from "@/data/proof.json";
import { CONTRACT_ADDRESS, explorerAddress, explorerTx } from "@/lib/config";
import { formatGen, shortHash, timeAgo } from "@/lib/format";
import { classify } from "@/lib/inspect";
import { useStore } from "@/lib/store";
import type { Report, ReportStatus } from "@/lib/types";
import { Chip, cn, GlassCard, Icon, SectionTitle, Skeleton, spring } from "./ui";

const STATUS: Record<ReportStatus, { label: string; tone: "amber" | "red" | "neutral" | "blue"; dot: string }> = {
  pending: { label: "Adjudicating", tone: "amber", dot: "bg-sys-amber animate-pulse" },
  confirmed: { label: "Blacklisted", tone: "red", dot: "bg-sys-red" },
  rejected: { label: "Dismissed", tone: "neutral", dot: "bg-zinc-500" },
  voided: { label: "Voided", tone: "blue", dot: "bg-sys-blue" },
};

type ProofEntry = (typeof proof.reports)[keyof typeof proof.reports];
const proofFor = (id: number): ProofEntry | null =>
  proof.instance.toLowerCase() === CONTRACT_ADDRESS.toLowerCase() ? ((proof.reports as Record<string, ProofEntry>)[String(id)] ?? null) : null;

function Meter({ label, value }: { label: string; value: number }) {
  const tone = value >= 70 ? "bg-sys-red" : value >= 40 ? "bg-sys-amber" : "bg-sys-green";
  return (
    <div>
      <div className="flex justify-between text-xs text-zinc-400">
        <span>{label}</span>
        <span className="tabular-nums text-zinc-200">{value}<span className="text-zinc-600"> / 100</span></span>
      </div>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-white/[0.07]">
        <motion.div className={cn("h-full rounded-full", tone)} initial={{ width: 0 }} animate={{ width: `${value}%` }} transition={{ ...spring, delay: 0.05 }} />
      </div>
    </div>
  );
}

function TxLink({ label, hash }: { label: string; hash: string }) {
  return (
    <a href={explorerTx(hash)} target="_blank" rel="noreferrer" className="group flex items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.03] px-3 py-2 text-xs transition-colors hover:bg-white/[0.07]">
      <span className="text-zinc-400">{label}</span>
      <span className="flex items-center gap-1.5 font-mono text-zinc-200">
        {shortHash(hash)}
        <Icon.external className="h-3.5 w-3.5 text-zinc-500 group-hover:text-zinc-300" />
      </span>
    </a>
  );
}

function Drawer({ report, demo }: { report: Report; demo: boolean }) {
  const p = demo ? null : proofFor(report.id);
  const resolved = report.status !== "pending";
  return (
    <div className="grid gap-6 border-t border-white/[0.07] p-5 sm:grid-cols-2">
      <div>
        <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-zinc-500">Threat analysis</p>
        {resolved ? (
          <div className="mt-3 space-y-4">
            <Meter label="Lexical match" value={report.lexical} />
            <Meter label="Visual mimicry" value={report.impersonation} />
            <Meter label="Drainer signatures" value={report.malicious} />
          </div>
        ) : (
          <p className="mt-3 text-sm text-zinc-400">Waiting for validators. Reports are adjudicated strictly in order, oldest first.</p>
        )}
        {report.reasoning && <p className="mt-4 text-sm leading-relaxed text-zinc-300">“{report.reasoning}”</p>}
      </div>

      <div>
        <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-zinc-500">Validator consensus</p>
        {p ? (
          <div className="mt-3 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="green">{p.consensus}</Chip>
              <Chip>{p.execution.replaceAll("_", " ").toLowerCase()}</Chip>
            </div>
            <p className="text-sm text-zinc-300">
              <span className="tabular-nums">{p.votes.AGREE}</span> agree · <span className="tabular-nums">0</span> disagree ·{" "}
              <span className="tabular-nums">{p.votes.IDLE}</span> idle
            </p>
            <p className="text-xs leading-relaxed text-zinc-500">
              Idle validators were not needed once a quorum agreed. {p.stateHashesIdentical && "Every validator that reported a contract state hash reported the same one."}
            </p>
            <p className="font-mono text-xs text-zinc-500">state {shortHash(p.stateHash ?? "", 10, 8)}</p>
            <div className="space-y-2">
              <TxLink label="Adjudication" hash={p.adjudicationTx} />
              <TxLink label="Report filed" hash={p.reportTx} />
            </div>
          </div>
        ) : (
          <div className="mt-3 space-y-3 text-sm text-zinc-400">
            <p>
              {demo
                ? "Demo data: no on-chain consensus record exists for this sample."
                : resolved
                  ? "Settled by validator consensus on-chain. The contract stores the verdict and scores; the transaction hash lives on the explorer."
                  : "No consensus yet."}
            </p>
            {!demo && (
              <a href={explorerAddress(CONTRACT_ADDRESS)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs text-[#5aa9ff] hover:underline">
                Open the contract on the explorer <Icon.external className="h-3.5 w-3.5" />
              </a>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Row({ report, brandName, open, onToggle, demo }: { report: Report; brandName: string; open: boolean; onToggle: () => void; demo: boolean }) {
  const st = STATUS[report.status];
  const classes = classify(report);
  return (
    <GlassCard id={`report-${report.id}`} className="scroll-mt-28 overflow-hidden rounded-[26px]" glow={false}>
      <button onClick={onToggle} aria-expanded={open} className="flex w-full items-center gap-3 p-4 text-left outline-none focus-visible:ring-2 focus-visible:ring-sys-blue/70 sm:gap-4 sm:p-5">
        <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full", st.dot)} />
        <div className="min-w-0 flex-1">
          <p className="truncate font-mono text-sm text-zinc-100 sm:text-[15px]">{report.host}</p>
          <p className="mt-0.5 truncate text-xs text-zinc-500">
            #{report.id} · {brandName} · {formatGen(report.bond)} GEN bond{report.timestamp ? ` · ${timeAgo(report.timestamp)}` : ""}
          </p>
        </div>
        <div className="hidden items-center gap-1.5 sm:flex">
          {report.status === "confirmed" && classes.map((c) => <Chip key={c} tone="red">{c}</Chip>)}
        </div>
        <Chip tone={st.tone}>{st.label}</Chip>
        <Icon.chevron className={cn("h-4 w-4 shrink-0 text-zinc-500 transition-transform", open && "rotate-180")} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ ...spring, stiffness: 300 }} className="overflow-hidden">
            <Drawer report={report} demo={demo} />
          </motion.div>
        )}
      </AnimatePresence>
    </GlassCard>
  );
}

export function LiveFeed() {
  const { snapshot, network } = useStore();
  const [openId, setOpenId] = useState<number | null>(null);
  const [limit, setLimit] = useState(6);

  useEffect(() => {
    const onFocus = (e: Event) => {
      const id = (e as CustomEvent<number>).detail;
      setOpenId(id);
      setLimit((l) => Math.max(l, 50));
      setTimeout(() => document.getElementById(`report-${id}`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 120);
    };
    window.addEventListener("pp:focus-report", onFocus);
    return () => window.removeEventListener("pp:focus-report", onFocus);
  }, []);

  const demo = snapshot?.source === "demo";
  const brandName = (id: number) => snapshot?.brands.find((b) => b.id === id)?.name ?? `Brand ${id}`;
  const reports = snapshot?.reports ?? [];

  return (
    <section aria-labelledby="feed-title">
      <SectionTitle
        id="feed"
        eyebrow="Adjudication"
        title="Live validator feed"
        hint={
          <div className="flex items-center gap-2">
            {demo && <Chip tone="amber">Demo data</Chip>}
            <Chip tone={network.status === "online" ? "green" : "neutral"}>
              <span className={cn("h-1.5 w-1.5 rounded-full", network.status === "online" ? "animate-pulse bg-sys-green" : "bg-zinc-500")} />
              {network.status === "online" ? "Streaming" : "Paused"}
            </Chip>
          </div>
        }
      />
      <div className="space-y-3">
        {snapshot === null ? (
          Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-[76px] rounded-[26px]" />)
        ) : reports.length === 0 ? (
          <GlassCard className="p-8 text-center text-sm text-zinc-500" glow={false}>No reports have been filed yet.</GlassCard>
        ) : (
          <>
            {reports.slice(0, limit).map((r) => (
              <Row key={r.id} report={r} brandName={brandName(r.brandId)} open={openId === r.id} onToggle={() => setOpenId(openId === r.id ? null : r.id)} demo={demo} />
            ))}
            {reports.length > limit && (
              <button onClick={() => setLimit((l) => l + 6)} className="mx-auto block rounded-full border border-white/10 bg-white/[0.04] px-5 py-2 text-sm text-zinc-300 hover:bg-white/[0.08]">
                Show more
              </button>
            )}
          </>
        )}
      </div>
    </section>
  );
}
