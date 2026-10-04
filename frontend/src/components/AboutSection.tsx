import { Network, Scale, ShieldCheck } from "lucide-react";
import { Chip, GlassCard } from "./ui";

function IconTile({ children, tone }: { children: React.ReactNode; tone: string }) {
  return (
    <span className={`grid h-12 w-12 place-items-center rounded-2xl border border-white/10 ${tone}`}>
      {children}
    </span>
  );
}

/** Bento overview of how the protocol works. Copy mirrors the contract's real behaviour. */
export function AboutSection() {
  return (
    <section aria-labelledby="about-title">
      <div id="about" className="mb-10 scroll-mt-28 text-center">
        <Chip tone="blue" className="tracking-[0.14em]">PROTOCOL ARCHITECTURE</Chip>
        <h2 id="about-title" className="mx-auto mt-5 max-w-2xl bg-gradient-to-b from-white to-zinc-400 bg-clip-text text-3xl font-semibold tracking-tight text-transparent sm:text-5xl">
          Autonomous Web3 Defense
        </h2>
        <p className="mx-auto mt-4 max-w-2xl text-base leading-relaxed text-zinc-400 sm:text-lg">
          A centralised blacklist asks you to trust one operator&apos;s scraper and one operator&apos;s judgement. PhishPatrol replaces it with
          independent validators that each read the page themselves and must reach the same verdict before anything is recorded.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-6">
        <GlassCard className="p-6 sm:p-8 md:col-span-4">
          <IconTile tone="bg-sys-blue/15 text-[#5aa9ff]"><Network className="h-6 w-6" strokeWidth={1.7} /></IconTile>
          <h3 className="mt-6 text-xl font-semibold tracking-tight text-zinc-50 sm:text-2xl">Multi-Validator Equivalence Consensus</h3>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-zinc-400 sm:text-[15px]">
            When a report reaches the front of the queue, the leader and every validator fetch the raw HTML and headers on their own. Each
            runs the same deterministic checks in code, such as host lookalike analysis and a scan for drainer signatures, then asks a model to
            score three threat dimensions. The verdict is computed from those scores by code, and the validators agree only if they reach the
            same one.
          </p>
          <ul className="mt-5 grid gap-2 text-sm text-zinc-300 sm:grid-cols-3">
            {["Raw page and headers", "Lexical and signature checks", "Verdict derived by code"].map((t) => (
              <li key={t} className="rounded-xl border border-white/[0.07] bg-white/[0.03] px-3 py-2 text-center text-xs">{t}</li>
            ))}
          </ul>
        </GlassCard>

        <GlassCard className="p-6 sm:p-8 md:col-span-2">
          <IconTile tone="bg-sys-amber/12 text-sys-amber"><Scale className="h-6 w-6" strokeWidth={1.7} /></IconTile>
          <h3 className="mt-6 text-xl font-semibold tracking-tight text-zinc-50">Game-Theoretic Economic Bonds</h3>
          <p className="mt-3 text-sm leading-relaxed text-zinc-400">
            Every report posts a bond of <span className="font-mono text-zinc-200">max(0.1 GEN, 2%)</span> of the brand&apos;s pool. A confirmed
            report returns the bond plus 20% of the pool, capped at 1 GEN. A false positive is slashed 50/50 between the targeted brand and
            the protocol vault.
          </p>
        </GlassCard>

        <GlassCard className="p-6 sm:p-8 md:col-span-6">
          <div className="grid gap-8 md:grid-cols-2 md:items-center">
            <div>
              <IconTile tone="bg-sys-green/12 text-sys-green"><ShieldCheck className="h-6 w-6" strokeWidth={1.7} /></IconTile>
              <h3 className="mt-6 text-xl font-semibold tracking-tight text-zinc-50 sm:text-2xl">Mathematically Proven Solvency</h3>
              <p className="mt-3 text-sm leading-relaxed text-zinc-400 sm:text-[15px]">
                Every wei sits in exactly one of four buckets, and every settlement only moves value between them. The identity is proved by
                induction over each method and re-checked after every call in a randomised ledger test. Payouts are non-custodial and
                pull-based: you withdraw your own credit; the contract never pushes funds.
              </p>
              <p className="mt-3 text-xs leading-relaxed text-zinc-500">
                Today, Studio Next skips payout transfers, which leaves an undelivered surplus rather than a shortfall, so no credit is ever
                under-collateralised.
              </p>
            </div>
            <div className="rounded-3xl border border-white/[0.08] bg-black/30 p-5 font-mono text-[13px] leading-7 text-zinc-300 sm:p-6 sm:text-sm">
              <p className="text-zinc-500">{"// holds after every transaction"}</p>
              <p><span className="text-sys-green">balance</span> ==</p>
              <p className="pl-4">bounties</p>
              <p className="pl-4">+ bonds</p>
              <p className="pl-4">+ credits</p>
              <p className="pl-4">+ vault</p>
            </div>
          </div>
        </GlassCard>
      </div>
    </section>
  );
}
