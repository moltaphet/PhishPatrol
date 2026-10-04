"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown } from "lucide-react";
import { useState, type ReactNode } from "react";
import { cn, SectionTitle, spring } from "./ui";

const code = (t: string) => <code className="rounded-md bg-white/[0.08] px-1.5 py-0.5 font-mono text-[13px] text-zinc-200">{t}</code>;

const FAQS: { q: string; a: ReactNode }[] = [
  {
    q: "How does PhishPatrol differentiate authentic mirrors from phishing drainers?",
    a: (
      <>
        <p>Authentic sites are never guessed: a domain is official only if a governor-verified brand registered it, by exact match. Everything else is judged on three signals.</p>
        <ul className="mt-3 list-disc space-y-2 pl-5">
          <li><strong className="font-medium text-zinc-200">Host analysis.</strong> Code measures the edit distance between the suspect&apos;s main label and each official domain, and checks for the brand name inside the host (including look-alike digits and letters), punycode, and an official domain embedded in the host.</li>
          <li><strong className="font-medium text-zinc-200">Impersonation.</strong> Validators read the page title and visible text, and a model scores how closely it copies the brand on an unofficial host. This is a text judgement, not a pixel or DOM comparison.</li>
          <li><strong className="font-medium text-zinc-200">Approval traps.</strong> The raw HTML is scanned in code for 26 drainer and credential-harvesting signatures, such as {code("setApprovalForAll")}, {code("eth_sign")} and &ldquo;seed phrase&rdquo;.</li>
        </ul>
        <p className="mt-3">The verdict is derived from the three scores by code, and validators must reach the same one.</p>
      </>
    ),
  },
  {
    q: "What prevents malicious actors from spamming or DDoSing the validator network?",
    a: (
      <>
        <p>Spam is made expensive rather than impossible. Every report needs a bond of {code("max(0.1 GEN, 2%)")} of the brand&apos;s pool. If the target is unreachable, returns a non-2xx status, is empty, or is over 4 MiB, the report is voided and a 20% bandwidth fee is kept. A false positive loses half its bond to the brand and half to the protocol.</p>
        <p className="mt-3">Only one report per host can be pending, and reports can only target brands the governor has verified. Reports settle independently, so one stuck page never blocks another. A report nobody could settle can be voided with a full refund by its reporter after 2 hours, or by anyone after 24 hours.</p>
      </>
    ),
  },
  {
    q: "Can dApps, wallets, and smart contracts query the oracle directly?",
    a: (
      <>
        <p>Yes. {code("is_phishing(host_or_url)")} is a public view method: no fee and no account. It normalises the input, then answers true if that host, or any parent domain, was confirmed as phishing.</p>
        <p className="mt-3">GenLayer contracts can read it synchronously, and wallets or back ends can call it over RPC. Input that cannot be normalised, such as plain HTTP or a raw IP, returns false instead of reverting, so an integration never breaks on bad input. A false result means &ldquo;no confirmed report&rdquo;, not &ldquo;safe&rdquo;.</p>
      </>
    ),
  },
  {
    q: "What happens if a reported URL goes offline (HTTP 404/500) before adjudication?",
    a: (
      <>
        <p>Validators judge the page as it is when they read it, which can be well after the report. If it is unreachable or answers with any non-2xx status, the report resolves as {code("AMBIGUOUS_VOID")}. Nothing is blacklisted.</p>
        <p className="mt-3">The reporter&apos;s bond is refunded minus the 20% bandwidth fee, so 80% comes back as a credit you collect with {code("pull_withdraw")}.</p>
      </>
    ),
  },
  {
    q: "How do brand owners manage and fund their anti-phishing bounty pools?",
    a: (
      <>
        <p>Call {code("register_brand")} with the brand name, its official domains and a seed of at least 0.5 GEN. Names and domains are unique, and the governor must verify the brand before it can be reported against. Only the owner (or governor) can top the pool up later with {code("fund_bounty")}, so a withdrawal can only ever return the owner&apos;s own deposits plus any slashed-bond share.</p>
        <p className="mt-3">Funding is frozen while any report against the brand is pending, so nobody can change the reward under a reporter who has already posted a bond. It reopens once those reports settle. Half of every slashed false-positive bond also flows into the brand&apos;s pool.</p>
      </>
    ),
  },
];

function Item({ q, a, open, onToggle, id }: { q: string; a: ReactNode; open: boolean; onToggle: () => void; id: string }) {
  return (
    <div className={cn("glass rounded-3xl transition-colors duration-300", open ? "border-white/[0.16] bg-white/[0.06]" : "hover:bg-white/[0.045]")}>
      <h3>
        <button
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={`${id}-panel`}
          id={`${id}-button`}
          className="flex w-full items-center justify-between gap-4 rounded-3xl p-5 text-left outline-none focus-visible:ring-2 focus-visible:ring-sys-blue/70 sm:p-6"
        >
          <span className="text-[15px] font-medium leading-snug tracking-tight text-zinc-100 sm:text-base">{q}</span>
          <motion.span animate={{ rotate: open ? 180 : 0 }} transition={spring} className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-white/[0.07] text-zinc-300">
            <ChevronDown className="h-4 w-4" />
          </motion.span>
        </button>
      </h3>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id={`${id}-panel`}
            role="region"
            aria-labelledby={`${id}-button`}
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ ...spring, stiffness: 300 }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-6 text-sm leading-relaxed text-zinc-400 sm:px-6 sm:text-[15px]">{a}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function FaqSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  return (
    <section aria-labelledby="faq-heading" className="mx-auto max-w-3xl">
      <SectionTitle id="faq" eyebrow="Questions" title="Frequently asked" />
      <span id="faq-heading" className="sr-only">Frequently asked questions</span>
      <div className="space-y-3">
        {FAQS.map((f, i) => (
          <Item key={f.q} id={`faq-${i}`} q={f.q} a={f.a} open={openIndex === i} onToggle={() => setOpenIndex(openIndex === i ? null : i)} />
        ))}
      </div>
    </section>
  );
}
