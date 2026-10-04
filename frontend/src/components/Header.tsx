"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { CHAIN_ID } from "@/lib/config";
import { shortHash } from "@/lib/format";
import { useStore } from "@/lib/store";
import { ClaimWidget } from "./ClaimWidget";
import { Button, cn, Icon, spring } from "./ui";

const NAV = [
  { href: "#inspect", label: "Inspect" },
  { href: "#vaults", label: "Vaults" },
  { href: "#feed", label: "Feed" },
  { href: "#about", label: "About" },
  { href: "#faq", label: "FAQ" },
];

function NetworkPill() {
  const { network } = useStore();
  const map = {
    checking: { dot: "bg-sys-amber animate-pulse", text: "Connecting" },
    online: { dot: "bg-sys-green", text: "Studio Next" },
    offline: { dot: "bg-sys-red", text: "Offline" },
    "wrong-chain": { dot: "bg-sys-amber", text: "Unexpected chain" },
  } as const;
  const m = map[network.status];
  return (
    <div
      className="flex h-9 items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 text-xs font-medium text-zinc-300"
      title={network.block !== null ? `Block ${network.block}` : undefined}
    >
      <span className={cn("h-2 w-2 rounded-full", m.dot)} />
      <span className="hidden sm:inline">{m.text}</span>
      <span className="tabular-nums text-zinc-500">{CHAIN_ID}</span>
    </div>
  );
}

export function Header() {
  const { wallet, connect, claimable } = useStore();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("pointerdown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const hasCredit = wallet.address && claimable !== null && claimable > BigInt(0);

  return (
    <header className="sticky top-3 z-50 mx-auto w-full max-w-6xl px-3 sm:top-4 sm:px-6">
      <div className="glass glass-specular flex h-14 items-center justify-between gap-2 rounded-full bg-zinc-950/40 pl-3 pr-2 sm:pl-4">
        <a href="#top" className="flex items-center gap-2.5 rounded-full outline-none focus-visible:ring-2 focus-visible:ring-sys-blue/70">
          <span className="grid h-8 w-8 place-items-center rounded-[10px] bg-gradient-to-br from-sys-blue to-[#5e5ce6] text-white shadow-[0_6px_16px_-6px_rgb(0_113_227/0.9)]">
            <Icon.shield className="h-[18px] w-[18px]" />
          </span>
          <span className="text-[15px] font-semibold tracking-tight text-zinc-50">PhishPatrol</span>
        </a>

        <nav className="hidden items-center gap-1 md:flex" aria-label="Sections">
          {NAV.map((n) => (
            <a key={n.href} href={n.href} className="rounded-full px-3.5 py-1.5 text-sm text-zinc-400 transition-colors hover:bg-white/[0.06] hover:text-zinc-100">
              {n.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <NetworkPill />
          <div ref={ref} className="relative">
            {wallet.address ? (
              <Button variant="glass" className="h-9 px-3 font-mono text-xs" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-haspopup="dialog">
                {hasCredit && <span className="h-2 w-2 rounded-full bg-sys-green" />}
                {shortHash(wallet.address, 6, 4)}
              </Button>
            ) : (
              <Button variant="primary" className="h-9 px-4" onClick={wallet.connecting ? undefined : connect} disabled={wallet.connecting}>
                {wallet.connecting ? "Connecting…" : "Connect"}
              </Button>
            )}
            <AnimatePresence>
              {open && wallet.address && (
                <motion.div
                  role="dialog"
                  aria-label="Account center"
                  initial={{ opacity: 0, y: -8, scale: 0.96 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -6, scale: 0.97 }}
                  transition={spring}
                  style={{ transformOrigin: "top right" }}
                  className="glass glass-specular absolute right-0 top-12 w-[min(20rem,calc(100vw-1.5rem))] rounded-3xl bg-zinc-950/70 p-5"
                >
                  <p className="text-xs font-medium uppercase tracking-[0.12em] text-zinc-500">Account</p>
                  <p className="mt-1 break-all font-mono text-xs text-zinc-300">{wallet.address}</p>
                  <div className="my-4 h-px bg-white/[0.08]" />
                  <ClaimWidget />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </header>
  );
}
