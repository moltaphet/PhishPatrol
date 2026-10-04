"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useMemo, useRef, useState } from "react";
import { inspectDomain } from "@/lib/inspect";
import { useStore } from "@/lib/store";
import type { Verdict } from "@/lib/types";
import { normalizeInput } from "@/lib/validate";
import { Icon, Spinner, spring } from "./ui";
import { VerdictCard } from "./VerdictCard";

const EXAMPLES = ["uniswap.org", "metamask.io", "blog.uniswap.org"];

/** Spotlight-style capsule that scans a domain against the live contract. */
export function Spotlight() {
  const { snapshot } = useStore();
  const [q, setQ] = useState("");
  const [result, setResult] = useState<{ key: string; verdict: Verdict } | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const seq = useRef(0);

  const parsed = useMemo(() => (q.trim() ? normalizeInput(q) : null), [q]);
  const key = parsed?.ok ? `${snapshot?.source ?? "?"}:${parsed.host}` : null;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Debounced real-time scan. State is only set from timer / promise callbacks.
  useEffect(() => {
    if (!key || !snapshot || !parsed?.ok) return;
    const my = ++seq.current;
    const timer = setTimeout(async () => {
      setBusyKey(key);
      try {
        const verdict = await inspectDomain(parsed.host, snapshot);
        if (seq.current === my) setResult({ key, verdict });
      } catch {
        if (seq.current === my) setResult({ key, verdict: { kind: "invalid", error: "The network did not answer. Try again in a moment." } });
      } finally {
        if (seq.current === my) setBusyKey(null);
      }
    }, 450);
    return () => clearTimeout(timer);
    // snapshot identity changes on every poll; the source decides live vs demo.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, snapshot?.source]);

  const scanning = key !== null && (busyKey === key || result?.key !== key);
  const shown = result && result.key === key ? result.verdict : null;
  const error = parsed && !parsed.ok ? parsed.error : shown?.kind === "invalid" ? shown.error : null;

  return (
    <div className="mx-auto w-full max-w-3xl">
      <motion.div
        layout
        transition={spring}
        className="glass glass-specular flex h-16 items-center gap-3 rounded-full bg-zinc-950/50 pl-5 pr-3 shadow-[0_30px_80px_-30px_rgb(0_0_0/0.9),0_0_0_1px_rgb(255_255_255/0.02)] focus-within:border-white/20 focus-within:shadow-[0_30px_90px_-30px_rgb(0_113_227/0.55)] sm:h-[72px] sm:pl-6"
      >
        <Icon.search className="h-5 w-5 shrink-0 text-zinc-500" />
        <input
          ref={inputRef}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          autoComplete="off"
          inputMode="url"
          aria-label="Check a domain or URL"
          placeholder="Check a domain or URL"
          className="min-w-0 flex-1 bg-transparent text-lg text-zinc-50 placeholder:text-zinc-500 outline-none sm:text-xl"
        />
        <div className="flex h-8 w-8 shrink-0 items-center justify-center">{scanning && <Spinner className="h-5 w-5 text-zinc-400" />}</div>
        <kbd className="hidden shrink-0 items-center gap-1 rounded-lg border border-white/10 bg-white/[0.05] px-2 py-1 font-sans text-xs text-zinc-400 sm:flex">
          <span className="text-sm" suppressHydrationWarning>{typeof navigator !== "undefined" && !/Mac|iPhone|iPad/.test(navigator.platform) ? "Ctrl " : "⌘"}</span>K
        </kbd>
      </motion.div>

      <div className="mt-3 flex min-h-8 flex-wrap items-center justify-center gap-2 px-2 text-sm">
        {error ? (
          <p className="text-sys-red" role="alert">{error}</p>
        ) : (
          <>
            <span className="text-zinc-500">Try</span>
            {EXAMPLES.map((e) => (
              <button key={e} onClick={() => setQ(e)} className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 font-mono text-xs text-zinc-300 transition-colors hover:bg-white/[0.09]">
                {e}
              </button>
            ))}
          </>
        )}
      </div>

      {/* Fixed-height stage so the verdict never shifts the page below it. */}
      <div className="mt-6 min-h-[9rem] text-left">
        <AnimatePresence mode="wait">
          {shown && shown.kind !== "invalid" ? (
            <VerdictCard key={key} verdict={shown} />
          ) : (
            !error && (
              <motion.p key="hint" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="pt-10 text-center text-sm text-zinc-500">
                Results come straight from the on-chain oracle. Paste any link to see whether validators have flagged it.
              </motion.p>
            )
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
