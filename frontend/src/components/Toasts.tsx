"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useStore } from "@/lib/store";
import { cn, spring } from "./ui";

const DOT = { green: "bg-sys-green", red: "bg-sys-red", amber: "bg-sys-amber", blue: "bg-sys-blue" } as const;

export function Toasts() {
  const { toasts, dismissToast } = useStore();
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[70] flex flex-col items-center gap-2 px-4" aria-live="polite">
      <AnimatePresence initial={false}>
        {toasts.map((t) => (
          <motion.button
            key={t.id}
            layout
            initial={{ opacity: 0, y: 24, scale: 0.94 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.96 }}
            transition={spring}
            onClick={() => dismissToast(t.id)}
            className="glass pointer-events-auto flex max-w-md items-start gap-3 rounded-2xl bg-zinc-900/70 px-4 py-3 text-left text-sm text-zinc-100"
          >
            <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", DOT[t.tone])} />
            <span>{t.text}</span>
          </motion.button>
        ))}
      </AnimatePresence>
    </div>
  );
}
