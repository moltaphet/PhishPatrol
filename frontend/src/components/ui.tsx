"use client";

import { motion, type HTMLMotionProps } from "framer-motion";
import { useRef, type ReactNode } from "react";

export const spring = { type: "spring", stiffness: 420, damping: 32, mass: 0.8 } as const;

export const cn = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(" ");

/** Frosted glass surface with a specular edge and a cursor-tracking glow. */
export function GlassCard({
  className, children, glow = true, ...rest
}: { className?: string; children: ReactNode; glow?: boolean } & React.HTMLAttributes<HTMLDivElement>) {
  const ref = useRef<HTMLDivElement>(null);
  return (
    <div
      ref={ref}
      onPointerMove={(e) => {
        const el = ref.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        el.style.setProperty("--mx", `${e.clientX - r.left}px`);
        el.style.setProperty("--my", `${e.clientY - r.top}px`);
      }}
      className={cn("glass glass-specular rounded-3xl", glow && "glass-glow", className)}
      {...rest}
    >
      {children}
    </div>
  );
}

type Tone = "green" | "red" | "amber" | "blue" | "neutral";
const TONES: Record<Tone, string> = {
  green: "bg-sys-green/12 text-sys-green border-sys-green/25",
  red: "bg-sys-red/12 text-sys-red border-sys-red/25",
  amber: "bg-sys-amber/12 text-sys-amber border-sys-amber/25",
  blue: "bg-sys-blue/15 text-[#5aa9ff] border-sys-blue/30",
  neutral: "bg-white/[0.05] text-zinc-300 border-white/10",
};

export function Chip({ tone = "neutral", children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium leading-5", TONES[tone], className)}>
      {children}
    </span>
  );
}

type Variant = "primary" | "glass" | "danger" | "pay";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-sys-blue text-white hover:bg-[#1a82f0] shadow-[0_8px_24px_-8px_rgb(0_113_227/0.7)]",
  glass: "bg-white/[0.06] text-zinc-100 border border-white/10 hover:bg-white/[0.1]",
  danger: "bg-sys-red/90 text-white hover:bg-sys-red",
  pay: "bg-white text-black hover:bg-zinc-200 shadow-[0_8px_24px_-10px_rgb(255_255_255/0.5)]",
};

/** Button with spring press and hover feedback. */
export function Button({
  variant = "glass", className, children, ...rest
}: { variant?: Variant; children: ReactNode } & Omit<HTMLMotionProps<"button">, "children">) {
  return (
    <motion.button
      whileHover={{ scale: 1.025 }}
      whileTap={{ scale: 0.965 }}
      transition={spring}
      className={cn(
        "inline-flex select-none items-center justify-center gap-2 rounded-full px-4 py-2 text-sm font-medium outline-none transition-colors",
        "focus-visible:ring-2 focus-visible:ring-sys-blue/70 disabled:cursor-not-allowed disabled:opacity-40",
        VARIANTS[variant], className,
      )}
      {...rest}
    >
      {children}
    </motion.button>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("h-4 w-4 animate-spin", className)} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-2xl bg-white/[0.05]", className)} />;
}

export function SectionTitle({ eyebrow, title, hint, id }: { eyebrow: string; title: string; hint?: ReactNode; id?: string }) {
  return (
    <div id={id} className="mb-6 flex scroll-mt-28 flex-wrap items-end justify-between gap-3">
      <div>
        <p className="text-xs font-medium uppercase tracking-[0.14em] text-zinc-500">{eyebrow}</p>
        <h2 className="mt-1 text-2xl font-semibold tracking-tight text-zinc-100 sm:text-3xl">{title}</h2>
      </div>
      {hint}
    </div>
  );
}

export const Icon = {
  shield: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M12 2.5 4.5 5.5v6c0 4.6 3.1 8.3 7.5 10 4.4-1.7 7.5-5.4 7.5-10v-6L12 2.5Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="m8.8 12.2 2.4 2.4 4.2-4.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  hazard: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M12 3.2 2.6 19.5a1 1 0 0 0 .9 1.5h17a1 1 0 0 0 .9-1.5L12 3.2Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M12 9.5v4.6M12 17.2h.01" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
    </svg>
  ),
  question: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <circle cx="12" cy="12" r="9.2" stroke="currentColor" strokeWidth="1.6" />
      <path d="M9.6 9.4a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1.1.9-1.1 1.7M12 16.8h.01" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  ),
  search: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <circle cx="11" cy="11" r="6.5" stroke="currentColor" strokeWidth="1.8" />
      <path d="m16 16 4.5 4.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  ),
  chevron: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="m6 9 6 6 6-6" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  external: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M14 4h6v6M20 4l-9 9M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  close: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M6 6l12 12M18 6 6 18" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
    </svg>
  ),
  plus: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M12 5v14M5 12h14" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
    </svg>
  ),
};
