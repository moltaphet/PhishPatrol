import { cn } from "./ui";

/** Deterministic hue per brand so cards and badges stay visually stable. */
export function brandHue(name: string): number {
  let h = 0;
  for (const c of name) h = (h * 31 + c.charCodeAt(0)) % 360;
  return h;
}

export function BrandBadge({ name, size = "md", className }: { name: string; size?: "sm" | "md" | "lg"; className?: string }) {
  const hue = brandHue(name);
  const dim = { sm: "h-7 w-7 text-xs rounded-lg", md: "h-10 w-10 text-base rounded-xl", lg: "h-12 w-12 text-lg rounded-2xl" }[size];
  return (
    <span
      aria-hidden
      className={cn("grid shrink-0 place-items-center font-semibold text-white shadow-inner", dim, className)}
      style={{ background: `linear-gradient(145deg, hsl(${hue} 80% 58%), hsl(${(hue + 40) % 360} 75% 38%))` }}
    >
      {name.slice(0, 1).toUpperCase()}
    </span>
  );
}
