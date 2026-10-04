import { ATTO } from "./config";

/** Wei to a short GEN string, trimming trailing zeros. */
export function formatGen(wei: bigint, maxDecimals = 3): string {
  const whole = wei / ATTO;
  const frac = wei % ATTO;
  if (frac === BigInt(0)) return whole.toString();
  const digits = frac.toString().padStart(18, "0").slice(0, maxDecimals).replace(/0+$/, "");
  return digits === "" ? whole.toString() : `${whole}.${digits}`;
}

/** Parses a decimal GEN amount to wei; returns null when invalid. */
export function parseGen(input: string): bigint | null {
  if (!/^\d+(\.\d{1,18})?$/.test(input.trim())) return null;
  const [w, f = ""] = input.trim().split(".");
  return BigInt(w) * ATTO + BigInt(f.padEnd(18, "0"));
}

export function shortHash(h: string, head = 8, tail = 6): string {
  return h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;
}

export function timeAgo(unixSeconds: number): string {
  if (!unixSeconds) return "";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
